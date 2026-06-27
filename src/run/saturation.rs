//! Saturation sweep (Phase D): drive a transport at a series of fixed offered
//! loads and find where goodput stops scaling and where loss leaves a budget.
//!
//! A single fixed-load run answers "how fast did it go?"; a sweep answers the
//! more useful "how fast can it go *without* falling over?". Each point reuses
//! [`run_once`] with a sustained, rate-limited pacer, so a point is exactly the
//! engine's normal measured window — only the offered rate changes between
//! points. This is what turns a raw 66%-loss blast number into a defensible
//! "sustains X Gbit/s within a 1% loss budget" statement.
#![allow(dead_code)]

use std::io;

use crate::config::{Pattern, Sender};
use crate::transport::Transport;

use super::engine::{run_once, RunParams};

/// One offered-load point of a sweep.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SweepPoint {
    /// Offered load for this point (Mbit/s).
    pub offered_mbps: f64,
    /// Achieved goodput over the measured window (Gbit/s).
    pub throughput_gbps: f64,
    /// Loss across the window (percent of expected messages).
    pub loss_pct: f64,
    /// p99 one-way latency over the window (µs).
    pub latency_p99_us: f64,
}

/// The offered-load grid and loss budget for a sweep.
#[derive(Debug, Clone, Copy)]
pub struct SweepPlan {
    /// First offered rate (Mbit/s).
    pub start_mbps: f64,
    /// Offered-rate increment between points (Mbit/s).
    pub step_mbps: f64,
    /// Last offered rate (inclusive, Mbit/s).
    pub max_mbps: f64,
    /// Loss budget (percent) defining the lossless knee.
    pub loss_threshold_pct: f64,
}

/// Outcome of a sweep: the full curve plus the two derived headline metrics.
#[derive(Debug, Clone)]
pub struct SweepResult {
    /// Per-point curve in offered-rate order.
    pub points: Vec<SweepPoint>,
    /// Highest achieved goodput across the whole sweep (Gbit/s); the throughput
    /// ceiling beyond which offering more load yields no more goodput.
    pub saturation_gbps: f64,
    /// Highest achieved goodput at a point whose loss stayed within budget
    /// (Gbit/s); the usable capacity (0.0 if every point exceeded the budget).
    pub max_lossfree_gbps: f64,
    /// Offered load (Mbit/s) at the max-lossfree knee (0.0 if none qualified).
    pub knee_offered_mbps: f64,
}

/// Build a sustained, rate-limited sender from `base` for one sweep point.
///
/// Only `pattern`/`rate_limit_mbps` matter for a sustained pacer, so the rest of
/// the base sender (interface, target) carries through unchanged.
fn sustained_at(base: &Sender, rate_mbps: f64) -> Sender {
    let mut s = base.clone();
    s.pattern = Pattern::Sustained;
    s.rate_limit_mbps = Some(rate_mbps);
    s
}

/// Run an offered-load sweep over `transport`, one measured run per point.
///
/// Each point is a single [`run_once`] at a sustained offered rate, so the sweep
/// costs `points x (warmup + measure + cooldown)`. Points are independent and
/// the derived metrics are simple reductions over the curve, so one noisy point
/// never destabilises a brittle "knee detector".
pub fn sweep_saturation(
    transport: &dyn Transport,
    base: &RunParams,
    plan: &SweepPlan,
) -> io::Result<SweepResult> {
    // Index-based iteration avoids float-accumulation drift and makes a
    // non-positive step degrade cleanly to a single point. Capped so a
    // pathological plan can never schedule an unbounded number of runs.
    let start = plan.start_mbps.max(0.0);
    let n_points = if plan.step_mbps > 0.0 {
        ((plan.max_mbps - start).max(0.0) / plan.step_mbps).floor() as usize + 1
    } else {
        1
    }
    .min(10_000);

    let mut points = Vec::with_capacity(n_points);
    for i in 0..n_points {
        let rate = start + i as f64 * plan.step_mbps;
        let mut params = base.clone();
        params.runs = 1;
        params.sender = sustained_at(&base.sender, rate);
        let (summary, _handshake, _lag) = run_once(transport, &params)?;
        points.push(SweepPoint {
            offered_mbps: rate,
            throughput_gbps: summary.throughput_gbps,
            loss_pct: summary.loss_pct,
            latency_p99_us: summary.latency_us.p99,
        });
    }

    let saturation_gbps = points
        .iter()
        .map(|p| p.throughput_gbps)
        .fold(0.0_f64, f64::max);
    let knee = points
        .iter()
        .filter(|p| p.loss_pct <= plan.loss_threshold_pct)
        .max_by(|a, b| a.throughput_gbps.total_cmp(&b.throughput_gbps));
    let (max_lossfree_gbps, knee_offered_mbps) =
        knee.map_or((0.0, 0.0), |p| (p.throughput_gbps, p.offered_mbps));

    Ok(SweepResult {
        points,
        saturation_gbps,
        max_lossfree_gbps,
        knee_offered_mbps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;
    use crate::run::engine::RunMode;
    use crate::transport::tcp::TcpTransport;
    use std::time::Duration;

    fn base_params() -> RunParams {
        RunParams {
            message_bytes: 1024,
            connections: 1,
            runs: 3,
            warmup: Duration::from_millis(40),
            measure: Duration::from_millis(120),
            cooldown: Duration::from_millis(20),
            remove_outliers: true,
            sender_cores: vec![],
            receiver_cores: vec![],
            sender: Sender {
                interface: Interface::Tcp,
                target_addr: "127.0.0.1:0".into(),
                pattern: Pattern::Sustained,
                rate_limit_mbps: None,
                interval_us: None,
                burst_count: None,
                burst_pause_us: None,
                ramp_start_mbps: None,
                ramp_step_mbps: None,
                ramp_step_interval_secs: None,
            },
            mode: RunMode::Throughput,
        }
    }

    #[test]
    fn sweep_produces_one_point_per_rate_and_derives_metrics() {
        let plan = SweepPlan {
            start_mbps: 100.0,
            step_mbps: 100.0,
            max_mbps: 300.0,
            loss_threshold_pct: 1.0,
        };
        let result = sweep_saturation(&TcpTransport, &base_params(), &plan).unwrap();
        // 100, 200, 300 -> exactly three points, in order.
        assert_eq!(result.points.len(), 3);
        assert_eq!(result.points[0].offered_mbps, 100.0);
        assert_eq!(result.points[2].offered_mbps, 300.0);
        // TCP loopback is reliable, so every point is lossless and the lossfree
        // knee coincides with the throughput ceiling.
        assert!(result.saturation_gbps > 0.0);
        assert_eq!(result.max_lossfree_gbps, result.saturation_gbps);
        assert!(result.knee_offered_mbps >= 100.0);
    }

    #[test]
    fn sweep_with_zero_step_is_bounded() {
        let plan = SweepPlan {
            start_mbps: 50.0,
            step_mbps: 0.0,
            max_mbps: 50.0,
            loss_threshold_pct: 1.0,
        };
        // A single point (start == max) regardless of the degenerate step.
        let result = sweep_saturation(&TcpTransport, &base_params(), &plan).unwrap();
        assert_eq!(result.points.len(), 1);
    }
}
