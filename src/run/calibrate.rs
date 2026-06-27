//! NFR-PERF calibration & headroom gate (WP1.7).
//!
//! The harness must never be the bottleneck — every reported number must
//! reflect the SCG's limit, not SESHAT's. This module measures the harness's
//! own null/loopback **ceiling** (max throughput it can generate *and* absorb
//! for a given message size and connection count) and compares it against the
//! throughput measured through the device under test:
//!
//! ```text
//!   headroom = ceiling_throughput / measured_throughput
//! ```
//!
//! When an SCG is in the path and `headroom < HEADROOM_MIN`, the harness is too
//! close to its own ceiling for the measurement to be trusted, and the scenario
//! is flagged `HARNESS-LIMITED`. It also quantifies the per-sample cost of the
//! off-hot-path statistics recording so we can show instrumentation overhead is
//! negligible relative to network latency.
#![allow(dead_code)] // consumed by the `calibrate` command and run integration.

use std::io;
use std::time::Duration;

use crate::config::{Interface, Pattern, Sender};
use crate::metrics::app::FlowMetrics;
use crate::run::engine::{self, RunParams};
use crate::time::monotonic_ns;
use crate::transport::Transport;

/// Minimum acceptable headroom: the harness must sustain at least this multiple
/// of the measured throughput (the plan's 3–5× rule, conservative lower bound).
pub const HEADROOM_MIN: f64 = 3.0;

/// A measured harness throughput ceiling for one (transport, size, conns) point.
#[derive(Debug, Clone)]
pub struct Ceiling {
    pub transport: &'static str,
    pub message_bytes: u32,
    pub connections: usize,
    pub throughput_gbps: f64,
    pub message_rate: f64,
}

/// Headroom outcome attached to a scenario result.
#[derive(Debug, Clone)]
pub struct Calibration {
    /// Harness ceiling throughput for this scenario's shape (Gbit/s).
    pub ceiling_gbps: f64,
    /// ceiling / measured.
    pub headroom: f64,
    /// Whether the scenario is harness-limited (only meaningful with an SCG).
    pub harness_limited: bool,
    /// Device under test: `loopback` (Phase 1 baseline) or `scg` (Phase 2+).
    pub dut: &'static str,
    /// Where the throughput limit most plausibly sits: `n/a` (loopback baseline),
    /// `scg-cpu` (the gateway's pinned cores are saturated — the SCG *is* the
    /// limit, trustworthy), `scg` (harness has ≥ HEADROOM_MIN margin, so the SCG
    /// is the limit), or `harness-io` (low headroom *and* the SCG is not CPU
    /// bound — the number is suspect and `harness_limited` is set).
    pub bottleneck: &'static str,
}

impl Calibration {
    /// Baseline: no SCG in the path, so the measured value *is* the loopback;
    /// headroom is informational and the harness-limited flag is never set.
    pub fn baseline(ceiling_gbps: f64, measured_gbps: f64) -> Self {
        Calibration {
            ceiling_gbps,
            headroom: headroom(ceiling_gbps, measured_gbps),
            harness_limited: false,
            dut: "loopback",
            bottleneck: "n/a",
        }
    }

    /// SCG in the path, no CPU signal available: flag the scenario purely on the
    /// throughput headroom gate.
    pub fn for_scg(ceiling_gbps: f64, measured_gbps: f64) -> Self {
        let (harness_limited, bottleneck) = classify(ceiling_gbps, measured_gbps, None);
        Calibration {
            ceiling_gbps,
            headroom: headroom(ceiling_gbps, measured_gbps),
            harness_limited,
            dut: "scg",
            bottleneck,
        }
    }

    /// SCG in the path *with* a gateway-CPU signal. When the gateway's pinned
    /// cores are saturated the SCG is genuinely the bottleneck, so the result is
    /// trusted even if throughput headroom is small (the routing case, where the
    /// SCG adds near-zero overhead and the harness can never show 3× headroom).
    pub fn for_scg_with_cpu(
        ceiling_gbps: f64,
        measured_gbps: f64,
        gw_cpu_peak_pct: f64,
        gw_core_count: usize,
    ) -> Self {
        let (harness_limited, bottleneck) = classify(
            ceiling_gbps,
            measured_gbps,
            Some((gw_cpu_peak_pct, gw_core_count)),
        );
        Calibration {
            ceiling_gbps,
            headroom: headroom(ceiling_gbps, measured_gbps),
            harness_limited,
            dut: "scg",
            bottleneck,
        }
    }
}

/// Fraction of a pinned core pool above which we call the gateway CPU-bound.
const CPU_SATURATION_RATIO: f64 = 0.85;

/// Decide `(harness_limited, bottleneck)` from headroom and an optional gateway
/// CPU signal `(peak_cpu_pct, core_count)` where `peak_cpu_pct` is summed across
/// the gateway's threads (100 % == one full core).
fn classify(
    ceiling_gbps: f64,
    measured_gbps: f64,
    cpu: Option<(f64, usize)>,
) -> (bool, &'static str) {
    if let Some((peak_pct, cores)) = cpu {
        let capacity_pct = cores.max(1) as f64 * 100.0;
        if peak_pct >= CPU_SATURATION_RATIO * capacity_pct {
            // The gateway's cores are pegged: the SCG is the bottleneck.
            return (false, "scg-cpu");
        }
    }
    if headroom(ceiling_gbps, measured_gbps) >= HEADROOM_MIN {
        (false, "scg")
    } else {
        (true, "harness-io")
    }
}

/// `ceiling / measured`, or +∞ if measured is zero.
pub fn headroom(ceiling_gbps: f64, measured_gbps: f64) -> f64 {
    if measured_gbps <= 0.0 {
        f64::INFINITY
    } else {
        ceiling_gbps / measured_gbps
    }
}

/// Whether the harness ceiling is too close to the measured throughput.
pub fn is_harness_limited(ceiling_gbps: f64, measured_gbps: f64) -> bool {
    headroom(ceiling_gbps, measured_gbps) < HEADROOM_MIN
}

/// A maximum-speed (unthrottled, sustained) sender for ceiling probing.
fn ceiling_sender() -> Sender {
    Sender {
        interface: Interface::Tcp, // unused by the engine (transport is explicit)
        target_addr: String::new(),
        pattern: Pattern::Sustained,
        rate_limit_mbps: None,
        interval_us: None,
        burst_count: None,
        burst_pause_us: None,
        ramp_start_mbps: None,
        ramp_step_mbps: None,
        ramp_step_interval_secs: None,
    }
}

/// Measure the harness's null-loopback ceiling: a single unthrottled run over
/// the given transport with no warmup/cooldown. Throughput counts *received*
/// bytes, so this reflects what the harness can both generate and absorb.
pub fn measure_ceiling(
    transport: &dyn Transport,
    message_bytes: u32,
    connections: usize,
    duration: Duration,
) -> io::Result<Ceiling> {
    let params = RunParams {
        message_bytes,
        connections: connections.max(1),
        runs: 1,
        warmup: Duration::ZERO,
        measure: duration,
        cooldown: Duration::ZERO,
        remove_outliers: false,
        sender_cores: Vec::new(),
        receiver_cores: Vec::new(),
        sender: ceiling_sender(),
        mode: engine::RunMode::Throughput,
    };
    let (fs, _handshake_us, _lag) = engine::run_once(transport, &params)?;
    Ok(Ceiling {
        transport: transport.name(),
        message_bytes,
        connections: params.connections,
        throughput_gbps: fs.throughput_gbps,
        message_rate: fs.message_rate,
    })
}

/// Average nanoseconds to record one sample into [`FlowMetrics`] — the only
/// per-message work the measurement path adds beyond a bare timestamp. With
/// pre-allocated buffers this is a couple of vector pushes; reporting it proves
/// the statistics path is off the hot path (NFR-PERF).
pub fn record_overhead_ns(iters: u64) -> f64 {
    if iters == 0 {
        return 0.0;
    }
    let mut m = FlowMetrics::with_capacity(iters as usize);
    let t0 = monotonic_ns();
    for i in 0..iters {
        m.record(i, 1_000, 1_400);
    }
    let dt = monotonic_ns().saturating_sub(t0);
    // Prevent the optimizer from eliding the loop.
    std::hint::black_box(&m);
    dt as f64 / iters as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{tcp::TcpTransport, udp::UdpTransport};

    #[test]
    fn headroom_math() {
        assert_eq!(headroom(10.0, 2.0), 5.0);
        assert!(headroom(10.0, 0.0).is_infinite());
        assert!(!is_harness_limited(10.0, 2.0)); // 5x ok
        assert!(is_harness_limited(10.0, 5.0)); // 2x < 3x
        assert!(is_harness_limited(10.0, 4.0)); // 2.5x < 3x
    }

    #[test]
    fn calibration_baseline_never_flags() {
        let c = Calibration::baseline(1.0, 1.0);
        assert!(!c.harness_limited);
        assert_eq!(c.dut, "loopback");
    }

    #[test]
    fn calibration_scg_flags_low_headroom() {
        let ok = Calibration::for_scg(10.0, 2.0);
        assert!(!ok.harness_limited);
        assert_eq!(ok.dut, "scg");
        let bad = Calibration::for_scg(10.0, 9.0);
        assert!(bad.harness_limited);
    }

    #[test]
    fn record_overhead_is_small() {
        let ns = record_overhead_ns(100_000);
        // A couple of vector pushes; comfortably sub-microsecond per sample.
        assert!(ns >= 0.0);
        assert!(ns < 1_000.0, "record overhead too high: {ns} ns/sample");
    }

    #[test]
    fn tcp_ceiling_is_positive() {
        let c = measure_ceiling(&TcpTransport, 1024, 1, Duration::from_millis(300)).unwrap();
        assert_eq!(c.transport, "tcp");
        assert!(c.throughput_gbps > 0.0);
        assert!(c.message_rate > 0.0);
    }

    #[test]
    fn udp_ceiling_is_measured() {
        let c = measure_ceiling(&UdpTransport, 256, 1, Duration::from_millis(300)).unwrap();
        assert_eq!(c.transport, "udp");
        // UDP may drop under a max-speed blast; throughput is whatever is absorbed.
        assert!(c.throughput_gbps >= 0.0);
    }
}
