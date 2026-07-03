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
    /// `scg-cpu` (the gateway's pinned core pool — or its hottest single thread —
    /// is saturated: the SCG *is* the limit, trustworthy), `scg` (harness has
    /// ≥ HEADROOM_MIN margin, so the SCG is the limit), `host-saturated` (low
    /// headroom with the whole host busy — loopback co-saturation; the number is
    /// a lower bound and `harness_limited` stays set), or `harness-io` (low
    /// headroom *and* no CPU signal explains it — the number is suspect and
    /// `harness_limited` is set).
    pub bottleneck: &'static str,
    /// Which null-loopback transport measured the ceiling (`tcp`, `udp`,
    /// `uds-null`, `shm-null`) — every row self-documents its ceiling
    /// provenance, including a TCP fallback after a failed null-transport probe.
    pub ceiling_transport: &'static str,
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
            ceiling_transport: "tcp",
        }
    }

    /// Record which transport measured this calibration's ceiling.
    pub fn with_transport(mut self, name: &'static str) -> Self {
        self.ceiling_transport = name;
        self
    }

    /// SCG in the path, no CPU signal available: flag the scenario purely on the
    /// throughput headroom gate.
    pub fn for_scg(ceiling_gbps: f64, measured_gbps: f64) -> Self {
        let (harness_limited, bottleneck) = classify(ceiling_gbps, measured_gbps, None);
        warn_if_suspect_ceiling(ceiling_gbps, measured_gbps);
        Calibration {
            ceiling_gbps,
            headroom: headroom(ceiling_gbps, measured_gbps),
            harness_limited,
            dut: "scg",
            bottleneck,
            ceiling_transport: "tcp",
        }
    }

    /// SCG in the path *with* gateway/host CPU signals. When the gateway's
    /// pinned cores — or its hottest single thread — are saturated, the SCG is
    /// genuinely the bottleneck, so the result is trusted even if throughput
    /// headroom is small (the routing case, where the SCG adds near-zero
    /// overhead and the harness can never show 3× headroom).
    pub fn for_scg_with_cpu(ceiling_gbps: f64, measured_gbps: f64, cpu: &CpuSignals) -> Self {
        let (harness_limited, bottleneck) = classify(ceiling_gbps, measured_gbps, Some(cpu));
        warn_if_suspect_ceiling(ceiling_gbps, measured_gbps);
        Calibration {
            ceiling_gbps,
            headroom: headroom(ceiling_gbps, measured_gbps),
            harness_limited,
            dut: "scg",
            bottleneck,
            ceiling_transport: "tcp",
        }
    }
}

/// Fraction of a pinned core pool above which we call the gateway CPU-bound.
const CPU_SATURATION_RATIO: f64 = 0.85;

/// Hottest single gateway thread at or above this % of one core (p95 over the
/// sampled ticks) means the serial per-connection data plane is pegged — the
/// SCG is the limit even when its pool-wide total looks idle. The 10 % margin
/// absorbs sampler tick quantization and scheduler preemption.
pub const HOT_THREAD_SATURATION_PCT: f64 = 90.0;

/// Whole host busy at or above this fraction (p95) means loopback
/// co-saturation: sender, receiver, and gateway together exhaust the machine,
/// so no harness improvement could produce more headroom. The measurement is a
/// lower bound imposed by single-host physics.
pub const HOST_SATURATION_FRAC: f64 = 0.90;

/// CPU signals feeding [`classify`], aggregated over a scenario's sampled
/// ticks (p95, so a single-tick spike cannot flip the classification and
/// cooldown ticks cannot dilute it).
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuSignals {
    /// Gateway CPU% summed across its threads/PIDs (100 == one full core).
    pub gw_pool_pct_p95: f64,
    /// Size of the gateway's pinned core pool (0 = unpinned).
    pub gw_pool_cores: usize,
    /// CPU% of the hottest single gateway thread (100 == one full core).
    pub gw_hot_thread_pct_p95: f64,
    /// Whole-host busy fraction, 0..1.
    pub host_busy_frac_p95: f64,
}

/// Decide `(harness_limited, bottleneck)` from headroom and optional CPU
/// signals. Precedence: gateway pool saturated → `scg-cpu`; hottest gateway
/// thread pegged → `scg-cpu`; enough headroom → `scg`; host saturated →
/// `host-saturated` (still harness-limited: the number is a trustworthy lower
/// bound but not a demonstrated gateway limit); else `harness-io`.
fn classify(
    ceiling_gbps: f64,
    measured_gbps: f64,
    cpu: Option<&CpuSignals>,
) -> (bool, &'static str) {
    if let Some(c) = cpu {
        let capacity_pct = c.gw_pool_cores.max(1) as f64 * 100.0;
        if c.gw_pool_pct_p95 >= CPU_SATURATION_RATIO * capacity_pct {
            // The gateway's cores are pegged: the SCG is the bottleneck.
            return (false, "scg-cpu");
        }
        if c.gw_hot_thread_pct_p95 >= HOT_THREAD_SATURATION_PCT {
            // One relay thread is pegged: the gateway's serial data plane is
            // the bottleneck regardless of how idle the rest of its pool is.
            return (false, "scg-cpu");
        }
    }
    if headroom(ceiling_gbps, measured_gbps) >= HEADROOM_MIN {
        return (false, "scg");
    }
    if let Some(c) = cpu {
        if c.host_busy_frac_p95 >= HOST_SATURATION_FRAC {
            return (true, "host-saturated");
        }
    }
    (true, "harness-io")
}

/// A measured throughput *well* above the harness's own ceiling means the
/// probe ran under easier or slower conditions than the scenario — warn loudly
/// so a miscalibration can never pass silently again.
///
/// A small overshoot (headroom just below 1.0) is legitimate on near-
/// transparent gateway paths: the sender→gateway→receiver relay is a
/// three-stage pipeline whose kernel work spreads across more cores than the
/// two-thread null probe, so a passthrough gateway can slightly out-pipeline
/// the direct pair. The margin below distinguishes that effect from a broken
/// probe.
const SUSPECT_CEILING_RATIO: f64 = 0.85;

fn warn_if_suspect_ceiling(ceiling_gbps: f64, measured_gbps: f64) {
    if measured_gbps > 0.0 && headroom(ceiling_gbps, measured_gbps) < SUSPECT_CEILING_RATIO {
        log::warn!(
            "suspect ceiling: measured {measured_gbps:.3} Gbit/s far exceeds the harness \
             ceiling {ceiling_gbps:.3} Gbit/s — the calibration probe under-measured \
             the harness's ability for this shape"
        );
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

/// Warmup before each ceiling measurement window. TCP is the binding case
/// (loopback buffer autotuning and allocator warm paths settle well within
/// this); one constant keeps probes comparable across transports.
pub const CEILING_WARMUP: Duration = Duration::from_millis(500);

/// Ceiling measurement window per probe — millions of messages at loopback
/// rates, so sampling error sits far below run-to-run variance.
pub const CEILING_MEASURE: Duration = Duration::from_millis(1000);

/// Best-of-N probes per shape; the max is the ceiling. Probe noise (scheduler
/// interference, page faults) is strictly one-sided — it can only depress a
/// probe below the harness's true ability, never lift it above — so max-of-N
/// is a from-below estimator that cannot overstate the harness.
pub const CEILING_PROBES: usize = 2;

/// Everything a ceiling probe needs to run under the *same conditions* as the
/// scenario it calibrates: shape (size, connections) and, critically, the same
/// sender/receiver core pools. An unpinned or unwarmed probe measures a
/// different harness than the one driving the scenario — the root cause of
/// "impossible" headroom < 1.0 rows.
#[derive(Debug, Clone)]
pub struct ProbeSpec<'a> {
    pub message_bytes: u32,
    pub connections: usize,
    pub warmup: Duration,
    pub measure: Duration,
    pub probes: usize,
    pub sender_cores: &'a [usize],
    pub receiver_cores: &'a [usize],
}

impl<'a> ProbeSpec<'a> {
    /// Probe spec matching a scenario's run parameters (same shape and core
    /// pools) with the canonical warmup/measure/probe-count constants.
    pub fn for_params(params: &'a RunParams) -> Self {
        ProbeSpec {
            message_bytes: params.message_bytes,
            connections: params.connections,
            warmup: CEILING_WARMUP,
            measure: CEILING_MEASURE,
            probes: CEILING_PROBES,
            sender_cores: &params.sender_cores,
            receiver_cores: &params.receiver_cores,
        }
    }
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

/// Engine parameters for one ceiling probe run (pure builder, unit-tested).
fn probe_params(spec: &ProbeSpec) -> RunParams {
    RunParams {
        message_bytes: spec.message_bytes,
        connections: spec.connections.max(1),
        runs: 1,
        warmup: spec.warmup,
        measure: spec.measure,
        cooldown: Duration::ZERO,
        remove_outliers: false,
        sender_cores: spec.sender_cores.to_vec(),
        receiver_cores: spec.receiver_cores.to_vec(),
        sender: ceiling_sender(),
        mode: engine::RunMode::Throughput,
    }
}

/// Measure the harness's null-loopback ceiling: `spec.probes` unthrottled runs
/// over the given transport, pinned to the spec's core pools and preceded by
/// the spec's warmup, keeping the **best** probe. Throughput counts *received*
/// bytes, so this reflects what the harness can both generate and absorb.
pub fn measure_ceiling(transport: &dyn Transport, spec: &ProbeSpec) -> io::Result<Ceiling> {
    let params = probe_params(spec);
    let mut best_gbps = 0.0_f64;
    let mut best_rate = 0.0_f64;
    for _ in 0..spec.probes.max(1) {
        let (fs, _handshake_us, _lag) = engine::run_once(transport, &params)?;
        if fs.throughput_gbps > best_gbps {
            best_gbps = fs.throughput_gbps;
            best_rate = fs.message_rate;
        }
    }
    Ok(Ceiling {
        transport: transport.name(),
        message_bytes: spec.message_bytes,
        connections: params.connections,
        throughput_gbps: best_gbps,
        message_rate: best_rate,
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
        assert_eq!(bad.bottleneck, "harness-io");
    }

    #[test]
    fn classify_pool_saturation_marks_scg_cpu() {
        let cpu = CpuSignals {
            gw_pool_pct_p95: 0.86 * 4.0 * 100.0, // 4-core pool at 86%
            gw_pool_cores: 4,
            gw_hot_thread_pct_p95: 0.0,
            host_busy_frac_p95: 0.0,
        };
        assert_eq!(classify(10.0, 9.0, Some(&cpu)), (false, "scg-cpu"));
    }

    #[test]
    fn classify_hot_thread_saturation_marks_scg_cpu() {
        // Pool-wide the gateway looks idle (2 busy threads on a 16-core pool),
        // but one relay thread is pegged: the SCG is the genuine bottleneck.
        let cpu = CpuSignals {
            gw_pool_pct_p95: 200.0,
            gw_pool_cores: 16,
            gw_hot_thread_pct_p95: 95.0,
            host_busy_frac_p95: 0.0,
        };
        assert_eq!(classify(10.0, 9.0, Some(&cpu)), (false, "scg-cpu"));
    }

    #[test]
    fn classify_host_saturated_flags_with_label() {
        // Low headroom, gateway not saturated, but the whole host is: the row
        // stays harness-limited (lower bound) under the distinct label.
        let cpu = CpuSignals {
            gw_pool_pct_p95: 200.0,
            gw_pool_cores: 16,
            gw_hot_thread_pct_p95: 50.0,
            host_busy_frac_p95: 0.95,
        };
        assert_eq!(classify(10.0, 9.0, Some(&cpu)), (true, "host-saturated"));
    }

    #[test]
    fn classify_precedence_and_boundaries() {
        // Headroom ≥ 3× wins over host saturation (scg, not host-saturated).
        let host_hot = CpuSignals {
            gw_pool_pct_p95: 0.0,
            gw_pool_cores: 16,
            gw_hot_thread_pct_p95: 0.0,
            host_busy_frac_p95: 1.0,
        };
        assert_eq!(classify(10.0, 2.0, Some(&host_hot)), (false, "scg"));
        // Exactly at the hot-thread threshold classifies scg-cpu.
        let at_hot = CpuSignals {
            gw_hot_thread_pct_p95: HOT_THREAD_SATURATION_PCT,
            gw_pool_cores: 16,
            ..Default::default()
        };
        assert_eq!(classify(10.0, 9.0, Some(&at_hot)), (false, "scg-cpu"));
        // Just below every CPU threshold with low headroom → harness-io.
        let below = CpuSignals {
            gw_pool_pct_p95: 100.0,
            gw_pool_cores: 16,
            gw_hot_thread_pct_p95: HOT_THREAD_SATURATION_PCT - 0.1,
            host_busy_frac_p95: HOST_SATURATION_FRAC - 0.01,
        };
        assert_eq!(classify(10.0, 9.0, Some(&below)), (true, "harness-io"));
        // Exactly at the headroom gate is trusted.
        assert_eq!(classify(9.0, 3.0, None), (false, "scg"));
    }

    #[test]
    fn record_overhead_is_small() {
        let ns = record_overhead_ns(100_000);
        // A couple of vector pushes; comfortably sub-microsecond per sample.
        assert!(ns >= 0.0);
        assert!(ns < 1_000.0, "record overhead too high: {ns} ns/sample");
    }

    /// Small, fast probe spec for tests.
    fn quick_spec(message_bytes: u32) -> ProbeSpec<'static> {
        ProbeSpec {
            message_bytes,
            connections: 1,
            warmup: Duration::from_millis(20),
            measure: Duration::from_millis(150),
            probes: 1,
            sender_cores: &[],
            receiver_cores: &[],
        }
    }

    #[test]
    fn probe_params_carries_shape_cores_and_warmup() {
        let spec = ProbeSpec {
            message_bytes: 512,
            connections: 3,
            warmup: Duration::from_millis(500),
            measure: Duration::from_millis(1000),
            probes: 2,
            sender_cores: &[1, 2],
            receiver_cores: &[3],
        };
        let p = probe_params(&spec);
        assert_eq!(p.message_bytes, 512);
        assert_eq!(p.connections, 3);
        assert_eq!(p.warmup, Duration::from_millis(500));
        assert_eq!(p.measure, Duration::from_millis(1000));
        assert_eq!(p.sender_cores, vec![1, 2]);
        assert_eq!(p.receiver_cores, vec![3]);
        assert_eq!(p.runs, 1);
    }

    #[test]
    fn probe_spec_for_params_mirrors_run_params() {
        let rp = probe_params(&ProbeSpec {
            message_bytes: 256,
            connections: 2,
            warmup: Duration::ZERO,
            measure: Duration::from_millis(100),
            probes: 1,
            sender_cores: &[5],
            receiver_cores: &[6],
        });
        let spec = ProbeSpec::for_params(&rp);
        assert_eq!(spec.message_bytes, 256);
        assert_eq!(spec.connections, 2);
        assert_eq!(spec.warmup, CEILING_WARMUP);
        assert_eq!(spec.measure, CEILING_MEASURE);
        assert_eq!(spec.probes, CEILING_PROBES);
        assert_eq!(spec.sender_cores, &[5]);
        assert_eq!(spec.receiver_cores, &[6]);
    }

    #[test]
    fn tcp_ceiling_is_positive() {
        let c = measure_ceiling(&TcpTransport, &quick_spec(1024)).unwrap();
        assert_eq!(c.transport, "tcp");
        assert!(c.throughput_gbps > 0.0);
        assert!(c.message_rate > 0.0);
    }

    #[test]
    fn udp_ceiling_is_measured() {
        let c = measure_ceiling(&UdpTransport, &quick_spec(256)).unwrap();
        assert_eq!(c.transport, "udp");
        // UDP may drop under a max-speed blast; throughput is whatever is absorbed.
        assert!(c.throughput_gbps >= 0.0);
    }
}
