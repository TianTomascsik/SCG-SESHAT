//! Application-level metrics (F-13a): throughput, latency, jitter, loss,
//! duplication, and reordering, derived purely from the [`WireHeader`] of each
//! received message.
//!
//! ## Hot path vs. cold path (NFR-PERF)
//! The receiver's hot path does the minimum: stamp `recv_ns` immediately and
//! push `(seq, latency)` into a pre-grown buffer — no sorting, no map lookups,
//! no allocation per message. All aggregation (percentiles, loss/dup/reorder)
//! happens here in [`FlowMetrics::finish`], off the hot path, after the run.
//!
//! ## Definitions
//! * **latency** — `recv_ns - hdr.ts_ns` (one-way, monotonic, same host).
//! * **loss** — `(max_seq - min_seq + 1) - distinct_received`, i.e. gaps in the
//!   sequence space that never arrived.
//! * **duplicate** — `received - distinct` (same seq seen more than once).
//! * **reorder** — arrivals whose seq is lower than a previously seen arrival
//!   (out-of-order delivery).
//! * **jitter** — mean absolute difference between consecutive latencies
//!   (packet delay variation), in the same unit as latency.
#![allow(dead_code)]

use std::collections::HashSet;

use serde::Serialize;

use super::stats::{self, Summary};

/// Throughput in **decimal** gigabits per second (`bytes * 8 / 1e9 / secs`).
///
/// We use decimal Gbit/s (not GiB/s) to match the SCG e2e-benchmark convention;
/// do not mix the two when comparing numbers.
pub fn throughput_gbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / 1e9 / secs
}

/// Messages per second.
pub fn message_rate(messages: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    messages as f64 / secs
}

/// Sequence-integrity counters derived from the received seq stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Integrity {
    pub received: u64,
    pub distinct: u64,
    pub lost: u64,
    pub duplicate: u64,
    pub reordered: u64,
}

/// Compute loss / duplicate / reorder counts from arrival-ordered seqs.
pub fn integrity(seqs: &[u64]) -> Integrity {
    if seqs.is_empty() {
        return Integrity {
            received: 0,
            distinct: 0,
            lost: 0,
            duplicate: 0,
            reordered: 0,
        };
    }
    let mut seen: HashSet<u64> = HashSet::with_capacity(seqs.len());
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut reordered = 0u64;
    let mut prev = seqs[0];
    for (i, &s) in seqs.iter().enumerate() {
        seen.insert(s);
        min = min.min(s);
        max = max.max(s);
        if i > 0 && s < prev {
            reordered += 1;
        }
        prev = s;
    }
    let received = seqs.len() as u64;
    let distinct = seen.len() as u64;
    let span = max - min + 1;
    // Distinct can never exceed the span, so this never underflows.
    let lost = span.saturating_sub(distinct);
    let duplicate = received - distinct;
    Integrity {
        received,
        distinct,
        lost,
        duplicate,
        reordered,
    }
}

/// Mean absolute difference between consecutive latency samples (jitter / PDV).
pub fn jitter(latencies: &[f64]) -> f64 {
    if latencies.len() < 2 {
        return 0.0;
    }
    let mut acc = 0.0;
    for w in latencies.windows(2) {
        acc += (w[1] - w[0]).abs();
    }
    acc / (latencies.len() - 1) as f64
}

/// Accumulator fed by the receiver, one per measured flow/stream.
///
/// `latencies_us` and `seqs` grow together (one entry per received message).
/// The vectors are the only per-message storage and are reserved up front by
/// [`FlowMetrics::with_capacity`] to avoid reallocation on the hot path.
#[derive(Debug, Default)]
pub struct FlowMetrics {
    latencies_us: Vec<f64>,
    seqs: Vec<u64>,
    bytes: u64,
    /// Wall duration of the measured window in seconds (set by the engine).
    duration_s: f64,
}

impl FlowMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-allocate storage for an expected message count.
    pub fn with_capacity(cap: usize) -> Self {
        FlowMetrics {
            latencies_us: Vec::with_capacity(cap),
            seqs: Vec::with_capacity(cap),
            bytes: 0,
            duration_s: 0.0,
        }
    }

    /// Record one received message: its sequence number, one-way latency in
    /// nanoseconds, and total wire bytes (header + payload).
    #[inline]
    pub fn record(&mut self, seq: u64, latency_ns: u64, wire_bytes: u64) {
        self.seqs.push(seq);
        self.latencies_us.push(latency_ns as f64 / 1000.0);
        self.bytes += wire_bytes;
    }

    /// Number of messages recorded so far.
    pub fn len(&self) -> usize {
        self.seqs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seqs.is_empty()
    }

    /// Recorded per-message latencies, microseconds (arrival order).
    pub fn latencies_us(&self) -> &[f64] {
        &self.latencies_us
    }

    /// Recorded sequence numbers (arrival order).
    pub fn seqs(&self) -> &[u64] {
        &self.seqs
    }

    /// Total wire bytes recorded.
    pub fn byte_count(&self) -> u64 {
        self.bytes
    }

    /// Set the measured-window duration used for throughput/rate.
    pub fn set_duration(&mut self, secs: f64) {
        self.duration_s = secs;
    }

    /// Finalise into a [`FlowSummary`], optionally removing latency outliers
    /// (Tukey IQR) before computing latency statistics. The removed-count is
    /// reported either way.
    pub fn finish(&self, remove_outliers: bool) -> FlowSummary {
        let integ = integrity(&self.seqs);
        let (lat_samples, outliers_removed) = if remove_outliers {
            stats::remove_outliers_iqr(&self.latencies_us)
        } else {
            (self.latencies_us.clone(), 0)
        };
        let latency_us = stats::summarize(&lat_samples);
        let jitter_us = jitter(&self.latencies_us);
        let messages = self.seqs.len() as u64;
        let loss_pct = if integ.received + integ.lost > 0 {
            integ.lost as f64 / (integ.distinct + integ.lost) as f64 * 100.0
        } else {
            0.0
        };
        FlowSummary {
            messages,
            bytes: self.bytes,
            duration_s: self.duration_s,
            throughput_gbps: throughput_gbps(self.bytes, self.duration_s),
            message_rate: message_rate(messages, self.duration_s),
            latency_us,
            jitter_us,
            integrity: integ,
            loss_pct,
            outliers_removed,
        }
    }
}

/// The finalised metrics for one flow over one measured window.
#[derive(Debug, Clone, Serialize)]
pub struct FlowSummary {
    pub messages: u64,
    pub bytes: u64,
    pub duration_s: f64,
    pub throughput_gbps: f64,
    pub message_rate: f64,
    /// Latency distribution, microseconds.
    pub latency_us: Summary,
    /// Packet delay variation (mean |Δlatency|), microseconds.
    pub jitter_us: f64,
    pub integrity: Integrity,
    pub loss_pct: f64,
    pub outliers_removed: usize,
}

/// Combine several per-connection [`FlowMetrics`] into one run-level summary.
///
/// Latency samples are pooled across connections for a single distribution;
/// integrity counters are computed per connection (each has its own sequence
/// space) and summed; throughput is total bytes over the measured window.
pub fn aggregate_run(
    metrics: &[FlowMetrics],
    duration_s: f64,
    remove_outliers: bool,
) -> FlowSummary {
    let mut all_lat: Vec<f64> = Vec::new();
    let mut bytes = 0u64;
    let mut integ = Integrity::default();
    let mut jitter_weighted = 0.0f64;
    let mut jitter_weight = 0u64;
    for m in metrics {
        all_lat.extend_from_slice(m.latencies_us());
        bytes += m.byte_count();
        let mi = integrity(m.seqs());
        integ.received += mi.received;
        integ.distinct += mi.distinct;
        integ.lost += mi.lost;
        integ.duplicate += mi.duplicate;
        integ.reordered += mi.reordered;
        let j = jitter(m.latencies_us());
        jitter_weighted += j * mi.received as f64;
        jitter_weight += mi.received;
    }
    let (lat_samples, outliers_removed) = if remove_outliers {
        stats::remove_outliers_iqr(&all_lat)
    } else {
        (all_lat, 0)
    };
    let latency_us = stats::summarize(&lat_samples);
    let jitter_us = if jitter_weight > 0 {
        jitter_weighted / jitter_weight as f64
    } else {
        0.0
    };
    let loss_pct = if integ.distinct + integ.lost > 0 {
        integ.lost as f64 / (integ.distinct + integ.lost) as f64 * 100.0
    } else {
        0.0
    };
    FlowSummary {
        messages: integ.received,
        bytes,
        duration_s,
        throughput_gbps: throughput_gbps(bytes, duration_s),
        message_rate: message_rate(integ.received, duration_s),
        latency_us,
        jitter_us,
        integrity: integ,
        loss_pct,
        outliers_removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() <= eps
    }

    #[test]
    fn throughput_decimal_gbps() {
        // 1.25e9 bytes in 1 s = 10 Gbit/s.
        assert!(approx(throughput_gbps(1_250_000_000, 1.0), 10.0, 1e-9));
        assert_eq!(throughput_gbps(100, 0.0), 0.0);
    }

    #[test]
    fn integrity_perfect_stream() {
        let seqs: Vec<u64> = (0..1000).collect();
        let i = integrity(&seqs);
        assert_eq!(i.received, 1000);
        assert_eq!(i.distinct, 1000);
        assert_eq!(i.lost, 0);
        assert_eq!(i.duplicate, 0);
        assert_eq!(i.reordered, 0);
    }

    #[test]
    fn integrity_with_loss() {
        // 0..10 but missing 3 and 7.
        let seqs: Vec<u64> = (0..10).filter(|s| *s != 3 && *s != 7).collect();
        let i = integrity(&seqs);
        assert_eq!(i.received, 8);
        assert_eq!(i.distinct, 8);
        assert_eq!(i.lost, 2);
        assert_eq!(i.duplicate, 0);
    }

    #[test]
    fn integrity_with_dup_and_reorder() {
        // 0,1,2,2,1,3 → distinct {0,1,2,3}=4, received 6, dup 2,
        // reorders: 2->1 (yes), so reordered counts arrivals lower than prev.
        let seqs = [0u64, 1, 2, 2, 1, 3];
        let i = integrity(&seqs);
        assert_eq!(i.received, 6);
        assert_eq!(i.distinct, 4);
        assert_eq!(i.duplicate, 2);
        assert_eq!(i.lost, 0);
        assert_eq!(i.reordered, 1); // the 2->1 step
    }

    #[test]
    fn jitter_constant_latency_is_zero() {
        assert_eq!(jitter(&[5.0, 5.0, 5.0, 5.0]), 0.0);
    }

    #[test]
    fn jitter_known() {
        // consecutive diffs: |2-1|, |4-2|, |4-4| = 1,2,0 → mean 3/3 = 1.0
        let j = jitter(&[1.0, 2.0, 4.0, 4.0]);
        assert!(approx(j, 1.0, 1e-9));
    }

    #[test]
    fn flow_metrics_end_to_end() {
        let mut m = FlowMetrics::with_capacity(100);
        for seq in 0..100u64 {
            // latency 10us each, 1024 wire bytes each
            m.record(seq, 10_000, 1024);
        }
        m.set_duration(1.0);
        let s = m.finish(true);
        assert_eq!(s.messages, 100);
        assert_eq!(s.bytes, 102_400);
        assert_eq!(s.integrity.lost, 0);
        assert!(approx(s.latency_us.mean, 10.0, 1e-9));
        assert!(approx(s.throughput_gbps, 102_400.0 * 8.0 / 1e9, 1e-12));
    }
}
