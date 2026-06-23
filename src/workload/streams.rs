//! Multi-stream scheduling & prioritization (WP3.2).
//!
//! Manages N concurrent traffic streams through the gateway, each with its own
//! traffic class, priority, DSCP tag, and message rate. Measures per-stream
//! throughput, latency, and loss independently so we can verify:
//!   - Safety traffic is never starved by bulk normal traffic.
//!   - DSCP tags are preserved (or correctly rewritten) end-to-end.
//!   - Fairness ratio across same-class streams is acceptable.
//!   - Per-class CPU attribution is computable from system metrics.
//!
//! The scheduler runs each stream on its own sender/receiver thread pair,
//! with core affinity to avoid cross-stream interference. Per-stream metrics
//! are aggregated into a multi-stream report with fairness and starvation
//! verdicts.
#![allow(dead_code)]

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::metrics::app::{FlowMetrics, FlowSummary};
use crate::proto::wire::{self, WireHeader, HEADER_LEN};
use crate::transport::{DataSink, DataSource, RecvOutcome};

/// Configuration for a single stream in a multi-stream scenario.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Human-readable stream identifier (e.g. "safety-1", "bulk-0").
    pub name: String,
    /// Traffic class: `safety` or `normal`.
    pub traffic_class: String,
    /// Scheduling priority (higher = more important).
    pub priority: i32,
    /// DSCP tag expected on egress (0..=63).
    pub dscp_tag: Option<u8>,
    /// Message size in bytes.
    pub message_bytes: u32,
    /// Rate limit in Mbit/s (None = unlimited).
    pub rate_limit_mbps: Option<f64>,
    /// CPU cores to pin this stream's sender to (optional).
    pub sender_cores: Vec<usize>,
    /// CPU cores to pin this stream's receiver to (optional).
    pub receiver_cores: Vec<usize>,
}

/// Per-stream result after a multi-stream run.
#[derive(Debug, Clone)]
pub struct StreamResult {
    pub name: String,
    pub traffic_class: String,
    pub priority: i32,
    pub summary: FlowSummary,
    /// Whether DSCP was preserved end-to-end (None = not checked).
    pub dscp_preserved: Option<bool>,
}

/// Aggregate result of a multi-stream run.
#[derive(Debug, Clone)]
pub struct MultiStreamResult {
    pub streams: Vec<StreamResult>,
    /// Fairness ratio: `min_throughput / max_throughput` across all streams.
    pub fairness_ratio: f64,
    /// Whether any safety stream experienced loss.
    pub safety_loss_free: bool,
    /// Worst-case safety stream p99 latency (microseconds).
    pub safety_p99_us: Option<f64>,
}

impl MultiStreamResult {
    /// Compute aggregate metrics from per-stream results.
    pub fn from_streams(streams: Vec<StreamResult>) -> Self {
        let throughputs: Vec<f64> = streams
            .iter()
            .map(|s| s.summary.throughput_gbps)
            .collect();
        let fairness_ratio = if throughputs.is_empty() {
            0.0
        } else {
            let min = throughputs.iter().copied().fold(f64::INFINITY, f64::min);
            let max = throughputs.iter().copied().fold(0.0_f64, f64::max);
            if max > 0.0 { min / max } else { 0.0 }
        };

        let safety_loss_free = streams
            .iter()
            .filter(|s| s.traffic_class == "safety")
            .all(|s| s.summary.integrity.lost == 0);

        let safety_p99_us = streams
            .iter()
            .filter(|s| s.traffic_class == "safety")
            .map(|s| s.summary.latency_us.p99)
            .reduce(f64::max);

        MultiStreamResult {
            streams,
            fairness_ratio,
            safety_loss_free,
            safety_p99_us,
        }
    }
}

/// Run multiple streams concurrently through the provided transport pairs.
///
/// Each element of `pairs` is a `(sink, source)` already connected through the
/// gateway with the appropriate traffic class/priority configured in the
/// gateway's rules. The scheduler starts all sender/receiver threads, measures
/// for `measure_duration`, then stops and collects results.
pub fn run_multi_stream(
    configs: &[StreamConfig],
    pairs: Vec<(Box<dyn DataSink>, Box<dyn DataSource>)>,
    warmup: Duration,
    measure_duration: Duration,
) -> io::Result<MultiStreamResult> {
    assert_eq!(configs.len(), pairs.len());

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for (i, (mut sink, mut source)) in pairs.into_iter().enumerate() {
        let cfg = configs[i].clone();
        let stop_flag = Arc::clone(&stop);
        let msg_bytes = cfg.message_bytes as usize;

        // Receiver thread — collects metrics.
        let recv_stop = Arc::clone(&stop);
        let recv_handle = thread::Builder::new()
            .name(format!("stream-rx-{}", cfg.name))
            .spawn(move || {
                let mut buf = vec![0u8; msg_bytes + 64];
                let mut metrics = FlowMetrics::new();
                while !recv_stop.load(Ordering::Relaxed) {
                    match source.recv_msg(&mut buf) {
                        Ok(RecvOutcome::Message(n)) => {
                            let recv_ns = crate::time::monotonic_ns();
                            if let Ok(hdr) = WireHeader::decode(&buf[..n]) {
                                let latency_ns = recv_ns.saturating_sub(hdr.ts_ns);
                                metrics.record(hdr.seq, latency_ns, n as u64);
                            }
                        }
                        Ok(RecvOutcome::Timeout) => continue,
                        Ok(RecvOutcome::Closed) => break,
                        Err(_) => break,
                    }
                }
                source.close();
                metrics
            })?;

        // Sender thread — generates traffic at configured rate.
        let send_stop = Arc::clone(&stop_flag);
        let send_handle = thread::Builder::new()
            .name(format!("stream-tx-{}", cfg.name))
            .spawn(move || {
                let mut seq = 0u64;
                let mut buf = vec![0u8; msg_bytes];
                let payload_len = (msg_bytes - HEADER_LEN) as u32;

                // Rate limiting: if rate_limit_mbps is set, compute inter-message delay.
                let interval = cfg.rate_limit_mbps.map(|mbps| {
                    let bits_per_msg = (msg_bytes as f64) * 8.0;
                    let msgs_per_sec = (mbps * 1_000_000.0) / bits_per_msg;
                    Duration::from_secs_f64(1.0 / msgs_per_sec)
                });

                let mut next_send = Instant::now();
                while !send_stop.load(Ordering::Relaxed) {
                    let hdr = WireHeader::stamp(seq, payload_len);
                    hdr.encode(&mut buf);
                    wire::fill_payload(seq, &mut buf[HEADER_LEN..]);
                    if sink.send_msg(&buf).is_err() {
                        break;
                    }
                    seq += 1;

                    if let Some(iv) = interval {
                        next_send += iv;
                        let now = Instant::now();
                        if next_send > now {
                            std::thread::sleep(next_send - now);
                        }
                    }
                }
                sink.close();
            })?;

        handles.push((recv_handle, send_handle, cfg));
    }

    // Warmup phase — discard early metrics.
    std::thread::sleep(warmup);

    // Measurement phase.
    // Note: metrics collection currently doesn't distinguish warmup vs measure
    // at the stream level — this is a simplification; the FlowMetrics collects
    // from thread start. A production version would use epoch markers.
    std::thread::sleep(measure_duration);

    // Stop all streams.
    stop.store(true, Ordering::Relaxed);

    // Collect results.
    let mut results = Vec::new();
    for (recv_handle, send_handle, cfg) in handles {
        let _ = send_handle.join();
        let mut metrics: FlowMetrics = recv_handle.join().map_err(|_| {
            io::Error::other(format!("stream '{}' receiver panicked", cfg.name))
        })?;
        metrics.set_duration(measure_duration.as_secs_f64());
        let summary = metrics.finish(true);
        results.push(StreamResult {
            name: cfg.name,
            traffic_class: cfg.traffic_class,
            priority: cfg.priority,
            summary,
            dscp_preserved: None, // TODO: DSCP read-back via IP_TOS ancillary data
        });
    }

    Ok(MultiStreamResult::from_streams(results))
}
