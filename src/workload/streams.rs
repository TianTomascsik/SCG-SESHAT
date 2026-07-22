//! Multi-stream scheduling & prioritization (WP3.2).
//!
//! Manages N concurrent traffic streams through the gateway, each with its own
//! traffic class, DSCP tag, and pacing. Each stream runs through the gateway
//! rule pair provisioned for its class (see
//! [`crate::transport::gateway::GatewayMultiClassTransport`]), so safety
//! streams exercise the gateway's safety QoS while contending with bulk
//! traffic for the same process. Per-stream throughput, latency, and loss are
//! measured independently so we can verify:
//!   - Safety traffic is never starved by bulk normal traffic.
//!   - Fairness ratio across streams is acceptable.
//!   - Per-class CPU attribution is computable from system metrics.
//!
//! ## Pacing & coordinated omission
//! A stream with `interval_us` is deadline-paced: the sender stamps each
//! message's *scheduled* send time (never "now"), mirroring the run engine's
//! CO correction, and accounts how late it woke per message ([`SendLag`]).
//! Blast streams stamp actual send time and are reported as not CO-corrected.
//!
//! ## DSCP
//! When a stream declares a DSCP tag the sender marks its own socket via
//! `IP_TOS`, so the class's ingress leg carries the tag, and the gateway marks
//! its egress legs from the rule's traffic class. End-to-end *verification* of
//! those marks is future work: the TCP data path cannot observe a peer's DS
//! field from userspace (`IP_RECVTOS` ancillary data is datagram-only), so
//! [`StreamResult::dscp_preserved`] stays `None` rather than fabricating a
//! verdict. A UDP multi-stream path or a pcap-based checker could fill it in.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::metrics::app::{FlowMetrics, FlowSummary};
use crate::time::{monotonic_ns, sleep_until_ns};
use crate::transport::{DataSink, DataSource, RecvOutcome};
use crate::workload::dscp;
use crate::workload::receiver;
use crate::workload::sender::{MessageBuilder, SendLag};

/// Configuration for a single stream in a multi-stream scenario.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Human-readable stream identifier (e.g. "safety-1", "bulk-0").
    pub name: String,
    /// Canonical traffic class: `safety` or `normal`.
    pub traffic_class: String,
    /// Configured DSCP tag label (e.g. `EF`, `AF41`, `BE`), for reporting.
    pub dscp_label: String,
    /// Numeric DSCP value (0..=63) stamped on the sender socket, when known.
    pub dscp_tag: Option<u8>,
    /// Message size in bytes.
    pub message_bytes: u32,
    /// Fixed inter-message interval for deadline-paced (periodic) streams;
    /// `None` sends unthrottled (blast).
    pub interval_us: Option<u64>,
    /// CPU cores to pin this stream's sender thread to (empty = unpinned).
    pub sender_cores: Vec<usize>,
    /// CPU cores to pin this stream's receiver thread to (empty = unpinned).
    pub receiver_cores: Vec<usize>,
}

/// Per-stream result after a multi-stream run.
#[derive(Debug, Clone)]
pub struct StreamResult {
    pub name: String,
    /// Canonical traffic class (`safety` | `normal`).
    pub traffic_class: String,
    /// Configured DSCP tag label (e.g. `EF`), as declared in the scenario.
    pub dscp_label: String,
    pub summary: FlowSummary,
    /// Whether the stream was deadline-paced — its latency stamps the
    /// scheduled send time and is therefore coordinated-omission-corrected.
    pub paced: bool,
    /// Mean send-side wake-up lag behind schedule (µs; 0 for blast streams).
    pub send_lag_mean_us: f64,
    /// Worst-case send-side wake-up lag behind schedule (µs).
    pub send_lag_max_us: f64,
    /// Whether DSCP was preserved end-to-end. Always `None` on the TCP path
    /// (unobservable from userspace — see the module docs); kept for a future
    /// UDP or pcap-based verifier rather than fabricating a verdict.
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

/// The canonical class label safety aggregates key on (config validation
/// funnels every accepted alias to this value).
const SAFETY_CLASS: &str = "safety";

impl MultiStreamResult {
    /// Compute aggregate metrics from per-stream results.
    pub fn from_streams(streams: Vec<StreamResult>) -> Self {
        let throughputs: Vec<f64> = streams.iter().map(|s| s.summary.throughput_gbps).collect();
        let fairness_ratio = if throughputs.is_empty() {
            0.0
        } else {
            let min = throughputs.iter().copied().fold(f64::INFINITY, f64::min);
            let max = throughputs.iter().copied().fold(0.0_f64, f64::max);
            if max > 0.0 {
                min / max
            } else {
                0.0
            }
        };

        let safety_loss_free = streams
            .iter()
            .filter(|s| s.traffic_class == SAFETY_CLASS)
            .all(|s| s.summary.integrity.lost == 0);

        let safety_p99_us = streams
            .iter()
            .filter(|s| s.traffic_class == SAFETY_CLASS)
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
/// gateway rule pair matching the stream's traffic class. The scheduler starts
/// all sender/receiver threads, measures for `measure_duration`, then stops
/// and collects per-stream results.
pub fn run_multi_stream(
    configs: &[StreamConfig],
    pairs: Vec<(Box<dyn DataSink>, Box<dyn DataSource>)>,
    warmup: Duration,
    measure_duration: Duration,
) -> io::Result<MultiStreamResult> {
    if configs.len() != pairs.len() {
        return Err(io::Error::other(format!(
            "stream config/pair mismatch: {} configs but {} transport pairs",
            configs.len(),
            pairs.len()
        )));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let measuring = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for (i, (mut sink, mut source)) in pairs.into_iter().enumerate() {
        let cfg = configs[i].clone();
        let msg_bytes = cfg.message_bytes as usize;

        // Egress DSCP marking on the sender's own socket (ingress leg). The
        // gateway marks its legs from the rule's traffic class; this covers
        // the harness→gateway hop so the whole path carries the declared tag.
        // Best-effort: a failed mark must not break the data path.
        if let (Some(dscp), Some(fd)) = (cfg.dscp_tag, sink.raw_fd()) {
            if let Err(e) = dscp::set_dscp(fd, dscp) {
                log::warn!(
                    "stream '{}': could not set DSCP {} on sender socket: {e}",
                    cfg.name,
                    dscp
                );
            }
        }

        // Receiver thread — collects metrics during the measure window.
        let recv_stop = Arc::clone(&stop);
        let recv_measuring = Arc::clone(&measuring);
        let recv_cores = cfg.receiver_cores.clone();
        let recv_handle = thread::Builder::new()
            .name(format!("stream-rx-{}", cfg.name))
            .spawn(move || {
                if !recv_cores.is_empty() {
                    crate::run::affinity::pin_current_thread(&recv_cores);
                }
                let mut buf = vec![0u8; msg_bytes + 64];
                let mut metrics = FlowMetrics::new();
                while !recv_stop.load(Ordering::Relaxed) {
                    match source.recv_msg(&mut buf) {
                        Ok(RecvOutcome::Message(n)) => {
                            let recv_ns = monotonic_ns();
                            if recv_measuring.load(Ordering::Relaxed) {
                                if n != msg_bytes {
                                    metrics.record_boundary_violation();
                                }
                                if receiver::ingest(&mut metrics, &buf[..n], recv_ns).is_err() {
                                    metrics.record_integrity_failure();
                                }
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

        // Sender thread — deadline-paced (CO-corrected stamps) or blast.
        let send_stop = Arc::clone(&stop);
        let send_measuring = Arc::clone(&measuring);
        let send_cores = cfg.sender_cores.clone();
        let interval_us = cfg.interval_us;
        let message_bytes = cfg.message_bytes;
        let send_handle = thread::Builder::new()
            .name(format!("stream-tx-{}", cfg.name))
            .spawn(move || {
                if !send_cores.is_empty() {
                    crate::run::affinity::pin_current_thread(&send_cores);
                }
                let mut builder = MessageBuilder::new(message_bytes);
                let mut lag = SendLag::default();
                let mut seq = 0u64;

                match interval_us.map(|us| us.saturating_mul(1_000)) {
                    Some(gap_ns) if gap_ns > 0 => {
                        // Fixed-deadline schedule with catch-up (`next += gap`),
                        // stamping the *scheduled* send time so a late wake-up
                        // stays visible in receiver-side latency (coordinated-
                        // omission correction, as in the run engine).
                        let mut next_ns = monotonic_ns();
                        while !send_stop.load(Ordering::Relaxed) {
                            sleep_until_ns(next_ns);
                            let woke = monotonic_ns();
                            if send_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let msg = builder.build_at(seq, next_ns);
                            if sink.send_msg(msg).is_err() {
                                break;
                            }
                            if send_measuring.load(Ordering::Relaxed) {
                                lag.record(woke.saturating_sub(next_ns));
                            }
                            seq = seq.wrapping_add(1);
                            next_ns = next_ns.saturating_add(gap_ns);
                        }
                    }
                    _ => {
                        // Blast: stamp the actual send time (not CO-correctable).
                        while !send_stop.load(Ordering::Relaxed) {
                            let msg = builder.build(seq);
                            if sink.send_msg(msg).is_err() {
                                break;
                            }
                            seq = seq.wrapping_add(1);
                        }
                    }
                }
                sink.close();
                lag
            })?;

        handles.push((recv_handle, send_handle, cfg));
    }

    // Warmup phase — send and validate, but do not admit samples into metrics.
    thread::sleep(warmup);

    // Measurement phase.
    measuring.store(true, Ordering::Release);
    thread::sleep(measure_duration);

    // Stop all streams.
    stop.store(true, Ordering::Relaxed);

    // Collect results.
    let mut results = Vec::new();
    for (recv_handle, send_handle, cfg) in handles {
        let lag: SendLag = send_handle
            .join()
            .map_err(|_| io::Error::other(format!("stream '{}' sender panicked", cfg.name)))?;
        let mut metrics: FlowMetrics = recv_handle
            .join()
            .map_err(|_| io::Error::other(format!("stream '{}' receiver panicked", cfg.name)))?;
        metrics.set_duration(measure_duration.as_secs_f64());
        let summary = metrics.finish(true);

        results.push(StreamResult {
            name: cfg.name,
            traffic_class: cfg.traffic_class,
            dscp_label: cfg.dscp_label,
            summary,
            paced: cfg.interval_us.is_some(),
            send_lag_mean_us: lag.mean_us(),
            send_lag_max_us: lag.max_us(),
            // TCP path: unobservable from userspace, so honestly unchecked
            // (see the module docs) instead of a fabricated boolean.
            dscp_preserved: None,
        });
    }

    Ok(MultiStreamResult::from_streams(results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{tcp::TcpTransport, Transport};

    fn stream_cfg(name: &str, class: &str, interval_us: Option<u64>) -> StreamConfig {
        StreamConfig {
            name: name.to_string(),
            traffic_class: class.to_string(),
            dscp_label: "EF".to_string(),
            dscp_tag: Some(46),
            message_bytes: 256,
            interval_us,
            sender_cores: vec![],
            receiver_cores: vec![],
        }
    }

    /// Paced + blast streams over plain TCP loopback: the paced stream must be
    /// CO-corrected (scheduled stamps, lag accounted) and hit its target rate;
    /// the blast stream must not claim correction.
    #[test]
    fn paced_stream_is_co_corrected_and_blast_is_not() {
        let transport = TcpTransport;
        let pairs = vec![
            transport.loopback_pair(256).expect("paced pair"),
            transport.loopback_pair(256).expect("blast pair"),
        ];
        let configs = vec![
            stream_cfg("safety-0", "safety", Some(1_000)), // 1 ms → ~1000 msg/s
            stream_cfg("bulk-1", "normal", None),
        ];

        let result = run_multi_stream(
            &configs,
            pairs,
            Duration::from_millis(100),
            Duration::from_millis(400),
        )
        .expect("multi-stream run");

        assert_eq!(result.streams.len(), 2);
        let paced = &result.streams[0];
        let blast = &result.streams[1];

        assert!(paced.paced);
        assert!(!blast.paced);
        assert_eq!(blast.send_lag_mean_us, 0.0);
        assert_eq!(blast.send_lag_max_us, 0.0);
        assert!(paced.send_lag_max_us >= paced.send_lag_mean_us);
        assert!(paced.send_lag_mean_us >= 0.0);

        // ~400 ms at 1 msg/ms ≈ 400 messages; allow generous scheduling slack.
        let msgs = paced.summary.messages;
        assert!(
            (100..=600).contains(&msgs),
            "paced stream sent {msgs} messages in 400 ms at a 1 ms interval"
        );

        // TCP path never fabricates a DSCP verdict.
        assert!(result.streams.iter().all(|s| s.dscp_preserved.is_none()));
    }

    /// Safety aggregates key on the canonical class label.
    #[test]
    fn safety_aggregates_use_canonical_class() {
        let mk = |class: &str, lost: u64, p99: f64| {
            let mut metrics = FlowMetrics::new();
            metrics.set_duration(1.0);
            let mut summary = metrics.finish(false);
            summary.integrity.lost = lost;
            summary.latency_us.p99 = p99;
            summary.throughput_gbps = 1.0;
            StreamResult {
                name: format!("s-{class}"),
                traffic_class: class.to_string(),
                dscp_label: "EF".to_string(),
                summary,
                paced: true,
                send_lag_mean_us: 0.0,
                send_lag_max_us: 0.0,
                dscp_preserved: None,
            }
        };

        let agg =
            MultiStreamResult::from_streams(vec![mk("safety", 0, 42.0), mk("normal", 7, 99.0)]);
        assert!(agg.safety_loss_free, "normal-class loss must not count");
        assert_eq!(agg.safety_p99_us, Some(42.0));

        let agg = MultiStreamResult::from_streams(vec![mk("safety", 1, 42.0)]);
        assert!(!agg.safety_loss_free);
    }
}
