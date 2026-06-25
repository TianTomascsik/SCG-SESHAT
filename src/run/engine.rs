//! The run lifecycle (F-15, F-04): connect → warmup → measure → cooldown,
//! repeated for N runs and aggregated with confidence intervals.
//!
//! ## Threading model (NFR-PERF)
//! For each connection the engine spawns one sender thread and one receiver
//! thread, pinned to the configured sender/receiver cores (kept separate from
//! the SCG). The main thread owns the wall clock and drives the phase flag:
//!
//! ```text
//!   warmup (discard)   measure (record)   cooldown (drain)
//!   |----------------|------------------|----------------|
//!                    ^ phase=MEASURE    ^ phase=COOLDOWN  ^ phase=DONE
//! ```
//!
//! Receivers check the phase per message (one relaxed atomic load) and only
//! record into their [`FlowMetrics`] during MEASURE, so warmup/cooldown traffic
//! never pollutes the statistics. Senders pace via [`Pacer`] and stop at DONE.
//! Socket read timeouts let receivers notice DONE even after the sender stops.
#![allow(dead_code)]

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Sender;
use crate::metrics::app::{self, FlowMetrics, FlowSummary};
use crate::metrics::stats::{self, Summary};
use crate::proto::wire::decode_message;
use crate::time::{monotonic_ns, sleep_until_ns};
use crate::transport::{
    BatchOutcome, ConnFactory, DataSource, DuplexEnd, RecvOutcome, Transport, BATCH_MAX,
};
use crate::workload::receiver;
use crate::workload::sender::{BatchBuilder, MessageBuilder, Pacer};

use super::affinity;

const PHASE_WARMUP: u8 = 0;
const PHASE_MEASURE: u8 = 1;
const PHASE_COOLDOWN: u8 = 2;
const PHASE_DONE: u8 = 3;

/// How a scenario drives traffic: an open-loop throughput blast/pace, a
/// closed-loop request/echo round-trip (ping-pong) that measures RTT with one
/// message in flight at a time (Phase F), or a connection-establishment churn
/// that measures setup rate and handshake latency (Phase G).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Open-loop: senders blast or pace messages one way; receivers record
    /// one-way latency and throughput. The default for every scenario.
    #[default]
    Throughput,
    /// Closed-loop: the client sends one message and waits for the echo,
    /// timing the round trip; an echo server bounces each message back. Used
    /// for low-load RTT scenarios where latency, not bandwidth, is the metric.
    PingPong,
    /// Connection churn: connector threads open and tear down fresh
    /// connections as fast as possible while an acceptor drains them. Measures
    /// connections per second and per-connection handshake latency.
    Connrate,
}

/// Everything needed to execute one scenario's runs over a transport.
#[derive(Debug, Clone)]
pub struct RunParams {
    /// On-wire message size in bytes.
    pub message_bytes: u32,
    /// Number of concurrent connections.
    pub connections: usize,
    /// Number of measured runs.
    pub runs: usize,
    pub warmup: Duration,
    pub measure: Duration,
    pub cooldown: Duration,
    /// Remove latency outliers (Tukey IQR) before summarising.
    pub remove_outliers: bool,
    /// Cores to pin sender threads to (empty = unpinned).
    pub sender_cores: Vec<usize>,
    /// Cores to pin receiver threads to (empty = unpinned).
    pub receiver_cores: Vec<usize>,
    /// Sender spec driving the [`Pacer`].
    pub sender: Sender,
    /// Traffic mode: open-loop throughput (default) or closed-loop ping-pong.
    pub mode: RunMode,
}

/// Aggregated result of N runs of a scenario.
#[derive(Debug, Clone)]
pub struct RunStats {
    /// Per-run summaries (length == `runs`).
    pub runs: Vec<FlowSummary>,
    /// Throughput across runs (Gbit/s), mean ± CI in `.mean`/`.ci95`.
    pub throughput_gbps: Summary,
    /// Mean latency across runs (µs).
    pub latency_mean_us: Summary,
    /// p99 latency across runs (µs).
    pub latency_p99_us: Summary,
    /// Connection-establishment time across runs (µs), measured as the first
    /// connection setup of each run (connect + any TLS/DTLS handshake).
    pub handshake_us: Summary,
    /// Total lost messages across all runs.
    pub total_lost: u64,
    /// Overall loss percentage across all runs.
    pub loss_pct: f64,
    /// The mode that produced these stats.
    pub mode: RunMode,
    /// Closed-loop round-trip summary, populated only in [`RunMode::PingPong`].
    pub rtt: Option<RttSummary>,
    /// Connection-rate summary, populated only in [`RunMode::Connrate`].
    pub conn: Option<ConnSummary>,
}

/// Closed-loop round-trip statistics (Phase F), aggregated across runs. Each
/// field is the across-run mean of the corresponding per-run RTT statistic, in
/// microseconds; `samples` is the total number of round trips measured.
#[derive(Debug, Clone, Copy, Default)]
pub struct RttSummary {
    /// Across-run mean RTT (µs).
    pub mean_us: f64,
    /// 95 % CI half-width about the mean RTT (µs).
    pub mean_ci95: f64,
    /// Across-run mean of the per-run median (p50) RTT (µs).
    pub p50_us: f64,
    /// Across-run mean of the per-run p99 RTT (µs).
    pub p99_us: f64,
    /// Total round trips measured across all runs.
    pub samples: u64,
}

/// Connection-rate statistics (Phase G), aggregated across runs. Each run
/// churns fresh connections during the measure window; the headline figure is
/// connections per second, with the per-connection handshake-latency
/// percentiles alongside.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnSummary {
    /// Across-run mean connection-establishment rate (connections/second).
    pub conns_per_sec: f64,
    /// 95 % CI half-width about the mean rate (connections/second).
    pub conns_per_sec_ci95: f64,
    /// Across-run mean of the per-run median (p50) handshake latency (µs).
    pub handshake_p50_us: f64,
    /// Across-run mean of the per-run p99 handshake latency (µs).
    pub handshake_p99_us: f64,
    /// Total connections established across all runs.
    pub total_conns: u64,
    /// Mean latency of the first (full/cold) handshake per connector (µs).
    /// Useful for measuring session-resumption speedup vs cold starts.
    pub first_handshake_us: f64,
    /// Mean latency of subsequent (potentially resumed) handshakes (µs).
    /// Compared with `first_handshake_us` to quantify resumption benefit.
    pub resumed_handshake_us: f64,
}

/// Receiver worker: record during MEASURE, validate-and-discard otherwise.
fn receiver_loop(
    mut source: Box<dyn DataSource>,
    phase: Arc<AtomicU8>,
    cores: Vec<usize>,
    message_bytes: u32,
    expected: usize,
) -> FlowMetrics {
    if !cores.is_empty() {
        affinity::pin_current_thread(&cores);
    }
    let mut metrics = FlowMetrics::with_capacity(expected);
    let stride = message_bytes as usize;
    // One contiguous buffer of BATCH_MAX message slots drained per recv_batch;
    // datagram transports fill several at once (recvmmsg), stream transports one.
    let mut buf = vec![0u8; stride * BATCH_MAX];
    let mut lens = vec![0usize; BATCH_MAX];
    loop {
        match source.recv_batch(&mut buf, stride, BATCH_MAX, &mut lens) {
            Ok(BatchOutcome::Messages(count)) => {
                // Timestamp as close to the read as possible (NFR-PERF). A whole
                // batch shares one arrival time; that only blurs latency under
                // blast, where per-message latency is queueing-dominated anyway.
                let recv_ns = monotonic_ns();
                let measuring = phase.load(Ordering::Relaxed) == PHASE_MEASURE;
                for i in 0..count {
                    let msg = &buf[i * stride..i * stride + lens[i]];
                    if measuring {
                        if msg.len() != stride {
                            metrics.record_boundary_violation();
                        }
                        if receiver::ingest(&mut metrics, msg, recv_ns).is_err() {
                            metrics.record_integrity_failure();
                        }
                    } else {
                        // Keep the stream validated during warmup/cooldown.
                        let _ = decode_message(msg);
                    }
                }
            }
            Ok(BatchOutcome::Timeout) => {
                if phase.load(Ordering::Relaxed) == PHASE_DONE {
                    break;
                }
            }
            Ok(BatchOutcome::Closed) => break,
            Err(_) => break,
        }
    }
    source.close();
    metrics
}

/// Sender worker: paced sends until DONE.
fn sender_loop(
    mut sink: Box<dyn crate::transport::DataSink>,
    phase: Arc<AtomicU8>,
    cores: Vec<usize>,
    sender_spec: Sender,
    message_bytes: u32,
) {
    if !cores.is_empty() {
        affinity::pin_current_thread(&cores);
    }
    let mut pacer = Pacer::from_sender(&sender_spec, message_bytes);
    if pacer.is_blast() {
        // Unthrottled blast: stage BATCH_MAX messages and push them with one
        // batched send (sendmmsg on UDP) per iteration, so the harness ceiling
        // is bounded by the socket/NIC rather than per-message syscalls.
        let mut batch = BatchBuilder::new(message_bytes, BATCH_MAX);
        let mut seq = 0u64;
        loop {
            if phase.load(Ordering::Relaxed) == PHASE_DONE {
                break;
            }
            let built = batch.build(seq, BATCH_MAX);
            let slices: Vec<&[u8]> = built.iter().map(|v| v.as_slice()).collect();
            match sink.send_batch(&slices) {
                // Socket buffer momentarily full: back off without losing seq.
                Ok(0) => std::thread::yield_now(),
                Ok(n) => seq = seq.wrapping_add(n as u64),
                Err(_) => break,
            }
        }
    } else {
        let mut builder = MessageBuilder::new(message_bytes);
        let start = monotonic_ns();
        let mut seq = 0u64;
        loop {
            if phase.load(Ordering::Relaxed) == PHASE_DONE {
                break;
            }
            let deadline = start + pacer.next_deadline_ns();
            sleep_until_ns(deadline);
            if phase.load(Ordering::Relaxed) == PHASE_DONE {
                break;
            }
            let msg = builder.build(seq);
            match sink.send_msg(msg) {
                Ok(()) => seq = seq.wrapping_add(1),
                // A non-blocking local-interface ring is momentarily full.
                // Yield, then loop so the phase flag remains observable.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(_) => break,
            }
        }
    }
    sink.close();
}

/// Execute a single run and return its combined [`FlowSummary`] together with
/// the connection-establishment time in microseconds.
pub fn run_once(transport: &dyn Transport, params: &RunParams) -> io::Result<(FlowSummary, f64)> {
    let phase = Arc::new(AtomicU8::new(PHASE_WARMUP));

    // Establish all connections up front (counts as the connect step). Time the
    // first one as the handshake cost (connect + any TLS/DTLS warmup); for
    // gateway transports this captures the real session-establishment latency.
    let mut handshake_us = 0.0;
    let mut pairs = Vec::with_capacity(params.connections);
    for i in 0..params.connections.max(1) {
        let t0 = monotonic_ns();
        let pair = transport.loopback_pair(params.message_bytes)?;
        if i == 0 {
            handshake_us = monotonic_ns().saturating_sub(t0) as f64 / 1000.0;
        }
        pairs.push(pair);
    }

    // Rough capacity hint for receiver buffers, to avoid reallocation.
    let expected = expected_messages(params);

    let mut rx_handles = Vec::with_capacity(pairs.len());
    let mut tx_handles = Vec::with_capacity(pairs.len());
    for (sink, source) in pairs {
        let rx_phase = phase.clone();
        let rx_cores = params.receiver_cores.clone();
        let msg = params.message_bytes;
        rx_handles.push(thread::spawn(move || {
            receiver_loop(source, rx_phase, rx_cores, msg, expected)
        }));

        let tx_phase = phase.clone();
        let tx_cores = params.sender_cores.clone();
        let spec = params.sender.clone();
        let msg = params.message_bytes;
        tx_handles.push(thread::spawn(move || {
            sender_loop(sink, tx_phase, tx_cores, spec, msg)
        }));
    }

    // Phase timing on the main thread.
    thread::sleep(params.warmup);
    phase.store(PHASE_MEASURE, Ordering::Relaxed);
    let measure_start = Instant::now();
    thread::sleep(params.measure);
    let measure_secs = measure_start.elapsed().as_secs_f64();
    phase.store(PHASE_COOLDOWN, Ordering::Relaxed);
    thread::sleep(params.cooldown);
    phase.store(PHASE_DONE, Ordering::Relaxed);

    for h in tx_handles {
        let _ = h.join();
    }
    let mut metrics = Vec::with_capacity(rx_handles.len());
    for h in rx_handles {
        if let Ok(m) = h.join() {
            metrics.push(m);
        }
    }

    Ok((
        app::aggregate_run(&metrics, measure_secs, params.remove_outliers),
        handshake_us,
    ))
}

/// Execute all N runs of a scenario, calling `on_run` after each for live
/// progress, then aggregate across runs with confidence intervals. Dispatches
/// on [`RunParams::mode`] to the open-loop throughput engine or the closed-loop
/// ping-pong engine (Phase F).
pub fn run_scenario<F>(
    transport: &dyn Transport,
    params: &RunParams,
    on_run: F,
) -> io::Result<RunStats>
where
    F: FnMut(usize, &FlowSummary),
{
    match params.mode {
        RunMode::Throughput => run_scenario_throughput(transport, params, on_run),
        RunMode::PingPong => run_scenario_pingpong(transport, params, on_run),
        RunMode::Connrate => run_scenario_connrate(transport, params, on_run),
    }
}

/// Open-loop throughput engine: N paced/blast runs aggregated with CIs.
fn run_scenario_throughput<F>(
    transport: &dyn Transport,
    params: &RunParams,
    mut on_run: F,
) -> io::Result<RunStats>
where
    F: FnMut(usize, &FlowSummary),
{
    let mut runs = Vec::with_capacity(params.runs);
    let mut handshakes = Vec::with_capacity(params.runs);
    for i in 0..params.runs.max(1) {
        let (summary, handshake_us) = run_once(transport, params)?;
        on_run(i, &summary);
        runs.push(summary);
        handshakes.push(handshake_us);
    }

    let thr: Vec<f64> = runs.iter().map(|r| r.throughput_gbps).collect();
    let latm: Vec<f64> = runs.iter().map(|r| r.latency_us.mean).collect();
    let p99: Vec<f64> = runs.iter().map(|r| r.latency_us.p99).collect();
    let total_lost: u64 = runs.iter().map(|r| r.integrity.lost).sum();
    let total_distinct: u64 = runs.iter().map(|r| r.integrity.distinct).sum();
    let loss_pct = if total_distinct + total_lost > 0 {
        total_lost as f64 / (total_distinct + total_lost) as f64 * 100.0
    } else {
        0.0
    };

    Ok(RunStats {
        runs,
        throughput_gbps: stats::summarize(&thr),
        latency_mean_us: stats::summarize(&latm),
        latency_p99_us: stats::summarize(&p99),
        handshake_us: stats::summarize(&handshakes),
        total_lost,
        loss_pct,
        mode: RunMode::Throughput,
        rtt: None,
        conn: None,
    })
}

/// Closed-loop ping-pong engine (Phase F): N runs, each measuring round-trip
/// time with one message in flight per connection, aggregated with CIs. The
/// per-run [`FlowSummary::latency_us`] carries the RTT distribution, so the
/// existing latency columns double as RTT for these scenarios; the dedicated
/// [`RttSummary`] is the canonical round-trip figure.
fn run_scenario_pingpong<F>(
    transport: &dyn Transport,
    params: &RunParams,
    mut on_run: F,
) -> io::Result<RunStats>
where
    F: FnMut(usize, &FlowSummary),
{
    let mut runs = Vec::with_capacity(params.runs);
    let mut handshakes = Vec::with_capacity(params.runs);
    for i in 0..params.runs.max(1) {
        let (summary, handshake_us) = run_once_pingpong(transport, params)?;
        on_run(i, &summary);
        runs.push(summary);
        handshakes.push(handshake_us);
    }

    let thr: Vec<f64> = runs.iter().map(|r| r.throughput_gbps).collect();
    let rtt_mean: Vec<f64> = runs.iter().map(|r| r.latency_us.mean).collect();
    let rtt_p50: Vec<f64> = runs.iter().map(|r| r.latency_us.p50).collect();
    let rtt_p99: Vec<f64> = runs.iter().map(|r| r.latency_us.p99).collect();
    let samples: u64 = runs.iter().map(|r| r.messages).sum();
    let mean_summary = stats::summarize(&rtt_mean);
    let rtt = RttSummary {
        mean_us: mean_summary.mean,
        mean_ci95: mean_summary.ci95,
        p50_us: stats::summarize(&rtt_p50).mean,
        p99_us: stats::summarize(&rtt_p99).mean,
        samples,
    };

    Ok(RunStats {
        runs,
        throughput_gbps: stats::summarize(&thr),
        latency_mean_us: mean_summary,
        latency_p99_us: stats::summarize(&rtt_p99),
        handshake_us: stats::summarize(&handshakes),
        total_lost: 0,
        loss_pct: 0.0,
        mode: RunMode::PingPong,
        rtt: Some(rtt),
        conn: None,
    })
}

/// Execute one closed-loop ping-pong run: stand up `connections` request/echo
/// pairs, drive each client closed-loop through warmup/measure/cooldown, and
/// pool the per-connection RTT samples into one [`FlowSummary`]. The first
/// pair's setup time is returned as the handshake cost.
fn run_once_pingpong(
    transport: &dyn Transport,
    params: &RunParams,
) -> io::Result<(FlowSummary, f64)> {
    let phase = Arc::new(AtomicU8::new(PHASE_WARMUP));

    let mut handshake_us = 0.0;
    let mut pairs = Vec::with_capacity(params.connections.max(1));
    for i in 0..params.connections.max(1) {
        let t0 = monotonic_ns();
        let pair = transport.pingpong_pair(params.message_bytes)?;
        if i == 0 {
            handshake_us = monotonic_ns().saturating_sub(t0) as f64 / 1000.0;
        }
        pairs.push(pair);
    }

    let mut client_handles = Vec::with_capacity(pairs.len());
    let mut server_handles = Vec::with_capacity(pairs.len());
    for (client, server) in pairs {
        let srv_phase = phase.clone();
        let msg = params.message_bytes;
        server_handles.push(thread::spawn(move || echo_loop(server, srv_phase, msg)));

        let cli_phase = phase.clone();
        let cores = params.sender_cores.clone();
        let msg = params.message_bytes;
        client_handles.push(thread::spawn(move || {
            pingpong_client_loop(client, cli_phase, cores, msg)
        }));
    }

    thread::sleep(params.warmup);
    phase.store(PHASE_MEASURE, Ordering::Relaxed);
    let measure_start = Instant::now();
    thread::sleep(params.measure);
    let measure_secs = measure_start.elapsed().as_secs_f64();
    phase.store(PHASE_COOLDOWN, Ordering::Relaxed);
    thread::sleep(params.cooldown);
    phase.store(PHASE_DONE, Ordering::Relaxed);

    let mut metrics = Vec::with_capacity(client_handles.len());
    for h in client_handles {
        if let Ok(m) = h.join() {
            metrics.push(m);
        }
    }
    for h in server_handles {
        let _ = h.join();
    }

    Ok((
        app::aggregate_run(&metrics, measure_secs, params.remove_outliers),
        handshake_us,
    ))
}

/// Client worker for ping-pong: send one message, wait for its echo, record the
/// round-trip time (measured locally, so no clock embedding is needed), repeat
/// with one message in flight. Records only during MEASURE.
fn pingpong_client_loop(
    mut client: Box<dyn DuplexEnd>,
    phase: Arc<AtomicU8>,
    cores: Vec<usize>,
    message_bytes: u32,
) -> FlowMetrics {
    if !cores.is_empty() {
        affinity::pin_current_thread(&cores);
    }
    let mut metrics = FlowMetrics::with_capacity(4096);
    let mut builder = MessageBuilder::new(message_bytes);
    let mut recv = vec![0u8; message_bytes as usize];
    let mut seq = 0u64;
    loop {
        if phase.load(Ordering::Relaxed) == PHASE_DONE {
            break;
        }
        let measuring = phase.load(Ordering::Relaxed) == PHASE_MEASURE;
        let msg = builder.build(seq);
        let t0 = monotonic_ns();
        if client.send_msg(msg).is_err() {
            break;
        }
        match client.recv_msg(&mut recv) {
            Ok(RecvOutcome::Message(n)) => {
                let rtt_ns = monotonic_ns().saturating_sub(t0);
                if measuring {
                    // Validate the echo and key the sample by its sequence so the
                    // integrity counters stay meaningful on a clean round trip.
                    if let Ok(hdr) = decode_message(&recv[..n]) {
                        metrics.record(hdr.seq, rtt_ns, n as u64);
                    }
                }
                seq = seq.wrapping_add(1);
            }
            // No echo within the poll window: stop if the run is over, else the
            // peer is slow — retry the same sequence on the next iteration.
            Ok(RecvOutcome::Timeout) => {
                if phase.load(Ordering::Relaxed) == PHASE_DONE {
                    break;
                }
            }
            Ok(RecvOutcome::Closed) => break,
            Err(_) => break,
        }
    }
    client.close();
    metrics
}

/// Echo-server worker for ping-pong: bounce each received message straight back
/// to the client until the run finishes or the client closes.
fn echo_loop(mut server: Box<dyn DuplexEnd>, phase: Arc<AtomicU8>, message_bytes: u32) {
    let mut buf = vec![0u8; message_bytes as usize];
    loop {
        match server.recv_msg(&mut buf) {
            Ok(RecvOutcome::Message(n)) => {
                if server.send_msg(&buf[..n]).is_err() {
                    break;
                }
            }
            Ok(RecvOutcome::Timeout) => {
                if phase.load(Ordering::Relaxed) == PHASE_DONE {
                    break;
                }
            }
            Ok(RecvOutcome::Closed) => break,
            Err(_) => break,
        }
    }
    server.close();
}

/// Connection-rate engine (Phase G): N runs, each churning fresh connections
/// during the measure window. Every connection is recorded as one "message"
/// keyed by a per-connector index, with its handshake time as the latency
/// sample, so the per-run [`FlowSummary::message_rate`] is the connection rate
/// and [`FlowSummary::latency_us`] the handshake-latency distribution; the
/// dedicated [`ConnSummary`] is the canonical figure.
fn run_scenario_connrate<F>(
    transport: &dyn Transport,
    params: &RunParams,
    mut on_run: F,
) -> io::Result<RunStats>
where
    F: FnMut(usize, &FlowSummary),
{
    let mut runs = Vec::with_capacity(params.runs);
    let mut first_hs_all = Vec::with_capacity(params.runs);
    let mut resumed_hs_all = Vec::with_capacity(params.runs);
    for i in 0..params.runs.max(1) {
        let (summary, first_us, resumed_us) = run_once_connrate(transport, params)?;
        on_run(i, &summary);
        runs.push(summary);
        first_hs_all.push(first_us);
        resumed_hs_all.push(resumed_us);
    }

    let rate: Vec<f64> = runs.iter().map(|r| r.message_rate).collect();
    let hs_mean_v: Vec<f64> = runs.iter().map(|r| r.latency_us.mean).collect();
    let hs_p50: Vec<f64> = runs.iter().map(|r| r.latency_us.p50).collect();
    let hs_p99: Vec<f64> = runs.iter().map(|r| r.latency_us.p99).collect();
    let thr: Vec<f64> = runs.iter().map(|r| r.throughput_gbps).collect();
    let total_conns: u64 = runs.iter().map(|r| r.messages).sum();
    let rate_summary = stats::summarize(&rate);
    let hs_mean = stats::summarize(&hs_mean_v);

    let first_hs_mean = if first_hs_all.is_empty() {
        0.0
    } else {
        first_hs_all.iter().sum::<f64>() / first_hs_all.len() as f64
    };
    let resumed_hs_mean = if resumed_hs_all.is_empty() {
        0.0
    } else {
        resumed_hs_all.iter().sum::<f64>() / resumed_hs_all.len() as f64
    };

    let conn = ConnSummary {
        conns_per_sec: rate_summary.mean,
        conns_per_sec_ci95: rate_summary.ci95,
        handshake_p50_us: stats::summarize(&hs_p50).mean,
        handshake_p99_us: stats::summarize(&hs_p99).mean,
        total_conns,
        first_handshake_us: first_hs_mean,
        resumed_handshake_us: resumed_hs_mean,
    };

    Ok(RunStats {
        runs,
        throughput_gbps: stats::summarize(&thr),
        latency_mean_us: hs_mean,
        latency_p99_us: stats::summarize(&hs_p99),
        // For connection-rate runs the per-connection setup time is the
        // handshake, so the handshake column mirrors the latency column.
        handshake_us: hs_mean,
        total_lost: 0,
        loss_pct: 0.0,
        mode: RunMode::Connrate,
        rtt: None,
        conn: Some(conn),
    })
}

/// Execute one connection-rate run: start the acceptor on its own thread, spawn
/// `connections` connector threads that churn fresh connections, drive the
/// phase clock, then pool the per-connector handshake samples into one
/// [`FlowSummary`] whose `message_rate` is the connection rate.
///
/// Returns `(summary, first_handshake_us, resumed_handshake_us)` for session-
/// resumption analysis (C3).
fn run_once_connrate(
    transport: &dyn Transport,
    params: &RunParams,
) -> io::Result<(FlowSummary, f64, f64)> {
    let (acceptor, factory) = transport.conn_harness(params.message_bytes)?;
    let phase = Arc::new(AtomicU8::new(PHASE_WARMUP));
    let stop = Arc::new(AtomicBool::new(false));

    let acc_stop = stop.clone();
    let acc_handle = thread::spawn(move || acceptor.serve(&acc_stop));

    let mut client_handles = Vec::with_capacity(params.connections.max(1));
    for _ in 0..params.connections.max(1) {
        let cli_phase = phase.clone();
        let cli_factory = factory.clone();
        let cores = params.sender_cores.clone();
        client_handles.push(thread::spawn(move || {
            connrate_client_loop(cli_factory, cli_phase, cores)
        }));
    }

    thread::sleep(params.warmup);
    phase.store(PHASE_MEASURE, Ordering::Relaxed);
    let measure_start = Instant::now();
    thread::sleep(params.measure);
    let measure_secs = measure_start.elapsed().as_secs_f64();
    phase.store(PHASE_COOLDOWN, Ordering::Relaxed);
    thread::sleep(params.cooldown);
    phase.store(PHASE_DONE, Ordering::Relaxed);

    let mut metrics = Vec::with_capacity(client_handles.len());
    let mut first_hs_samples = Vec::new();
    let mut resumed_hs_samples = Vec::new();
    for h in client_handles {
        if let Ok((m, first, resumed)) = h.join() {
            metrics.push(m);
            if let Some(ns) = first {
                first_hs_samples.push(ns as f64 / 1000.0);
            }
            if let Some(ns) = resumed {
                resumed_hs_samples.push(ns as f64 / 1000.0);
            }
        }
    }
    // Connectors are done; stop draining and reclaim the acceptor thread.
    stop.store(true, Ordering::Relaxed);
    let _ = acc_handle.join();

    let first_us = if first_hs_samples.is_empty() {
        0.0
    } else {
        first_hs_samples.iter().sum::<f64>() / first_hs_samples.len() as f64
    };
    let resumed_us = if resumed_hs_samples.is_empty() {
        0.0
    } else {
        resumed_hs_samples.iter().sum::<f64>() / resumed_hs_samples.len() as f64
    };

    Ok((
        app::aggregate_run(&metrics, measure_secs, params.remove_outliers),
        first_us,
        resumed_us,
    ))
}

/// Connector worker (Phase G): open and tear down fresh connections in a tight
/// loop, recording each successful connection's handshake time during MEASURE.
/// A failed connect (e.g. transient ephemeral-port pressure) backs off briefly
/// rather than aborting the run.
fn connrate_client_loop(
    factory: Arc<dyn ConnFactory>,
    phase: Arc<AtomicU8>,
    cores: Vec<usize>,
) -> (FlowMetrics, Option<u64>, Option<u64>) {
    if !cores.is_empty() {
        affinity::pin_current_thread(&cores);
    }
    let mut metrics = FlowMetrics::with_capacity(4096);
    let mut seq = 0u64;
    let mut first_hs_ns: Option<u64> = None;
    let mut second_hs_ns: Option<u64> = None;
    loop {
        let p = phase.load(Ordering::Relaxed);
        if p == PHASE_DONE {
            break;
        }
        match factory.connect_once() {
            Ok(handshake_ns) => {
                if p == PHASE_MEASURE {
                    metrics.record(seq, handshake_ns, 0);
                    // Track first vs second handshake for resumption analysis.
                    if first_hs_ns.is_none() {
                        first_hs_ns = Some(handshake_ns);
                    } else if second_hs_ns.is_none() {
                        second_hs_ns = Some(handshake_ns);
                    }
                    seq = seq.wrapping_add(1);
                }
            }
            Err(_) => thread::sleep(Duration::from_micros(50)),
        }
    }
    (metrics, first_hs_ns, second_hs_ns)
}

/// Estimate how many messages a run will record, to pre-size buffers.
fn expected_messages(params: &RunParams) -> usize {
    // Heuristic upper-ish bound: assume the measure window at line rate for the
    // message size, capped so we never reserve absurd amounts.
    let secs = params.measure.as_secs_f64().max(1.0);
    let per_sec = 2_000_000.0; // generous loopback msg/s guess
    ((secs * per_sec) as usize).clamp(1024, 8_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Interface, Pattern};
    use crate::transport::tcp::TcpTransport;
    use crate::transport::udp::UdpTransport;

    fn periodic_sender(interval_us: u64) -> Sender {
        Sender {
            interface: Interface::Tcp,
            target_addr: "127.0.0.1:0".into(),
            pattern: Pattern::Periodic,
            rate_limit_mbps: None,
            interval_us: Some(interval_us),
            burst_count: None,
            burst_pause_us: None,
            ramp_start_mbps: None,
            ramp_step_mbps: None,
            ramp_step_interval_secs: None,
        }
    }

    fn quick_params(sender: Sender) -> RunParams {
        RunParams {
            message_bytes: 256,
            connections: 1,
            runs: 2,
            warmup: Duration::from_millis(60),
            measure: Duration::from_millis(200),
            cooldown: Duration::from_millis(40),
            remove_outliers: true,
            sender_cores: vec![],
            receiver_cores: vec![],
            sender,
            mode: RunMode::Throughput,
        }
    }

    #[test]
    fn tcp_loopback_run_produces_metrics() {
        let stats = run_scenario(
            &TcpTransport,
            &quick_params(periodic_sender(200)),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(stats.runs.len(), 2);
        // TCP is reliable: zero loss and some messages measured.
        assert_eq!(stats.total_lost, 0);
        assert!(stats.runs.iter().all(|r| r.messages > 0));
        assert!(stats.throughput_gbps.mean > 0.0);
        assert!(stats.latency_mean_us.mean >= 0.0);
        // Connection-establishment time is measured per run.
        assert!(stats.handshake_us.mean >= 0.0);
    }

    #[test]
    fn udp_loopback_run_produces_metrics() {
        let mut s = periodic_sender(200);
        s.interface = Interface::Udp;
        let stats = run_scenario(&UdpTransport, &quick_params(s), |_, _| {}).unwrap();
        assert_eq!(stats.runs.len(), 2);
        assert!(stats.runs.iter().all(|r| r.messages > 0));
    }

    #[test]
    fn tcp_pingpong_measures_rtt() {
        let mut s = periodic_sender(200);
        s.interface = Interface::Tcp;
        let mut params = quick_params(s);
        params.mode = RunMode::PingPong;
        let stats = run_scenario(&TcpTransport, &params, |_, _| {}).unwrap();
        assert_eq!(stats.mode, RunMode::PingPong);
        let rtt = stats.rtt.expect("ping-pong populates an RTT summary");
        assert!(rtt.samples > 0, "some round trips were measured");
        assert!(rtt.mean_us > 0.0, "a closed-loop round trip takes time");
        // The tail can only be at or above the median.
        assert!(rtt.p99_us >= rtt.p50_us);
    }

    #[test]
    fn udp_pingpong_measures_rtt() {
        let mut s = periodic_sender(200);
        s.interface = Interface::Udp;
        let mut params = quick_params(s);
        params.mode = RunMode::PingPong;
        let stats = run_scenario(&UdpTransport, &params, |_, _| {}).unwrap();
        let rtt = stats.rtt.expect("ping-pong populates an RTT summary");
        assert!(rtt.samples > 0);
        assert!(rtt.p99_us >= rtt.p50_us);
    }

    #[test]
    fn tcp_connrate_measures_connections() {
        let mut s = periodic_sender(200);
        s.interface = Interface::Tcp;
        let mut params = quick_params(s);
        params.mode = RunMode::Connrate;
        let stats = run_scenario(&TcpTransport, &params, |_, _| {}).unwrap();
        assert_eq!(stats.mode, RunMode::Connrate);
        let conn = stats.conn.expect("connrate populates a connection summary");
        assert!(conn.total_conns > 0, "some connections were established");
        assert!(conn.conns_per_sec > 0.0, "a positive connection rate");
        // The tail can only be at or above the median.
        assert!(conn.handshake_p99_us >= conn.handshake_p50_us);
    }

    #[test]
    fn udp_connrate_is_unsupported() {
        let mut s = periodic_sender(200);
        s.interface = Interface::Udp;
        let mut params = quick_params(s);
        params.mode = RunMode::Connrate;
        // UDP is connectionless: the connection-rate engine surfaces the
        // transport's Unsupported error rather than inventing a metric.
        let err = run_scenario(&UdpTransport, &params, |_, _| {}).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}

// ─── F-01: Distributed Mode ─────────────────────────────────────────────────

/// Parameters for distributed (multi-host) sender/receiver execution.
#[derive(Debug, Clone)]
pub struct DistributedParams {
    /// On-wire message size in bytes.
    pub message_bytes: u32,
    /// Number of parallel connections.
    pub connections: usize,
    /// Warmup duration (data discarded).
    pub warmup: Duration,
    /// Measurement duration.
    pub measure: Duration,
    /// Cooldown duration.
    pub cooldown: Duration,
    /// CPU cores to pin to (empty = unpinned).
    pub cores: Vec<usize>,
    /// Sender traffic pattern.
    pub sender: Sender,
    /// Remove latency outliers.
    pub remove_outliers: bool,
}

/// Run the sender side of a distributed benchmark.
///
/// Connects to `target` (TCP), sends WireHeader-stamped messages for the
/// configured duration, then disconnects. Prints per-connection message counts
/// on completion.
pub fn run_distributed_sender(params: &DistributedParams, target: &str) -> io::Result<u64> {
    use crate::proto::wire::{self, WireHeader, HEADER_LEN};
    use std::net::{TcpStream, ToSocketAddrs};

    let addr = target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("could not resolve target address"))?;

    let phase = Arc::new(AtomicU8::new(PHASE_WARMUP));
    let msg_bytes = params.message_bytes.max(HEADER_LEN as u32) as usize;
    let payload_len = (msg_bytes - HEADER_LEN) as u32;

    if !params.cores.is_empty() {
        super::affinity::pin_current_thread(&params.cores);
    }

    let mut handles = Vec::with_capacity(params.connections.max(1));
    for _ in 0..params.connections.max(1) {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_nodelay(true)?;
        let p = phase.clone();
        handles.push(thread::spawn(move || -> u64 {
            use std::io::Write;
            let mut buf = vec![0u8; msg_bytes];
            let mut seq = 0u64;
            let mut measured = 0u64;
            let mut stream = stream;
            loop {
                let ph = p.load(Ordering::Relaxed);
                if ph == PHASE_DONE {
                    break;
                }
                let hdr = WireHeader::stamp(seq, payload_len);
                hdr.encode(&mut buf);
                wire::fill_payload(seq, &mut buf[HEADER_LEN..]);
                if stream.write_all(&buf).is_err() {
                    break;
                }
                if ph == PHASE_MEASURE {
                    measured += 1;
                }
                seq += 1;
            }
            measured
        }));
    }

    // Phase timing.
    thread::sleep(params.warmup);
    phase.store(PHASE_MEASURE, Ordering::Relaxed);
    thread::sleep(params.measure);
    phase.store(PHASE_COOLDOWN, Ordering::Relaxed);
    thread::sleep(params.cooldown);
    phase.store(PHASE_DONE, Ordering::Relaxed);

    let mut total = 0u64;
    for h in handles {
        if let Ok(n) = h.join() {
            total += n;
        }
    }
    log::info!("distributed sender: sent {total} messages during measurement");
    Ok(total)
}

/// Run the receiver side of a distributed benchmark.
///
/// Binds to `bind_addr` (TCP), accepts connections, ingests WireHeader-stamped
/// messages, and reports a [`FlowSummary`] at completion.
pub fn run_distributed_receiver(
    params: &DistributedParams,
    bind_addr: &str,
) -> io::Result<FlowSummary> {
    use crate::metrics::app::{self, FlowMetrics};
    use crate::proto::wire::{WireHeader, HEADER_LEN};
    use crate::time::monotonic_ns;
    use std::net::TcpListener;

    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    log::info!("distributed receiver: listening on {bind_addr}");

    let phase = Arc::new(AtomicU8::new(PHASE_WARMUP));
    let msg_bytes = params.message_bytes.max(HEADER_LEN as u32) as usize;

    if !params.cores.is_empty() {
        super::affinity::pin_current_thread(&params.cores);
    }

    // Accept connections in a spawned thread.
    let phase_acc = phase.clone();
    let accept_handle = thread::spawn(move || -> Vec<std::net::TcpStream> {
        let mut conns = Vec::new();
        loop {
            if phase_acc.load(Ordering::Relaxed) >= PHASE_COOLDOWN {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    conns.push(stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        conns
    });

    // Wait for at least one connection before starting the phase clock.
    thread::sleep(Duration::from_millis(500));

    // Phase timing.
    thread::sleep(params.warmup);
    phase.store(PHASE_MEASURE, Ordering::Relaxed);
    let measure_start = Instant::now();
    thread::sleep(params.measure);
    let measure_secs = measure_start.elapsed().as_secs_f64();
    phase.store(PHASE_COOLDOWN, Ordering::Relaxed);
    thread::sleep(params.cooldown);
    phase.store(PHASE_DONE, Ordering::Relaxed);

    let conns = accept_handle
        .join()
        .map_err(|_| io::Error::other("accept thread panicked"))?;
    log::info!("distributed receiver: accepted {} connections", conns.len());

    // Read all remaining data from connections and build metrics.
    // Note: in a real distributed mode the receiver threads would run concurrently
    // with the phase clock. This simplified version works for basic validation.
    let mut all_metrics = Vec::new();
    for stream in conns {
        let mut buf = vec![0u8; msg_bytes];
        let mut metrics = FlowMetrics::new();
        loop {
            use std::io::Read;
            let mut s = &stream;
            match s.read_exact(&mut buf) {
                Ok(()) => {
                    let recv_ns = monotonic_ns();
                    if let Ok(hdr) = WireHeader::decode(&buf) {
                        let latency_ns = recv_ns.saturating_sub(hdr.ts_ns);
                        metrics.record(hdr.seq, latency_ns, msg_bytes as u64);
                    }
                }
                Err(_) => break,
            }
        }
        all_metrics.push(metrics);
    }

    let summary = app::aggregate_run(&all_metrics, measure_secs, params.remove_outliers);
    log::info!(
        "distributed receiver: {:.3} Gbit/s, p99={:.0}µs, lost={}",
        summary.throughput_gbps,
        summary.latency_us.p99,
        summary.integrity.lost
    );
    Ok(summary)
}
