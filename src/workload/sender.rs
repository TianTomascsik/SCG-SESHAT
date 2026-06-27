//! Sender-side workload generation (F-07, F-12).
//!
//! Two concerns, kept separate from any transport:
//!   * [`Pacer`] — *when* to send the next message. It turns a scenario's
//!     [`Pattern`] (sustained / periodic / burst / ramp) into a stream of
//!     monotonic send deadlines, relative to the run start. It performs no I/O
//!     and no sleeping, so it is fully deterministic and unit-testable; the run
//!     engine (WP1.4) reads each deadline and parks the thread via
//!     [`crate::time::sleep_until_ns`].
//!   * [`MessageBuilder`] — *what* to send. It owns one reusable buffer and
//!     stamps a fresh [`WireHeader`] + deterministic payload per sequence
//!     number with zero per-message allocation (NFR-PERF).
//!
//! `message_size_bytes` is interpreted as the **total on-wire size** of each
//! message; the 24-byte SESHAT header is carved out of it, so the SCG sees
//! exactly the configured message size and throughput accounting is exact.
#![allow(dead_code)]

use crate::config::{Pattern, Sender};
use crate::proto::wire::{encode_message, encode_message_at, HEADER_LEN};

/// Minimum on-wire message size (header only, empty payload).
pub const MIN_MESSAGE_SIZE: u32 = HEADER_LEN as u32;

/// Convert a target rate in Mbit/s to the inter-message gap in nanoseconds.
///
/// `gap = message_bits / (rate_mbps * 1e6) * 1e9`. A non-positive rate means
/// "as fast as possible" → gap 0.
fn gap_ns_for_rate(message_bytes: u32, rate_mbps: f64) -> u64 {
    if rate_mbps <= 0.0 {
        return 0;
    }
    let message_bits = message_bytes as f64 * 8.0;
    (message_bits / (rate_mbps * 1e6) * 1e9) as u64
}

/// Internal pacing state machine, one variant per [`Pattern`].
#[derive(Debug, Clone)]
enum PacerKind {
    /// Fixed gap between messages (0 = unthrottled, or a steady rate limit).
    Fixed { gap_ns: u64 },
    /// `count` messages spaced `gap_ns` apart, then a `pause_ns` gap.
    Burst {
        count: u64,
        gap_ns: u64,
        pause_ns: u64,
        pos: u64,
    },
    /// Rate climbs by `step_mbps` every `step_interval_ns`, from `start_mbps`.
    Ramp {
        message_bytes: u32,
        start_mbps: f64,
        step_mbps: f64,
        step_interval_ns: u64,
    },
}

/// Produces the monotonic send deadline (ns, relative to run start) of each
/// successive message.
#[derive(Debug, Clone)]
pub struct Pacer {
    kind: PacerKind,
    /// Deadline (relative ns) of the next message to be emitted.
    next_ns: u64,
}

impl Pacer {
    /// Build a pacer for a scenario sender and its on-wire message size.
    ///
    /// Field requirements per pattern are enforced earlier by config
    /// validation; missing optionals fall back to sane defaults here.
    pub fn from_sender(sender: &Sender, message_bytes: u32) -> Self {
        let kind = match sender.pattern {
            Pattern::Sustained => PacerKind::Fixed {
                gap_ns: sender
                    .rate_limit_mbps
                    .map(|r| gap_ns_for_rate(message_bytes, r))
                    .unwrap_or(0),
            },
            Pattern::Periodic => {
                let gap_ns = sender
                    .interval_us
                    .map(|us| us.saturating_mul(1_000))
                    .or_else(|| {
                        sender
                            .rate_limit_mbps
                            .map(|r| gap_ns_for_rate(message_bytes, r))
                    })
                    .unwrap_or(0);
                PacerKind::Fixed { gap_ns }
            }
            Pattern::Burst => {
                let intra = sender
                    .interval_us
                    .map(|us| us.saturating_mul(1_000))
                    .or_else(|| {
                        sender
                            .rate_limit_mbps
                            .map(|r| gap_ns_for_rate(message_bytes, r))
                    })
                    .unwrap_or(0);
                PacerKind::Burst {
                    count: sender.burst_count.unwrap_or(1).max(1),
                    gap_ns: intra,
                    pause_ns: sender.burst_pause_us.unwrap_or(0).saturating_mul(1_000),
                    pos: 0,
                }
            }
            Pattern::Ramp => PacerKind::Ramp {
                message_bytes,
                start_mbps: sender.ramp_start_mbps.unwrap_or(0.0).max(0.0),
                step_mbps: sender.ramp_step_mbps.unwrap_or(0.0).max(0.0),
                step_interval_ns: sender
                    .ramp_step_interval_secs
                    .unwrap_or(1)
                    .max(1)
                    .saturating_mul(1_000_000_000),
            },
        };
        Pacer { kind, next_ns: 0 }
    }

    /// Return the relative-ns deadline for the next message, advancing internal
    /// state so the following call yields the message after it.
    pub fn next_deadline_ns(&mut self) -> u64 {
        let deadline = self.next_ns;
        match &mut self.kind {
            PacerKind::Fixed { gap_ns } => {
                self.next_ns = self.next_ns.saturating_add(*gap_ns);
            }
            PacerKind::Burst {
                count,
                gap_ns,
                pause_ns,
                pos,
            } => {
                *pos += 1;
                if *pos >= *count {
                    *pos = 0;
                    self.next_ns = self
                        .next_ns
                        .saturating_add(*gap_ns)
                        .saturating_add(*pause_ns);
                } else {
                    self.next_ns = self.next_ns.saturating_add(*gap_ns);
                }
            }
            PacerKind::Ramp {
                message_bytes,
                start_mbps,
                step_mbps,
                step_interval_ns,
            } => {
                let steps = deadline / *step_interval_ns;
                let rate = *start_mbps + *step_mbps * steps as f64;
                let gap = gap_ns_for_rate(*message_bytes, rate);
                self.next_ns = self.next_ns.saturating_add(gap);
            }
        }
        deadline
    }

    /// Whether this pacer sends with no inter-message delay (unthrottled blast),
    /// in which case the run engine drives the vectored batch send path.
    pub fn is_blast(&self) -> bool {
        matches!(self.kind, PacerKind::Fixed { gap_ns: 0 })
    }
}

/// Builds successive on-wire messages into one reusable buffer.
#[derive(Debug)]
pub struct MessageBuilder {
    buf: Vec<u8>,
    payload_len: u32,
    message_bytes: u32,
}

impl MessageBuilder {
    /// Create a builder for the given total on-wire message size. Sizes below
    /// the header length are clamped up to a header-only message.
    pub fn new(message_bytes: u32) -> Self {
        let message_bytes = message_bytes.max(MIN_MESSAGE_SIZE);
        let payload_len = message_bytes - MIN_MESSAGE_SIZE;
        MessageBuilder {
            buf: vec![0u8; message_bytes as usize],
            payload_len,
            message_bytes,
        }
    }

    /// Encode the message for `seq` (fresh send timestamp) and return it.
    #[inline]
    pub fn build(&mut self, seq: u64) -> &[u8] {
        let total = encode_message(seq, self.payload_len, &mut self.buf);
        &self.buf[..total]
    }

    /// Encode the message for `seq` stamping the explicit send time `ts_ns`
    /// instead of "now". The paced run engine passes the message's *scheduled*
    /// send time here so receiver-side latency is coordinated-omission-corrected.
    #[inline]
    pub fn build_at(&mut self, seq: u64, ts_ns: u64) -> &[u8] {
        let total = encode_message_at(seq, self.payload_len, ts_ns, &mut self.buf);
        &self.buf[..total]
    }

    /// Total on-wire size of each message.
    pub fn message_len(&self) -> usize {
        self.message_bytes as usize
    }

    /// Payload size (message size minus the 24-byte header).
    pub fn payload_len(&self) -> u32 {
        self.payload_len
    }
}

/// Builds a batch of successive on-wire messages into N reusable buffers, so a
/// vectored send (`sendmmsg`) can transmit the whole batch in one syscall on the
/// unthrottled blast path. Like [`MessageBuilder`] it allocates only once, at
/// construction (NFR-PERF).
#[derive(Debug)]
pub struct BatchBuilder {
    bufs: Vec<Vec<u8>>,
    payload_len: u32,
}

impl BatchBuilder {
    /// Create a builder staging `batch` messages of `message_bytes` total size.
    pub fn new(message_bytes: u32, batch: usize) -> Self {
        let message_bytes = message_bytes.max(MIN_MESSAGE_SIZE);
        let payload_len = message_bytes - MIN_MESSAGE_SIZE;
        BatchBuilder {
            bufs: (0..batch.max(1))
                .map(|_| vec![0u8; message_bytes as usize])
                .collect(),
            payload_len,
        }
    }

    /// Encode messages for `seq_start .. seq_start + count` (each with a fresh
    /// send timestamp) and return them. `count` is clamped to the batch size.
    pub fn build(&mut self, seq_start: u64, count: usize) -> &[Vec<u8>] {
        let count = count.min(self.bufs.len());
        for (i, buf) in self.bufs.iter_mut().enumerate().take(count) {
            encode_message(seq_start.wrapping_add(i as u64), self.payload_len, buf);
        }
        &self.bufs[..count]
    }

    /// Number of messages this builder can stage at once.
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;

    fn sender(pattern: Pattern) -> Sender {
        Sender {
            interface: Interface::Tcp,
            target_addr: "127.0.0.1:9000".into(),
            pattern,
            rate_limit_mbps: None,
            interval_us: None,
            burst_count: None,
            burst_pause_us: None,
            ramp_start_mbps: None,
            ramp_step_mbps: None,
            ramp_step_interval_secs: None,
        }
    }

    fn deadlines(p: &mut Pacer, n: usize) -> Vec<u64> {
        (0..n).map(|_| p.next_deadline_ns()).collect()
    }

    #[test]
    fn sustained_is_unthrottled() {
        let mut p = Pacer::from_sender(&sender(Pattern::Sustained), 1024);
        assert_eq!(deadlines(&mut p, 5), vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn sustained_rate_limited() {
        // 1250-byte msg = 10000 bits; 10 Mbit/s → 1 ms gap = 1_000_000 ns.
        let mut s = sender(Pattern::Sustained);
        s.rate_limit_mbps = Some(10.0);
        let mut p = Pacer::from_sender(&s, 1250);
        assert_eq!(
            deadlines(&mut p, 4),
            vec![0, 1_000_000, 2_000_000, 3_000_000]
        );
    }

    #[test]
    fn periodic_uses_interval() {
        let mut s = sender(Pattern::Periodic);
        s.interval_us = Some(500); // 500 µs = 500_000 ns
        let mut p = Pacer::from_sender(&s, 256);
        assert_eq!(deadlines(&mut p, 3), vec![0, 500_000, 1_000_000]);
    }

    #[test]
    fn burst_groups_then_pauses() {
        let mut s = sender(Pattern::Burst);
        s.burst_count = Some(3);
        s.burst_pause_us = Some(10); // 10 µs = 10_000 ns
        let mut p = Pacer::from_sender(&s, 128);
        // 3 back-to-back (gap 0), then a 10_000 ns pause, then 3 more.
        assert_eq!(deadlines(&mut p, 6), vec![0, 0, 0, 10_000, 10_000, 10_000]);
    }

    #[test]
    fn ramp_increases_offered_load() {
        let mut s = sender(Pattern::Ramp);
        s.ramp_start_mbps = Some(10.0);
        s.ramp_step_mbps = Some(10.0);
        s.ramp_step_interval_secs = Some(1);
        let mut p = Pacer::from_sender(&s, 1250); // 10000 bits/msg
        let d0 = p.next_deadline_ns();
        let d1 = p.next_deadline_ns();
        assert_eq!(d0, 0);
        assert_eq!(d1 - d0, 1_000_000); // step 0: rate 10 Mbit/s → 1 ms gap

        // Advance until a deadline lands in the second 1-second step.
        let mut d = d1;
        while d < 1_000_000_000 {
            d = p.next_deadline_ns();
        }
        // Gap for a message in the higher-rate (>= 20 Mbit/s) step must shrink.
        let nxt = p.next_deadline_ns();
        let gap_step1 = nxt - d;
        assert!(
            gap_step1 < 1_000_000,
            "ramp gap did not shrink: {gap_step1}"
        );
        assert!(gap_step1 <= 500_000, "expected <= 500 µs, got {gap_step1}");
    }

    #[test]
    fn message_builder_sizes_and_round_trip() {
        use crate::proto::wire::decode_message;
        let mut b = MessageBuilder::new(128);
        assert_eq!(b.message_len(), 128);
        assert_eq!(b.payload_len(), 128 - 24);
        let msg = b.build(42);
        assert_eq!(msg.len(), 128);
        let hdr = decode_message(msg).unwrap();
        assert_eq!(hdr.seq, 42);
        assert_eq!(hdr.payload_len, 104);
    }

    #[test]
    fn message_builder_build_at_stamps_scheduled_time() {
        use crate::proto::wire::decode_message;
        let mut b = MessageBuilder::new(128);
        let msg = b.build_at(7, 9_999);
        let hdr = decode_message(msg).unwrap();
        assert_eq!(hdr.seq, 7);
        assert_eq!(hdr.ts_ns, 9_999, "build_at records the scheduled send time");
    }

    #[test]
    fn message_builder_clamps_tiny_size() {
        let b = MessageBuilder::new(4);
        assert_eq!(b.message_len(), MIN_MESSAGE_SIZE as usize);
        assert_eq!(b.payload_len(), 0);
    }
}
