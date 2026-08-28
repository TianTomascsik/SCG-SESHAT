//! Transport abstraction (F-05) and the loopback baseline transports.
//!
//! A *transport* knows how to stand up a connected sender→receiver pair so the
//! run engine can drive traffic without caring whether the bytes travel over
//! TCP, UDP, a Unix socket, or shared memory. Phase 1 implements the two
//! loopback baselines (no gateway); later phases add gateway-backed UDS/SHM.
//!
//! The data plane is split into two halves so each can live on its own
//! core-pinned thread (NFR-PERF):
//!   * [`DataSink`] — the sender side, writes whole messages.
//!   * [`DataSource`] — the receiver side, yields whole messages with a
//!     [`RecvOutcome`] that distinguishes a real message from an idle timeout
//!     (used to poll the run-phase flag) or a closed peer.
//!
//! Stream transports (TCP, UDS) must re-frame the byte stream into messages;
//! [`FramedReader`] does that using the `payload_len` in each [`WireHeader`],
//! tolerating reads that block/time out mid-message.
//!
//! The trait API here is consumed by the run engine (WP1.4).
#![allow(dead_code)]

pub mod gateway;
pub mod shm;
pub mod shm_null;
pub mod tcp;
pub mod tproxy;
pub mod udp;
pub mod uds;
pub mod uds_null;

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::proto::wire::{WireHeader, HEADER_LEN};

/// Default socket read timeout, so receiver loops can periodically re-check the
/// run-phase flag and exit cleanly when the sender stops.
pub const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Default messages a transport batches into a single vectored syscall
/// (`sendmmsg`/`recvmmsg`). Sized to amortise per-syscall overhead on the
/// datagram blast path without large stalls. Stream transports report a
/// larger, size-dependent batch via [`DataSink::preferred_batch`] /
/// [`DataSource::preferred_batch`].
pub const BATCH_MAX: usize = 32;

/// Hard upper bound on a batch, matching the kernel's `UIO_MAXIOV` iovec limit
/// for a single vectored write.
pub const BATCH_ABS_MAX: usize = 1024;

/// Soft byte budget for one stream batch: enough to amortise syscall cost at
/// small message sizes without unbounded staging memory per connection.
pub const BATCH_BYTES_BUDGET: usize = 256 * 1024;

/// Batch size for stream transports: fill [`BATCH_BYTES_BUDGET`] with
/// `message_bytes`-sized messages, floored at [`BATCH_MAX`] (so large messages
/// keep today's staging footprint) and capped at [`BATCH_ABS_MAX`] (`writev`'s
/// iovec limit).
pub fn stream_batch_size(message_bytes: u32) -> usize {
    (BATCH_BYTES_BUDGET / (message_bytes.max(1) as usize)).clamp(BATCH_MAX, BATCH_ABS_MAX)
}

/// Per-connection management `app_id` for the UDS/SHM gateway transports.
///
/// The gateway keys each dynamically-provisioned endpoint by
/// `(uid, app_id, class, direction)` with **no** per-connection component, and
/// re-registering that key tears down the previous endpoint. So N concurrent
/// connections that all reuse one `app_id` evict each other down to a single
/// survivor — the historical multi-connection UDS/SHM zero-metric failure
/// (1 connection passes, ≥2 collapse to zero messages). Giving connection `i` a
/// distinct `app_id` (paired at the call site with its own reserved upstream
/// port) makes the N pipelines independent.
///
/// The `-c{i}` suffix is length-bounded like [`scenario_app_id`]: the id is
/// embedded in a Unix-socket path capped by `SUN_LEN` (~108 bytes), so the total
/// stays ≤ 40 bytes by trimming the readable head — never the unique suffix.
pub(crate) fn conn_app_id(base: &str, index: usize) -> String {
    const MAX: usize = 40;
    let suffix = format!("-c{index}");
    let room = MAX.saturating_sub(suffix.len());
    let head: String = base.chars().take(room).collect();
    format!("{head}{suffix}")
}

/// Outcome of a single [`DataSource::recv_msg`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvOutcome {
    /// A complete message of this many bytes was written to the caller buffer.
    Message(usize),
    /// No message within the poll timeout (socket idle).
    Timeout,
    /// The peer closed the connection / stream ended.
    Closed,
}

/// Outcome of a single [`DataSource::recv_batch`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// This many messages were received; their lengths are in the caller's
    /// `lens` slice and their bytes laid out `stride`-apart in the buffer.
    Messages(usize),
    /// No message within the poll timeout (socket idle).
    Timeout,
    /// The peer closed the connection / stream ended.
    Closed,
}

/// The sender half of a connected transport.
pub trait DataSink: Send {
    /// Send one complete message. Must transmit the whole buffer.
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()>;
    /// Return the underlying OS file descriptor, if applicable. Used for
    /// egress DSCP/TOS marking (`IP_TOS`) on QoS streams.
    fn raw_fd(&self) -> Option<i32> {
        None
    }
    /// Send a batch of complete messages, in as few syscalls as the transport
    /// allows. Returns the number of messages actually sent (`< msgs.len()`
    /// only on a partial batch send). The default sends them one at a time;
    /// datagram transports override this with a single `sendmmsg`, stream
    /// transports with a single `writev`.
    ///
    /// Contract: implementations must return **only at message boundaries** —
    /// a partially transmitted message must be completed before returning,
    /// because callers rebuild and resend everything after the returned count
    /// (a partial-message return would permanently desynchronise a stream).
    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        for (i, m) in msgs.iter().enumerate() {
            if let Err(e) = self.send_msg(m) {
                return if i == 0 { Err(e) } else { Ok(i) };
            }
        }
        Ok(msgs.len())
    }
    /// How many messages of `message_bytes` this sink prefers per
    /// [`Self::send_batch`] call. Datagram transports keep the [`BATCH_MAX`]
    /// default; stream transports report a size-dependent batch so small
    /// messages amortise syscall cost.
    fn preferred_batch(&self, _message_bytes: u32) -> usize {
        BATCH_MAX
    }
    /// Reserve `len` bytes for **in-place** production, returning a writable
    /// region the caller fills directly (the workload generator writes straight
    /// into it), avoiding a staging buffer and the buffer→ring copy `send_msg`
    /// makes. Returns `None` if the sink has no in-place path (the caller then
    /// builds a buffer and uses [`send_msg`](Self::send_msg)) or the ring is
    /// momentarily full. On `Some`, fill the slice then call
    /// [`commit_reserved`](Self::commit_reserved) exactly once. Default:
    /// unsupported.
    fn reserve(&mut self, _len: usize) -> Option<&mut [u8]> {
        None
    }
    /// Publish the region from the last successful [`reserve`](Self::reserve) and
    /// wake the peer. Valid only immediately after a `reserve` that returned
    /// `Some`. Default: no-op (paired with the `None`-returning default).
    fn commit_reserved(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Whether this sink supports in-place **batched** production
    /// ([`reserve`](Self::reserve) + [`commit_batched`](Self::commit_batched) +
    /// [`flush_batch`](Self::flush_batch)) — the blast-path zero-copy generator.
    /// Default: no.
    fn supports_inplace(&self) -> bool {
        false
    }
    /// Publish the region from the last [`reserve`](Self::reserve) **without**
    /// waking the peer, so a whole batch of in-place sends costs one
    /// [`flush_batch`](Self::flush_batch) wakeup (matching the copy-based
    /// [`send_batch`](Self::send_batch)'s one-signal-per-batch). Returns whether a
    /// frame was published (false = ring filled). Default: unsupported.
    fn commit_batched(&mut self) -> io::Result<bool> {
        Ok(false)
    }
    /// Wake the peer once after a run of [`commit_batched`](Self::commit_batched).
    /// Default: no-op.
    fn flush_batch(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Release the underlying resource.
    fn close(&mut self);
}

/// The receiver half of a connected transport.
pub trait DataSource: Send {
    /// Receive the next complete message into `buf`, returning the outcome.
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome>;
    /// Receive up to `max` messages into `buf`, where message `i` is written to
    /// `buf[i*stride ..]` and its length recorded in `lens[i]`. Returns the
    /// batch outcome. The default receives a single message; datagram
    /// transports override this with a `recvmmsg` that drains several datagrams
    /// per syscall so the receiver keeps up with a blasting sender (loss→0).
    fn recv_batch(
        &mut self,
        buf: &mut [u8],
        stride: usize,
        max: usize,
        lens: &mut [usize],
    ) -> io::Result<BatchOutcome> {
        if max == 0 || stride == 0 || buf.len() < stride || lens.is_empty() {
            return Ok(BatchOutcome::Timeout);
        }
        match self.recv_msg(&mut buf[..stride])? {
            RecvOutcome::Message(n) => {
                lens[0] = n;
                Ok(BatchOutcome::Messages(1))
            }
            RecvOutcome::Timeout => Ok(BatchOutcome::Timeout),
            RecvOutcome::Closed => Ok(BatchOutcome::Closed),
        }
    }
    /// Receive the next complete message and, when this transport can observe
    /// it, the IP TOS byte of the packet that carried it.
    ///
    /// Datagram transports override this with an `IP_RECVTOS` `recvmsg` (see
    /// [`crate::workload::dscp::recv_one_with_tos`]). The default delegates to
    /// [`Self::recv_msg`] and reports `None`: Linux delivers TOS ancillary data
    /// only for datagram sockets, so a stream transport must report the mark as
    /// unobserved rather than fabricate a verdict.
    fn recv_msg_with_tos(&mut self, buf: &mut [u8]) -> io::Result<(RecvOutcome, Option<u8>)> {
        Ok((self.recv_msg(buf)?, None))
    }
    /// Return the underlying OS file descriptor, if applicable. Used for
    /// DSCP/TOS verification via `recvmsg` ancillary data.
    fn raw_fd(&self) -> Option<i32> {
        None
    }
    /// How many message slots of `message_bytes` this source prefers per
    /// [`Self::recv_batch`] call. Datagram transports keep the [`BATCH_MAX`]
    /// default; stream transports report a size-dependent batch so one read
    /// syscall can be carved into many messages.
    fn preferred_batch(&self, _message_bytes: u32) -> usize {
        BATCH_MAX
    }
    /// Whether this source supports **in-place** (zero-copy) receive via
    /// [`recv_inplace`](Self::recv_inplace) — the SHM slot ring. Default: no.
    fn supports_inplace_recv(&self) -> bool {
        false
    }
    /// Zero-copy receive: wait for data, then hand each ready message's payload
    /// to `f` **in place** — borrowed straight from the ring, never copied into a
    /// batch buffer — consuming it after `f` returns. Drains up to `max` messages
    /// this call. Returns `Messages(n)` / `Timeout` / `Closed`. Only the SHM slot
    /// ring implements this; the engine gates on
    /// [`supports_inplace_recv`](Self::supports_inplace_recv), so the default is
    /// unreachable.
    fn recv_inplace(&mut self, _max: usize, _f: &mut dyn FnMut(&[u8])) -> io::Result<BatchOutcome> {
        Ok(BatchOutcome::Timeout)
    }
    /// Release the underlying resource.
    fn close(&mut self);
}

/// A bidirectional message endpoint for the closed-loop ping-pong mode (Phase
/// F): it can both send and receive whole framed messages over one connection.
///
/// Unlike the one-way [`DataSink`]/[`DataSource`] split used by the throughput
/// engine, a `DuplexEnd` is a single full-duplex handle. The client end sends a
/// request then reads the echo on the same connection; the server end reads a
/// request then writes the echo back. TCP and connected UDP are duplex, so the
/// same connection carries both directions.
pub trait DuplexEnd: Send {
    /// Send one complete message. Must transmit the whole buffer.
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()>;
    /// Receive the next complete message into `buf`, returning the outcome.
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome>;
    /// Release the underlying resource.
    fn close(&mut self);
}

/// Client side of the connection-rate mode (Phase G): opens one fresh
/// connection, completing the full establishment handshake (TCP three-way, or
/// the gateway's upstream TLS), and tears it back down.
///
/// One factory is shared (`Arc`) across all connector threads, so it must be
/// `Sync`; for the loopback transports it holds only the listener address.
pub trait ConnFactory: Send + Sync {
    /// Open one connection, returning the establishment time in nanoseconds,
    /// then close it. The connector loop calls this repeatedly and records the
    /// returned handshake time per connection.
    fn connect_once(&self) -> io::Result<u64>;
}

/// Server side of the connection-rate mode (Phase G): accepts and immediately
/// closes each incoming connection so the client churns through fresh
/// establishments. Runs on its own thread for the duration of a run.
pub trait ConnAcceptor: Send {
    /// Accept-and-close loop; returns once `stop` is set. The acceptor closes
    /// each connection first (active close) so the client side does not
    /// accumulate `TIME_WAIT` ephemeral ports at high churn.
    fn serve(self: Box<Self>, stop: &AtomicBool);
}

/// A transport able to set up a connected loopback pair on `127.0.0.1`.
pub trait Transport {
    /// Short identifier for logs / results (e.g. `"tcp"`).
    fn name(&self) -> &'static str;

    /// Identity for ceiling-cache keying. Defaults to [`Self::name`];
    /// transports whose measured ability depends on construction parameters
    /// (e.g. the SHM null ring capacity) fold those parameters in.
    fn cache_key(&self) -> String {
        self.name().to_string()
    }

    /// Establish one connected `(sink, source)` pair sized for `message_bytes`
    /// on-wire messages. The sink is the sender end, the source the receiver
    /// end; both are ready to use.
    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)>;

    /// Establish a connected pair for a specific gateway traffic class.
    ///
    /// Most transports do not need separate local provisioning per class and
    /// therefore fall back to the normal loopback pair. Gateway-backed UDS/SHM
    /// override this so safety streams request safety endpoints from SCG.
    fn loopback_pair_for_class(
        &self,
        message_bytes: u32,
        _traffic_class: &str,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        self.loopback_pair(message_bytes)
    }

    /// Establish one connected `(client, server)` full-duplex pair for the
    /// closed-loop ping-pong RTT mode (Phase F). The client drives the loop;
    /// the server echoes each message back. Transports that cannot offer a
    /// duplex path (e.g. the one-way DTLS gateway) return [`io::ErrorKind::Unsupported`].
    fn pingpong_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{} transport does not support ping-pong RTT", self.name()),
        ))
    }

    /// Stand up a connection-rate harness (Phase G): an `(acceptor, factory)`
    /// pair where the acceptor drains incoming connections on its own thread
    /// and the factory — shared across the connector threads — opens fresh
    /// connections as fast as possible. Connectionless or one-way transports
    /// (UDP, the DTLS gateway) return [`io::ErrorKind::Unsupported`].
    fn conn_harness(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn ConnAcceptor>, Arc<dyn ConnFactory>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{} transport does not support connection-rate benchmarking",
                self.name()
            ),
        ))
    }
}

/// Outcome of one [`FramedReader::fill_once`] read attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillOutcome {
    /// The read appended at least one byte to the buffer.
    Filled,
    /// No data within the poll timeout (socket idle).
    Timeout,
    /// The peer closed the connection / stream ended.
    Closed,
}

/// Re-frames a byte stream into discrete SESHAT messages.
///
/// Buffered bytes live in one fixed allocation between a `start` (first
/// unconsumed byte) and `end` (one past last valid byte) cursor, so consuming a
/// message advances `start` in O(1); the buffer is compacted with a single
/// memmove only when the write end is exhausted, never per message. A message
/// split over several reads — or a read that times out mid-message — is
/// reassembled correctly across calls.
pub struct FramedReader {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl FramedReader {
    /// New reader sized to hold at least two full frames (and at least 128 KiB
    /// so one `read` can drain many small messages per syscall).
    pub fn new(message_bytes: u32) -> Self {
        let cap = ((message_bytes as usize) + HEADER_LEN).max(64 * 1024) * 2;
        FramedReader {
            buf: vec![0u8; cap],
            start: 0,
            end: 0,
        }
    }

    /// Try to pull one complete message out of the buffer into `out`.
    ///
    /// On a desynchronised stream (bad magic, or a declared length that could
    /// never fit the buffer) this drops one byte and rescans in place — no read
    /// syscall per dropped byte. In practice loopback streams never desync.
    fn take_one(&mut self, out: &mut [u8]) -> Option<usize> {
        loop {
            if self.end - self.start < HEADER_LEN {
                return None;
            }
            let hdr = match WireHeader::decode(&self.buf[self.start..self.end]) {
                Ok(h) => h,
                Err(_) => {
                    self.start += 1;
                    continue;
                }
            };
            let total = HEADER_LEN + hdr.payload_len as usize;
            if total > self.buf.len() {
                // A corrupt length that can never fit even a compacted buffer:
                // treat it as desync rather than stalling forever.
                self.start += 1;
                continue;
            }
            if self.end - self.start < total {
                return None;
            }
            let n = total.min(out.len());
            out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
            self.start += total;
            return Some(n);
        }
    }

    /// Carve up to `max` complete already-buffered messages into `out_buf`,
    /// message `i` at `out_buf[i*stride..]` with its length in `lens[i]`.
    /// Performs no I/O; returns the number of messages carved.
    pub fn take_messages(
        &mut self,
        out_buf: &mut [u8],
        stride: usize,
        max: usize,
        lens: &mut [usize],
    ) -> usize {
        if stride == 0 {
            return 0;
        }
        let cap = max.min(lens.len()).min(out_buf.len() / stride);
        let mut count = 0;
        while count < cap {
            let slot = &mut out_buf[count * stride..(count + 1) * stride];
            match self.take_one(slot) {
                Some(n) => {
                    lens[count] = n;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Issue one read into the free tail of the buffer, compacting first if the
    /// tail is exhausted. `read_fn` returns `Ok(0)` on EOF and a `WouldBlock` /
    /// `TimedOut` error on idle timeout.
    pub(crate) fn fill_once<F>(&mut self, read_fn: &mut F) -> io::Result<FillOutcome>
    where
        F: FnMut(&mut [u8]) -> io::Result<usize>,
    {
        if self.start == self.end {
            // Steady state: everything consumed, reset in O(1).
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            // Write end exhausted with a partial message pending: one memmove
            // per buffer-full, not per message.
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buf.len() {
            // Cannot happen with the capacity chosen in `new` (≥ 2 frames), but
            // reading into an empty slice would misreport EOF; fail loudly.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "framed-reader buffer full without a complete message",
            ));
        }
        match read_fn(&mut self.buf[self.end..]) {
            Ok(0) => Ok(FillOutcome::Closed),
            Ok(n) => {
                self.end += n;
                Ok(FillOutcome::Filled)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(FillOutcome::Timeout),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(FillOutcome::Timeout),
            // A signal interrupted the read before any byte arrived: report
            // `Filled` so the caller's take→fill loop simply retries the read.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(FillOutcome::Filled),
            Err(e) => Err(e),
        }
    }

    /// Read from `read_fn` until a full message is available, a timeout occurs,
    /// or the stream closes. `read_fn` returns `Ok(0)` on EOF and a `WouldBlock`
    /// / `TimedOut` error on idle timeout.
    pub fn next_message<F>(&mut self, out: &mut [u8], mut read_fn: F) -> io::Result<RecvOutcome>
    where
        F: FnMut(&mut [u8]) -> io::Result<usize>,
    {
        loop {
            if let Some(n) = self.take_one(out) {
                return Ok(RecvOutcome::Message(n));
            }
            match self.fill_once(&mut read_fn)? {
                FillOutcome::Filled => continue,
                FillOutcome::Timeout => return Ok(RecvOutcome::Timeout),
                FillOutcome::Closed => return Ok(RecvOutcome::Closed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::encode_message;

    #[test]
    fn framed_reader_splits_stream() {
        let msg_size = 64u32;
        let payload = msg_size - HEADER_LEN as u32;
        // Build a stream of 3 messages back-to-back.
        let mut stream = Vec::new();
        for seq in 0..3u64 {
            let mut m = vec![0u8; msg_size as usize];
            encode_message(seq, payload, &mut m);
            stream.extend_from_slice(&m);
        }

        // Feed the stream a few bytes at a time to exercise reassembly.
        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        let mut out = vec![0u8; msg_size as usize];
        let mut got = Vec::new();
        loop {
            let outcome = reader
                .next_message(&mut out, |dst| {
                    if cursor >= stream.len() {
                        // emulate idle timeout once drained
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    let take = (stream.len() - cursor).min(7).min(dst.len());
                    dst[..take].copy_from_slice(&stream[cursor..cursor + take]);
                    cursor += take;
                    Ok(take)
                })
                .unwrap();
            match outcome {
                RecvOutcome::Message(n) => {
                    let hdr = crate::proto::wire::decode_message(&out[..n]).unwrap();
                    got.push(hdr.seq);
                }
                RecvOutcome::Timeout | RecvOutcome::Closed => break,
            }
        }
        assert_eq!(got, vec![0, 1, 2]);
    }

    /// Build a contiguous byte stream of `count` back-to-back messages of
    /// `msg_size` on-wire bytes, sequenced from `seq_start`.
    fn message_stream(seq_start: u64, count: u64, msg_size: u32) -> Vec<u8> {
        let payload = msg_size - HEADER_LEN as u32;
        let mut stream = Vec::new();
        for seq in seq_start..seq_start + count {
            let mut m = vec![0u8; msg_size as usize];
            encode_message(seq, payload, &mut m);
            stream.extend_from_slice(&m);
        }
        stream
    }

    /// Feed `stream` into `reader` in one gulp (as far as the buffer allows).
    fn fill_from(reader: &mut FramedReader, stream: &[u8], cursor: &mut usize) -> FillOutcome {
        reader
            .fill_once(&mut |dst: &mut [u8]| {
                if *cursor >= stream.len() {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let take = (stream.len() - *cursor).min(dst.len());
                dst[..take].copy_from_slice(&stream[*cursor..*cursor + take]);
                *cursor += take;
                Ok(take)
            })
            .unwrap()
    }

    #[test]
    fn take_messages_carves_multiple_buffered() {
        let msg_size = 64u32;
        let stream = message_stream(0, 10, msg_size);
        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        assert_eq!(
            fill_from(&mut reader, &stream, &mut cursor),
            FillOutcome::Filled
        );
        assert_eq!(cursor, stream.len(), "whole stream fits one read");

        let stride = msg_size as usize;
        let mut out = vec![0u8; stride * 4];
        let mut lens = [0usize; 4];
        let mut seqs = Vec::new();
        for expected in [4usize, 4, 2] {
            let n = reader.take_messages(&mut out, stride, 4, &mut lens);
            assert_eq!(n, expected);
            for i in 0..n {
                assert_eq!(lens[i], stride);
                let hdr =
                    crate::proto::wire::decode_message(&out[i * stride..i * stride + lens[i]])
                        .unwrap();
                seqs.push(hdr.seq);
            }
        }
        assert_eq!(seqs, (0..10).collect::<Vec<_>>());
        assert_eq!(reader.take_messages(&mut out, stride, 4, &mut lens), 0);
    }

    #[test]
    fn take_messages_respects_lens_and_bufcap() {
        let msg_size = 64u32;
        let stream = message_stream(0, 8, msg_size);
        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        fill_from(&mut reader, &stream, &mut cursor);

        let stride = msg_size as usize;
        // lens shorter than max caps the carve.
        let mut out = vec![0u8; stride * 8];
        let mut lens = [0usize; 3];
        assert_eq!(reader.take_messages(&mut out, stride, 8, &mut lens), 3);
        // out shorter than max×stride caps the carve.
        let mut small_out = vec![0u8; stride * 2];
        let mut lens8 = [0usize; 8];
        assert_eq!(
            reader.take_messages(&mut small_out, stride, 8, &mut lens8),
            2
        );
        // zero stride is a no-op, not a panic.
        assert_eq!(reader.take_messages(&mut out, 0, 8, &mut lens8), 0);
    }

    #[test]
    fn desync_drops_bytes_until_next_magic() {
        let msg_size = 64u32;
        // Garbage prefix, one message, mid-stream garbage, another message.
        let mut stream = vec![0xAAu8; 13];
        stream.extend_from_slice(&message_stream(7, 1, msg_size));
        stream.extend_from_slice(&[0x55u8; 9]);
        stream.extend_from_slice(&message_stream(8, 1, msg_size));

        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        let mut out = vec![0u8; msg_size as usize];
        let mut got = Vec::new();
        loop {
            let outcome = reader
                .next_message(&mut out, |dst| {
                    if cursor >= stream.len() {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    let take = (stream.len() - cursor).min(dst.len());
                    dst[..take].copy_from_slice(&stream[cursor..cursor + take]);
                    cursor += take;
                    Ok(take)
                })
                .unwrap();
            match outcome {
                RecvOutcome::Message(n) => {
                    got.push(crate::proto::wire::decode_message(&out[..n]).unwrap().seq)
                }
                RecvOutcome::Timeout | RecvOutcome::Closed => break,
            }
        }
        assert_eq!(got, vec![7, 8]);
    }

    #[test]
    fn oversized_payload_len_resyncs() {
        let msg_size = 64u32;
        // A header with valid magic but a payload_len that can never fit the
        // buffer, followed by a real message: the reader must skip past the
        // bogus header instead of stalling or growing without bound.
        let mut stream = Vec::new();
        stream.extend_from_slice(&crate::proto::wire::MAGIC);
        stream.extend_from_slice(&[0u8; 16]); // seq + ts
        stream.extend_from_slice(&u32::MAX.to_le_bytes()); // absurd payload_len
        stream.extend_from_slice(&message_stream(42, 1, msg_size));

        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        let mut out = vec![0u8; msg_size as usize];
        let outcome = reader
            .next_message(&mut out, |dst| {
                if cursor >= stream.len() {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let take = (stream.len() - cursor).min(dst.len());
                dst[..take].copy_from_slice(&stream[cursor..cursor + take]);
                cursor += take;
                Ok(take)
            })
            .unwrap();
        match outcome {
            RecvOutcome::Message(n) => {
                assert_eq!(
                    crate::proto::wire::decode_message(&out[..n]).unwrap().seq,
                    42
                );
            }
            other => panic!("expected recovered message, got {other:?}"),
        }
    }

    #[test]
    fn compaction_preserves_split_messages() {
        // Push several buffer-capacities of messages through with pseudo-random
        // chunk sizes so partial messages straddle every compaction memmove.
        let msg_size = 1000u32;
        let count = 400u64; // 400 kB through a ~128 KiB buffer
        let stream = message_stream(0, count, msg_size);
        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        let mut rng: u64 = 0x5EED;
        let mut out = vec![0u8; msg_size as usize];
        let mut next_seq = 0u64;
        loop {
            let outcome = reader
                .next_message(&mut out, |dst| {
                    if cursor >= stream.len() {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    // Deterministic LCG chunk size in 1..=4096.
                    rng = rng
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let chunk = ((rng >> 33) as usize % 4096) + 1;
                    let take = (stream.len() - cursor).min(chunk).min(dst.len());
                    dst[..take].copy_from_slice(&stream[cursor..cursor + take]);
                    cursor += take;
                    Ok(take)
                })
                .unwrap();
            match outcome {
                RecvOutcome::Message(n) => {
                    let hdr = crate::proto::wire::decode_message(&out[..n]).unwrap();
                    assert_eq!(hdr.seq, next_seq);
                    next_seq += 1;
                }
                RecvOutcome::Timeout | RecvOutcome::Closed => break,
            }
        }
        assert_eq!(next_seq, count, "every message must survive compaction");
    }

    #[test]
    fn timeout_and_eof_semantics() {
        let msg_size = 64u32;
        let stream = message_stream(0, 2, msg_size);
        let split = msg_size as usize + 10; // first message + a partial second
        let mut reader = FramedReader::new(msg_size);
        let mut out = vec![0u8; msg_size as usize];

        // Phase 1: one complete + one partial message, then idle.
        let mut cursor = 0usize;
        let first = &stream[..split];
        let outcome = reader
            .next_message(&mut out, |dst| {
                if cursor >= first.len() {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let take = (first.len() - cursor).min(dst.len());
                dst[..take].copy_from_slice(&first[cursor..cursor + take]);
                cursor += take;
                Ok(take)
            })
            .unwrap();
        assert!(matches!(outcome, RecvOutcome::Message(_)));
        let outcome = reader
            .next_message(&mut out, |_dst: &mut [u8]| {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            })
            .unwrap();
        assert_eq!(outcome, RecvOutcome::Timeout);

        // Phase 2: the rest of the second message arrives, then EOF: the
        // buffered message is returned before Closed.
        let rest = &stream[split..];
        let mut cursor2 = 0usize;
        let outcome = reader
            .next_message(&mut out, |dst| {
                if cursor2 >= rest.len() {
                    return Ok(0); // EOF
                }
                let take = (rest.len() - cursor2).min(dst.len());
                dst[..take].copy_from_slice(&rest[cursor2..cursor2 + take]);
                cursor2 += take;
                Ok(take)
            })
            .unwrap();
        match outcome {
            RecvOutcome::Message(n) => {
                assert_eq!(
                    crate::proto::wire::decode_message(&out[..n]).unwrap().seq,
                    1
                );
            }
            other => panic!("expected buffered message before EOF, got {other:?}"),
        }
        let outcome = reader
            .next_message(&mut out, |_dst: &mut [u8]| Ok(0))
            .unwrap();
        assert_eq!(outcome, RecvOutcome::Closed);
    }

    #[test]
    fn truncating_out_buffer_consumes_whole_message() {
        let msg_size = 128u32;
        let stream = message_stream(0, 2, msg_size);
        let mut reader = FramedReader::new(msg_size);
        let mut cursor = 0usize;
        fill_from(&mut reader, &stream, &mut cursor);

        // Out buffer shorter than the wire message: the copy is truncated but
        // the whole message is consumed, keeping the stream in sync.
        let mut small = vec![0u8; 64];
        assert_eq!(reader.take_one(&mut small), Some(64));
        let mut out = vec![0u8; msg_size as usize];
        match reader.take_one(&mut out) {
            Some(n) => {
                assert_eq!(n, msg_size as usize);
                assert_eq!(
                    crate::proto::wire::decode_message(&out[..n]).unwrap().seq,
                    1
                );
            }
            None => panic!("second message must still parse after truncation"),
        }
    }

    #[test]
    fn batch_size_math() {
        assert_eq!(stream_batch_size(64), BATCH_ABS_MAX); // 4096 capped at 1024
        assert_eq!(stream_batch_size(1024), 256);
        assert_eq!(stream_batch_size(4096), 64);
        assert_eq!(stream_batch_size(16384), BATCH_MAX); // floored at 32
        assert_eq!(stream_batch_size(65536), BATCH_MAX);
        assert_eq!(stream_batch_size(0), BATCH_ABS_MAX); // guarded division
        assert_eq!(BATCH_ABS_MAX, libc::UIO_MAXIOV as usize);
    }
}
