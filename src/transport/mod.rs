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
pub mod tcp;
pub mod tproxy;
pub mod udp;
pub mod uds;

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::proto::wire::{WireHeader, HEADER_LEN};

/// Default socket read timeout, so receiver loops can periodically re-check the
/// run-phase flag and exit cleanly when the sender stops.
pub const RECV_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum messages a transport batches into a single vectored syscall
/// (`sendmmsg`/`recvmmsg`). Sized to amortise per-syscall overhead on the
/// datagram blast path without large stalls; stream transports ignore it.
pub const BATCH_MAX: usize = 32;

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
    /// Send a batch of complete messages, in as few syscalls as the transport
    /// allows. Returns the number of messages actually sent (`< msgs.len()`
    /// only on a partial datagram-batch send). The default sends them one at a
    /// time; datagram transports override this with a single `sendmmsg`.
    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        for (i, m) in msgs.iter().enumerate() {
            if let Err(e) = self.send_msg(m) {
                return if i == 0 { Err(e) } else { Ok(i) };
            }
        }
        Ok(msgs.len())
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
    /// Return the underlying OS file descriptor, if applicable. Used for
    /// DSCP/TOS verification via `recvmsg` ancillary data.
    fn raw_fd(&self) -> Option<i32> {
        None
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

/// Re-frames a byte stream into discrete SESHAT messages.
///
/// Holds an internal accumulator across calls so a message split over several
/// reads — or a read that times out mid-message — is reassembled correctly.
pub struct FramedReader {
    acc: Vec<u8>,
    scratch: Vec<u8>,
}

impl FramedReader {
    /// New reader sized to comfortably hold a couple of `message_bytes` frames.
    pub fn new(message_bytes: u32) -> Self {
        let cap = (message_bytes as usize).max(HEADER_LEN) * 2;
        FramedReader {
            acc: Vec::with_capacity(cap),
            scratch: vec![0u8; cap.max(64 * 1024)],
        }
    }

    /// Try to pull one complete message out of the accumulator into `out`.
    fn take_message(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.acc.len() < HEADER_LEN {
            return None;
        }
        let hdr = match WireHeader::decode(&self.acc) {
            Ok(h) => h,
            // A bad magic here means the stream is desynchronised; surface it as
            // a zero-length frame would be wrong, so we drop one byte and retry
            // on the next call. In practice loopback streams never desync.
            Err(_) => {
                self.acc.drain(..1);
                return None;
            }
        };
        let total = HEADER_LEN + hdr.payload_len as usize;
        if self.acc.len() < total {
            return None;
        }
        let n = total.min(out.len());
        out[..n].copy_from_slice(&self.acc[..n]);
        self.acc.drain(..total);
        Some(n)
    }

    /// Read from `read_fn` until a full message is available, a timeout occurs,
    /// or the stream closes. `read_fn` returns `Ok(0)` on EOF and a `WouldBlock`
    /// / `TimedOut` error on idle timeout.
    pub fn next_message<F>(&mut self, out: &mut [u8], mut read_fn: F) -> io::Result<RecvOutcome>
    where
        F: FnMut(&mut [u8]) -> io::Result<usize>,
    {
        loop {
            if let Some(n) = self.take_message(out) {
                return Ok(RecvOutcome::Message(n));
            }
            match read_fn(&mut self.scratch) {
                Ok(0) => return Ok(RecvOutcome::Closed),
                Ok(n) => self.acc.extend_from_slice(&self.scratch[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(RecvOutcome::Timeout),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(RecvOutcome::Timeout),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
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
}
