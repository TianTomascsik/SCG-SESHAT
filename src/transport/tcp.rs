//! TCP loopback transport (F-05 `tcp`).
//!
//! Baseline path with no gateway: a sender `TcpStream` writes framed messages
//! to an accepted server `TcpStream`. `TCP_NODELAY` is set so latency reflects
//! the path rather than Nagle batching, and the server side gets a read timeout
//! so the receiver loop can poll the run-phase flag.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    stream_batch_size, BatchOutcome, ConnAcceptor, ConnFactory, DataSink, DataSource, DuplexEnd,
    FillOutcome, FramedReader, RecvOutcome, Transport, BATCH_ABS_MAX, RECV_POLL_TIMEOUT,
};
use crate::time::monotonic_ns;

/// TCP transport factory.
pub struct TcpTransport;

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let client = TcpStream::connect(addr)?;
        client.set_nodelay(true)?;

        let (server, _peer) = listener.accept()?;
        server.set_nodelay(true)?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        let sink = Box::new(TcpSink { stream: client });
        let source = Box::new(TcpSource {
            stream: server,
            reader: FramedReader::new(message_bytes),
        });
        Ok((sink, source))
    }

    fn pingpong_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let client = TcpStream::connect(addr)?;
        client.set_nodelay(true)?;
        client.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        let (server, _peer) = listener.accept()?;
        server.set_nodelay(true)?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        Ok((
            duplex_from_stream(client, message_bytes),
            duplex_from_stream(server, message_bytes),
        ))
    }

    fn conn_harness(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn ConnAcceptor>, Arc<dyn ConnFactory>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        // Non-blocking so the accept loop can poll the stop flag instead of
        // parking forever on the last connection of a run.
        listener.set_nonblocking(true)?;
        let acceptor = Box::new(TcpConnAcceptor { listener });
        let factory = Arc::new(TcpConnFactory {
            addr,
            message_bytes,
        });
        Ok((acceptor, factory))
    }
}

struct TcpSink {
    stream: TcpStream,
}

/// Wrap an already-connected stream as a [`DataSink`] (reused by the
/// gateway-backed transport, where the stream comes from `connect`).
pub(crate) fn sink_from_stream(stream: TcpStream) -> Box<dyn DataSink> {
    Box::new(TcpSink { stream })
}

/// Wrap an already-accepted stream as a framed [`DataSource`] (reused by the
/// gateway-backed transport, where the stream comes from the backend listener).
pub(crate) fn source_from_stream(stream: TcpStream, message_bytes: u32) -> Box<dyn DataSource> {
    Box::new(TcpSource {
        stream,
        reader: FramedReader::new(message_bytes),
    })
}

/// Wrap an already-connected stream as a full-duplex [`DuplexEnd`] for the
/// ping-pong mode (reused by the gateway-backed transport, where both the
/// client and backend streams are duplex and the gateway relays each
/// direction). The stream should already have its read timeout configured.
pub(crate) fn duplex_from_stream(stream: TcpStream, message_bytes: u32) -> Box<dyn DuplexEnd> {
    Box::new(TcpDuplex {
        stream,
        reader: FramedReader::new(message_bytes),
    })
}

/// Write every byte of `msgs` to `fd` via vectored writes, chunked at
/// `iov_cap` iovecs per `writev` call. Returns only at message boundaries: a
/// message the kernel accepted partially is completed (from its offset) before
/// this returns, as required by the [`DataSink::send_batch`] contract.
/// Expects a blocking stream socket.
pub(crate) fn writev_full(fd: i32, msgs: &[&[u8]], iov_cap: usize) -> io::Result<usize> {
    let iov_cap = iov_cap.clamp(1, BATCH_ABS_MAX);
    // First not-fully-sent message, and how many of its bytes are on the wire.
    let mut idx = 0usize;
    let mut off = 0usize;
    while idx < msgs.len() {
        // Stack-allocated iovec array: no heap allocation on the hot path, and
        // no `libc::iovec` (which is `!Send`) stored in the sink itself.
        let mut iov = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; BATCH_ABS_MAX];
        let n_iov = (msgs.len() - idx).min(iov_cap);
        for (i, slot) in iov.iter_mut().enumerate().take(n_iov) {
            let m = msgs[idx + i];
            let skip = if i == 0 { off.min(m.len()) } else { 0 };
            slot.iov_base = m[skip..].as_ptr() as *mut libc::c_void;
            slot.iov_len = m.len() - skip;
        }
        // SAFETY: fd is a valid connected stream socket owned by the caller for
        // the duration of this call; iov[..n_iov] points into caller-borrowed
        // slices that outlive the syscall.
        let ret = unsafe { libc::writev(fd, iov.as_ptr(), n_iov as libc::c_int) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => continue,
                // Momentarily full socket buffer at a clean message boundary:
                // report progress so the caller can yield and resend the rest.
                io::ErrorKind::WouldBlock if off == 0 => return Ok(idx),
                // Mid-message we must finish the in-flight message (sockets
                // here are blocking; this arm is belt-and-braces).
                io::ErrorKind::WouldBlock => continue,
                _ => return Err(e),
            }
        }
        if ret == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "writev accepted zero bytes",
            ));
        }
        // Advance (idx, off) across whole messages consumed by this write.
        let mut written = ret as usize;
        while written > 0 && idx < msgs.len() {
            let rem = msgs[idx].len() - off;
            if written >= rem {
                written -= rem;
                idx += 1;
                off = 0;
            } else {
                off += written;
                written = 0;
            }
        }
    }
    Ok(msgs.len())
}

impl DataSink for TcpSink {
    #[inline]
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)
    }

    /// Push the whole batch with as few `writev` syscalls as possible, so the
    /// stream blast path is bounded by the socket rather than per-message
    /// syscall overhead (NFR-PERF).
    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        writev_full(self.stream.as_raw_fd(), msgs, BATCH_ABS_MAX)
    }

    fn preferred_batch(&self, message_bytes: u32) -> usize {
        stream_batch_size(message_bytes)
    }

    fn close(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

struct TcpSource {
    stream: TcpStream,
    reader: FramedReader,
}

impl DataSource for TcpSource {
    #[inline]
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let stream = &mut self.stream;
        self.reader.next_message(buf, |dst| stream.read(dst))
    }

    /// Carve as many complete messages as one read syscall yields: at most one
    /// `read` once any message is buffered, so a paced sender still sees
    /// batch≈1 (unbiased latency) while a blast drains many messages per
    /// syscall.
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
        let stream = &mut self.stream;
        loop {
            let n = self.reader.take_messages(buf, stride, max, lens);
            if n > 0 {
                return Ok(BatchOutcome::Messages(n));
            }
            match self.reader.fill_once(&mut |dst| stream.read(dst))? {
                FillOutcome::Filled => continue,
                FillOutcome::Timeout => return Ok(BatchOutcome::Timeout),
                FillOutcome::Closed => return Ok(BatchOutcome::Closed),
            }
        }
    }

    fn preferred_batch(&self, message_bytes: u32) -> usize {
        stream_batch_size(message_bytes)
    }

    fn raw_fd(&self) -> Option<i32> {
        Some(self.stream.as_raw_fd())
    }

    fn close(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// A full-duplex TCP endpoint for the ping-pong mode: writes whole messages and
/// re-frames the byte stream on read, on the same connection.
struct TcpDuplex {
    stream: TcpStream,
    reader: FramedReader,
}

impl DuplexEnd for TcpDuplex {
    #[inline]
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)
    }

    #[inline]
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let stream = &mut self.stream;
        self.reader.next_message(buf, |dst| stream.read(dst))
    }

    fn close(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Server side of the TCP connection-rate harness (Phase G): accept each
/// connection and drop it at once. Closing first makes this fixed listener port
/// the side that holds `TIME_WAIT`, so the connector's ephemeral ports stay
/// free under heavy churn.
struct TcpConnAcceptor {
    listener: TcpListener,
}

impl ConnAcceptor for TcpConnAcceptor {
    fn serve(self: Box<Self>, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            match self.listener.accept() {
                // The kernel already completed the three-way handshake; dropping
                // the stream here closes it (active close on this side).
                Ok((_stream, _peer)) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_micros(200));
                }
                Err(_) => break,
            }
        }
    }
}

/// Client side of the TCP connection-rate harness (Phase G): open a fresh
/// connection, time the three-way handshake, then read to EOF so the server's
/// close drives teardown (this side passive-closes → no client-side
/// `TIME_WAIT` ephemeral-port exhaustion at high rates).
struct TcpConnFactory {
    addr: SocketAddr,
    message_bytes: u32,
}

impl ConnFactory for TcpConnFactory {
    fn connect_once(&self) -> io::Result<u64> {
        let _ = self.message_bytes; // reserved for gateway handshake probing
        let t0 = monotonic_ns();
        let stream = TcpStream::connect(self.addr)?;
        let handshake_ns = monotonic_ns().saturating_sub(t0);
        stream.set_nodelay(true).ok();
        // Bound the wait for the server's FIN so a briefly-behind acceptor
        // cannot stall the connector loop.
        stream.set_read_timeout(Some(RECV_POLL_TIMEOUT)).ok();
        let mut reader: &TcpStream = &stream;
        let mut buf = [0u8; 64];
        let _ = reader.read(&mut buf);
        Ok(handshake_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::{decode_message, encode_message, HEADER_LEN};

    #[test]
    fn tcp_loopback_round_trip() {
        let t = TcpTransport;
        let msg_size = 256u32;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let sender = std::thread::spawn(move || {
            let mut buf = vec![0u8; msg_size as usize];
            for seq in 0..50u64 {
                encode_message(seq, msg_size - HEADER_LEN as u32, &mut buf);
                sink.send_msg(&buf).unwrap();
            }
            // give the reader time, then close
            std::thread::sleep(std::time::Duration::from_millis(50));
            sink.close();
        });

        let mut out = vec![0u8; msg_size as usize];
        let mut seen = 0u64;
        loop {
            match source.recv_msg(&mut out).unwrap() {
                RecvOutcome::Message(n) => {
                    let hdr = decode_message(&out[..n]).unwrap();
                    assert_eq!(hdr.seq, seen);
                    seen += 1;
                }
                RecvOutcome::Closed => break,
                RecvOutcome::Timeout => {
                    if seen >= 50 {
                        break;
                    }
                }
            }
        }
        sender.join().unwrap();
        assert_eq!(seen, 50);
    }

    /// Build `count` framed messages of `msg_size` on-wire bytes.
    fn build_messages(count: u64, msg_size: u32) -> Vec<Vec<u8>> {
        (0..count)
            .map(|seq| {
                let mut m = vec![0u8; msg_size as usize];
                encode_message(seq, msg_size - HEADER_LEN as u32, &mut m);
                m
            })
            .collect()
    }

    #[test]
    fn writev_full_resumes_after_partial_writes() {
        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        // Shrink the send buffer so writev returns short, mid-message counts
        // (the kernel floors the value at a few KiB — still far below the
        // 512 KiB we push).
        let sndbuf: libc::c_int = 4096;
        // SAFETY: writer is a valid open socket for the duration of the call;
        // the option value points at a live c_int of the size passed.
        let rc = unsafe {
            libc::setsockopt(
                writer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);

        let msg_size = 8192u32;
        let count = 64u64;
        let msgs = build_messages(count, msg_size);
        let expected: Vec<u8> = msgs.iter().flatten().copied().collect();

        let writer_thread = std::thread::spawn(move || {
            let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            let sent = writev_full(writer.as_raw_fd(), &slices, BATCH_ABS_MAX).unwrap();
            assert_eq!(sent, count as usize);
            drop(writer); // EOF for the reader
        });

        // Drain slowly so the writer keeps hitting a full socket buffer.
        let mut got = Vec::with_capacity(expected.len());
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    got.extend_from_slice(&chunk[..n]);
                    std::thread::sleep(Duration::from_micros(200));
                }
                Err(e) => panic!("reader failed: {e}"),
            }
        }
        writer_thread.join().unwrap();
        assert_eq!(got.len(), expected.len());
        assert_eq!(
            got, expected,
            "byte stream must survive partial writev resumes"
        );
    }

    #[test]
    fn writev_full_chunks_beyond_iov_cap() {
        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let msg_size = 100u32;
        let count = 11u64;
        let msgs = build_messages(count, msg_size);
        let expected: Vec<u8> = msgs.iter().flatten().copied().collect();

        let writer_thread = std::thread::spawn(move || {
            let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            // iov_cap = 4 forces ceil(11/4) = 3 writev calls.
            let sent = writev_full(writer.as_raw_fd(), &slices, 4).unwrap();
            assert_eq!(sent, count as usize);
            drop(writer);
        });

        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("reader failed: {e}"),
            }
        }
        writer_thread.join().unwrap();
        assert_eq!(got, expected);
    }

    /// Local-only perf smoke (not a CI assertion): isolates the three stream
    /// hot-path stages so a regression in one is attributable. Run with
    /// `cargo test --release -- --ignored --nocapture stream_stage_rates`.
    #[test]
    #[ignore]
    fn stream_stage_rates() {
        use std::time::Instant;
        let msg_size = 64u32;
        let batch = crate::transport::stream_batch_size(msg_size);

        // Stage 1: message encoding (BatchBuilder::build).
        let mut builder = crate::workload::sender::BatchBuilder::new(msg_size, batch);
        let iters = 2_000usize;
        let t0 = Instant::now();
        for i in 0..iters {
            let built = builder.build((i * batch) as u64, batch);
            std::hint::black_box(built);
        }
        let per_msg = t0.elapsed().as_nanos() as f64 / (iters * batch) as f64;
        eprintln!("encode: {per_msg:.0} ns/msg");

        // Stage 2: writev over a unix socketpair with a raw draining reader.
        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let msgs = build_messages(batch as u64, msg_size);
        let total_msgs = 2_000_000u64;
        let drain = std::thread::spawn(move || {
            let mut sink_buf = vec![0u8; 1 << 20];
            let mut total = 0u64;
            loop {
                match reader.read(&mut sink_buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(_) => break,
                }
            }
            total
        });
        let t0 = Instant::now();
        let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let mut sent = 0u64;
        while sent < total_msgs {
            sent += writev_full(writer.as_raw_fd(), &slices, BATCH_ABS_MAX).unwrap() as u64;
        }
        drop(writer);
        let bytes = drain.join().unwrap();
        let rate = sent as f64 / t0.elapsed().as_secs_f64();
        eprintln!("writev+drain (uds pair): {rate:.0} msg/s ({bytes} bytes)");

        // Stage 3: same but over loopback TCP with the real recv_batch parser.
        let t = TcpTransport;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();
        let parse = std::thread::spawn(move || {
            let stride = msg_size as usize;
            let max = crate::transport::stream_batch_size(msg_size);
            let mut buf = vec![0u8; stride * max];
            let mut lens = vec![0usize; max];
            let mut seen = 0u64;
            loop {
                match source.recv_batch(&mut buf, stride, max, &mut lens) {
                    Ok(BatchOutcome::Messages(n)) => seen += n as u64,
                    Ok(BatchOutcome::Closed) | Err(_) => break,
                    Ok(BatchOutcome::Timeout) => {}
                }
            }
            seen
        });
        let t0 = Instant::now();
        let mut sent = 0u64;
        while sent < total_msgs {
            sent += sink.send_batch(&slices).unwrap() as u64;
        }
        sink.close();
        let seen = parse.join().unwrap();
        let rate = seen as f64 / t0.elapsed().as_secs_f64();
        eprintln!("tcp send_batch → recv_batch: {rate:.0} msg/s");
    }

    #[test]
    fn tcp_send_batch_and_recv_batch_round_trip() {
        let t = TcpTransport;
        let msg_size = 256u32;
        let count = 40u64;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let msgs = build_messages(count, msg_size);
        let sender = std::thread::spawn(move || {
            let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            assert_eq!(sink.send_batch(&slices).unwrap(), count as usize);
            std::thread::sleep(Duration::from_millis(50));
            sink.close();
        });

        let stride = msg_size as usize;
        let max = 32usize;
        let mut buf = vec![0u8; stride * max];
        let mut lens = vec![0usize; max];
        let mut seen = 0u64;
        let mut best_batch = 0usize;
        loop {
            match source.recv_batch(&mut buf, stride, max, &mut lens).unwrap() {
                BatchOutcome::Messages(n) => {
                    best_batch = best_batch.max(n);
                    for i in 0..n {
                        let hdr = decode_message(&buf[i * stride..i * stride + lens[i]]).unwrap();
                        assert_eq!(hdr.seq, seen);
                        seen += 1;
                    }
                }
                BatchOutcome::Closed => break,
                BatchOutcome::Timeout => {
                    if seen >= count {
                        break;
                    }
                }
            }
        }
        sender.join().unwrap();
        assert_eq!(seen, count);
        assert!(
            best_batch > 1,
            "a 40-message burst must carve more than one message per recv_batch (got {best_batch})"
        );
    }
}
