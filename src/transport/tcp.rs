//! TCP loopback transport (F-05 `tcp`).
//!
//! Baseline path with no gateway: a sender `TcpStream` writes framed messages
//! to an accepted server `TcpStream`. `TCP_NODELAY` is set so latency reflects
//! the path rather than Nagle batching, and the server side gets a read timeout
//! so the receiver loop can poll the run-phase flag.
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    ConnAcceptor, ConnFactory, DataSink, DataSource, DuplexEnd, FramedReader, RecvOutcome,
    Transport, RECV_POLL_TIMEOUT,
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

impl DataSink for TcpSink {
    #[inline]
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)
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
}
