//! UDP loopback transport (F-05 `udp`).
//!
//! Datagram baseline with no gateway: each SESHAT message maps to exactly one
//! UDP datagram, so no re-framing is needed and datagram boundaries are
//! preserved (relevant for the agility checks later). The receiver socket has a
//! read timeout so the loop can poll the run-phase flag, and loss/reorder are
//! observed naturally from the sequence numbers.
#![allow(dead_code)]

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;

use super::{
    BatchOutcome, DataSink, DataSource, DuplexEnd, RecvOutcome, Transport, RECV_POLL_TIMEOUT,
};

/// UDP transport factory.
pub struct UdpTransport;

/// Build a datagram sink bound to an ephemeral local port and connected to
/// `target`, so `send` delivers one datagram per message. Used by the
/// gateway-backed UDP transport to feed the encrypt-rule ingress.
pub(crate) fn sink_connected_to(target: SocketAddr) -> io::Result<Box<dyn DataSink>> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.connect(target)?;
    Ok(Box::new(UdpSink { sock }))
}

/// Wrap an already-bound (unconnected) UDP socket as a datagram source. The
/// caller is responsible for setting a read timeout so the receive loop can poll
/// the run-phase flag.
pub(crate) fn source_from_socket(sock: UdpSocket) -> Box<dyn DataSource> {
    Box::new(UdpSource { sock })
}

impl Transport for UdpTransport {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn loopback_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let server = UdpSocket::bind("127.0.0.1:0")?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
        let server_addr = server.local_addr()?;

        let client = UdpSocket::bind("127.0.0.1:0")?;
        client.connect(server_addr)?;

        let sink = Box::new(UdpSink { sock: client });
        let source = Box::new(UdpSource { sock: server });
        Ok((sink, source))
    }

    fn pingpong_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let server = UdpSocket::bind("127.0.0.1:0")?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
        let server_addr = server.local_addr()?;

        let client = UdpSocket::bind("127.0.0.1:0")?;
        client.connect(server_addr)?;
        client.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        // The client is connected (send/recv); the server stays unconnected and
        // learns the client's address from the first datagram so it can echo
        // back with `send_to`.
        let client_end = Box::new(UdpDuplex {
            sock: client,
            peer: None,
            connected: true,
        });
        let server_end = Box::new(UdpDuplex {
            sock: server,
            peer: None,
            connected: false,
        });
        Ok((client_end, server_end))
    }
}

struct UdpSink {
    sock: UdpSocket,
}

impl DataSink for UdpSink {
    #[inline]
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        // One datagram per message. A short write is a transport error.
        let n = self.sock.send(buf)?;
        if n != buf.len() {
            return Err(io::Error::other("short UDP datagram send"));
        }
        Ok(())
    }

    /// Push a whole batch of datagrams with a single `sendmmsg` syscall, so the
    /// blast path is bounded by the NIC/socket buffer rather than per-message
    /// syscall overhead (NFR-PERF). Returns the number of datagrams accepted.
    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        let fd = self.sock.as_raw_fd();
        // One iovec + one mmsghdr per message; the socket is connected so no
        // per-message destination address is needed (msg_name stays null).
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(msgs.len());
        for m in msgs {
            iovecs.push(libc::iovec {
                iov_base: m.as_ptr() as *mut libc::c_void,
                iov_len: m.len(),
            });
        }
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(msgs.len());
        for i in 0..msgs.len() {
            // SAFETY: zeroed mmsghdr with only the iov pointer/len set.
            let mut mh: libc::mmsghdr = unsafe { std::mem::zeroed() };
            // SAFETY: `iovecs` has reserved capacity and is not grown again, so
            // the pointer stays valid for the `sendmmsg` call below.
            mh.msg_hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
            mh.msg_hdr.msg_iovlen = 1;
            hdrs.push(mh);
        }
        // SAFETY: fd is a valid datagram socket; hdrs/iovecs outlive the call
        // and describe `msgs.len()` messages.
        let ret = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), hdrs.len() as libc::c_uint, 0) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            // A full socket buffer on a blocking socket is transient: report 0
            // sent rather than aborting the run.
            return match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(e),
            };
        }
        Ok(ret as usize)
    }

    fn close(&mut self) {}
}

struct UdpSource {
    sock: UdpSocket,
}

impl DataSource for UdpSource {
    #[inline]
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        match self.sock.recv(buf) {
            Ok(n) => Ok(RecvOutcome::Message(n)),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(RecvOutcome::Timeout)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(RecvOutcome::Timeout),
            Err(e) => Err(e),
        }
    }

    /// Drain up to `max` datagrams with a single `recvmmsg` syscall so the
    /// receiver keeps pace with a blasting sender. `MSG_WAITFORONE` returns as
    /// soon as at least one datagram is available; the socket's read timeout
    /// (`SO_RCVTIMEO`) bounds the wait so the run-phase flag is still polled.
    fn recv_batch(
        &mut self,
        buf: &mut [u8],
        stride: usize,
        max: usize,
        lens: &mut [usize],
    ) -> io::Result<BatchOutcome> {
        if stride == 0 {
            return Ok(BatchOutcome::Timeout);
        }
        let vlen = max.min(buf.len() / stride).min(lens.len());
        if vlen == 0 {
            return Ok(BatchOutcome::Timeout);
        }
        let fd = self.sock.as_raw_fd();
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(vlen);
        for i in 0..vlen {
            iovecs.push(libc::iovec {
                // SAFETY: i < vlen <= buf.len()/stride, so the slice fits.
                iov_base: unsafe { buf.as_mut_ptr().add(i * stride) } as *mut libc::c_void,
                iov_len: stride,
            });
        }
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(vlen);
        for i in 0..vlen {
            // SAFETY: zeroed mmsghdr with only the iov pointer/len set.
            let mut mh: libc::mmsghdr = unsafe { std::mem::zeroed() };
            // SAFETY: `iovecs` keeps its capacity, so the pointer stays valid.
            mh.msg_hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
            mh.msg_hdr.msg_iovlen = 1;
            hdrs.push(mh);
        }
        // SAFETY: fd is a valid datagram socket; hdrs/iovecs outlive the call.
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                vlen as libc::c_uint,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => Ok(BatchOutcome::Timeout),
                _ => Err(e),
            };
        }
        let count = ret as usize;
        for (i, slot) in lens.iter_mut().enumerate().take(count) {
            *slot = hdrs[i].msg_len as usize;
        }
        Ok(BatchOutcome::Messages(count))
    }

    fn close(&mut self) {}

    fn raw_fd(&self) -> Option<i32> {
        Some(self.sock.as_raw_fd())
    }
}

/// A full-duplex datagram endpoint for the ping-pong mode. The client side is
/// connected to the server so it uses `send`/`recv`; the server side is
/// unconnected and learns the client's address from the first datagram so it
/// can echo back with `send_to`.
struct UdpDuplex {
    sock: UdpSocket,
    peer: Option<SocketAddr>,
    connected: bool,
}

impl DuplexEnd for UdpDuplex {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        let n = if self.connected {
            self.sock.send(buf)?
        } else if let Some(peer) = self.peer {
            self.sock.send_to(buf, peer)?
        } else {
            // The server echoes only in response to a received datagram, so a
            // peer is always known by the time it sends.
            return Err(io::Error::other("UDP echo before a peer was learned"));
        };
        if n != buf.len() {
            return Err(io::Error::other("short UDP datagram send"));
        }
        Ok(())
    }

    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let result = if self.connected {
            self.sock.recv(buf)
        } else {
            self.sock.recv_from(buf).map(|(n, peer)| {
                self.peer = Some(peer);
                n
            })
        };
        match result {
            Ok(n) => Ok(RecvOutcome::Message(n)),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                Ok(RecvOutcome::Timeout)
            }
            Err(e) => Err(e),
        }
    }

    fn close(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::{decode_message, encode_message, HEADER_LEN};

    #[test]
    fn udp_loopback_round_trip() {
        let t = UdpTransport;
        let msg_size = 512u32;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let sender = std::thread::spawn(move || {
            let mut buf = vec![0u8; msg_size as usize];
            for seq in 0..20u64 {
                encode_message(seq, msg_size - HEADER_LEN as u32, &mut buf);
                sink.send_msg(&buf).unwrap();
                // small spacing so the loopback socket buffer doesn't drop
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        });

        let mut out = vec![0u8; msg_size as usize];
        let mut seen = 0u64;
        let mut timeouts = 0;
        loop {
            match source.recv_msg(&mut out).unwrap() {
                RecvOutcome::Message(n) => {
                    let hdr = decode_message(&out[..n]).unwrap();
                    assert_eq!(hdr.payload_len, msg_size - HEADER_LEN as u32);
                    let _ = hdr.seq;
                    seen += 1;
                    if seen >= 20 {
                        break;
                    }
                }
                RecvOutcome::Timeout => {
                    timeouts += 1;
                    if timeouts > 20 {
                        break;
                    }
                }
                RecvOutcome::Closed => break,
            }
        }
        sender.join().unwrap();
        // Loopback UDP is reliable in practice; require most datagrams.
        assert!(seen >= 18, "received only {seen}/20 datagrams");
    }

    #[test]
    fn udp_batch_round_trip() {
        // Exercises the vectored fast paths end to end: `sendmmsg` via
        // `send_batch` and `recvmmsg` via `recv_batch`.
        let t = UdpTransport;
        let msg_size = 256u32;
        let stride = msg_size as usize;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let batches = 4u64;
        let per_batch = 8usize;
        let total = batches as usize * per_batch;

        let sender = std::thread::spawn(move || {
            for b in 0..batches {
                let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(per_batch);
                for i in 0..per_batch {
                    let seq = b * per_batch as u64 + i as u64;
                    let mut buf = vec![0u8; stride];
                    encode_message(seq, msg_size - HEADER_LEN as u32, &mut buf);
                    bufs.push(buf);
                }
                let slices: Vec<&[u8]> = bufs.iter().map(|v| v.as_slice()).collect();
                let mut sent = 0usize;
                while sent < per_batch {
                    match sink.send_batch(&slices[sent..]) {
                        Ok(0) => std::thread::yield_now(),
                        Ok(n) => sent += n,
                        Err(e) => panic!("send_batch failed: {e}"),
                    }
                }
                // Spacing so the loopback socket buffer does not overflow.
                std::thread::sleep(std::time::Duration::from_micros(300));
            }
        });

        let mut buf = vec![0u8; stride * crate::transport::BATCH_MAX];
        let mut lens = vec![0usize; crate::transport::BATCH_MAX];
        let mut seen = 0usize;
        let mut timeouts = 0;
        while seen < total {
            match source
                .recv_batch(&mut buf, stride, crate::transport::BATCH_MAX, &mut lens)
                .unwrap()
            {
                BatchOutcome::Messages(count) => {
                    for (i, &len) in lens.iter().enumerate().take(count) {
                        let msg = &buf[i * stride..i * stride + len];
                        let hdr = decode_message(msg).unwrap();
                        assert_eq!(hdr.payload_len, msg_size - HEADER_LEN as u32);
                        seen += 1;
                    }
                }
                BatchOutcome::Timeout => {
                    timeouts += 1;
                    if timeouts > 20 {
                        break;
                    }
                }
                BatchOutcome::Closed => break,
            }
        }
        sender.join().unwrap();
        assert!(seen >= total - 2, "received only {seen}/{total} datagrams");
    }
}
