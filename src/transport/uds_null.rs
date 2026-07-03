//! UDS null-loopback transport for harness-ceiling calibration.
//!
//! A pure harness↔harness Unix-domain stream pair with **no gateway** in the
//! path: the ceiling it measures is what the harness itself can generate and
//! absorb over the same kernel object a `scg-uds` scenario's access interface
//! uses. Comparing a UDS gateway scenario against a TCP ceiling (as the
//! pre-2026-07 calibrator did) mixes two different kernel paths and produces
//! impossible headroom values.
//!
//! Mirrors [`super::tcp::TcpTransport`]: framed stream, `writev`-batched send,
//! multi-message `recv_batch` carve.
#![allow(dead_code)]

use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::tcp::writev_full;
use super::{
    stream_batch_size, BatchOutcome, DataSink, DataSource, FillOutcome, FramedReader, RecvOutcome,
    Transport, BATCH_ABS_MAX, RECV_POLL_TIMEOUT,
};

/// Monotonic counter making concurrent socket paths unique within a process.
static PAIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// UDS null-loopback transport factory (no gateway; calibration only).
pub struct UdsNullTransport;

impl Transport for UdsNullTransport {
    fn name(&self) -> &'static str {
        "uds-null"
    }

    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let path = socket_path();
        let listener = UnixListener::bind(&path)?;

        let client = UnixStream::connect(&path)?;
        let (server, _peer) = listener.accept()?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        // The socket node is bound + connected; unlink now so an aborted run
        // never leaves stale nodes behind (the open fds keep the pair alive).
        let _ = std::fs::remove_file(&path);

        let sink = Box::new(UdsNullSink { stream: client });
        let source = Box::new(UdsNullSource {
            stream: server,
            reader: FramedReader::new(message_bytes),
        });
        Ok((sink, source))
    }
}

/// A unique abstract-namespace-free socket path in the temp dir.
fn socket_path() -> PathBuf {
    let seq = PAIR_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "seshat-uds-null-{}-{}.sock",
        std::process::id(),
        seq
    ))
}

struct UdsNullSink {
    stream: UnixStream,
}

impl DataSink for UdsNullSink {
    #[inline]
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.stream.write_all(buf)
    }

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

struct UdsNullSource {
    stream: UnixStream,
    reader: FramedReader,
}

impl DataSource for UdsNullSource {
    #[inline]
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        let stream = &mut self.stream;
        self.reader.next_message(buf, |dst| stream.read(dst))
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::{decode_message, encode_message, HEADER_LEN};

    #[test]
    fn uds_null_loopback_round_trip() {
        let t = UdsNullTransport;
        let msg_size = 256u32;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let msgs: Vec<Vec<u8>> = (0..50u64)
            .map(|seq| {
                let mut m = vec![0u8; msg_size as usize];
                encode_message(seq, msg_size - HEADER_LEN as u32, &mut m);
                m
            })
            .collect();
        let sender = std::thread::spawn(move || {
            let slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            assert_eq!(sink.send_batch(&slices).unwrap(), 50);
            std::thread::sleep(std::time::Duration::from_millis(50));
            sink.close();
        });

        let stride = msg_size as usize;
        let mut buf = vec![0u8; stride * 32];
        let mut lens = vec![0usize; 32];
        let mut seen = 0u64;
        loop {
            match source.recv_batch(&mut buf, stride, 32, &mut lens).unwrap() {
                BatchOutcome::Messages(n) => {
                    for i in 0..n {
                        let hdr = decode_message(&buf[i * stride..i * stride + lens[i]]).unwrap();
                        assert_eq!(hdr.seq, seen);
                        seen += 1;
                    }
                }
                BatchOutcome::Closed => break,
                BatchOutcome::Timeout => {
                    if seen >= 50 {
                        break;
                    }
                }
            }
        }
        sender.join().unwrap();
        assert_eq!(seen, 50);
    }

    #[test]
    fn uds_null_ceiling_is_positive() {
        use crate::run::calibrate::{measure_ceiling, ProbeSpec};
        let c = measure_ceiling(
            &UdsNullTransport,
            &ProbeSpec {
                message_bytes: 1024,
                connections: 1,
                warmup: std::time::Duration::from_millis(20),
                measure: std::time::Duration::from_millis(150),
                probes: 1,
                sender_cores: &[],
                receiver_cores: &[],
            },
        )
        .unwrap();
        assert_eq!(c.transport, "uds-null");
        assert!(c.throughput_gbps > 0.0);
    }
}
