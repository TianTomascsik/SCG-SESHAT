//! SHM null-loopback transport for harness-ceiling calibration.
//!
//! A pure harness↔harness shared-memory ring with **no gateway** attached: the
//! sender thread pushes frames into one `scg-ipc` SPSC ring and the receiver
//! thread pops them, exactly the per-message mechanics of a `scg-shm`
//! scenario's access interface. The ceiling it measures is the harness's own
//! ring push/pop ability (memcpy-bound), which is the honest comparison point
//! for SHM gateway rows — a TCP ceiling (as the pre-2026-07 calibrator used)
//! measured a slower kernel path and produced headroom < 1.0 rows.
//!
//! Both ends live in the same process, so the "shared" region is one 64-byte
//! aligned heap allocation: the `scg_ipc::shm` ring primitives only need
//! pointers that stay valid for the handles' lifetime plus their SPSC
//! discipline, both of which the [`Region`]-holding sink/source guarantee.
#![allow(dead_code)]

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use scg_ipc::shm::{RingConsumer, RingProducer, ShmControl, SHM_CONTROL_SIZE};

use super::{DataSink, DataSource, RecvOutcome, Transport, RECV_POLL_TIMEOUT};

/// SHM null-loopback transport factory (no gateway; calibration only).
pub struct ShmNullTransport {
    ring_capacity: usize,
}

impl ShmNullTransport {
    /// A null SHM pair whose ring holds `ring_capacity` data bytes (matching
    /// the scenario's configured ring size keeps backpressure comparable).
    pub fn new(ring_capacity: u64) -> Self {
        ShmNullTransport {
            // Floor: one control page's worth, so init can never be degenerate.
            ring_capacity: (ring_capacity as usize).max(4096),
        }
    }
}

impl Transport for ShmNullTransport {
    fn name(&self) -> &'static str {
        "shm-null"
    }

    fn cache_key(&self) -> String {
        // Ring capacity changes the measured ceiling (backpressure point), so
        // it is part of the cache identity.
        format!("shm-null/{}", self.ring_capacity)
    }

    fn loopback_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let region = Arc::new(Region::alloc(self.ring_capacity)?);
        let closed = Arc::new(AtomicBool::new(false));

        // SAFETY: `region` is a live, exclusively-owned mapping of
        // `SHM_CONTROL_SIZE + ring_capacity` zeroed bytes, 64-byte aligned, not
        // yet shared with any other handle at init time.
        unsafe {
            ShmControl::init(region.ptr, self.ring_capacity, self.ring_capacity, 0);
        }
        // SAFETY: the control page was initialised above within this mapping;
        // `attach` only validates magic/version and borrows for the block.
        let (producer, consumer) = unsafe {
            let ctl = ShmControl::attach(region.ptr, SHM_CONTROL_SIZE)
                .map_err(|e| io::Error::other(format!("shm-null control: {e}")))?;
            let data = region.ptr.add(SHM_CONTROL_SIZE);
            // SAFETY (both handles): the index block and data region point into
            // the `region` mapping, which each handle keeps alive via its own
            // `Arc<Region>`; the sink is the single producer and the source the
            // single consumer (SPSC), each moved to exactly one engine thread.
            (
                RingProducer::new(&ctl.c2g, data, self.ring_capacity),
                RingConsumer::new(&ctl.c2g, data, self.ring_capacity),
            )
        };

        let sink = Box::new(ShmNullSink {
            producer,
            closed: closed.clone(),
            _region: region.clone(),
        });
        let source = Box::new(ShmNullSource {
            consumer,
            closed,
            _region: region,
        });
        Ok((sink, source))
    }
}

/// One 64-byte-aligned heap region holding the control page plus the ring's
/// data bytes, freed when the last handle drops.
struct Region {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

// SAFETY: the region is a plain allocation; all concurrent access goes through
// the Acquire/Release ring indices inside it (SPSC discipline upheld by the
// one-sink/one-source split), so sharing the handle across threads is sound.
unsafe impl Send for Region {}
// SAFETY: as above — `Region` itself exposes no interior mutation; the ring
// handles own the synchronisation.
unsafe impl Sync for Region {}

impl Region {
    fn alloc(ring_capacity: usize) -> io::Result<Region> {
        let size = SHM_CONTROL_SIZE
            .checked_add(ring_capacity)
            .ok_or_else(|| io::Error::other("shm-null ring capacity overflow"))?;
        let layout = std::alloc::Layout::from_size_align(size, 64)
            .map_err(|e| io::Error::other(format!("shm-null layout: {e}")))?;
        // SAFETY: `layout` has non-zero size (SHM_CONTROL_SIZE > 0) and valid
        // 64-byte alignment; `alloc_zeroed` returns null on failure, handled.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::Error::other("shm-null region allocation failed"));
        }
        Ok(Region { ptr, layout })
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `alloc_zeroed` with exactly `layout`.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

struct ShmNullSink {
    producer: RingProducer,
    closed: Arc<AtomicBool>,
    _region: Arc<Region>,
}

impl DataSink for ShmNullSink {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        match self
            .producer
            .try_push(0, buf)
            .map_err(|e| io::Error::other(format!("shm-null push: {e}")))?
        {
            true => Ok(()),
            // Ring full: transient backpressure, mirrored from the gateway SHM
            // sink so the engine yields and retries.
            false => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        // Push until the ring backpressures; a short count makes the engine
        // yield and resend the rest (same contract as the gateway SHM sink).
        for (i, m) in msgs.iter().enumerate() {
            match self
                .producer
                .try_push(0, m)
                .map_err(|e| io::Error::other(format!("shm-null push: {e}")))?
            {
                true => {}
                false => return Ok(i),
            }
        }
        Ok(msgs.len())
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

struct ShmNullSource {
    consumer: RingConsumer,
    closed: Arc<AtomicBool>,
    _region: Arc<Region>,
}

impl ShmNullSource {
    /// Pop one frame, spinning (with yields) up to the poll timeout so the
    /// engine's phase flag stays observable on an idle ring.
    fn pop_one(&self, out: &mut [u8]) -> RecvOutcome {
        let deadline = Instant::now() + RECV_POLL_TIMEOUT;
        loop {
            if let Some((_tid, len)) = self.consumer.try_pop_into_slice(out) {
                return RecvOutcome::Message(len);
            }
            if self.closed.load(Ordering::Acquire) && self.consumer.is_empty() {
                return RecvOutcome::Closed;
            }
            if Instant::now() >= deadline {
                return RecvOutcome::Timeout;
            }
            std::thread::yield_now();
        }
    }
}

impl DataSource for ShmNullSource {
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        Ok(self.pop_one(buf))
    }

    fn recv_batch(
        &mut self,
        buf: &mut [u8],
        stride: usize,
        max: usize,
        lens: &mut [usize],
    ) -> io::Result<super::BatchOutcome> {
        use super::BatchOutcome;
        if max == 0 || stride == 0 || buf.len() < stride || lens.is_empty() {
            return Ok(BatchOutcome::Timeout);
        }
        let cap = max.min(buf.len() / stride).min(lens.len());
        // Wait (bounded) for the first message, then drain without blocking so
        // one wake services a whole burst.
        let mut count = match self.pop_one(&mut buf[..stride]) {
            RecvOutcome::Message(len) => {
                lens[0] = len;
                1
            }
            RecvOutcome::Timeout => return Ok(BatchOutcome::Timeout),
            RecvOutcome::Closed => return Ok(BatchOutcome::Closed),
        };
        while count < cap {
            let base = count * stride;
            match self
                .consumer
                .try_pop_into_slice(&mut buf[base..base + stride])
            {
                Some((_tid, len)) => {
                    lens[count] = len;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(BatchOutcome::Messages(count))
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::{decode_message, encode_message, HEADER_LEN};

    #[test]
    fn shm_null_round_trip_and_backpressure() {
        let t = ShmNullTransport::new(8192);
        let msg_size = 256u32;
        let (mut sink, mut source) = t.loopback_pair(msg_size).unwrap();

        let mut m = vec![0u8; msg_size as usize];
        // Fill the ring until it backpressures: send_batch must return a short
        // count, not an error.
        encode_message(0, msg_size - HEADER_LEN as u32, &mut m);
        let many: Vec<&[u8]> = std::iter::repeat_n(m.as_slice(), 100).collect();
        let pushed = sink.send_batch(&many).unwrap();
        assert!(
            pushed > 0 && pushed < 100,
            "8 KiB ring must backpressure: {pushed}"
        );

        // Drain everything back out.
        let mut out = vec![0u8; msg_size as usize];
        let mut got = 0;
        while let RecvOutcome::Message(n) = source.recv_msg(&mut out).unwrap() {
            assert_eq!(n, msg_size as usize);
            decode_message(&out[..n]).unwrap();
            got += 1;
            if got == pushed {
                break;
            }
        }
        assert_eq!(got, pushed);

        // Close from the sink side: an empty ring now reads Closed.
        sink.close();
        assert_eq!(source.recv_msg(&mut out).unwrap(), RecvOutcome::Closed);
    }

    #[test]
    fn shm_null_ceiling_is_positive() {
        use crate::run::calibrate::{measure_ceiling, ProbeSpec};
        let c = measure_ceiling(
            &ShmNullTransport::new(1024 * 1024),
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
        assert_eq!(c.transport, "shm-null");
        assert!(c.throughput_gbps > 0.0);
    }
}
