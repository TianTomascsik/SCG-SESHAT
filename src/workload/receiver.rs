//! Receiver-side workload handling (F-07, F-12, F-13).
//!
//! The receive hot path must do as little as possible (NFR-PERF): the caller
//! stamps `recv_ns` with [`crate::time::monotonic_ns`] the instant bytes arrive,
//! then hands the buffer here. [`ingest`] decodes + validates the message and
//! records `(seq, latency, bytes)` into a [`FlowMetrics`]; all heavy
//! aggregation is deferred to [`FlowMetrics::finish`] after the run.
//!
//! Validation covers magic, declared length, and the deterministic payload fill
//! — so corruption, truncation, and framing errors are caught and surfaced as a
//! [`WireError`] rather than silently skewing latency stats.
#![allow(dead_code)]

use crate::metrics::app::FlowMetrics;
use crate::proto::wire::{decode_message, WireHeader, HEADER_LEN};
use crate::time::monotonic_ns;

/// Decode + validate one received message and record it into `metrics`.
///
/// `recv_ns` is the monotonic timestamp taken the moment the bytes were read.
/// On success the parsed [`WireHeader`] is returned; on failure (bad magic,
/// truncation, corrupt fill) the message is **not** recorded and the
/// [`WireError`](crate::proto::wire::WireError) is returned for the caller to
/// count as an integrity failure.
#[inline]
pub fn ingest(
    metrics: &mut FlowMetrics,
    buf: &[u8],
    recv_ns: u64,
) -> Result<WireHeader, crate::proto::wire::WireError> {
    let hdr = decode_message(buf)?;
    // Monotonic on one host: recv_ns >= ts_ns. Clamp defensively against any
    // cross-core read skew so a stray negative never poisons the stats.
    let latency_ns = recv_ns.saturating_sub(hdr.ts_ns);
    let wire_bytes = (HEADER_LEN + hdr.payload_len as usize) as u64;
    metrics.record(hdr.seq, latency_ns, wire_bytes);
    Ok(hdr)
}

/// Convenience wrapper that stamps the receive time itself, for callers that
/// cannot timestamp closer to the syscall.
#[inline]
pub fn ingest_now(
    metrics: &mut FlowMetrics,
    buf: &[u8],
) -> Result<WireHeader, crate::proto::wire::WireError> {
    let recv_ns = monotonic_ns();
    ingest(metrics, buf, recv_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::wire::{encode_message, WireError, HEADER_LEN};

    #[test]
    fn ingest_records_valid_messages() {
        let mut m = FlowMetrics::with_capacity(16);
        let mut buf = vec![0u8; 256];
        for seq in 0..10u64 {
            let total = encode_message(seq, 256 - HEADER_LEN as u32, &mut buf);
            // pretend it arrived 5 µs after it was stamped
            let hdr_ts = {
                let h = crate::proto::wire::WireHeader::decode(&buf[..total]).unwrap();
                h.ts_ns
            };
            ingest(&mut m, &buf[..total], hdr_ts + 5_000).unwrap();
        }
        let s = m.finish(false);
        assert_eq!(s.messages, 10);
        assert_eq!(s.integrity.lost, 0);
        // each latency ~5 µs
        assert!((s.latency_us.mean - 5.0).abs() < 1e-6);
        assert_eq!(s.bytes, 256 * 10);
    }

    #[test]
    fn ingest_rejects_corruption() {
        let mut m = FlowMetrics::with_capacity(4);
        let mut buf = vec![0u8; 128];
        let total = encode_message(1, 128 - HEADER_LEN as u32, &mut buf);
        buf[HEADER_LEN + 10] ^= 0xff; // corrupt a payload byte
        let err = ingest(&mut m, &buf[..total], monotonic_ns()).unwrap_err();
        assert!(matches!(err, WireError::CorruptPayload { .. }));
        assert_eq!(m.len(), 0); // not recorded
    }

    #[test]
    fn ingest_rejects_bad_magic() {
        let mut m = FlowMetrics::with_capacity(4);
        let mut buf = vec![0u8; 64];
        let total = encode_message(1, 64 - HEADER_LEN as u32, &mut buf);
        buf[0] = b'X';
        assert!(matches!(
            ingest(&mut m, &buf[..total], monotonic_ns()),
            Err(WireError::BadMagic { .. })
        ));
        assert_eq!(m.len(), 0);
    }
}
