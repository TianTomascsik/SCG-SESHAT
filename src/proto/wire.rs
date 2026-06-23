//! Self-describing on-wire message header (F-12).
//!
//! Every benchmark message starts with a fixed 24-byte header followed by a
//! deterministic payload. The header lets the receiver, with no out-of-band
//! state, recover:
//!   * **latency** — `now - ts_ns` (sender's monotonic send time),
//!   * **loss / duplication / reordering** — from the monotonic `seq`,
//!   * **integrity** — `payload_len` plus the deterministic fill pattern.
//!
//! Layout (little-endian, packed, total 24 bytes):
//! ```text
//!   offset  size  field
//!   0       4     magic        b"SESH"
//!   4       8     seq          u64  monotonic sequence number
//!   12      8     ts_ns        u64  sender CLOCK_MONOTONIC nanoseconds
//!   20      4     payload_len  u32  bytes of payload following the header
//! ```
//!
//! We serialise explicitly in little-endian instead of casting a `#[repr(C,
//! packed)]` struct, which keeps the format portable and avoids unaligned-
//! reference UB while pinning an exact byte layout.
//!
//! These are the wire primitives consumed by the workload sender/receiver and
//! metrics engine in later phases, so `dead_code` is allowed for now.
#![allow(dead_code)]

use crate::time::monotonic_ns;

/// Protocol magic — identifies a SESHAT message and guards against framing
/// errors / cross-talk on a shared transport.
pub const MAGIC: [u8; 4] = *b"SESH";

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 24;

/// Errors when decoding a header or validating a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Buffer shorter than a full header.
    ShortHeader { have: usize },
    /// Magic did not match [`MAGIC`].
    BadMagic { found: [u8; 4] },
    /// Declared `payload_len` does not fit the supplied buffer.
    TruncatedPayload { need: usize, have: usize },
    /// Payload fill pattern did not match the one implied by `seq`.
    CorruptPayload { offset: usize },
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::ShortHeader { have } => {
                write!(f, "short header: have {have} bytes, need {HEADER_LEN}")
            }
            WireError::BadMagic { found } => {
                write!(f, "bad magic: found {found:02x?}, expected {MAGIC:02x?}")
            }
            WireError::TruncatedPayload { need, have } => {
                write!(f, "truncated payload: need {need} bytes, have {have}")
            }
            WireError::CorruptPayload { offset } => {
                write!(f, "corrupt payload at byte {offset}")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// The 24-byte message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHeader {
    pub seq: u64,
    pub ts_ns: u64,
    pub payload_len: u32,
}

impl WireHeader {
    /// Build a header, stamping the current monotonic time.
    #[inline]
    pub fn stamp(seq: u64, payload_len: u32) -> Self {
        WireHeader {
            seq,
            ts_ns: monotonic_ns(),
            payload_len,
        }
    }

    /// Serialise the header into the first [`HEADER_LEN`] bytes of `buf`.
    ///
    /// Returns the number of bytes written (always [`HEADER_LEN`]).
    #[inline]
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        debug_assert!(buf.len() >= HEADER_LEN);
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..12].copy_from_slice(&self.seq.to_le_bytes());
        buf[12..20].copy_from_slice(&self.ts_ns.to_le_bytes());
        buf[20..24].copy_from_slice(&self.payload_len.to_le_bytes());
        HEADER_LEN
    }

    /// Parse a header from the start of `buf`, validating the magic.
    #[inline]
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::ShortHeader { have: buf.len() });
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if magic != MAGIC {
            return Err(WireError::BadMagic { found: magic });
        }
        let seq = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        let ts_ns = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let payload_len = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        Ok(WireHeader {
            seq,
            ts_ns,
            payload_len,
        })
    }
}

/// Deterministic payload byte for message `seq` at byte index `i`.
///
/// A per-message ramp: byte 0 is `seq % 256` (the F-12 base), then it increases.
/// Tying the pattern to `seq` and byte index catches truncation, single-byte
/// corruption, and accidental payload swaps between messages — all without
/// carrying a checksum.
#[inline]
pub fn fill_byte(seq: u64, i: usize) -> u8 {
    (seq.wrapping_add(i as u64) & 0xff) as u8
}

/// Fill `payload` with the deterministic pattern for `seq`.
#[inline]
pub fn fill_payload(seq: u64, payload: &mut [u8]) {
    for (i, b) in payload.iter_mut().enumerate() {
        *b = fill_byte(seq, i);
    }
}

/// Verify `payload` matches the deterministic pattern for `seq`.
///
/// Returns `Ok(())` on match, or the offset of the first mismatching byte.
#[inline]
pub fn verify_payload(seq: u64, payload: &[u8]) -> Result<(), WireError> {
    for (i, &b) in payload.iter().enumerate() {
        if b != fill_byte(seq, i) {
            return Err(WireError::CorruptPayload { offset: i });
        }
    }
    Ok(())
}

/// Encode a complete message (header + deterministic payload) into `buf`.
///
/// `buf` must be at least `HEADER_LEN + payload_len` bytes. Returns the total
/// message length. Stamps the send time at call.
#[inline]
pub fn encode_message(seq: u64, payload_len: u32, buf: &mut [u8]) -> usize {
    let total = HEADER_LEN + payload_len as usize;
    debug_assert!(buf.len() >= total);
    let hdr = WireHeader::stamp(seq, payload_len);
    hdr.encode(buf);
    fill_payload(seq, &mut buf[HEADER_LEN..total]);
    total
}

/// Decode and fully validate a message from `buf`.
///
/// Checks magic, that the declared payload fits, and the fill pattern. Returns
/// the parsed header on success.
#[inline]
pub fn decode_message(buf: &[u8]) -> Result<WireHeader, WireError> {
    let hdr = WireHeader::decode(buf)?;
    let need = HEADER_LEN + hdr.payload_len as usize;
    if buf.len() < need {
        return Err(WireError::TruncatedPayload {
            need,
            have: buf.len(),
        });
    }
    verify_payload(hdr.seq, &buf[HEADER_LEN..need])?;
    Ok(hdr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_is_24_bytes() {
        assert_eq!(HEADER_LEN, 24);
        let mut buf = [0u8; HEADER_LEN];
        let hdr = WireHeader {
            seq: 1,
            ts_ns: 2,
            payload_len: 3,
        };
        assert_eq!(hdr.encode(&mut buf), 24);
        assert_eq!(&buf[0..4], b"SESH");
    }

    #[test]
    fn header_round_trips() {
        let hdr = WireHeader {
            seq: 0xDEAD_BEEF_1234_5678,
            ts_ns: 0x0102_0304_0506_0708,
            payload_len: 1400,
        };
        let mut buf = [0u8; HEADER_LEN];
        hdr.encode(&mut buf);
        assert_eq!(WireHeader::decode(&buf).unwrap(), hdr);
    }

    #[test]
    fn short_header_rejected() {
        let buf = [0u8; 10];
        assert_eq!(
            WireHeader::decode(&buf),
            Err(WireError::ShortHeader { have: 10 })
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = [0u8; HEADER_LEN];
        WireHeader {
            seq: 1,
            ts_ns: 1,
            payload_len: 0,
        }
        .encode(&mut buf);
        buf[1] = b'X';
        match WireHeader::decode(&buf) {
            Err(WireError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn payload_fill_round_trips() {
        for seq in [0u64, 1, 255, 256, 1000, u64::MAX] {
            let mut p = vec![0u8; 64];
            fill_payload(seq, &mut p);
            assert_eq!(p[0], (seq & 0xff) as u8);
            assert!(verify_payload(seq, &p).is_ok());
        }
    }

    #[test]
    fn payload_tamper_detected() {
        let seq = 42;
        let mut p = vec![0u8; 32];
        fill_payload(seq, &mut p);
        p[17] ^= 0x01;
        assert_eq!(
            verify_payload(seq, &p),
            Err(WireError::CorruptPayload { offset: 17 })
        );
    }

    #[test]
    fn full_message_round_trips() {
        let mut buf = vec![0u8; HEADER_LEN + 1400];
        let total = encode_message(7, 1400, &mut buf);
        assert_eq!(total, HEADER_LEN + 1400);
        let hdr = decode_message(&buf).unwrap();
        assert_eq!(hdr.seq, 7);
        assert_eq!(hdr.payload_len, 1400);
        assert!(hdr.ts_ns > 0);
    }

    #[test]
    fn truncated_payload_detected() {
        let mut buf = vec![0u8; HEADER_LEN + 100];
        encode_message(3, 100, &mut buf);
        // Claim full length but only hand over part of the payload.
        assert!(matches!(
            decode_message(&buf[..HEADER_LEN + 50]),
            Err(WireError::TruncatedPayload { .. })
        ));
    }
}
