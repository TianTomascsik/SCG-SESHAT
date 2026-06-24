//! Encapsulation overhead calculation (C4).
//!
//! Computes the per-message byte overhead added by each protocol layer so we
//! can report bandwidth efficiency (`payload / wire_bytes`) and compare the
//! cost of different security protocols on the same workload.
//!
//! Overhead is deterministic for a given protocol+cipher choice; no runtime
//! measurement is needed. Values are derived from protocol specifications:
//!
//! | Layer         | Overhead                                     |
//! |---------------|----------------------------------------------|
//! | IPv4          | 20 bytes (no options)                        |
//! | IPv6          | 40 bytes (no extensions)                     |
//! | TCP           | 20 bytes (no options) / 32 (timestamps)      |
//! | UDP           | 8 bytes                                      |
//! | TLS 1.2       | 5 (record) + MAC + padding (cipher-dep)     |
//! | TLS 1.3       | 5 (record) + 1 (content type) + AEAD tag    |
//! | DTLS 1.2      | 13 (record) + MAC + padding                 |
//! | DTLS 1.3      | varies (unified header)                     |
#![allow(dead_code)]

/// Protocol encapsulation profile for overhead calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncapProfile {
    /// Raw TCP (no TLS).
    Tcp,
    /// Raw UDP (no DTLS).
    Udp,
    /// TLS 1.2 with AES-128-GCM (AEAD, no CBC padding).
    Tls12Gcm,
    /// TLS 1.2 with AES-256-CBC-SHA256 (block cipher + HMAC).
    Tls12Cbc,
    /// TLS 1.3 with AES-128-GCM or AES-256-GCM or ChaCha20-Poly1305.
    Tls13Aead,
    /// DTLS 1.2 with AES-128-GCM.
    Dtls12Gcm,
    /// DTLS 1.2 with AES-256-CBC-SHA256.
    Dtls12Cbc,
    /// Unix domain socket (no network headers).
    Uds,
    /// Shared memory (no network headers, no kernel copy).
    Shm,
}

/// Per-message overhead breakdown.
#[derive(Debug, Clone, Copy)]
pub struct Overhead {
    /// IP header bytes (0 for UDS/SHM).
    pub ip_header: u32,
    /// Transport header bytes (TCP/UDP, 0 for UDS/SHM).
    pub transport_header: u32,
    /// Security layer per-record overhead (TLS/DTLS record header + auth tag).
    pub security_overhead: u32,
    /// Total per-message overhead.
    pub total: u32,
}

impl Overhead {
    /// Compute bandwidth efficiency: `payload / (payload + overhead)`.
    pub fn efficiency(&self, payload_bytes: u32) -> f64 {
        if payload_bytes == 0 {
            return 0.0;
        }
        payload_bytes as f64 / (payload_bytes + self.total) as f64
    }
}

/// Compute per-message overhead for a given encapsulation profile.
///
/// Assumes IPv4 (20B) for network transports. For IPv6, add 20B to `ip_header`.
/// TCP assumes 32B (20B header + 12B timestamps option, typical on Linux).
pub fn compute(profile: EncapProfile) -> Overhead {
    match profile {
        EncapProfile::Tcp => Overhead {
            ip_header: 20,
            transport_header: 32, // TCP with timestamps
            security_overhead: 0,
            total: 52,
        },
        EncapProfile::Udp => Overhead {
            ip_header: 20,
            transport_header: 8,
            security_overhead: 0,
            total: 28,
        },
        EncapProfile::Tls12Gcm => Overhead {
            ip_header: 20,
            transport_header: 32,
            // TLS 1.2 record: 5B header + 8B explicit IV + 16B auth tag = 29B
            security_overhead: 29,
            total: 81,
        },
        EncapProfile::Tls12Cbc => Overhead {
            ip_header: 20,
            transport_header: 32,
            // TLS 1.2 CBC: 5B header + 16B IV + 32B HMAC-SHA256 + up to 15B padding
            // Use average padding (8B) for estimate.
            security_overhead: 61,
            total: 113,
        },
        EncapProfile::Tls13Aead => Overhead {
            ip_header: 20,
            transport_header: 32,
            // TLS 1.3: 5B record header + 1B content type + 16B AEAD tag = 22B
            security_overhead: 22,
            total: 74,
        },
        EncapProfile::Dtls12Gcm => Overhead {
            ip_header: 20,
            transport_header: 8,
            // DTLS 1.2: 13B record header + 8B explicit IV + 16B auth tag = 37B
            security_overhead: 37,
            total: 65,
        },
        EncapProfile::Dtls12Cbc => Overhead {
            ip_header: 20,
            transport_header: 8,
            // DTLS 1.2 CBC: 13B header + 16B IV + 32B HMAC + ~8B padding = 69B
            security_overhead: 69,
            total: 97,
        },
        EncapProfile::Uds => Overhead {
            ip_header: 0,
            transport_header: 0,
            security_overhead: 0,
            total: 0,
        },
        EncapProfile::Shm => Overhead {
            ip_header: 0,
            transport_header: 0,
            security_overhead: 0,
            total: 0,
        },
    }
}

/// Map a protocol name (as used in config) to an encapsulation profile.
///
/// Returns `None` for unknown protocol strings.
pub fn profile_from_protocol(protocol: &str) -> Option<EncapProfile> {
    match protocol.to_lowercase().as_str() {
        "tcp" | "plain-tcp" => Some(EncapProfile::Tcp),
        "udp" | "plain-udp" => Some(EncapProfile::Udp),
        "tls" | "tls12" | "tls-gcm" | "tls12-gcm" => Some(EncapProfile::Tls12Gcm),
        "tls-cbc" | "tls12-cbc" => Some(EncapProfile::Tls12Cbc),
        "tls13" | "tls13-gcm" | "tls13-aead" => Some(EncapProfile::Tls13Aead),
        "dtls" | "dtls12" | "dtls-gcm" | "dtls12-gcm" => Some(EncapProfile::Dtls12Gcm),
        "dtls-cbc" | "dtls12-cbc" => Some(EncapProfile::Dtls12Cbc),
        "uds" | "unix" => Some(EncapProfile::Uds),
        "shm" | "shared-memory" => Some(EncapProfile::Shm),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efficiency_decreases_with_overhead() {
        let tcp = compute(EncapProfile::Tcp);
        let tls13 = compute(EncapProfile::Tls13Aead);
        let payload = 1400;
        assert!(tcp.efficiency(payload) > tls13.efficiency(payload));
    }

    #[test]
    fn uds_shm_zero_overhead() {
        assert_eq!(compute(EncapProfile::Uds).total, 0);
        assert_eq!(compute(EncapProfile::Shm).total, 0);
    }

    #[test]
    fn profile_lookup() {
        assert_eq!(profile_from_protocol("tls13"), Some(EncapProfile::Tls13Aead));
        assert_eq!(profile_from_protocol("dtls"), Some(EncapProfile::Dtls12Gcm));
        assert_eq!(profile_from_protocol("unknown"), None);
    }
}
