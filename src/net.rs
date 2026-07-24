//! IP address-family selection for benchmark paths.
//!
//! SESHAT drives the real gateway over either IPv4 loopback (`127.0.0.1`) or
//! IPv6 loopback (`::1`). The selected [`AddressFamily`] threads from a
//! scenario's `address_family` field into every port reservation, listener
//! bind, and emitted gateway rule so a path is v4- or v6-only end to end.
//!
//! Unix-domain and shared-memory interfaces are address-family agnostic (they
//! are named by path, not by IP) and ignore this selection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// IP address family for a benchmark path's IP transports (TCP / UDP / TPROXY).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4 loopback (`127.0.0.1`). The default, so v4 paths are unchanged.
    #[default]
    Ipv4,
    /// IPv6 loopback (`::1`).
    Ipv6,
}

impl AddressFamily {
    /// `true` for [`AddressFamily::Ipv6`].
    pub fn is_ipv6(self) -> bool {
        matches!(self, AddressFamily::Ipv6)
    }

    /// Loopback host literal without a port: `127.0.0.1` or `::1`.
    pub fn loopback_host(self) -> &'static str {
        match self {
            AddressFamily::Ipv4 => "127.0.0.1",
            AddressFamily::Ipv6 => "::1",
        }
    }

    /// Loopback IP address, for binding sockets directly.
    pub fn loopback_ip(self) -> IpAddr {
        match self {
            AddressFamily::Ipv4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
            AddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    }

    /// This family's loopback address formatted with `port`, bracketing IPv6:
    /// `127.0.0.1:8080` or `[::1]:8080`.
    pub fn loopback_socket(self, port: u16) -> String {
        join_host_port(self.loopback_host(), port)
    }
}

/// Join a host literal and `port` into a socket-address string, wrapping bare
/// IPv6 literals (those containing a `:` and not already bracketed) in
/// brackets: `join_host_port("::1", 80)` is `[::1]:80`;
/// `join_host_port("127.0.0.1", 80)` is `127.0.0.1:80`.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_the_default() {
        assert_eq!(AddressFamily::default(), AddressFamily::Ipv4);
        assert!(!AddressFamily::default().is_ipv6());
    }

    #[test]
    fn loopback_helpers_pick_the_right_family() {
        assert_eq!(AddressFamily::Ipv4.loopback_host(), "127.0.0.1");
        assert_eq!(AddressFamily::Ipv6.loopback_host(), "::1");
        assert_eq!(
            AddressFamily::Ipv4.loopback_ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            AddressFamily::Ipv6.loopback_ip(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn ipv6_sockets_are_bracketed() {
        assert_eq!(AddressFamily::Ipv4.loopback_socket(8080), "127.0.0.1:8080");
        assert_eq!(AddressFamily::Ipv6.loopback_socket(8080), "[::1]:8080");
    }

    #[test]
    fn join_host_port_brackets_only_bare_ipv6() {
        assert_eq!(join_host_port("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
        assert_eq!(join_host_port("::", 80), "[::]:80");
        // Already bracketed input is left untouched (no double brackets).
        assert_eq!(join_host_port("[::1]", 80), "[::1]:80");
        // A hostname is treated as-is.
        assert_eq!(join_host_port("localhost", 80), "localhost:80");
    }

    #[test]
    fn serde_uses_lowercase_family_names() {
        assert_eq!(
            serde_json::to_string(&AddressFamily::Ipv4).unwrap(),
            "\"ipv4\""
        );
        assert_eq!(
            serde_json::to_string(&AddressFamily::Ipv6).unwrap(),
            "\"ipv6\""
        );
        let parsed: AddressFamily = serde_json::from_str("\"ipv6\"").unwrap();
        assert_eq!(parsed, AddressFamily::Ipv6);
    }
}
