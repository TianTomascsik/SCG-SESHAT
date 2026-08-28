//! Gateway integration: JSON config generation, child-process lifecycle, and
//! secured-path topology (WP2.1).
//!
//! A benchmark path runs traffic through one or two real `gateway` processes:
//!
//! ```text
//!   sender ──plaintext──▶ encrypt.listen ──secured──▶ decrypt.listen ──plaintext──▶ receiver
//! ```
//!
//! [`build_path`] wires the ports/rules for a [`Topology`]; [`start_path`] spawns
//! the gateway(s) and waits until they are accepting connections.
#![allow(dead_code)] // topology/security surface is consumed across Phase 2 work packages.

pub mod config;
pub mod grpc_client;
pub mod logscan;
pub mod process;
pub mod reload;

use std::collections::BTreeMap;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use crate::net::AddressFamily;
use crate::pki::CaBundle;

use config::{ApiConfig, GatewayConfig, RuleConfig};
pub use process::GatewayProcess;

/// Per-process counter making each injected management-socket path unique.
static NEXT_MGMT_ID: AtomicU64 = AtomicU64::new(0);

/// Endpoint-ring capacity for the injected management API. Only used by
/// `uds`/`shm` app rules (none here), so the exact value is immaterial.
const MGMT_RING_CAPACITY: usize = 1024;

/// Long result-directory paths are fine for CSV artifacts but cannot be used
/// as a base for Unix sockets: Linux limits a pathname socket address to about
/// 108 bytes.  Local-interface endpoints append an app id, UID, traffic class,
/// direction, and suffix, so reserve a deliberately short runtime directory.
///
/// `SESHAT_RUNTIME_DIR` gives operators an explicit override. Otherwise prefer
/// the per-user runtime directory, then `/dev/shm` (both are normally short
/// writable tmpfs locations), before falling back to the system temp directory.
pub fn short_runtime_dir(prefix: &str, id: u64) -> io::Result<PathBuf> {
    const MAX_DIR_BYTES: usize = 32;

    let mut bases = Vec::new();
    if let Some(base) = std::env::var_os("SESHAT_RUNTIME_DIR") {
        bases.push(PathBuf::from(base));
    }
    if let Some(base) = std::env::var_os("XDG_RUNTIME_DIR") {
        bases.push(PathBuf::from(base));
    }
    bases.push(PathBuf::from("/dev/shm"));
    bases.push(std::env::temp_dir());

    let pid = std::process::id();
    let mut last_error = None;
    for base in bases {
        let dir = base.join(format!("{prefix}-{pid}-{id}"));
        if dir.as_os_str().as_encoded_bytes().len() > MAX_DIR_BYTES {
            continue;
        }
        match std::fs::create_dir_all(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::other(
            "could not create a short Unix-socket runtime directory; set SESHAT_RUNTIME_DIR to a writable path shorter than 32 bytes",
        )
    }))
}

/// Reserve a localhost TCP port for gateway plumbing.
///
/// Ports are handed out from a dedicated range *below* the OS ephemeral range
/// (`/proc/sys/net/ipv4/ip_local_port_range`, 32768+ on Linux) using a monotonic
/// counter, then confirmed bindable. This avoids the race an OS-chosen `:0` port
/// suffers: there the OS readily re-hands a just-freed ephemeral port to the
/// next probe, so two concurrent reservations (parallel scenarios, or the two
/// gateways of an scg-to-scg chain) could target the same port and the second
/// gateway would fail with "address already in use". A monotonic counter
/// guarantees distinct ports, and staying below the ephemeral range keeps
/// unrelated `:0` binds from ever landing on a reserved port between our probe
/// and the gateway's rebind.
pub fn reserve_local_port() -> io::Result<u16> {
    reserve_local_port_for(AddressFamily::Ipv4)
}

/// Reserve a loopback port for gateway plumbing on the given address `family`.
///
/// Identical to [`reserve_local_port`] but probes bindability on the family's
/// loopback (`127.0.0.1` for IPv4, `::1` for IPv6) so an IPv6 path never hands
/// out a port only a v4 socket confirmed. See [`reserve_local_port`] for why
/// the reserved sub-ephemeral range plus monotonic counter avoids the `:0`
/// re-handout race.
pub fn reserve_local_port_for(family: AddressFamily) -> io::Result<u16> {
    /// First port of the reserved range (below the Linux ephemeral floor 32768
    /// and clear of the example configs' 10000–13000 ports).
    const BASE: u16 = 20_000;
    /// Size of the reserved range: 20000..=31999.
    const RANGE: u16 = 12_000;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let loopback = family.loopback_ip();
    for _ in 0..RANGE {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed) % RANGE;
        let port = BASE + offset;
        if let Ok(listener) = TcpListener::bind((loopback, port)) {
            drop(listener);
            return Ok(port);
        }
    }
    // Range exhausted (pathological): fall back to an OS-chosen ephemeral port.
    let listener = TcpListener::bind((loopback, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Serialises the integration tests that spawn real `gateway` child processes.
///
/// `cargo test` runs the whole suite in one process at `num_cpus` parallelism.
/// Without this lock, a dozen real gateways (plus their routing-probe children)
/// race to spawn, bind, and complete TLS handshakes at the same time; under that
/// CPU/socket contention their startup intermittently failed with `AddrInUse`
/// or readiness timeouts. The benchmark itself runs scenarios sequentially, so
/// serialising these tests matches real usage and costs only test wall-time.
#[cfg(test)]
static GATEWAY_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire the gateway-test serialisation lock, ignoring poisoning so a single
/// panicking test does not cascade into spurious failures of the rest.
#[cfg(test)]
pub(crate) fn gateway_test_guard() -> std::sync::MutexGuard<'static, ()> {
    GATEWAY_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Physical layout of the secured path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    /// One gateway process hosting both the encrypt and decrypt rules.
    SingleGateway,
    /// Two gateway processes: encrypt on box A, decrypt on box B.
    ScgToScg,
}

/// Security/transport parameters applied to a secured path's rules.
///
/// `Debug` is implemented by hand (not derived) so PSK secret material
/// (`psk_hex`, `psk_identity`) is never printed if this struct is logged with
/// `{:?}`. A hand-written impl is also safer against drift: a future field is
/// not emitted unless explicitly added, so a new secret cannot leak by omission.
#[derive(Clone)]
pub struct SecuritySpec {
    /// `routing | tls | ktls | dtls`.
    pub provider: String,
    /// `tcp | udp`.
    pub proto: String,
    /// `tls1.2 | tls1.3 | dtls1.0 | dtls1.2`.
    pub protocol_version: Option<String>,
    /// `none | server | mutual`.
    pub verify: Option<String>,
    pub server_name: Option<String>,
    /// Decrypt-side (server) identity.
    pub server_cert: Option<PathBuf>,
    pub server_key: Option<PathBuf>,
    /// Encrypt-side (client) identity, for mutual TLS.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    /// Trust anchor for peer verification.
    pub ca_cert: Option<PathBuf>,
    /// `ale | raw` application framing.
    pub app_protocol: Option<String>,
    /// Cipher/security profile (e.g. `integrity-only`, `subset146-pki`).
    pub profile: Option<String>,
    /// `normal | safety`.
    pub traffic_class: String,
    /// PSK identity for subset146-psk profile.
    pub psk_identity: Option<String>,
    /// PSK hex-encoded key for subset146-psk profile.
    pub psk_hex: Option<String>,
    /// Cipher list override (e.g. for subset146-pki pinning).
    pub cipher_list: Option<String>,
    /// TLS 1.3 ciphersuites override.
    pub ciphersuites: Option<String>,
    /// ECDHE key-exchange named-group override (e.g. `X25519` / `P-256`), for the
    /// handshake-algorithm sweep. The gateway allowlist-validates it (TRA #84).
    pub groups: Option<String>,
    /// Enable TLS session resumption/tickets.
    pub resumption: bool,
    /// Per-direction listen/upstream proto overrides for asymmetric paths
    /// (ALE/RAW: encrypt listens UDP, forwards TCP; decrypt listens TCP,
    /// forwards UDP). When `None`, both directions use `self.proto`.
    pub encrypt_listen_proto: Option<String>,
    pub encrypt_upstream_proto: Option<String>,
    pub decrypt_listen_proto: Option<String>,
    pub decrypt_upstream_proto: Option<String>,
    /// Enable zero-copy relay path (splice/sendfile). Only valid for routing/kTLS.
    pub zero_copy: bool,
    /// SHM ring busy-poll microseconds before blocking (0 = immediate block).
    pub spin_wait_us: u64,
    /// Gateway performance profile (`throughput | latency | balanced`).
    pub perf_profile: Option<String>,
    pub sock_buf_size: Option<usize>,
    pub pipe_size: Option<usize>,
    pub relay_buf_size: Option<usize>,
    pub notsent_lowat: Option<usize>,
    pub busy_poll_us: Option<u32>,
    pub bdp_adaptive: bool,
    pub bdp_queue_budget_us: Option<u64>,
    /// Development-mode simulated per-hop network delay in milliseconds
    /// (geo-location / WAN latency simulation). `0` is a no-op.
    pub simulated_delay_ms: u64,
    /// IP address family (`ipv4` / `ipv6`) for the path's plaintext ingress,
    /// inter-gateway, and backend addresses. Defaults to IPv4.
    pub address_family: AddressFamily,
    /// Extra provider params passed through verbatim for custom (out-of-tree)
    /// crypto providers. Empty for all built-in providers.
    pub extra_params: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for SecuritySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PSK material is redacted; presence (`Some`/`None`) is preserved.
        f.debug_struct("SecuritySpec")
            .field("provider", &self.provider)
            .field("proto", &self.proto)
            .field("protocol_version", &self.protocol_version)
            .field("verify", &self.verify)
            .field("server_name", &self.server_name)
            .field("server_cert", &self.server_cert)
            .field("server_key", &self.server_key)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("ca_cert", &self.ca_cert)
            .field("app_protocol", &self.app_protocol)
            .field("profile", &self.profile)
            .field("traffic_class", &self.traffic_class)
            .field(
                "psk_identity",
                &self.psk_identity.as_ref().map(|_| "[REDACTED]"),
            )
            .field("psk_hex", &self.psk_hex.as_ref().map(|_| "[REDACTED]"))
            .field("cipher_list", &self.cipher_list)
            .field("ciphersuites", &self.ciphersuites)
            .field("groups", &self.groups)
            .field("resumption", &self.resumption)
            .field("encrypt_listen_proto", &self.encrypt_listen_proto)
            .field("encrypt_upstream_proto", &self.encrypt_upstream_proto)
            .field("decrypt_listen_proto", &self.decrypt_listen_proto)
            .field("decrypt_upstream_proto", &self.decrypt_upstream_proto)
            .field("zero_copy", &self.zero_copy)
            .field("spin_wait_us", &self.spin_wait_us)
            .field("perf_profile", &self.perf_profile)
            .field("sock_buf_size", &self.sock_buf_size)
            .field("pipe_size", &self.pipe_size)
            .field("relay_buf_size", &self.relay_buf_size)
            .field("notsent_lowat", &self.notsent_lowat)
            .field("busy_poll_us", &self.busy_poll_us)
            .field("bdp_adaptive", &self.bdp_adaptive)
            .field("bdp_queue_budget_us", &self.bdp_queue_budget_us)
            .field("simulated_delay_ms", &self.simulated_delay_ms)
            .field("address_family", &self.address_family)
            .field("extra_params", &self.extra_params)
            .finish()
    }
}

impl SecuritySpec {
    /// Plaintext L4 routing over TCP (no crypto, no certificates).
    pub fn routing_tcp() -> Self {
        SecuritySpec {
            provider: "routing".to_string(),
            proto: "tcp".to_string(),
            protocol_version: None,
            verify: None,
            extra_params: BTreeMap::new(),
            simulated_delay_ms: 0,
            address_family: AddressFamily::Ipv4,
            server_name: None,
            server_cert: None,
            server_key: None,
            client_cert: None,
            client_key: None,
            ca_cert: None,
            app_protocol: None,
            profile: None,
            traffic_class: "normal".to_string(),
            psk_identity: None,
            psk_hex: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            resumption: false,
            encrypt_listen_proto: None,
            encrypt_upstream_proto: None,
            decrypt_listen_proto: None,
            decrypt_upstream_proto: None,
            zero_copy: false,
            spin_wait_us: 0,
            perf_profile: None,
            sock_buf_size: None,
            pipe_size: None,
            relay_buf_size: None,
            notsent_lowat: None,
            busy_poll_us: None,
            bdp_adaptive: false,
            bdp_queue_budget_us: None,
        }
    }

    /// Plaintext L4 routing over UDP (no crypto): the gateway's `routing` provider
    /// binds a UDP listener and forwards datagrams verbatim to a UDP upstream.
    /// Identical to [`Self::routing_tcp`] except the transport is `udp` on both legs.
    pub fn routing_udp() -> Self {
        SecuritySpec {
            proto: "udp".to_string(),
            ..Self::routing_tcp()
        }
    }

    /// A custom out-of-tree crypto provider (for `protocol.type = "custom"`).
    /// `provider` is passed through verbatim as the gateway rule's
    /// `security_provider`; `params` become flattened `provider_params`. This is
    /// the generic escape hatch that lets internal/proprietary providers be
    /// benchmarked without teaching SESHAT their specifics.
    pub fn custom(
        provider: &str,
        proto: &str,
        params: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        SecuritySpec {
            provider: provider.to_string(),
            proto: proto.to_string(),
            extra_params: params,
            ..Self::routing_tcp()
        }
    }

    /// One-way TLS over TCP: the decrypt side presents `cert`/`key`; the encrypt
    /// side connects without verifying the peer (`verify=none`). `version` is a
    /// gateway TLS version string such as `tls1.2` or `tls1.3`.
    pub fn tls_server(version: &str, cert: &Path, key: &Path) -> Self {
        SecuritySpec {
            provider: "tls".to_string(),
            proto: "tcp".to_string(),
            protocol_version: Some(version.to_string()),
            verify: Some("none".to_string()),
            extra_params: BTreeMap::new(),
            simulated_delay_ms: 0,
            address_family: AddressFamily::Ipv4,
            server_name: None,
            server_cert: Some(cert.to_path_buf()),
            server_key: Some(key.to_path_buf()),
            client_cert: None,
            client_key: None,
            ca_cert: None,
            app_protocol: None,
            profile: None,
            traffic_class: "normal".to_string(),
            psk_identity: None,
            psk_hex: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            resumption: false,
            encrypt_listen_proto: None,
            encrypt_upstream_proto: None,
            decrypt_listen_proto: None,
            decrypt_upstream_proto: None,
            zero_copy: false,
            spin_wait_us: 0,
            perf_profile: None,
            sock_buf_size: None,
            pipe_size: None,
            relay_buf_size: None,
            notsent_lowat: None,
            busy_poll_us: None,
            bdp_adaptive: false,
            bdp_queue_budget_us: None,
        }
    }

    /// Mutual TLS over TCP: the decrypt side presents the server identity and
    /// requires+verifies a client certificate against the bundle CA
    /// (`verify=mutual`); the encrypt side presents the client identity and
    /// verifies the server against the same CA (hostname `localhost`).
    pub fn tls_mutual(version: &str, bundle: &CaBundle) -> Self {
        SecuritySpec {
            provider: "tls".to_string(),
            proto: "tcp".to_string(),
            protocol_version: Some(version.to_string()),
            verify: Some("mutual".to_string()),
            extra_params: BTreeMap::new(),
            simulated_delay_ms: 0,
            address_family: AddressFamily::Ipv4,
            server_name: Some("localhost".to_string()),
            server_cert: Some(bundle.server.cert.clone()),
            server_key: Some(bundle.server.key.clone()),
            client_cert: Some(bundle.client.cert.clone()),
            client_key: Some(bundle.client.key.clone()),
            ca_cert: Some(bundle.ca_cert.clone()),
            app_protocol: None,
            profile: None,
            traffic_class: "normal".to_string(),
            psk_identity: None,
            psk_hex: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            resumption: false,
            encrypt_listen_proto: None,
            encrypt_upstream_proto: None,
            decrypt_listen_proto: None,
            decrypt_upstream_proto: None,
            zero_copy: false,
            spin_wait_us: 0,
            perf_profile: None,
            sock_buf_size: None,
            pipe_size: None,
            relay_buf_size: None,
            notsent_lowat: None,
            busy_poll_us: None,
            bdp_adaptive: false,
            bdp_queue_budget_us: None,
        }
    }

    /// One-way DTLS over UDP: the decrypt side presents `cert`/`key`; the
    /// encrypt side connects without verifying the peer (`verify=none`). Both
    /// rules speak UDP (datagram in, datagram out); the gateway runs the DTLS
    /// session between them. `version` is a gateway DTLS string (`dtls1.2`).
    pub fn dtls_server(version: &str, cert: &Path, key: &Path) -> Self {
        SecuritySpec {
            provider: "dtls".to_string(),
            proto: "udp".to_string(),
            protocol_version: Some(version.to_string()),
            verify: Some("none".to_string()),
            extra_params: BTreeMap::new(),
            simulated_delay_ms: 0,
            address_family: AddressFamily::Ipv4,
            server_name: None,
            server_cert: Some(cert.to_path_buf()),
            server_key: Some(key.to_path_buf()),
            client_cert: None,
            client_key: None,
            ca_cert: None,
            app_protocol: None,
            profile: None,
            traffic_class: "normal".to_string(),
            psk_identity: None,
            psk_hex: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            resumption: false,
            encrypt_listen_proto: None,
            encrypt_upstream_proto: None,
            decrypt_listen_proto: None,
            decrypt_upstream_proto: None,
            zero_copy: false,
            spin_wait_us: 0,
            perf_profile: None,
            sock_buf_size: None,
            pipe_size: None,
            relay_buf_size: None,
            notsent_lowat: None,
            busy_poll_us: None,
            bdp_adaptive: false,
            bdp_queue_budget_us: None,
        }
    }

    /// Mutual DTLS over UDP: the decrypt side requires+verifies a client
    /// certificate against the bundle CA (`verify=mutual`); the encrypt side
    /// presents the client identity and verifies the server (hostname
    /// `localhost`). Datagram in, datagram out, DTLS in between.
    pub fn dtls_mutual(version: &str, bundle: &CaBundle) -> Self {
        SecuritySpec {
            provider: "dtls".to_string(),
            proto: "udp".to_string(),
            protocol_version: Some(version.to_string()),
            verify: Some("mutual".to_string()),
            extra_params: BTreeMap::new(),
            simulated_delay_ms: 0,
            address_family: AddressFamily::Ipv4,
            server_name: Some("localhost".to_string()),
            server_cert: Some(bundle.server.cert.clone()),
            server_key: Some(bundle.server.key.clone()),
            client_cert: Some(bundle.client.cert.clone()),
            client_key: Some(bundle.client.key.clone()),
            ca_cert: Some(bundle.ca_cert.clone()),
            app_protocol: None,
            profile: None,
            traffic_class: "normal".to_string(),
            psk_identity: None,
            psk_hex: None,
            cipher_list: None,
            ciphersuites: None,
            groups: None,
            resumption: false,
            encrypt_listen_proto: None,
            encrypt_upstream_proto: None,
            decrypt_listen_proto: None,
            decrypt_upstream_proto: None,
            zero_copy: false,
            spin_wait_us: 0,
            perf_profile: None,
            sock_buf_size: None,
            pipe_size: None,
            relay_buf_size: None,
            notsent_lowat: None,
            busy_poll_us: None,
            bdp_adaptive: false,
            bdp_queue_budget_us: None,
        }
    }

    /// Override the security provider (e.g. switch `tls` → `ktls` for kernel
    /// TLS while keeping the same certificate material).
    pub fn provider(mut self, provider: &str) -> Self {
        self.provider = provider.to_string();
        self
    }

    /// Set the cipher/security profile (e.g. `integrity-only` for a NULL-cipher,
    /// integrity-protected path that still authenticates but does not encrypt).
    pub fn with_profile(mut self, profile: &str) -> Self {
        self.profile = Some(profile.to_string());
        self
    }

    /// Set the gateway traffic class (`normal` | `safety`) both rules of a path
    /// inherit. Safety engages the gateway's QoS: DSCP EF egress marking,
    /// `SO_PRIORITY`, and relay-thread priority.
    pub fn with_traffic_class(mut self, class: &str) -> Self {
        self.traffic_class = class.to_string();
        self
    }

    /// Set the IP address family (`ipv4` / `ipv6`) the path's plaintext ingress,
    /// inter-gateway, and backend addresses are formatted and bound on. UDS/SHM
    /// paths ignore it.
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self
    }

    /// Set PSK identity and key material (for subset146-psk profile).
    pub fn with_psk(mut self, identity: &str, hex_key: &str) -> Self {
        self.psk_identity = Some(identity.to_string());
        self.psk_hex = Some(hex_key.to_string());
        self
    }

    /// Set cipher list override (TLS 1.2 cipher string).
    pub fn with_cipher_list(mut self, ciphers: &str) -> Self {
        self.cipher_list = Some(ciphers.to_string());
        self
    }

    /// Set TLS 1.3 ciphersuites override.
    pub fn with_ciphersuites(mut self, suites: &str) -> Self {
        self.ciphersuites = Some(suites.to_string());
        self
    }

    /// Set the ECDHE key-exchange named-group override (e.g. `X25519` / `P-256`).
    pub fn with_groups(mut self, groups: &str) -> Self {
        self.groups = Some(groups.to_string());
        self
    }

    /// Enable/disable TLS session resumption.
    pub fn with_resumption(mut self, enabled: bool) -> Self {
        self.resumption = enabled;
        self
    }

    /// Override the generated benchmark PKI with scenario-selected certificate
    /// material. Any field left unset keeps the identity already present on the
    /// spec, which lets SESHAT generate the missing default when no explicit
    /// certificate was requested.
    pub fn with_certificate_selection(
        mut self,
        certs: &crate::config::schema::CertificateSelection,
    ) -> Self {
        if let Some(v) = &certs.server_cert {
            self.server_cert = Some(v.clone());
        }
        if let Some(v) = &certs.server_key {
            self.server_key = Some(v.clone());
        }
        if let Some(v) = &certs.client_cert {
            self.client_cert = Some(v.clone());
        }
        if let Some(v) = &certs.client_key {
            self.client_key = Some(v.clone());
        }
        if let Some(v) = &certs.ca_cert {
            self.ca_cert = Some(v.clone());
        }
        if let Some(v) = &certs.server_name {
            self.server_name = Some(v.clone());
        }
        self
    }

    /// Configure asymmetric per-direction protocols for ALE/RAW UDP-over-TLS.
    ///
    /// ALE/RAW framing: encrypt listens on UDP, forwards to TCP (TLS); decrypt
    /// listens on TCP, forwards to UDP. The security layer runs between the two
    /// gateways (or encrypt→decrypt rules) on the TCP segment.
    pub fn with_asymmetric_ale(mut self, app_proto: &str) -> Self {
        self.app_protocol = Some(app_proto.to_string());
        self.encrypt_listen_proto = Some("udp".to_string());
        self.encrypt_upstream_proto = Some("tcp".to_string());
        self.decrypt_listen_proto = Some("tcp".to_string());
        self.decrypt_upstream_proto = Some("udp".to_string());
        self
    }

    /// Default busy-poll budget applied when a scenario asks for `spin_wait`
    /// but does not pin an explicit `spin_wait_us`.
    const DEFAULT_SPIN_WAIT_US: u64 = 50;

    /// Apply optimization flags from the scenario config (F1/F2).
    pub fn with_optimizations(mut self, flags: &crate::config::schema::OptimizationFlags) -> Self {
        self.zero_copy = flags.zero_copy;
        // Honor the `spin_wait` toggle even without an explicit budget: a bare
        // `spin_wait: true` enables a small default busy-poll, so an A/B run that
        // flips only that flag actually changes the gateway behaviour.
        self.spin_wait_us = match (flags.spin_wait_us, flags.spin_wait) {
            (Some(us), _) => us,
            (None, true) => Self::DEFAULT_SPIN_WAIT_US,
            (None, false) => 0,
        };
        self.perf_profile = flags.perf_profile.clone();
        self.sock_buf_size = flags.sock_buf_size;
        self.pipe_size = flags.pipe_size;
        self.relay_buf_size = flags.relay_buf_size;
        self.notsent_lowat = flags.notsent_lowat;
        self.busy_poll_us = flags.busy_poll_us;
        self.bdp_adaptive = flags.bdp_adaptive;
        self.bdp_queue_budget_us = flags.bdp_queue_budget_us;
        self.simulated_delay_ms = flags.simulated_delay_ms.unwrap_or(0);
        self
    }

    /// Apply common provider/transport settings shared by both directions.
    fn apply_common(&self, mut rule: RuleConfig) -> RuleConfig {
        rule = rule
            .security(&self.provider)
            .proto(&self.proto)
            .traffic_class(&self.traffic_class);
        if let Some(v) = &self.protocol_version {
            rule = rule.protocol_version(v);
        }
        if let Some(v) = &self.app_protocol {
            rule = rule.app_protocol(v);
        }
        if let Some(v) = &self.profile {
            rule = rule.param("profile", v.clone());
        }
        if let Some(v) = &self.psk_identity {
            rule = rule.param("psk_identity", v.clone());
        }
        if let Some(v) = &self.psk_hex {
            rule = rule.param("psk_hex", v.clone());
        }
        if let Some(v) = &self.cipher_list {
            rule = rule.param("cipher_list", v.clone());
        }
        if let Some(v) = &self.ciphersuites {
            rule = rule.param("ciphersuites", v.clone());
        }
        if let Some(v) = &self.groups {
            rule = rule.param("groups", v.clone());
        }
        if self.resumption {
            rule = rule.param("resumption", true);
        }
        // Pass through any custom-provider params verbatim.
        for (k, v) in &self.extra_params {
            rule = rule.param(k, v.clone());
        }
        // Optimization flags (F1/F2/perf_profile).
        rule.zero_copy = self.zero_copy;
        rule.spin_wait_us = self.spin_wait_us;
        rule.perf_profile = self.perf_profile.clone();
        rule.sock_buf_size = self.sock_buf_size;
        rule.pipe_size = self.pipe_size;
        rule.relay_buf_size = self.relay_buf_size;
        rule.notsent_lowat = self.notsent_lowat;
        rule.busy_poll_us = self.busy_poll_us.unwrap_or(0);
        rule.bdp_adaptive = self.bdp_adaptive;
        rule.bdp_queue_budget_us = self.bdp_queue_budget_us;
        // Dev-mode geo delay: emit the key only when a delay is requested so
        // baseline rules stay byte-identical to before this knob existed.
        rule.simulated_delay_ms = (self.simulated_delay_ms > 0).then_some(self.simulated_delay_ms);
        rule
    }

    /// Build the encrypt rule (TLS client side: trusts the peer, optionally
    /// presents a client identity for mutual auth).
    pub(crate) fn apply_encrypt(&self, rule: RuleConfig) -> RuleConfig {
        let mut rule = self.apply_common(rule);
        // Client-side verification is decided per direction (it differs from the
        // server's `verify`): verify the server only when we both trust a CA and
        // present a client identity (mutual TLS); otherwise skip (the self-signed
        // server-auth path uses `verify=none`).
        if self.provider != "routing" {
            // The Subset-146 PKI profile validates the requested verify mode
            // before role-specific TLS setup. It therefore requires `mutual`
            // on the connector too (the connector implementation still only
            // verifies its server peer). Ordinary mTLS keeps `server` here.
            let v = if self.profile.as_deref() == Some("subset146-pki") {
                "mutual"
            } else if self.client_cert.is_some() && self.ca_cert.is_some() {
                "server"
            } else {
                "none"
            };
            rule = rule.param("verify", v);
        }
        if let Some(v) = &self.server_name {
            rule = rule.param("server_name", v.clone());
        }
        if let Some(v) = &self.ca_cert {
            rule = rule.param("ca_path", path_str(v));
        }
        if let Some(v) = &self.client_cert {
            rule = rule.param("cert_path", path_str(v));
        }
        if let Some(v) = &self.client_key {
            rule = rule.param("key_path", path_str(v));
        }
        rule
    }

    /// Build the decrypt rule (TLS server side: presents an identity, optionally
    /// verifies the client against the CA for mutual auth).
    pub(crate) fn apply_decrypt(&self, rule: RuleConfig) -> RuleConfig {
        let mut rule = self.apply_common(rule);
        // Server-side verification policy (`none` | `server` | `mutual`).
        if let Some(v) = &self.verify {
            rule = rule.param("verify", v.clone());
        }
        if let Some(v) = &self.server_cert {
            rule = rule.param("cert_path", path_str(v));
        }
        if let Some(v) = &self.server_key {
            rule = rule.param("key_path", path_str(v));
        }
        if matches!(self.verify.as_deref(), Some("mutual")) {
            if let Some(v) = &self.ca_cert {
                rule = rule.param("ca_path", path_str(v));
            }
        }
        rule
    }
}

/// A named gateway config (one process worth of rules).
#[derive(Debug, Clone)]
pub struct NamedGateway {
    pub label: String,
    pub config: GatewayConfig,
}

/// A fully-wired secured path ready to be spawned.
#[derive(Debug, Clone)]
pub struct PathPlan {
    /// Address the SESHAT sender connects to (plaintext ingress).
    pub ingress_addr: String,
    /// Address the SESHAT receiver listens on (plaintext egress target).
    pub backend_addr: String,
    /// One config for [`Topology::SingleGateway`], two for [`Topology::ScgToScg`].
    pub gateways: Vec<NamedGateway>,
}

/// Build one encrypt/decrypt rule pair for `spec` — `ingress → mid → backend`
/// — with the per-direction proto overrides for asymmetric paths (ALE/RAW)
/// applied. Shared by the single-path and per-class multi-stream builders.
fn build_rule_pair(
    spec: &SecuritySpec,
    encrypt_name: &str,
    decrypt_name: &str,
    ingress: &str,
    mid: &str,
    backend_addr: &str,
) -> (RuleConfig, RuleConfig) {
    let mut encrypt = spec.apply_encrypt(RuleConfig::new(encrypt_name, "encrypt", ingress, mid));
    let mut decrypt =
        spec.apply_decrypt(RuleConfig::new(decrypt_name, "decrypt", mid, backend_addr));

    if let Some(lp) = &spec.encrypt_listen_proto {
        encrypt = encrypt.listen_proto(lp);
    }
    if let Some(up) = &spec.encrypt_upstream_proto {
        encrypt = encrypt.upstream_proto(up);
    }
    if let Some(lp) = &spec.decrypt_listen_proto {
        decrypt = decrypt.listen_proto(lp);
    }
    if let Some(up) = &spec.decrypt_upstream_proto {
        decrypt = decrypt.upstream_proto(up);
    }
    (encrypt, decrypt)
}

/// Split rules into per-topology gateway configs: one process owning the whole
/// path, or an encrypt-side and a decrypt-side process (SCG↔SCG).
fn gateways_for_topology(
    topology: Topology,
    encrypts: Vec<RuleConfig>,
    decrypts: Vec<RuleConfig>,
    connections: usize,
) -> Vec<NamedGateway> {
    let named = |label: &str, rules: Vec<RuleConfig>| NamedGateway {
        label: label.to_string(),
        config: GatewayConfig::new(rules)
            .log_level("info")
            .allow_all()
            .pool_for_connections(connections),
    };
    match topology {
        Topology::SingleGateway => {
            let mut rules = encrypts;
            rules.extend(decrypts);
            vec![named("scg", rules)]
        }
        Topology::ScgToScg => vec![named("scg-a", encrypts), named("scg-b", decrypts)],
    }
}

/// Wire ports and rules for `topology`, forwarding plaintext to `backend_addr`
/// (where the SESHAT receiver must already be listening). `connections` is the
/// number of concurrent connections the run will open; it sizes each gateway's
/// connection pool so none of them queue behind the default `2×CPU` workers.
pub fn build_path(
    spec: &SecuritySpec,
    topology: Topology,
    backend_addr: &str,
    connections: usize,
) -> io::Result<PathPlan> {
    let family = spec.address_family;
    let ingress = family.loopback_socket(reserve_local_port_for(family)?);
    let mid = family.loopback_socket(reserve_local_port_for(family)?);

    let (encrypt, decrypt) = build_rule_pair(
        spec,
        "seshat-encrypt",
        "seshat-decrypt",
        &ingress,
        &mid,
        backend_addr,
    );
    let gateways = gateways_for_topology(topology, vec![encrypt], vec![decrypt], connections);

    Ok(PathPlan {
        ingress_addr: ingress,
        backend_addr: backend_addr.to_string(),
        gateways,
    })
}

/// One per-class slice of a multi-class path: the canonical traffic class and
/// the plaintext ingress/egress addresses of its dedicated rule pair.
#[derive(Debug, Clone)]
pub struct ClassPath {
    pub class: String,
    pub ingress_addr: String,
    pub backend_addr: String,
}

/// A multi-class secured path (multi-stream scheduling): one encrypt/decrypt
/// rule pair **per traffic class**, all served by the same gateway process(es)
/// so classes contend for the same DUT resources while each class's rules carry
/// its own `traffic_class` — the knob that engages the gateway's safety QoS
/// (DSCP EF egress marking, `SO_PRIORITY`, relay-thread priority).
#[derive(Debug, Clone)]
pub struct MultiClassPathPlan {
    pub paths: Vec<ClassPath>,
    pub gateways: Vec<NamedGateway>,
}

/// Wire one rule pair per `(class, backend_addr)` entry for `topology`. Every
/// class gets its own ingress/mid ports (rule names `seshat-encrypt-<class>` /
/// `seshat-decrypt-<class>`, matching the UDS/SHM per-class naming), while all
/// pairs share the same gateway process(es) and connection pool.
pub fn build_multi_class_path(
    spec: &SecuritySpec,
    topology: Topology,
    class_backends: &[(String, String)],
    connections: usize,
) -> io::Result<MultiClassPathPlan> {
    if class_backends.is_empty() {
        return Err(io::Error::other(
            "multi-class path needs at least one traffic class",
        ));
    }

    let mut paths = Vec::with_capacity(class_backends.len());
    let mut encrypts = Vec::with_capacity(class_backends.len());
    let mut decrypts = Vec::with_capacity(class_backends.len());

    for (class, backend_addr) in class_backends {
        let family = spec.address_family;
        let ingress = family.loopback_socket(reserve_local_port_for(family)?);
        let mid = family.loopback_socket(reserve_local_port_for(family)?);
        let class_spec = spec.clone().with_traffic_class(class);
        let (encrypt, decrypt) = build_rule_pair(
            &class_spec,
            &format!("seshat-encrypt-{class}"),
            &format!("seshat-decrypt-{class}"),
            &ingress,
            &mid,
            backend_addr,
        );
        encrypts.push(encrypt);
        decrypts.push(decrypt);
        paths.push(ClassPath {
            class: class.clone(),
            ingress_addr: ingress,
            backend_addr: backend_addr.clone(),
        });
    }

    let gateways = gateways_for_topology(topology, encrypts, decrypts, connections);
    Ok(MultiClassPathPlan { paths, gateways })
}

/// Add the control-plane pieces needed to exercise dynamic local-endpoint
/// creation on an otherwise TCP-based path.
///
/// The hot-reload benchmark keeps its measured data plane on TCP, but its
/// `add_connection`/`remove_connection` action is a management-API operation.
/// A UDS rule is therefore needed as an endpoint template; without it a gRPC
/// request has no rule to instantiate. This is currently intentionally limited
/// to the direct, single-gateway topology: the endpoint belongs on the encrypt
/// process, while the management client needs that process's API socket.
pub fn add_management_uds_template(plan: &mut PathPlan, app_id: &str) -> io::Result<()> {
    if plan.gateways.len() != 1 {
        return Err(io::Error::other(
            "dynamic UDS endpoint benchmarks require the single-gateway topology",
        ));
    }

    let config = &mut plan.gateways[0].config;
    let mut template = config
        .rules
        .iter()
        .find(|rule| rule.direction == "encrypt" && rule.listen_proto == "tcp")
        .cloned()
        .ok_or_else(|| io::Error::other("TCP encrypt rule missing for endpoint template"))?;
    template.name = "seshat-hotreload-template".to_string();
    template.listen_addr = "unused".to_string();
    template.listen_proto = "uds".to_string();
    template.app_id = Some(app_id.to_string());
    // SAFETY: `libc::getuid()` is an always-safe POSIX syscall wrapper: it takes
    // no arguments, dereferences no pointers, cannot fail, and simply returns the
    // calling process's real UID. No invariant is required for soundness.
    template.allowed_uids = vec![unsafe { libc::getuid() }];
    config.rules.push(template);

    let id = NEXT_MGMT_ID.fetch_add(1, Ordering::Relaxed);
    let runtime_dir = short_runtime_dir("sm", id)?;
    let socket = runtime_dir.join("mgmt.sock");
    config.api = Some(ApiConfig::new(
        &socket.to_string_lossy(),
        &runtime_dir.to_string_lossy(),
        MGMT_RING_CAPACITY,
    ));
    Ok(())
}

/// A running secured path: the spawned gateway processes plus their endpoints.
pub struct RunningPath {
    pub ingress_addr: String,
    pub backend_addr: String,
    processes: Vec<GatewayProcess>,
}

impl RunningPath {
    /// OS pids of the gateway processes (for `/proc/<pid>` system metrics).
    pub fn pids(&self) -> Vec<i32> {
        self.processes.iter().map(GatewayProcess::pid).collect()
    }

    /// Captured log files of the gateway processes, for post-run effective-
    /// protocol scanning ([`crate::gateway::logscan`]).
    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.processes
            .iter()
            .map(|p| p.log_path().to_path_buf())
            .collect()
    }

    /// The management UDS socket path of the first gateway process (if any).
    /// Used by UDS/SHM transports to provision endpoints via gRPC.
    pub fn mgmt_socket_path(&self) -> Option<PathBuf> {
        self.processes
            .first()
            .and_then(|p| p.mgmt_socket_path())
            .map(|p| p.to_path_buf())
    }

    /// Config file paths of all gateway processes (for hot-reload injection).
    pub fn config_paths(&self) -> Vec<PathBuf> {
        self.processes
            .iter()
            .map(|p| p.config_path().to_path_buf())
            .collect()
    }

    /// Borrow the first gateway process (for PID-targeted reload signals).
    pub fn first_process(&self) -> Option<&GatewayProcess> {
        self.processes.first()
    }

    /// Gracefully stop every gateway process.
    pub fn shutdown(self) -> io::Result<()> {
        for proc in self.processes {
            proc.shutdown()?;
        }
        Ok(())
    }
}

/// Spawn the gateway(s) for `plan` and wait until each is accepting connections.
///
/// Gateways are started downstream-first (decrypt before encrypt) so an
/// encrypt-side upstream connection always has a peer to reach. Each spawned
/// process is best-effort pinned to `gateway_cores` (when non-empty) so the
/// gateway never shares cores with the harness sender/receiver (NFR-PERF).
pub fn start_path(
    plan: &PathPlan,
    binary: &Path,
    work_dir: &Path,
    ready_timeout: Duration,
    gateway_cores: &[usize],
) -> io::Result<RunningPath> {
    let processes = start_gateways(
        &plan.gateways,
        binary,
        work_dir,
        ready_timeout,
        gateway_cores,
    )?;
    Ok(RunningPath {
        ingress_addr: plan.ingress_addr.clone(),
        backend_addr: plan.backend_addr.clone(),
        processes,
    })
}

/// Spawn the gateway(s) for a multi-class plan (multi-stream scheduling).
///
/// Same downstream-first startup as [`start_path`]; the returned
/// [`RunningPath`]'s `ingress_addr`/`backend_addr` are those of the plan's
/// **first** class path (callers address per-class endpoints via
/// [`MultiClassPathPlan::paths`], not via these fields).
pub fn start_multi_class_path(
    plan: &MultiClassPathPlan,
    binary: &Path,
    work_dir: &Path,
    ready_timeout: Duration,
    gateway_cores: &[usize],
) -> io::Result<RunningPath> {
    let first = plan
        .paths
        .first()
        .ok_or_else(|| io::Error::other("multi-class plan has no class paths"))?;
    let processes = start_gateways(
        &plan.gateways,
        binary,
        work_dir,
        ready_timeout,
        gateway_cores,
    )?;
    Ok(RunningPath {
        ingress_addr: first.ingress_addr.clone(),
        backend_addr: first.backend_addr.clone(),
        processes,
    })
}

/// Spawn and readiness-gate one process per [`NamedGateway`], downstream-first.
fn start_gateways(
    gateways: &[NamedGateway],
    binary: &Path,
    work_dir: &Path,
    ready_timeout: Duration,
    gateway_cores: &[usize],
) -> io::Result<Vec<GatewayProcess>> {
    let mut processes = Vec::with_capacity(gateways.len());
    for named in gateways.iter().rev() {
        let config = ensure_readiness_api(&named.config)?;
        let mut proc = GatewayProcess::spawn(binary, &config, work_dir, &named.label, "info")?;
        if !gateway_cores.is_empty() && !crate::run::affinity::pin_pid(proc.pid(), gateway_cores) {
            log::warn!(
                "could not pin gateway '{}' (pid {}) to cores {:?}",
                named.label,
                proc.pid(),
                gateway_cores
            );
        }
        proc.wait_ready(ready_timeout)?;
        processes.push(proc);
    }
    Ok(processes)
}

/// Ensure a gateway config exposes a readiness signal. TCP/ALE paths are probed
/// by connecting to a TCP listener, but a pure UDP/DTLS process has no TCP
/// listener to poll, so we inject a management-API block: its UDS appears once
/// the process is fully initialised, which [`GatewayProcess::wait_ready`] polls.
///
/// The socket lives in a short per-process runtime directory to respect the
/// `AF_UNIX` 108-byte path limit. Configs that already have a TCP listener or
/// an explicit API block are returned unchanged.
///
/// Note: we deliberately do **not** inject the API for configs that already have
/// a TCP listener. Doing so makes `wait_ready` also gate on the management UDS,
/// and some gateway builds bring that socket up late (or not at all) for TLS
/// paths, which would stall readiness. The benign "management API server error"
/// such builds log for TCP paths is harmless and does not affect measurements.
fn ensure_readiness_api(config: &GatewayConfig) -> io::Result<GatewayConfig> {
    let has_tcp_listener = config
        .rules
        .iter()
        .any(|r| r.listen_proto == "tcp" && r.listen_addr != "unused");
    if has_tcp_listener || config.api.is_some() {
        return Ok(config.clone());
    }
    let id = NEXT_MGMT_ID.fetch_add(1, Ordering::Relaxed);
    let runtime_dir = short_runtime_dir("sm", id)?;
    let sock = runtime_dir.join("mgmt.sock");
    let api = ApiConfig::new(
        &sock.to_string_lossy(),
        &runtime_dir.to_string_lossy(),
        MGMT_RING_CAPACITY,
    );
    Ok(config.clone().api(api))
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Find the first candidate `gateway` binary whose build actually serves a
/// `routing` rule, exercising spawn/ready/shutdown as the probe.
///
/// Cached release binaries can predate the `routing` provider; this guards the
/// benchmark from silently selecting one that rejects the config at runtime.
/// Returns `None` if no candidate comes up within the probe timeout.
pub fn locate_working_binary(work_dir: &Path) -> Option<PathBuf> {
    if std::fs::create_dir_all(work_dir).is_err() {
        return None;
    }
    for binary in process::candidate_gateway_binaries() {
        let Ok(port) = reserve_local_port() else {
            continue;
        };
        let listen = format!("127.0.0.1:{port}");
        let cfg = GatewayConfig::new(vec![RuleConfig::new(
            "probe",
            "encrypt",
            &listen,
            "127.0.0.1:1",
        )])
        .log_level("error")
        .allow_all();
        let Ok(mut proc) = GatewayProcess::spawn(&binary, &cfg, work_dir, "probe", "error") else {
            continue;
        };
        let ready = proc.wait_ready(Duration::from_secs(3)).is_ok();
        let _ = proc.shutdown();
        if ready {
            return Some(binary);
        }
    }
    None
}

#[cfg(test)]
mod secret_redaction_tests {
    use super::*;

    #[test]
    fn securityspec_debug_redacts_psk() {
        let mut s = SecuritySpec::routing_tcp();
        s.psk_identity = Some("super-secret-identity".to_string());
        s.psk_hex = Some("00112233445566778899aabbccddeeff".to_string());
        let out = format!("{s:?}");
        assert!(
            !out.contains("super-secret-identity"),
            "psk_identity leaked: {out}"
        );
        assert!(
            !out.contains("00112233445566778899aabbccddeeff"),
            "psk_hex leaked: {out}"
        );
        assert!(out.contains("REDACTED"), "expected redaction marker: {out}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn optimization_flags_reach_emitted_rule() {
        use crate::config::schema::OptimizationFlags;
        let flags = OptimizationFlags {
            zero_copy: true,
            spin_wait: true, // no explicit budget → default applies
            spin_wait_us: None,
            sock_buf_size: Some(1 << 20),
            pipe_size: Some(65_536),
            relay_buf_size: Some(32_768),
            notsent_lowat: Some(16_384),
            busy_poll_us: Some(25),
            bdp_adaptive: true,
            bdp_queue_budget_us: Some(200),
            perf_profile: Some("throughput".to_string()),
            ..Default::default()
        };
        let spec = SecuritySpec::routing_tcp().with_optimizations(&flags);
        let rule = spec.apply_encrypt(RuleConfig::new(
            "r",
            "encrypt",
            "127.0.0.1:1",
            "127.0.0.1:2",
        ));
        assert!(rule.zero_copy);
        assert_eq!(rule.spin_wait_us, SecuritySpec::DEFAULT_SPIN_WAIT_US);
        assert_eq!(rule.sock_buf_size, Some(1 << 20));
        assert_eq!(rule.pipe_size, Some(65_536));
        assert_eq!(rule.relay_buf_size, Some(32_768));
        assert_eq!(rule.notsent_lowat, Some(16_384));
        assert_eq!(rule.busy_poll_us, 25);
        assert!(rule.bdp_adaptive);
        assert_eq!(rule.bdp_queue_budget_us, Some(200));
        assert_eq!(rule.perf_profile.as_deref(), Some("throughput"));
        // The knobs must survive serialization — that JSON is what the SCG reads.
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["zero_copy"], true);
        assert_eq!(json["pipe_size"], 65_536);
        assert_eq!(json["perf_profile"], "throughput");
    }

    #[test]
    fn geo_delay_flag_reaches_emitted_rule() {
        use crate::config::schema::OptimizationFlags;
        // A configured dev-mode geo delay must surface as `simulated_delay_ms`
        // on the emitted rule JSON (this drives the gateway's apply_geo_delay).
        let flags = OptimizationFlags {
            simulated_delay_ms: Some(50),
            ..Default::default()
        };
        let spec = SecuritySpec::routing_tcp().with_optimizations(&flags);
        assert_eq!(spec.simulated_delay_ms, 50);
        let rule = spec.apply_encrypt(RuleConfig::new(
            "r",
            "encrypt",
            "127.0.0.1:1",
            "127.0.0.1:2",
        ));
        assert_eq!(rule.simulated_delay_ms, Some(50));
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["simulated_delay_ms"], 50);

        // Absent/zero delay must omit the key entirely, keeping baseline rules
        // byte-identical to before the knob existed.
        let baseline = SecuritySpec::routing_tcp().apply_encrypt(RuleConfig::new(
            "r",
            "encrypt",
            "127.0.0.1:1",
            "127.0.0.1:2",
        ));
        assert_eq!(baseline.simulated_delay_ms, None);
        let baseline_json = serde_json::to_value(&baseline).unwrap();
        assert!(baseline_json.get("simulated_delay_ms").is_none());
    }

    #[test]
    fn custom_provider_flattens_name_and_params() {
        // The generic `custom` hook: an out-of-tree provider name and its
        // provider_params must reach the emitted rule verbatim so the SCG (or an
        // internal build registering that provider) can consume them.
        let mut params = BTreeMap::new();
        params.insert(
            "vendor_key_hex".to_string(),
            serde_json::Value::String("00112233".to_string()),
        );
        params.insert(
            "vendor_accept_window_ms".to_string(),
            serde_json::Value::from(60_000),
        );
        let spec = SecuritySpec::custom("vendor-udp", "udp", params);
        let rule = spec.apply_encrypt(RuleConfig::new(
            "r",
            "encrypt",
            "127.0.0.1:1",
            "127.0.0.1:2",
        ));
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["security_provider"], "vendor-udp");
        assert_eq!(json["listen_proto"], "udp");
        // provider_params are flattened to the rule's top level.
        assert_eq!(json["vendor_key_hex"], "00112233");
        assert_eq!(json["vendor_accept_window_ms"], 60_000);
    }

    #[test]
    fn build_path_single_gateway_has_two_rules() {
        let spec = SecuritySpec::routing_tcp();
        let plan = build_path(&spec, Topology::SingleGateway, "127.0.0.1:65000", 1).unwrap();
        assert_eq!(plan.gateways.len(), 1);
        assert_eq!(plan.gateways[0].config.rules.len(), 2);
        assert_eq!(plan.backend_addr, "127.0.0.1:65000");
        // encrypt.upstream feeds decrypt.listen.
        let enc = &plan.gateways[0].config.rules[0];
        let dec = &plan.gateways[0].config.rules[1];
        assert_eq!(enc.direction, "encrypt");
        assert_eq!(dec.direction, "decrypt");
        assert_eq!(enc.upstream_addr, dec.listen_addr);
        assert_eq!(dec.upstream_addr, "127.0.0.1:65000");
    }

    #[test]
    fn build_path_scg_to_scg_splits_processes() {
        let spec = SecuritySpec::routing_tcp();
        let plan = build_path(&spec, Topology::ScgToScg, "127.0.0.1:65001", 1).unwrap();
        assert_eq!(plan.gateways.len(), 2);
        assert_eq!(plan.gateways[0].config.rules.len(), 1);
        assert_eq!(plan.gateways[1].config.rules.len(), 1);
        assert_eq!(plan.gateways[0].config.rules[0].direction, "encrypt");
        assert_eq!(plan.gateways[1].config.rules[0].direction, "decrypt");
    }

    #[test]
    fn build_path_ipv6_brackets_ingress_and_mid() {
        // An IPv6 spec formats the reserved loopback ingress/inter-gateway
        // addresses in bracketed `[::1]:port` form; the caller-supplied backend
        // is passed through verbatim.
        let spec = SecuritySpec::routing_tcp().with_address_family(AddressFamily::Ipv6);
        let plan = build_path(&spec, Topology::SingleGateway, "[::1]:65004", 1).unwrap();
        assert_eq!(plan.backend_addr, "[::1]:65004");
        assert!(
            plan.ingress_addr.starts_with("[::1]:"),
            "ingress must be a bracketed v6 loopback: {}",
            plan.ingress_addr
        );
        // The reserved ingress/mid addresses must parse as IPv6 socket addrs.
        let enc = &plan.gateways[0].config.rules[0];
        assert!(enc
            .listen_addr
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .is_ipv6());
        assert!(enc
            .upstream_addr
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .is_ipv6());
    }

    #[test]
    fn multi_class_path_emits_one_rule_pair_per_class() {
        let spec = SecuritySpec::routing_tcp();
        let classes = vec![
            ("safety".to_string(), "127.0.0.1:65010".to_string()),
            ("normal".to_string(), "127.0.0.1:65011".to_string()),
        ];
        let plan = build_multi_class_path(&spec, Topology::SingleGateway, &classes, 2).unwrap();

        // One gateway process, one encrypt+decrypt pair per class.
        assert_eq!(plan.gateways.len(), 1);
        let rules = &plan.gateways[0].config.rules;
        assert_eq!(rules.len(), 4);
        assert_eq!(plan.paths.len(), 2);

        // Each class's rules carry its traffic_class and are wired
        // ingress → mid → that class's backend.
        for path in &plan.paths {
            let enc = rules
                .iter()
                .find(|r| r.name == format!("seshat-encrypt-{}", path.class))
                .expect("encrypt rule for class");
            let dec = rules
                .iter()
                .find(|r| r.name == format!("seshat-decrypt-{}", path.class))
                .expect("decrypt rule for class");
            assert_eq!(enc.traffic_class, path.class);
            assert_eq!(dec.traffic_class, path.class);
            assert_eq!(enc.listen_addr, path.ingress_addr);
            assert_eq!(enc.upstream_addr, dec.listen_addr);
            assert_eq!(dec.upstream_addr, path.backend_addr);
        }

        // Distinct ports everywhere: the two ingresses differ, and no class's
        // mid hop collides with another's.
        let mut listens: Vec<&str> = rules.iter().map(|r| r.listen_addr.as_str()).collect();
        listens.sort_unstable();
        listens.dedup();
        assert_eq!(listens.len(), 4, "listen addresses must be distinct");
    }

    #[test]
    fn multi_class_path_scg_to_scg_splits_directions() {
        let spec = SecuritySpec::routing_tcp();
        let classes = vec![
            ("safety".to_string(), "127.0.0.1:65012".to_string()),
            ("normal".to_string(), "127.0.0.1:65013".to_string()),
        ];
        let plan = build_multi_class_path(&spec, Topology::ScgToScg, &classes, 2).unwrap();
        assert_eq!(plan.gateways.len(), 2);
        assert!(plan.gateways[0]
            .config
            .rules
            .iter()
            .all(|r| r.direction == "encrypt"));
        assert!(plan.gateways[1]
            .config
            .rules
            .iter()
            .all(|r| r.direction == "decrypt"));
        assert_eq!(plan.gateways[0].config.rules.len(), 2);
        assert_eq!(plan.gateways[1].config.rules.len(), 2);
    }

    #[test]
    fn multi_class_path_rejects_empty_class_list() {
        let spec = SecuritySpec::routing_tcp();
        assert!(build_multi_class_path(&spec, Topology::SingleGateway, &[], 1).is_err());
    }

    #[test]
    fn selected_certificates_are_emitted_to_tls_rules() {
        let generated = crate::pki::CaBundle {
            ca_cert: PathBuf::from("/generated/ca.pem"),
            server: crate::pki::Identity {
                cert: PathBuf::from("/generated/server.pem"),
                key: PathBuf::from("/generated/server.key"),
            },
            client: crate::pki::Identity {
                cert: PathBuf::from("/generated/client.pem"),
                key: PathBuf::from("/generated/client.key"),
            },
        };
        let certs = crate::config::schema::CertificateSelection {
            server_cert: Some(PathBuf::from("/chosen/server.pem")),
            server_key: Some(PathBuf::from("/chosen/server.key")),
            client_cert: Some(PathBuf::from("/chosen/client.pem")),
            client_key: Some(PathBuf::from("/chosen/client.key")),
            ca_cert: Some(PathBuf::from("/chosen/ca.pem")),
            server_name: Some("bench.local".to_string()),
        };
        let spec =
            SecuritySpec::tls_mutual("tls1.3", &generated).with_certificate_selection(&certs);
        let plan = build_path(&spec, Topology::SingleGateway, "127.0.0.1:65002", 1).unwrap();
        let enc = &plan.gateways[0].config.rules[0];
        let dec = &plan.gateways[0].config.rules[1];

        assert_eq!(enc.provider_params["verify"].as_str(), Some("server"));
        assert_eq!(
            enc.provider_params["server_name"].as_str(),
            Some("bench.local")
        );
        assert_eq!(
            enc.provider_params["cert_path"].as_str(),
            Some("/chosen/client.pem")
        );
        assert_eq!(
            enc.provider_params["key_path"].as_str(),
            Some("/chosen/client.key")
        );
        assert_eq!(
            enc.provider_params["ca_path"].as_str(),
            Some("/chosen/ca.pem")
        );
        assert_eq!(dec.provider_params["verify"].as_str(), Some("mutual"));
        assert_eq!(
            dec.provider_params["cert_path"].as_str(),
            Some("/chosen/server.pem")
        );
        assert_eq!(
            dec.provider_params["key_path"].as_str(),
            Some("/chosen/server.key")
        );
        assert_eq!(
            dec.provider_params["ca_path"].as_str(),
            Some("/chosen/ca.pem")
        );
    }

    #[test]
    fn ktls_keeps_selected_server_certificate() {
        let certs = crate::config::schema::CertificateSelection {
            server_cert: Some(PathBuf::from("/chosen/server.pem")),
            server_key: Some(PathBuf::from("/chosen/server.key")),
            ..Default::default()
        };
        let spec = SecuritySpec::tls_server(
            "tls1.3",
            Path::new("/generated/server.pem"),
            Path::new("/generated/server.key"),
        )
        .provider("ktls")
        .with_certificate_selection(&certs);
        let plan = build_path(&spec, Topology::SingleGateway, "127.0.0.1:65003", 1).unwrap();
        let enc = &plan.gateways[0].config.rules[0];
        let dec = &plan.gateways[0].config.rules[1];

        assert_eq!(enc.security_provider, "ktls");
        assert_eq!(dec.security_provider, "ktls");
        assert_eq!(enc.provider_params["verify"].as_str(), Some("none"));
        assert_eq!(dec.provider_params["verify"].as_str(), Some("none"));
        assert_eq!(
            dec.provider_params["cert_path"].as_str(),
            Some("/chosen/server.pem")
        );
        assert_eq!(
            dec.provider_params["key_path"].as_str(),
            Some("/chosen/server.key")
        );
    }

    /// Serve exactly one 4-byte echo, tolerating spurious readiness-probe
    /// connections (which arrive with no payload and close immediately).
    fn echo_backend(listener: std::net::TcpListener) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() > deadline {
                return Err(io::Error::other("backend timed out waiting for payload"));
            }
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_nonblocking(false)?;
                    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
                    let mut buf = [0u8; 4];
                    if sock.read_exact(&mut buf).is_ok() {
                        sock.write_all(&buf)?;
                        sock.flush()?;
                        return Ok(());
                    }
                    // Spurious probe connection — keep serving.
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Probe each candidate binary with a trivial routing rule and return the
    /// first that brings its listener up. Thin wrapper over the public
    /// [`locate_working_binary`] so the tests share one selection path.
    fn find_routing_capable_binary(work_dir: &Path) -> Option<PathBuf> {
        super::locate_working_binary(work_dir)
    }

    /// Drive a single 4-byte echo through `spec`/`topology` using `binary`,
    /// asserting the payload survives the round-trip. The SESHAT client and
    /// backend always speak plaintext TCP — any TLS happens internally between
    /// the gateway's encrypt and decrypt rules.
    fn drive_roundtrip(binary: &Path, spec: &SecuritySpec, topology: Topology, work_dir: &Path) {
        let backend = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap().to_string();
        let server = thread::spawn(move || echo_backend(backend));

        let plan = build_path(spec, topology, &backend_addr, 1).unwrap();
        let ingress = plan.ingress_addr.clone();
        let running = start_path(&plan, binary, work_dir, Duration::from_secs(10), &[]).unwrap();

        let addr = ingress.to_socket_addrs().unwrap().next().unwrap();
        let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"ping", "round-trip through gateway failed");

        drop(client);
        server.join().unwrap().expect("backend echo");
        running.shutdown().unwrap();
    }

    fn run_echo_roundtrip(topology: Topology) {
        let _guard = gateway_test_guard();
        let work_dir = std::env::temp_dir().join(format!(
            "seshat-gw-test-{}-{topology:?}",
            std::process::id()
        ));
        let Some(binary) = find_routing_capable_binary(&work_dir) else {
            eprintln!("skip: no gateway binary supports the routing provider");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };
        drive_roundtrip(&binary, &SecuritySpec::routing_tcp(), topology, &work_dir);
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    fn run_tls_roundtrip(topology: Topology) {
        let _guard = gateway_test_guard();
        let work_dir =
            std::env::temp_dir().join(format!("seshat-gw-tls-{}-{topology:?}", std::process::id()));
        let Some(binary) = find_routing_capable_binary(&work_dir) else {
            eprintln!("skip: no modern gateway binary available");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };
        if !crate::pki::openssl_available() {
            eprintln!("skip: openssl CLI not available for TLS certificates");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        }
        let id = crate::pki::generate_self_signed(&work_dir, 2).unwrap();
        let spec = SecuritySpec::tls_server("tls1.3", &id.cert, &id.key);
        drive_roundtrip(&binary, &spec, topology, &work_dir);
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    fn run_mtls_roundtrip(topology: Topology) {
        let _guard = gateway_test_guard();
        let work_dir = std::env::temp_dir().join(format!(
            "seshat-gw-mtls-{}-{topology:?}",
            std::process::id()
        ));
        let Some(binary) = find_routing_capable_binary(&work_dir) else {
            eprintln!("skip: no modern gateway binary available");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };
        if !crate::pki::openssl_available() {
            eprintln!("skip: openssl CLI not available for TLS certificates");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        }
        let bundle = crate::pki::generate_mtls_bundle(&work_dir, 2).unwrap();
        let spec = SecuritySpec::tls_mutual("tls1.3", &bundle);
        drive_roundtrip(&binary, &spec, topology, &work_dir);
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    fn run_integrity_only_roundtrip(topology: Topology) {
        let _guard = gateway_test_guard();
        let work_dir = std::env::temp_dir().join(format!(
            "seshat-gw-integ-{}-{topology:?}",
            std::process::id()
        ));
        let Some(binary) = find_routing_capable_binary(&work_dir) else {
            eprintln!("skip: no modern gateway binary available");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };
        if !crate::pki::openssl_available() {
            eprintln!("skip: openssl CLI not available for TLS certificates");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        }
        let id = crate::pki::generate_self_signed(&work_dir, 2).unwrap();
        // Integrity-only uses a NULL cipher (authenticated, not encrypted), which
        // is a TLS 1.2 construct in the gateway's profiles.
        let spec =
            SecuritySpec::tls_server("tls1.2", &id.cert, &id.key).with_profile("integrity-only");
        drive_roundtrip(&binary, &spec, topology, &work_dir);
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    #[test]
    fn routing_single_gateway_roundtrip() {
        run_echo_roundtrip(Topology::SingleGateway);
    }

    #[test]
    fn routing_scg_to_scg_roundtrip() {
        run_echo_roundtrip(Topology::ScgToScg);
    }

    #[test]
    fn tls_single_gateway_roundtrip() {
        run_tls_roundtrip(Topology::SingleGateway);
    }

    #[test]
    fn mtls_single_gateway_roundtrip() {
        run_mtls_roundtrip(Topology::SingleGateway);
    }

    #[test]
    fn integrity_only_single_gateway_roundtrip() {
        run_integrity_only_roundtrip(Topology::SingleGateway);
    }
}
