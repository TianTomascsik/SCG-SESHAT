//! Configuration schema (F-03..F-11).
//!
//! These `serde` types mirror the JSON config that *is* the experiment
//! specification: a suite header, execution defaults, and a list of scenarios.
//! Each scenario carries its transport/protocol/topology/impairment/streams and
//! optional hot-reload event. Unknown fields are rejected so typos surface as
//! precise errors during `validate`.
//!
//! This is a data model: many fields are populated by `serde` and consumed by
//! several consumers (the execution engine, gateway config-gen, reporting), so
//! `dead_code` is allowed while the harness is built out.
#![allow(dead_code)]

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub use crate::net::AddressFamily;

/// Top-level config document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema identifier (informational), e.g. `"seshat-config-v1"`.
    #[serde(rename = "$schema", default)]
    pub schema: Option<String>,
    /// Suite header.
    pub suite: Suite,
    /// Execution defaults applied to every scenario.
    #[serde(default)]
    pub defaults: Defaults,
    /// The scenarios to run.
    pub scenarios: Vec<Scenario>,
}

/// Human-readable suite header (F-03).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    /// Suite title (appears in every report).
    pub name: String,
    /// What the suite tests.
    #[serde(default)]
    pub description: String,
    /// Suite author.
    #[serde(default)]
    pub author: String,
    /// Semantic version of the config itself.
    pub version: String,
}

/// Execution defaults (F-04, plus F-13 metric controls).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// Repetitions per scenario.
    pub runs: u32,
    /// Measurement phase length in seconds.
    pub duration_secs: u64,
    /// Warmup phase length in seconds (discarded).
    pub warmup_secs: u64,
    /// Pause between runs in seconds.
    pub cooldown_secs: u64,
    /// CPU cores to pin sender threads to.
    pub cpu_affinity_sender: Vec<usize>,
    /// CPU cores to pin receiver threads to.
    pub cpu_affinity_receiver: Vec<usize>,
    /// CPU cores to pin the gateway (SCG) process(es) to. Empty = auto/unpinned.
    pub cpu_affinity_gateway: Vec<usize>,
    /// Auto-derive disjoint sender/receiver/gateway core pools from the host's
    /// logical CPUs when no affinity is configured, keeping the harness off the
    /// SCG's cores so it never becomes the measurement bottleneck (NFR-PERF).
    pub auto_affinity: bool,
    /// Per-scenario packet-loss budget (%). The saturation knee is the highest
    /// offered rate whose loss stays at or below this threshold.
    pub loss_threshold_pct: f64,
    /// Process name used to auto-detect the SCG PID.
    pub scg_process_name: String,
    /// Whether to collect `/proc`/`perf` system metrics.
    pub collect_system_metrics: bool,
    /// Outlier-removal strategy across runs.
    pub outlier_removal: OutlierRemoval,
    /// Confidence level for reported means (0,1).
    pub confidence_level: f64,
    /// System-metrics backend.
    pub metrics_backend: MetricsBackend,
    /// System-metrics sample rate in Hz. Drives the per-PID `/proc` timeseries
    /// (peak CPU and spike visibility); headline CPU/context-switch totals are
    /// derived from exact cumulative-counter deltas and are independent of it.
    pub metrics_sample_rate_hz: u32,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            runs: 5,
            duration_secs: 30,
            warmup_secs: 5,
            cooldown_secs: 2,
            cpu_affinity_sender: Vec::new(),
            cpu_affinity_receiver: Vec::new(),
            cpu_affinity_gateway: Vec::new(),
            auto_affinity: true,
            loss_threshold_pct: 1.0,
            scg_process_name: "gateway".to_string(),
            collect_system_metrics: true,
            outlier_removal: OutlierRemoval::Iqr,
            confidence_level: 0.95,
            metrics_backend: MetricsBackend::Procfs,
            // 50 Hz (20 ms) gives the timeseries enough resolution to catch
            // sub-second CPU/scheduling spikes; the headline totals are exact
            // regardless. Three tiny `/proc` reads per PID per tick stays well
            // off the measurement hot path (NFR-PERF).
            metrics_sample_rate_hz: 50,
        }
    }
}

/// Outlier-removal strategy (F-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum OutlierRemoval {
    #[serde(rename = "none")]
    None,
    #[default]
    #[serde(rename = "iqr")]
    Iqr,
    #[serde(rename = "percentile")]
    Percentile,
}

/// System-metrics backend (F-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum MetricsBackend {
    #[default]
    #[serde(rename = "procfs")]
    Procfs,
    #[serde(rename = "perf")]
    Perf,
    #[serde(rename = "ebpf")]
    Ebpf,
    #[serde(rename = "none")]
    None,
}

impl MetricsBackend {
    /// Stable lowercase label used in CLI output and result metadata.
    pub fn label(self) -> &'static str {
        match self {
            MetricsBackend::Procfs => "procfs",
            MetricsBackend::Perf => "perf",
            MetricsBackend::Ebpf => "ebpf",
            MetricsBackend::None => "none",
        }
    }
}

/// Traffic mode for a scenario (Phases F & G). `throughput` is the default
/// open-loop blast/pace; `pingpong` is the closed-loop request/echo round-trip
/// that reports RTT; `connrate` churns fresh connections and reports
/// connection-establishment rate and handshake latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Open-loop throughput (the default).
    #[default]
    Throughput,
    /// Closed-loop ping-pong RTT.
    Pingpong,
    /// Connection-establishment rate.
    Connrate,
}

/// A single benchmark scenario (F-05..F-11).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Unique scenario name.
    pub name: String,
    /// Free-form category label (e.g. `performance`, `scheduling`).
    #[serde(default)]
    pub category: Option<String>,
    /// Traffic mode: open-loop `throughput` (default) or closed-loop `pingpong`
    /// RTT (Phase F).
    #[serde(default)]
    pub mode: Mode,
    /// Whether the scenario is executed.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Reason shown when the scenario is disabled.
    #[serde(default)]
    pub disabled_reason: Option<String>,
    /// Total on-wire message size in bytes (includes the 24 B SESHAT header;
    /// payload is the remainder). Should be >= 24.
    #[serde(default)]
    pub message_size_bytes: Option<u32>,
    /// Number of parallel connections for the single-stream sender.
    #[serde(default = "default_connections")]
    pub connections: u32,
    /// Single-stream traffic source (mutually informative with `streams`).
    #[serde(default)]
    pub sender: Option<Sender>,
    /// Security/app protocol configuration.
    #[serde(default)]
    pub protocol: Protocol,
    /// Network topology.
    #[serde(default)]
    pub topology: Topology,
    /// IP address family (`ipv4` / `ipv6`) for this scenario's IP transports
    /// (TCP / UDP / TPROXY). Unix-domain and shared-memory interfaces ignore it.
    /// Defaults to IPv4.
    #[serde(default)]
    pub address_family: AddressFamily,
    /// Gateway chaining (direct baseline vs through the SCG).
    #[serde(default)]
    pub gateway: Gateway,
    /// Optional network impairment.
    #[serde(default)]
    pub network_impairment: Option<NetworkImpairment>,
    /// Multi-stream definition (scheduling scenarios, F-10).
    #[serde(default)]
    pub streams: Vec<Stream>,
    /// Optional hot-reload event (F-11).
    #[serde(default)]
    pub reload_event: Option<ReloadEvent>,
    /// SCG optimization toggles (Phase 5).
    #[serde(default)]
    pub optimization_flags: OptimizationFlags,
    /// Per-scenario override: repetitions.
    #[serde(default)]
    pub runs: Option<u32>,
    /// Per-scenario override: measurement seconds.
    #[serde(default)]
    pub duration_secs: Option<u64>,
    /// Per-scenario override: warmup seconds.
    #[serde(default)]
    pub warmup_secs: Option<u64>,
    /// Per-scenario override: cooldown seconds.
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    /// Optional saturation sweep (Phase D): when set, also sweep offered load.
    #[serde(default)]
    pub saturation: Option<Saturation>,
    /// Host capabilities required to execute this scenario.  Matrix generation
    /// uses this to make environment-dependent rows explicit instead of
    /// silently changing or dropping them at runtime.
    #[serde(default)]
    pub requirements: Requirements,
    /// Optional membership in a generated comparison group.  This is metadata
    /// for report consolidation; it does not alter the data-plane path.
    #[serde(default)]
    pub comparison: Option<Comparison>,
    /// Optional one-line human description, shown in the live progress and the
    /// per-scenario result line when `--describe` is set.  When absent,
    /// [`Scenario::describe`] composes a compact fallback from the scenario's
    /// own fields, so the description is never blank.
    #[serde(default)]
    pub description: Option<String>,
}

/// Runtime capabilities required by a scenario generated from the matrix.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Requirements {
    /// The OpenSSL command-line utility is needed for ephemeral certificates.
    pub openssl: bool,
    /// A usable Linux kTLS implementation is required (no userspace fallback).
    pub ktls: bool,
    /// The local OpenSSL build must permit DTLS 1.0.
    pub dtls10: bool,
    /// The process must have CAP_NET_ADMIN (TPROXY, veth, netns, tc).
    pub cap_net_admin: bool,
    /// The process must be allowed to collect perf events.
    pub perf: bool,
    /// An eBPF-capable environment is required for optional attribution.
    pub ebpf: bool,
}

/// Declarative metadata used to compare otherwise matched interface scenarios.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    /// Stable group identifier shared by matched scenarios.
    pub group: String,
    /// Reference scenario for the primary delta columns.
    pub reference: String,
    /// Optional gateway-only reference used to isolate endpoint overhead.
    #[serde(default)]
    pub gateway_reference: Option<String>,
    /// Throughput group used to derive a common paced latency offered load.
    #[serde(default)]
    pub calibration_group: Option<String>,
    /// Fraction of the lowest loss-free measured throughput used for the
    /// comparison's periodic latency runs.
    #[serde(default)]
    pub calibration_fraction: Option<f64>,
}

/// Single-stream traffic source (F-05 transport + F-07 pattern).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sender {
    /// Transport interface.
    pub interface: Interface,
    /// Destination address (format depends on `interface`).
    pub target_addr: String,
    /// Traffic pattern.
    #[serde(default)]
    pub pattern: Pattern,
    /// Optional rate limit in Mbit/s.
    #[serde(default)]
    pub rate_limit_mbps: Option<f64>,
    /// Inter-message interval for `periodic`.
    #[serde(default)]
    pub interval_us: Option<u64>,
    /// Messages per burst for `burst`.
    #[serde(default)]
    pub burst_count: Option<u64>,
    /// Pause between bursts for `burst`.
    #[serde(default)]
    pub burst_pause_us: Option<u64>,
    /// Ramp start rate in Mbit/s.
    #[serde(default)]
    pub ramp_start_mbps: Option<f64>,
    /// Ramp step in Mbit/s.
    #[serde(default)]
    pub ramp_step_mbps: Option<f64>,
    /// Ramp step interval in seconds.
    #[serde(default)]
    pub ramp_step_interval_secs: Option<u64>,
}

/// Saturation-sweep configuration (Phase D). When present on a scenario, the
/// scenario additionally runs an offered-load sweep (sustained at each rate)
/// to find where goodput saturates and where loss leaves the budget, written
/// to `saturation.csv` and surfaced as `saturation_gbps`/`max_lossfree_gbps`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saturation {
    /// First offered rate (Mbit/s).
    pub start_mbps: f64,
    /// Offered-rate increment between points (Mbit/s).
    pub step_mbps: f64,
    /// Last offered rate (inclusive, Mbit/s).
    pub max_mbps: f64,
}

/// Transport interface (F-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Interface {
    /// TCP socket.
    Tcp,
    /// UDP socket.
    Udp,
    /// Unix domain socket.
    Unix,
    /// Shared-memory ring buffer.
    Shm,
    /// Transparent proxy (TPROXY) — requires CAP_NET_ADMIN.
    Tproxy,
}

/// Traffic pattern (F-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pattern {
    /// Send as fast as possible.
    #[default]
    Sustained,
    /// One message every `interval_us`.
    Periodic,
    /// `burst_count` messages, pause, repeat.
    Burst,
    /// Ramp the offered load to find saturation.
    Ramp,
}

/// Security and application protocol (F-06, plus SCG kTLS/app-protocol adds).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    /// Base protocol type.
    #[serde(rename = "type", default)]
    pub kind: ProtocolType,
    /// TLS/DTLS version.
    #[serde(default)]
    pub version: TlsVersion,
    /// Use kernel TLS (kTLS) instead of userspace TLS.
    #[serde(default)]
    pub kernel: bool,
    /// Require mutual authentication (mTLS).
    #[serde(default)]
    pub mutual_auth: bool,
    /// Override cipher suite (e.g. AES-GCM vs ChaCha20).
    #[serde(default)]
    pub cipher_suite: Option<String>,
    /// Override the generated server cert's key algorithm (`rsa` or `ecdsa`),
    /// independent of the cipher suite — for the handshake-algorithm sweep that
    /// compares RSA-2048 vs ECDSA-P256 authentication cost. `None` keeps the
    /// cipher-derived default (TLS 1.3 / ECDHE-ECDSA → EC, ECDHE-RSA → RSA).
    #[serde(default)]
    pub cert_key_type: Option<String>,
    /// Override the ECDHE key-exchange named group (e.g. `X25519` / `P-256`) for
    /// the handshake-algorithm sweep's key-exchange axis. Passed to the gateway's
    /// `groups` provider-param, which allowlist-validates it. `None`
    /// leaves the gateway's default group set.
    #[serde(default)]
    pub kex_group: Option<String>,
    /// Protection depth.
    #[serde(default)]
    pub protection_mode: ProtectionMode,
    /// UDP-over-TLS application framing.
    #[serde(default)]
    pub app_protocol: AppProtocol,
    /// TLS profile name (e.g. `subset146-pki`, `subset146-psk`,
    /// `integrity-only`). When set, overrides the default profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// PSK identity for pre-shared key mode (subset146-psk).
    #[serde(default)]
    pub psk_identity: Option<String>,
    /// PSK hex-encoded key material.
    #[serde(default)]
    pub psk_hex: Option<String>,
    /// Enable TLS session resumption/tickets for reconnect-heavy scenarios.
    #[serde(default)]
    pub resumption: bool,
    /// Certificate material to use instead of SESHAT's generated benchmark PKI.
    #[serde(default)]
    pub certificates: CertificateSelection,
    /// Crypto-provider name for `type = "custom"` — passed through verbatim as
    /// the gateway rule's `security_provider`, so an out-of-tree provider (e.g.
    /// a proprietary one registered via `gateway::run`) can be benchmarked
    /// without SESHAT needing to know about it. Ignored for the built-in types.
    #[serde(default)]
    pub security_provider: Option<String>,
    /// Extra `provider_params` for `type = "custom"`, passed through verbatim to
    /// the gateway rule. Keys/values are provider-specific and opaque to SESHAT.
    #[serde(default)]
    pub provider_params: BTreeMap<String, ProviderParam>,
}

/// A single custom-provider parameter value. Deliberately limited to
/// string / integer / boolean so [`Protocol`] can stay `Eq`; each maps 1:1 onto
/// the gateway rule's JSON `provider_params`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProviderParam {
    /// Boolean flag (e.g. a toggle).
    Bool(bool),
    /// Integer (e.g. a window size in ms).
    Int(i64),
    /// String (e.g. a hex-encoded key or identity).
    Str(String),
}

impl ProviderParam {
    /// Convert to the JSON value the gateway rule expects.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ProviderParam::Bool(b) => serde_json::Value::Bool(*b),
            ProviderParam::Int(i) => serde_json::Value::from(*i),
            ProviderParam::Str(s) => serde_json::Value::String(s.clone()),
        }
    }
}

/// TLS/DTLS certificate material selected by a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertificateSelection {
    /// Decrypt-side/server certificate PEM.
    pub server_cert: Option<PathBuf>,
    /// Decrypt-side/server private key PEM.
    pub server_key: Option<PathBuf>,
    /// Encrypt-side/client certificate PEM for mutual TLS.
    pub client_cert: Option<PathBuf>,
    /// Encrypt-side/client private key PEM for mutual TLS.
    pub client_key: Option<PathBuf>,
    /// Trust anchor used for peer verification.
    pub ca_cert: Option<PathBuf>,
    /// SNI/hostname used by the TLS/DTLS connector.
    pub server_name: Option<String>,
}

impl CertificateSelection {
    /// Whether no certificate-related override was supplied.
    pub fn is_empty(&self) -> bool {
        self.server_cert.is_none()
            && self.server_key.is_none()
            && self.client_cert.is_none()
            && self.client_key.is_none()
            && self.ca_cert.is_none()
            && self.server_name.is_none()
    }

    /// Whether the selection contains a complete server identity.
    pub fn has_server_identity(&self) -> bool {
        self.server_cert.is_some() && self.server_key.is_some()
    }

    /// Whether the selection contains a complete mutual-TLS bundle.
    pub fn has_mutual_bundle(&self) -> bool {
        self.has_server_identity()
            && self.client_cert.is_some()
            && self.client_key.is_some()
            && self.ca_cert.is_some()
    }
}

/// Base protocol type (F-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum ProtocolType {
    /// No crypto — plaintext baseline / routing-only.
    #[default]
    #[serde(rename = "none")]
    None,
    /// TLS (userspace or kernel via `kernel=true`).
    #[serde(rename = "tls")]
    Tls,
    /// DTLS.
    #[serde(rename = "dtls")]
    Dtls,
    /// WireGuard (SCG stub — disabled).
    #[serde(rename = "wireguard")]
    Wireguard,
    /// IPSec/IKEv2 (SCG stub — disabled).
    #[serde(rename = "ipsec")]
    Ipsec,
    /// Out-of-tree custom crypto provider, named via `security_provider`.
    /// Lets internal/proprietary providers be benchmarked without SESHAT
    /// knowing their specifics.
    #[serde(rename = "custom")]
    Custom,
}

/// Security protocol version.  TLS supports 1.2/1.3; DTLS supports 1.0/1.2.
/// The semantic validator rejects invalid protocol/version pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum TlsVersion {
    /// DTLS 1.0 (invalid for TLS scenarios).
    #[serde(rename = "1.0")]
    V1_0,
    /// TLS 1.2.
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[default]
    #[serde(rename = "1.3")]
    V1_3,
}

/// Protection depth (F-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionMode {
    /// Full encryption + integrity.
    #[default]
    Full,
    /// MAC/integrity only (TLS NULL cipher).
    IntegrityOnly,
    /// Tunnel/routing only, no crypto.
    RoutingOnly,
}

/// UDP-over-TLS application framing (SCG `ale`/`raw`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum AppProtocol {
    /// Not applicable.
    #[default]
    #[serde(rename = "none")]
    None,
    /// Application-layer encapsulation (ALE).
    #[serde(rename = "ale")]
    Ale,
    /// Raw UDP-over-TLS framing.
    #[serde(rename = "raw")]
    Raw,
}

/// Network topology (F-08).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Topology {
    /// Topology mode.
    pub mode: TopologyMode,
    /// Auto-create the topology before running.
    pub auto_setup: bool,
    /// Left namespace name.
    pub left_namespace: String,
    /// Right namespace name.
    pub right_namespace: String,
    /// Left IP address.
    pub left_ip: String,
    /// Right IP address.
    pub right_ip: String,
    /// Subnet prefix length.
    pub subnet_mask: u8,
    /// Link MTU.
    pub mtu: u32,
}

impl Default for Topology {
    fn default() -> Self {
        Self {
            mode: TopologyMode::Loopback,
            auto_setup: false,
            left_namespace: "scg_left".to_string(),
            right_namespace: "scg_right".to_string(),
            left_ip: "10.0.0.1".to_string(),
            right_ip: "10.0.0.2".to_string(),
            subnet_mask: 24,
            mtu: 1500,
        }
    }
}

/// Topology mode (F-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TopologyMode {
    /// Same-host loopback (default).
    #[default]
    Loopback,
    /// Virtual ethernet pair.
    Veth,
    /// Network namespaces with routing.
    Netns,
    /// Real NIC.
    Physical,
    /// Two real hosts.
    Remote,
}

/// Gateway chaining: direct baseline vs through one or two SCGs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gateway {
    /// Route traffic through the SCG (false = direct loopback baseline).
    pub enabled: bool,
    /// Chain shape.
    pub chain: GatewayChain,
}

/// Gateway chain shape (metadata `topology` field: scg-direct / scg-scg).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayChain {
    /// client ↔ SCG ↔ client.
    #[default]
    ScgDirect,
    /// client ↔ SCG ↔ SCG ↔ client.
    ScgScg,
}

/// Network impairment (F-09).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkImpairment {
    /// Whether impairment is applied.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Interface/namespace endpoint to impair.
    pub apply_to: String,
    /// Added latency in milliseconds.
    #[serde(default)]
    pub latency_ms: f64,
    /// Latency jitter in milliseconds.
    #[serde(default)]
    pub jitter_ms: f64,
    /// Packet loss percentage.
    #[serde(default)]
    pub loss_percent: f64,
    /// Bandwidth limit in Mbit/s (0 = unlimited).
    #[serde(default)]
    pub bandwidth_limit_mbps: u32,
    /// Packet reorder percentage.
    #[serde(default)]
    pub reorder_percent: f64,
    /// Packet duplication percentage.
    #[serde(default)]
    pub duplicate_percent: f64,
}

/// One stream in a multi-stream scheduling scenario (F-10).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    /// Stream role label.
    pub role: StreamRole,
    /// Transport interface.
    pub interface: Interface,
    /// Destination address.
    pub target_addr: String,
    /// Parallel connections.
    #[serde(default = "default_connections")]
    pub connections: u32,
    /// Message payload size in bytes.
    pub message_size_bytes: u32,
    /// Traffic pattern.
    #[serde(default)]
    pub pattern: Pattern,
    /// Inter-message interval for `periodic`.
    #[serde(default)]
    pub interval_us: Option<u64>,
    /// Security protocol for this stream (overrides scenario-level default).
    #[serde(default)]
    pub protocol: Protocol,
    /// QoS priority.
    pub priority: Priority,
}

/// Stream role (F-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamRole {
    /// Safety-critical traffic.
    Safety,
    /// Bulk/low-priority traffic.
    Bulk,
    /// Monitoring traffic.
    Monitoring,
}

/// QoS priority (F-10).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Priority {
    /// DSCP tag (e.g. `EF`, `AF41`, `BE`, `CS0`..`CS7`).
    pub dscp_tag: String,
    /// Traffic class label (canonicalised via [`canonical_traffic_class`]).
    pub traffic_class: String,
    /// Expected DSCP tag after SCG processing (for DSCP manipulation tests).
    /// If `None`, the tag should be preserved unchanged.
    #[serde(default)]
    pub expected_dscp: Option<String>,
}

/// Map a user-facing traffic-class label to the gateway's canonical vocabulary
/// (`safety` | `normal`), or `None` when the label is unknown.
///
/// The gateway config only understands `safety`/`normal`, and the multi-stream
/// safety aggregates (loss-free / p99 verdicts) key on the canonical string, so
/// every label is funnelled through here at validation and at run wiring.
/// Accepted aliases (case-insensitive): `safety`, `safety-critical` → `safety`;
/// `normal`, `non-safety`, `bulk` → `normal`.
pub fn canonical_traffic_class(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "safety" | "safety-critical" => Some("safety"),
        "normal" | "non-safety" | "bulk" => Some("normal"),
        _ => None,
    }
}

/// Hot-reload event (F-11).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadEvent {
    /// When to fire the reload, in seconds into the measurement phase.
    pub trigger_at_secs: u64,
    /// gRPC management address.
    #[serde(default)]
    pub grpc_addr: Option<String>,
    /// Reload action.
    pub action: ReloadAction,
    /// Payload file for the action (e.g. a new TLS profile).
    #[serde(default)]
    pub payload_file: Option<String>,
    /// Assert zero connection drops.
    #[serde(default = "default_true")]
    pub expect_zero_drops: bool,
    /// Measurement window before the event, in seconds.
    #[serde(default)]
    pub measure_window_before_secs: u64,
    /// Measurement window after the event, in seconds.
    #[serde(default)]
    pub measure_window_after_secs: u64,
}

/// Reload action (F-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadAction {
    /// Change the TLS profile on an active connection.
    UpdateTlsProfile,
    /// Add a connection definition.
    AddConnection,
    /// Remove a connection definition.
    RemoveConnection,
    /// Rotate a certificate.
    RotateCert,
    /// Push an invalid config → verify rollback (gateway rejects, keeps running).
    InvalidConfig,
}

/// SCG optimization toggles written into the generated gateway config (Phase 5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OptimizationFlags {
    /// Enable the zero-copy relay path (routing/kTLS only).
    pub zero_copy: bool,
    /// Enable ring busy-poll before blocking.
    pub spin_wait: bool,
    /// Busy-poll budget in microseconds (implies `spin_wait`).
    pub spin_wait_us: Option<u64>,
    /// Socket buffer size override.
    pub sock_buf_size: Option<usize>,
    /// Splice pipe/chunk size override.
    pub pipe_size: Option<usize>,
    /// Userspace relay buffer size override.
    pub relay_buf_size: Option<usize>,
    /// TCP_NOTSENT_LOWAT override. A value of 0 disables it.
    pub notsent_lowat: Option<usize>,
    /// TCP SO_BUSY_POLL / pre-poll spin override in microseconds.
    pub busy_poll_us: Option<u32>,
    /// Enable latency-profile BDP-adaptive sizing.
    pub bdp_adaptive: bool,
    /// Target queueing budget for BDP-adaptive sizing.
    pub bdp_queue_budget_us: Option<u64>,
    /// Development-mode simulated per-hop network delay in milliseconds
    /// (geo-location / WAN latency simulation). Emitted onto the gateway rule
    /// as `simulated_delay_ms`; the gateway sleeps this long before each
    /// upstream send. `None`/`0` is a no-op (the key is omitted).
    pub simulated_delay_ms: Option<u64>,
    /// Number of buffer slots.
    pub buffer_slots: Option<usize>,
    /// Buffer slot size.
    pub buffer_slot_size: Option<usize>,
    /// SHM ring capacity.
    pub shm_ring_capacity: Option<usize>,
    /// SHM ring implementation: `byte_stream` (default) or `slot`.
    pub shm_ring_kind: Option<String>,
    /// Fixed slot size in bytes (slot ring only).
    pub shm_segment_size: Option<usize>,
    /// Number of slots per direction (slot ring only).
    pub shm_num_segments: Option<usize>,
    /// Slot-ring gateway→client wakeup: `eventfd` (default) or `futex`.
    pub shm_g2c_notify: Option<String>,
    /// Gateway performance profile written into the config: `throughput`,
    /// `latency`, or `balanced` (gateway default when unset).
    pub perf_profile: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_connections() -> u32 {
    1
}

impl Interface {
    /// Lowercase interface label for reports.
    pub fn label(self) -> &'static str {
        match self {
            Interface::Tcp => "tcp",
            Interface::Udp => "udp",
            Interface::Unix => "unix",
            Interface::Shm => "shm",
            Interface::Tproxy => "tproxy",
        }
    }
}

impl Scenario {
    /// Short protocol label for `list`, e.g. `tls/1.3`, `ktls/1.3`, `none`.
    /// Mutual auth and integrity-only paths gain a `+mtls` / `+integrity`
    /// suffix so otherwise-identical TLS rows stay distinguishable.
    pub fn protocol_label(&self) -> String {
        let p = &self.protocol;
        match p.kind {
            ProtocolType::None => "none".to_string(),
            ProtocolType::Tls => {
                let base = if p.kernel { "ktls" } else { "tls" };
                let mut label = format!("{base}/{}", p.version.label());
                if p.protection_mode == ProtectionMode::IntegrityOnly {
                    label.push_str("+integrity");
                } else if p.mutual_auth {
                    label.push_str("+mtls");
                }
                if p.resumption {
                    label.push_str("+resume");
                }
                label
            }
            ProtocolType::Dtls => {
                let mut label = format!("dtls/{}", p.version.label());
                if p.mutual_auth {
                    label.push_str("+mtls");
                }
                label
            }
            ProtocolType::Wireguard => "wireguard".to_string(),
            ProtocolType::Ipsec => "ipsec".to_string(),
            ProtocolType::Custom => self
                .protocol
                .security_provider
                .clone()
                .unwrap_or_else(|| "custom".to_string()),
        }
    }

    /// Interface label(s) for this scenario: the single-stream sender's
    /// interface, the sorted/deduped set of multi-stream interfaces, or `None`
    /// when the scenario has no sender (e.g. a not-yet-implemented path).
    pub fn interface_summary(&self) -> Option<String> {
        if let Some(sender) = &self.sender {
            Some(sender.interface.label().to_string())
        } else if !self.streams.is_empty() {
            let mut labels: Vec<&str> =
                self.streams.iter().map(|st| st.interface.label()).collect();
            labels.sort_unstable();
            labels.dedup();
            Some(labels.join("+"))
        } else {
            None
        }
    }

    /// One-line human description for the progress UI. Returns the explicit
    /// `description` when set; otherwise composes a compact summary from the
    /// mode, interface, protocol, message size, and connection count so the
    /// description is never blank.
    pub fn describe(&self) -> String {
        if let Some(desc) = &self.description {
            let trimmed = desc.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let mode = match self.mode {
            Mode::Throughput => "throughput",
            Mode::Pingpong => "round-trip",
            Mode::Connrate => "conn-rate",
        };
        let mut parts: Vec<String> = Vec::new();
        match self.interface_summary() {
            Some(iface) => parts.push(format!("{mode} · {iface} · {}", self.protocol_label())),
            None => parts.push(format!("{mode} · {}", self.protocol_label())),
        }
        if let Some(size) = self.message_size_bytes {
            parts.push(fmt_bytes(size));
        }
        parts.push(format!(
            "{} conn{}",
            self.connections,
            if self.connections == 1 { "" } else { "s" }
        ));
        parts.join(" · ")
    }
}

/// Compact byte size for scenario descriptions (`1 KB`, `1.4 KB`, `512 B`).
fn fmt_bytes(n: u32) -> String {
    if n >= 1024 && n.is_multiple_of(1024) {
        format!("{} KB", n / 1024)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

impl TlsVersion {
    /// Version label used in scenario and report names.
    pub fn label(self) -> &'static str {
        match self {
            TlsVersion::V1_0 => "1.0",
            TlsVersion::V1_2 => "1.2",
            TlsVersion::V1_3 => "1.3",
        }
    }
}

impl ProtocolType {
    /// Lowercase protocol-kind label for validation messages and reports.
    pub fn label(self) -> &'static str {
        match self {
            ProtocolType::None => "none",
            ProtocolType::Tls => "tls",
            ProtocolType::Dtls => "dtls",
            ProtocolType::Wireguard => "wireguard",
            ProtocolType::Ipsec => "ipsec",
            ProtocolType::Custom => "custom",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(json: &str) -> Scenario {
        serde_json::from_str(json).expect("scenario parses")
    }

    #[test]
    fn canonical_traffic_class_accepts_known_aliases() {
        assert_eq!(canonical_traffic_class("safety"), Some("safety"));
        assert_eq!(canonical_traffic_class("Safety-Critical"), Some("safety"));
        assert_eq!(canonical_traffic_class("  SAFETY  "), Some("safety"));
        assert_eq!(canonical_traffic_class("normal"), Some("normal"));
        assert_eq!(canonical_traffic_class("non-safety"), Some("normal"));
        assert_eq!(canonical_traffic_class("Bulk"), Some("normal"));
    }

    #[test]
    fn canonical_traffic_class_rejects_unknown_labels() {
        assert_eq!(canonical_traffic_class(""), None);
        assert_eq!(canonical_traffic_class("critical"), None);
        assert_eq!(canonical_traffic_class("safety critical"), None);
        assert_eq!(canonical_traffic_class("low"), None);
    }

    #[test]
    fn describe_prefers_explicit_text_trimmed() {
        let s = scenario(
            r#"{"name":"x","description":"  hand written  ",
                "sender":{"interface":"tcp","target_addr":"127.0.0.1:1"}}"#,
        );
        assert_eq!(s.describe(), "hand written");
    }

    #[test]
    fn describe_falls_back_to_composed_summary() {
        let s = scenario(
            r#"{"name":"x","message_size_bytes":1024,"connections":4,
                "sender":{"interface":"tcp","target_addr":"127.0.0.1:1"}}"#,
        );
        let d = s.describe();
        assert!(d.contains("throughput"), "got {d}");
        assert!(d.contains("tcp"), "got {d}");
        assert!(d.contains("1 KB"), "got {d}");
        assert!(d.contains("4 conns"), "got {d}");
    }

    #[test]
    fn describe_singular_connection_and_small_size() {
        let s = scenario(
            r#"{"name":"x","message_size_bytes":64,"connections":1,
                "sender":{"interface":"udp","target_addr":"127.0.0.1:1"}}"#,
        );
        let d = s.describe();
        assert!(d.contains("64 B"), "got {d}");
        assert!(d.ends_with("1 conn"), "got {d}");
        assert!(d.contains("udp"), "got {d}");
    }

    #[test]
    fn blank_explicit_description_uses_fallback() {
        let s = scenario(
            r#"{"name":"x","description":"   ","connections":2,
                "sender":{"interface":"tcp","target_addr":"127.0.0.1:1"}}"#,
        );
        assert!(s.describe().contains("2 conns"));
    }
}
