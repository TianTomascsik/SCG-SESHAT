//! Configuration schema (F-03..F-11).
//!
//! These `serde` types mirror the JSON config that *is* the experiment
//! specification: a suite header, execution defaults, and a list of scenarios.
//! Each scenario carries its transport/protocol/topology/impairment/streams and
//! optional hot-reload event. Unknown fields are rejected so typos surface as
//! precise errors during `validate`.
//!
//! This is a data model: many fields are populated by `serde` and consumed by
//! later phases (the execution engine, gateway config-gen, reporting), so
//! `dead_code` is allowed while the harness is built out.
#![allow(dead_code)]

use serde::Deserialize;

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
    /// System-metrics sample rate in Hz.
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
            metrics_sample_rate_hz: 1,
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
}

/// TLS/DTLS version (F-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum TlsVersion {
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
    /// Traffic class label.
    pub traffic_class: String,
    /// Expected DSCP tag after SCG processing (for DSCP manipulation tests).
    /// If `None`, the tag should be preserved unchanged.
    #[serde(default)]
    pub expected_dscp: Option<String>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
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
    /// Number of buffer slots.
    pub buffer_slots: Option<usize>,
    /// Buffer slot size.
    pub buffer_slot_size: Option<usize>,
    /// SHM ring capacity.
    pub shm_ring_capacity: Option<usize>,
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
        }
    }
}

impl TlsVersion {
    /// Version label, `1.2` or `1.3`.
    pub fn label(self) -> &'static str {
        match self {
            TlsVersion::V1_2 => "1.2",
            TlsVersion::V1_3 => "1.3",
        }
    }
}
