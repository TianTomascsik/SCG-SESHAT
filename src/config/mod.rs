//! Configuration loading and validation.
//!
//! [`load`] reads and parses a JSON config; [`validate`] runs semantic checks
//! and returns a structured [`ValidationReport`] that the `validate`, `list`,
//! and `run --dry-run` commands render. Validation is intentionally strict so
//! mistakes surface before any benchmark executes.

pub mod schema;

pub use schema::*;

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

/// An error loading or parsing a config file.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Read and parse a JSON config file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("cannot read config '{}': {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| ConfigError(format!("invalid config '{}': {e}", path.display())))
}

/// Per-scenario validation outcome.
#[derive(Debug, Default)]
pub struct ScenarioReport {
    /// Scenario name.
    pub name: String,
    /// Whether the scenario is enabled.
    pub enabled: bool,
    /// Hard errors (block execution).
    pub errors: Vec<String>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Informational notes (e.g. nested stream/reload summaries).
    pub notes: Vec<String>,
}

impl ScenarioReport {
    /// Whether the scenario passed validation.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Full validation result for a config.
#[derive(Debug, Default)]
pub struct ValidationReport {
    /// Suite-level errors (e.g. duplicate names).
    pub suite_errors: Vec<String>,
    /// Per-scenario reports.
    pub scenarios: Vec<ScenarioReport>,
}

impl ValidationReport {
    /// Whether the whole config is valid.
    pub fn ok(&self) -> bool {
        self.suite_errors.is_empty() && self.scenarios.iter().all(ScenarioReport::ok)
    }

    /// Count of enabled scenarios.
    pub fn enabled_count(&self) -> usize {
        self.scenarios.iter().filter(|s| s.enabled).count()
    }

    /// Total scenario count.
    pub fn total_count(&self) -> usize {
        self.scenarios.len()
    }
}

/// Validate a parsed config and return a structured report.
pub fn validate(config: &Config) -> ValidationReport {
    let mut report = ValidationReport::default();

    if config.suite.name.trim().is_empty() {
        report.suite_errors.push("suite.name is empty".to_string());
    }
    if config.suite.version.trim().is_empty() {
        report
            .suite_errors
            .push("suite.version is empty".to_string());
    }

    let d = &config.defaults;
    if d.runs == 0 {
        report
            .suite_errors
            .push("defaults.runs must be >= 1".to_string());
    }
    if !(0.0..1.0).contains(&d.confidence_level) || d.confidence_level <= 0.0 {
        report
            .suite_errors
            .push("defaults.confidence_level must be in (0, 1)".to_string());
    }
    if d.metrics_sample_rate_hz == 0 {
        report
            .suite_errors
            .push("defaults.metrics_sample_rate_hz must be >= 1".to_string());
    }

    // Duplicate scenario names.
    let mut seen = std::collections::HashSet::new();
    for s in &config.scenarios {
        if !seen.insert(s.name.as_str()) {
            report
                .suite_errors
                .push(format!("duplicate scenario name '{}'", s.name));
        }
    }

    for s in &config.scenarios {
        report.scenarios.push(validate_scenario(s));
    }

    report
}

fn validate_scenario(s: &Scenario) -> ScenarioReport {
    let mut r = ScenarioReport {
        name: s.name.clone(),
        enabled: s.enabled,
        ..Default::default()
    };

    if s.name.trim().is_empty() {
        r.errors.push("name is empty".to_string());
    }

    if !s.enabled {
        let reason = s
            .disabled_reason
            .clone()
            .unwrap_or_else(|| "disabled".to_string());
        r.notes.push(format!("SKIP ({reason})"));
        return r;
    }

    let has_sender = s.sender.is_some();
    let has_streams = !s.streams.is_empty();
    if !has_sender && !has_streams {
        r.errors
            .push("scenario needs a `sender` or at least one `streams` entry".to_string());
    }

    // WireGuard is a kernel-offload SCG crypto provider over UDP datagrams.
    // IPSec is still an SCG stub and must be disabled.
    match s.protocol.kind {
        ProtocolType::Wireguard => {
            // The gateway provisions a kernel `wg` interface and relays UDP
            // datagrams through it, so WireGuard scenarios must use the UDP
            // interface (as DTLS does).
            if let Some(snd) = s.sender.as_ref() {
                if snd.interface != Interface::Udp {
                    r.errors
                        .push("protocol.type=wireguard requires sender.interface=udp".to_string());
                }
            }
        }
        ProtocolType::Ipsec => r
            .errors
            .push("protocol.type=ipsec is an SCG stub; set enabled=false (see WP6.1)".to_string()),
        _ => {}
    }

    // kTLS requires TLS.
    if s.protocol.kernel && s.protocol.kind != ProtocolType::Tls {
        r.errors
            .push("protocol.kernel=true (kTLS) requires protocol.type=tls".to_string());
    }

    // Single-stream sender checks.
    if let Some(sender) = &s.sender {
        validate_addr(
            sender.interface,
            &sender.target_addr,
            "sender.target_addr",
            &mut r,
        );
        validate_pattern(sender, &mut r);
        validate_transport_needs_gateway(sender.interface, &s.gateway, &mut r);
        validate_protocol_transport(s, sender.interface, &mut r);
    }

    // Latency scenarios must be paced sub-saturation: an unthrottled sustained
    // sender fills the buffers and measures bufferbloat, not the gateway's
    // per-message processing latency.
    if is_latency_category(s.category.as_deref()) {
        if let Some(sender) = &s.sender {
            if sender.pattern == Pattern::Sustained && sender.rate_limit_mbps.is_none() {
                r.warnings.push(
                    "category=latency with an unthrottled sustained sender measures \
                     bufferbloat, not gateway latency; use a periodic pattern \
                     (interval_us) or set sender.rate_limit_mbps well below saturation"
                        .to_string(),
                );
            }
        }
    }

    // Saturation sweep grid sanity (Phase D).
    if let Some(sat) = &s.saturation {
        let finite =
            sat.start_mbps.is_finite() && sat.step_mbps.is_finite() && sat.max_mbps.is_finite();
        if !finite {
            r.errors
                .push("saturation rates must be finite numbers".to_string());
        } else {
            if sat.start_mbps <= 0.0 {
                r.errors
                    .push("saturation.start_mbps must be > 0".to_string());
            }
            if sat.step_mbps <= 0.0 {
                r.errors
                    .push("saturation.step_mbps must be > 0".to_string());
            }
            if sat.max_mbps < sat.start_mbps {
                r.errors
                    .push("saturation.max_mbps must be >= saturation.start_mbps".to_string());
            }
        }
    }

    // Multi-stream checks.
    for (i, stream) in s.streams.iter().enumerate() {
        let ctx = format!("streams[{i}].target_addr");
        validate_addr(stream.interface, &stream.target_addr, &ctx, &mut r);
        validate_transport_needs_gateway(stream.interface, &s.gateway, &mut r);
        if stream.message_size_bytes == 0 {
            r.errors
                .push(format!("streams[{i}].message_size_bytes must be > 0"));
        }
        if stream.pattern == Pattern::Periodic && stream.interval_us.is_none() {
            r.errors
                .push(format!("streams[{i}] periodic pattern needs interval_us"));
        }
        validate_dscp(&stream.priority.dscp_tag, &format!("streams[{i}]"), &mut r);

        // The multi-stream scheduler provisions per-class TCP pairs through the
        // gateway; anything it cannot honour must fail validation rather than
        // silently run something else than the config claims.
        if canonical_traffic_class(&stream.priority.traffic_class).is_none() {
            r.errors.push(format!(
                "streams[{i}].priority.traffic_class '{}' is not recognised; use \
                 safety|safety-critical or normal|non-safety|bulk",
                stream.priority.traffic_class
            ));
        }
        if stream.interface != Interface::Tcp {
            r.errors.push(format!(
                "streams[{i}].interface must be tcp (multi-stream scheduling runs \
                 over the gateway's TCP path; got {})",
                stream.interface.label()
            ));
        }
        if stream.connections != 1 {
            r.errors.push(format!(
                "streams[{i}].connections must be 1 (the scheduler opens exactly one \
                 connection per stream; add more streams instead)"
            ));
        }
        if stream.protocol.kind != ProtocolType::None && stream.protocol.kind != s.protocol.kind {
            r.warnings.push(format!(
                "streams[{i}].protocol ({}) differs from the scenario protocol ({}); \
                 per-stream protocol overrides are not supported — the scenario-level \
                 protocol applies to every stream",
                stream.protocol.kind.label(),
                s.protocol.kind.label()
            ));
        }
    }
    if has_streams {
        if !s.gateway.enabled {
            r.errors.push(
                "multi-stream scenarios require gateway.enabled=true (streams are \
                 scheduled through per-class gateway rules)"
                    .to_string(),
            );
        }
        if matches!(
            s.protocol.kind,
            ProtocolType::Dtls | ProtocolType::Wireguard | ProtocolType::Ipsec
        ) {
            r.errors.push(format!(
                "multi-stream scenarios support TCP-based protocols only \
                 (none/tls/mtls/integrity-only); got {}",
                s.protocol.kind.label()
            ));
        }
        r.notes.push(format!("streams: {}", s.streams.len()));
    }

    // Zero-copy is only meaningful for routing-only or kTLS paths.
    if s.optimization_flags.zero_copy {
        let routing = s.protocol.protection_mode == ProtectionMode::RoutingOnly
            || s.protocol.kind == ProtocolType::None;
        let ktls = s.protocol.kernel;
        if !routing && !ktls {
            r.errors.push(
                "optimization_flags.zero_copy requires routing-only or kTLS (userspace TLS cannot be zero-copy)"
                    .to_string(),
            );
        }
    }

    // Performance profile must be one of the gateway's known values.
    if let Some(profile) = &s.optimization_flags.perf_profile {
        if !matches!(profile.as_str(), "throughput" | "latency" | "balanced") {
            r.errors.push(format!(
                "optimization_flags.perf_profile '{profile}' is invalid (expected throughput, latency, or balanced)"
            ));
        }
    }

    if s.protocol.resumption && s.protocol.kind != ProtocolType::Tls {
        r.errors
            .push("protocol.resumption is only valid for TLS/kTLS scenarios".to_string());
    }

    validate_certificate_selection(s, &mut r);

    // Hot-reload needs the gateway.
    if let Some(reload) = &s.reload_event {
        if !s.gateway.enabled {
            r.errors
                .push("reload_event requires gateway.enabled=true".to_string());
        }
        // RotateCert stages its own swap identity at run time and needs no
        // payload_file; only the (still no-op) profile update warns.
        if matches!(reload.action, ReloadAction::UpdateTlsProfile) && reload.payload_file.is_none()
        {
            r.warnings.push(format!(
                "reload_event action {:?} usually needs a payload_file",
                reload.action
            ));
        }
        r.notes.push(format!("reload_event: {:?}", reload.action));
    }

    // Topology that needs setup.
    if matches!(s.topology.mode, TopologyMode::Veth | TopologyMode::Netns) && !s.topology.auto_setup
    {
        r.warnings.push(format!(
            "topology.mode={:?} but auto_setup=false (run `seshat setup` first)",
            s.topology.mode
        ));
    }

    r
}

fn validate_certificate_selection(s: &Scenario, r: &mut ScenarioReport) {
    let certs = &s.protocol.certificates;
    if certs.is_empty() {
        return;
    }

    if !matches!(s.protocol.kind, ProtocolType::Tls | ProtocolType::Dtls) {
        r.errors.push(
            "protocol.certificates is only valid for TLS, kTLS, or DTLS scenarios".to_string(),
        );
    }

    match (&certs.server_cert, &certs.server_key) {
        (Some(_), None) => r
            .errors
            .push("protocol.certificates.server_cert requires server_key".to_string()),
        (None, Some(_)) => r
            .errors
            .push("protocol.certificates.server_key requires server_cert".to_string()),
        _ => {}
    }

    match (&certs.client_cert, &certs.client_key) {
        (Some(_), None) => r
            .errors
            .push("protocol.certificates.client_cert requires client_key".to_string()),
        (None, Some(_)) => r
            .errors
            .push("protocol.certificates.client_key requires client_cert".to_string()),
        _ => {}
    }

    let pki_profile = s.protocol.profile.as_deref() == Some("subset146-pki");
    let has_path_material = certs.server_cert.is_some()
        || certs.server_key.is_some()
        || certs.client_cert.is_some()
        || certs.client_key.is_some()
        || certs.ca_cert.is_some();
    if (s.protocol.mutual_auth || pki_profile) && has_path_material {
        if !certs.has_mutual_bundle() {
            r.errors.push(
                "protocol.certificates for mutual TLS/subset146-pki must include \
                 server_cert, server_key, client_cert, client_key, and ca_cert"
                    .to_string(),
            );
        }
    } else if certs.client_cert.is_some() || certs.client_key.is_some() {
        r.warnings.push(
            "protocol.certificates.client_cert/client_key are ignored unless mutual_auth=true"
                .to_string(),
        );
    }
}

fn validate_addr(interface: Interface, addr: &str, ctx: &str, r: &mut ScenarioReport) {
    match interface {
        Interface::Tcp | Interface::Udp => {
            if addr.parse::<SocketAddr>().is_err() {
                // Accept host:port where host is a name and port is numeric.
                let ok = addr
                    .rsplit_once(':')
                    .map(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
                    .unwrap_or(false);
                if !ok {
                    r.errors
                        .push(format!("{ctx}: '{addr}' is not a valid host:port"));
                }
            }
        }
        Interface::Unix => {
            if !addr.starts_with('/') {
                r.errors
                    .push(format!("{ctx}: unix socket path must be absolute"));
            }
        }
        Interface::Shm => {
            let name = addr.strip_prefix("shm:///");
            if name.map(str::is_empty).unwrap_or(true) {
                r.errors
                    .push(format!("{ctx}: shm address must be 'shm:///<name>'"));
            }
        }
        Interface::Tproxy => {
            // TPROXY uses a standard TCP address for the redirect target.
            if addr.parse::<SocketAddr>().is_err() {
                let ok = addr
                    .rsplit_once(':')
                    .map(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
                    .unwrap_or(false);
                if !ok {
                    r.errors
                        .push(format!("{ctx}: tproxy address must be a valid host:port"));
                }
            }
        }
    }
}

/// Whether a scenario's category marks it as a latency measurement.
fn is_latency_category(category: Option<&str>) -> bool {
    category
        .map(|c| c.eq_ignore_ascii_case("latency"))
        .unwrap_or(false)
}

fn validate_pattern(sender: &Sender, r: &mut ScenarioReport) {
    match sender.pattern {
        Pattern::Sustained => {}
        Pattern::Periodic => {
            if sender.interval_us.is_none() {
                r.errors
                    .push("sender periodic pattern needs interval_us".to_string());
            }
        }
        Pattern::Burst => {
            if sender.burst_count.is_none() {
                r.errors
                    .push("sender burst pattern needs burst_count".to_string());
            }
        }
        Pattern::Ramp => {
            if sender.ramp_start_mbps.is_none()
                || sender.ramp_step_mbps.is_none()
                || sender.ramp_step_interval_secs.is_none()
            {
                r.errors.push(
                    "sender ramp pattern needs ramp_start_mbps, ramp_step_mbps, ramp_step_interval_secs"
                        .to_string(),
                );
            }
        }
    }
}

fn validate_transport_needs_gateway(
    interface: Interface,
    gateway: &Gateway,
    r: &mut ScenarioReport,
) {
    if matches!(interface, Interface::Unix | Interface::Shm) && !gateway.enabled {
        r.errors.push(format!(
            "interface={} requires gateway.enabled=true (provisioned via the gRPC management API)",
            interface.label()
        ));
    }
}

fn validate_protocol_transport(s: &Scenario, interface: Interface, r: &mut ScenarioReport) {
    match s.protocol.kind {
        ProtocolType::Tls if s.protocol.version == TlsVersion::V1_0 => r
            .errors
            .push("protocol.type=tls does not support version=1.0".to_string()),
        ProtocolType::Dtls if s.protocol.version == TlsVersion::V1_3 => r
            .errors
            .push("protocol.type=dtls supports version=1.0 or version=1.2".to_string()),
        _ => {}
    }
    // DTLS is a datagram protocol — UDP only.
    if s.protocol.kind == ProtocolType::Dtls && interface != Interface::Udp {
        r.errors.push(format!(
            "protocol.type=dtls requires a udp interface (got {})",
            interface.label()
        ));
    }
    // ALE/RAW app-protocol framing is UDP-over-TLS.
    if s.protocol.app_protocol != AppProtocol::None {
        if interface != Interface::Udp {
            r.errors
                .push("protocol.app_protocol (ale/raw) requires a udp interface".to_string());
        }
        if s.protocol.kind != ProtocolType::Tls {
            r.errors
                .push("protocol.app_protocol (ale/raw) requires protocol.type=tls".to_string());
        }
    }

    if let Some(comparison) = &s.comparison {
        if comparison.group.trim().is_empty() || comparison.reference.trim().is_empty() {
            r.errors
                .push("comparison.group and comparison.reference must be non-empty".to_string());
        }
    }
}

const KNOWN_DSCP: &[&str] = &[
    "EF", "BE", "AF11", "AF12", "AF13", "AF21", "AF22", "AF23", "AF31", "AF32", "AF33", "AF41",
    "AF42", "AF43", "CS0", "CS1", "CS2", "CS3", "CS4", "CS5", "CS6", "CS7",
];

fn validate_dscp(tag: &str, ctx: &str, r: &mut ScenarioReport) {
    if !KNOWN_DSCP.contains(&tag) {
        r.warnings.push(format!("{ctx}: unknown DSCP tag '{tag}'"));
    }
}

/// Effective per-run wall time for a scenario, honouring overrides.
pub fn scenario_run_secs(s: &Scenario, d: &Defaults) -> u64 {
    let warmup = s.warmup_secs.unwrap_or(d.warmup_secs);
    let duration = s.duration_secs.unwrap_or(d.duration_secs);
    let cooldown = s.cooldown_secs.unwrap_or(d.cooldown_secs);
    warmup + duration + cooldown
}

/// Effective repetition count for a scenario.
pub fn scenario_runs(s: &Scenario, d: &Defaults) -> u32 {
    s.runs.unwrap_or(d.runs)
}

/// Total estimated wall time (seconds) for all enabled scenarios.
pub fn estimate_total_secs(config: &Config) -> u64 {
    config
        .scenarios
        .iter()
        .filter(|s| s.enabled)
        .map(|s| scenario_run_secs(s, &config.defaults) * scenario_runs(s, &config.defaults) as u64)
        .sum()
}

/// Format a number of seconds as `2h 25m 35s` (omitting leading zero units).
pub fn human_secs(total: u64) -> String {
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h "));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m "));
    }
    out.push_str(&format!("{s}s"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Config {
        serde_json::from_str(json).expect("parse")
    }

    const MINIMAL: &str = r#"{
        "suite": { "name": "t", "version": "1.0.0" },
        "scenarios": [
            { "name": "tcp_baseline", "message_size_bytes": 1400,
              "sender": { "interface": "tcp", "target_addr": "127.0.0.1:10000" } }
        ]
    }"#;

    #[test]
    fn minimal_config_is_valid() {
        let cfg = parse(MINIMAL);
        let rep = validate(&cfg);
        assert!(rep.ok(), "expected valid, got {:?}", rep);
        assert_eq!(rep.enabled_count(), 1);
    }

    #[test]
    fn defaults_are_applied() {
        let cfg = parse(MINIMAL);
        assert_eq!(cfg.defaults.runs, 5);
        assert_eq!(cfg.defaults.duration_secs, 30);
        assert_eq!(cfg.defaults.scg_process_name, "gateway");
    }

    #[test]
    fn duplicate_names_rejected() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "dup", "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } },
                  { "name": "dup", "sender": { "interface": "tcp", "target_addr": "127.0.0.1:2" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.suite_errors.iter().any(|e| e.contains("duplicate")));
    }

    #[test]
    fn shm_without_gateway_rejected() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "shm", "sender": { "interface": "shm", "target_addr": "shm:///r" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("gateway.enabled=true")));
    }

    #[test]
    fn wireguard_enabled_accepted() {
        // WireGuard is now a real kernel-offload provider over UDP.
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "wg", "gateway": { "enabled": true },
                    "protocol": { "type": "wireguard" },
                    "sender": { "interface": "udp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        assert!(validate(&cfg).ok());
    }

    #[test]
    fn wireguard_non_udp_rejected() {
        // WireGuard is datagram-only; a TCP sender is a configuration error.
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "wg", "gateway": { "enabled": true },
                    "protocol": { "type": "wireguard" },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        assert!(!validate(&cfg).ok());
    }

    /// A syntactically complete multi-stream scenario the stream-validation
    /// tests below perturb one field at a time.
    fn multistream_json(streams: &str, protocol: &str, gateway_enabled: bool) -> String {
        format!(
            r#"{{ "suite": {{ "name": "t", "version": "1" }}, "scenarios": [
                {{ "name": "ms", "gateway": {{ "enabled": {gateway_enabled} }},
                   "protocol": {protocol},
                   "streams": [{streams}] }}
            ] }}"#
        )
    }

    const SAFETY_STREAM: &str = r#"{ "role": "safety", "interface": "tcp",
        "target_addr": "127.0.0.1:1", "message_size_bytes": 256,
        "priority": { "dscp_tag": "EF", "traffic_class": "safety" } }"#;

    #[test]
    fn multistream_canonical_and_alias_classes_accepted() {
        let bulk = r#"{ "role": "bulk", "interface": "tcp",
            "target_addr": "127.0.0.1:1", "message_size_bytes": 1024,
            "priority": { "dscp_tag": "BE", "traffic_class": "non-safety" } }"#;
        let cfg = parse(&multistream_json(
            &format!("{SAFETY_STREAM}, {bulk}"),
            r#"{ "type": "none" }"#,
            true,
        ));
        let rep = validate(&cfg);
        assert!(rep.ok(), "expected valid, got {rep:?}");
    }

    #[test]
    fn multistream_unknown_class_rejected() {
        let bad = r#"{ "role": "bulk", "interface": "tcp",
            "target_addr": "127.0.0.1:1", "message_size_bytes": 1024,
            "priority": { "dscp_tag": "BE", "traffic_class": "low" } }"#;
        let cfg = parse(&multistream_json(bad, r#"{ "type": "none" }"#, true));
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("traffic_class 'low'")));
    }

    #[test]
    fn multistream_non_tcp_interface_rejected() {
        let udp = r#"{ "role": "safety", "interface": "udp",
            "target_addr": "127.0.0.1:1", "message_size_bytes": 256,
            "priority": { "dscp_tag": "EF", "traffic_class": "safety" } }"#;
        let cfg = parse(&multistream_json(udp, r#"{ "type": "none" }"#, true));
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("interface must be tcp")));
    }

    #[test]
    fn multistream_multi_connection_stream_rejected() {
        let multi = r#"{ "role": "bulk", "interface": "tcp",
            "target_addr": "127.0.0.1:1", "connections": 32, "message_size_bytes": 1024,
            "priority": { "dscp_tag": "BE", "traffic_class": "normal" } }"#;
        let cfg = parse(&multistream_json(multi, r#"{ "type": "none" }"#, true));
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("connections must be 1")));
    }

    #[test]
    fn multistream_requires_gateway_and_tcp_protocol() {
        let no_gw = parse(&multistream_json(
            SAFETY_STREAM,
            r#"{ "type": "none" }"#,
            false,
        ));
        let rep = validate(&no_gw);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("require gateway.enabled=true")));

        let dtls = parse(&multistream_json(
            SAFETY_STREAM,
            r#"{ "type": "dtls", "version": "1.2" }"#,
            true,
        ));
        let rep = validate(&dtls);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("TCP-based protocols only")));
    }

    #[test]
    fn multistream_per_stream_protocol_mismatch_warns() {
        let tls_stream = r#"{ "role": "safety", "interface": "tcp",
            "target_addr": "127.0.0.1:1", "message_size_bytes": 256,
            "protocol": { "type": "tls", "version": "1.3" },
            "priority": { "dscp_tag": "EF", "traffic_class": "safety" } }"#;
        let cfg = parse(&multistream_json(tls_stream, r#"{ "type": "none" }"#, true));
        let rep = validate(&cfg);
        assert!(rep.ok(), "mismatch is a warning, not an error: {rep:?}");
        assert!(rep.scenarios[0]
            .warnings
            .iter()
            .any(|w| w.contains("per-stream protocol overrides are not supported")));
    }

    #[test]
    fn dtls10_is_accepted_but_tls10_is_rejected() {
        let dtls = parse(
            r#"{ "suite": { "name": "t", "version": "1" }, "scenarios": [
                { "name": "dtls10", "gateway": { "enabled": true },
                  "protocol": { "type": "dtls", "version": "1.0" },
                  "sender": { "interface": "udp", "target_addr": "127.0.0.1:1" } }
            ] }"#,
        );
        assert!(validate(&dtls).ok());

        let tls = parse(
            r#"{ "suite": { "name": "t", "version": "1" }, "scenarios": [
                { "name": "tls10", "gateway": { "enabled": true },
                  "protocol": { "type": "tls", "version": "1.0" },
                  "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
            ] }"#,
        );
        assert!(!validate(&tls).ok());
    }

    #[test]
    fn disabled_scenario_skips_deep_checks() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "wg", "enabled": false, "disabled_reason": "SCG support pending",
                    "protocol": { "type": "wireguard" },
                    "sender": { "interface": "udp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(rep.ok());
        assert!(rep.scenarios[0].notes.iter().any(|n| n.contains("SKIP")));
    }

    #[test]
    fn zero_copy_userspace_tls_rejected() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "zc", "gateway": { "enabled": true },
                    "protocol": { "type": "tls" },
                    "optimization_flags": { "zero_copy": true },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("zero_copy")));
    }

    #[test]
    fn latency_sustained_without_rate_warns() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "lat", "category": "latency",
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1",
                                "pattern": "sustained" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        // A warning, not an error: the run still executes but the methodology
        // is flagged.
        assert!(rep.ok(), "expected valid with warning, got {:?}", rep);
        assert!(rep.scenarios[0]
            .warnings
            .iter()
            .any(|w| w.contains("bufferbloat")));
    }

    #[test]
    fn latency_periodic_does_not_warn() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "lat", "category": "latency",
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1",
                                "pattern": "periodic", "interval_us": 500 } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(rep.ok());
        assert!(!rep.scenarios[0]
            .warnings
            .iter()
            .any(|w| w.contains("bufferbloat")));
    }

    #[test]
    fn saturation_valid_grid_accepted() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "sat", "saturation": { "start_mbps": 100, "step_mbps": 100, "max_mbps": 500 },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(rep.ok(), "expected valid grid, got {:?}", rep);
    }

    #[test]
    fn saturation_bad_grid_rejected() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "sat", "saturation": { "start_mbps": 0, "step_mbps": 0, "max_mbps": 50 },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("start_mbps")));
    }

    #[test]
    fn tls_resumption_flag_is_validated() {
        let tls = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "tls-resume", "protocol": { "type": "tls", "resumption": true },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        assert!(validate(&tls).ok());

        let plain = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "bad-resume", "protocol": { "type": "none", "resumption": true },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&plain);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("resumption")));
    }

    #[test]
    fn external_certificate_paths_validate_for_ktls() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "ktls-cert", "gateway": { "enabled": true },
                    "protocol": {
                      "type": "tls",
                      "kernel": true,
                      "certificates": {
                        "server_cert": "/certs/server.pem",
                        "server_key": "/certs/server.key"
                      }
                    },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        assert!(validate(&cfg).ok());
    }

    #[test]
    fn certificate_pairing_is_validated() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "bad-cert", "gateway": { "enabled": true },
                    "protocol": {
                      "type": "tls",
                      "certificates": { "server_cert": "/certs/server.pem" }
                    },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("server_cert requires server_key")));
    }

    #[test]
    fn mutual_certificate_selection_requires_complete_bundle() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "bad-mtls", "gateway": { "enabled": true },
                    "protocol": {
                      "type": "tls",
                      "mutual_auth": true,
                      "certificates": {
                        "server_cert": "/certs/server.pem",
                        "server_key": "/certs/server.key"
                      }
                    },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("mutual TLS")));
    }

    #[test]
    fn certificates_require_crypto_protocol() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "plain-cert",
                    "protocol": {
                      "type": "none",
                      "certificates": { "server_name": "localhost" }
                    },
                    "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
        assert!(rep.scenarios[0]
            .errors
            .iter()
            .any(|e| e.contains("TLS, kTLS, or DTLS")));
    }

    #[test]
    fn profile_regression_config_validates() {
        let cfg = parse(include_str!("../../configs/profile_regression.json"));
        let rep = validate(&cfg);
        assert!(
            rep.ok(),
            "profile regression config should validate cleanly: {:?}",
            rep
        );
        assert_eq!(cfg.scenarios.len(), 30);

        for prefix in ["profile_routing", "profile_tls13", "profile_ktls13"] {
            for profile in ["latency", "balanced", "throughput"] {
                assert!(cfg
                    .scenarios
                    .iter()
                    .any(|s| s.name == format!("{prefix}_{profile}_throughput_1KB")));
                assert!(cfg
                    .scenarios
                    .iter()
                    .any(|s| s.name == format!("{prefix}_{profile}_latency_1KB")));
                assert!(cfg
                    .scenarios
                    .iter()
                    .any(|s| s.name == format!("{prefix}_{profile}_pingpong_1KB")));
            }
        }
    }

    #[test]
    fn unknown_field_rejected() {
        let err = serde_json::from_str::<Config>(
            r#"{ "suite": { "name": "t", "version": "1" }, "scenarios": [], "bogus": 1 }"#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn human_secs_formats() {
        assert_eq!(human_secs(8735), "2h 25m 35s");
        assert_eq!(human_secs(75), "1m 15s");
        assert_eq!(human_secs(5), "5s");
    }
}
