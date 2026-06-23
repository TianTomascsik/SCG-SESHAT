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
        report.suite_errors.push("suite.version is empty".to_string());
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

    // WireGuard / IPSec are SCG stubs — must be disabled.
    match s.protocol.kind {
        ProtocolType::Wireguard => r.errors.push(
            "protocol.type=wireguard is an SCG stub; set enabled=false (see WP6.1)".to_string(),
        ),
        ProtocolType::Ipsec => r.errors.push(
            "protocol.type=ipsec is an SCG stub; set enabled=false (see WP6.1)".to_string(),
        ),
        _ => {}
    }

    // kTLS requires TLS.
    if s.protocol.kernel && s.protocol.kind != ProtocolType::Tls {
        r.errors
            .push("protocol.kernel=true (kTLS) requires protocol.type=tls".to_string());
    }

    // Single-stream sender checks.
    if let Some(sender) = &s.sender {
        validate_addr(sender.interface, &sender.target_addr, "sender.target_addr", &mut r);
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
    }
    if has_streams {
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

    // Hot-reload needs the gateway.
    if let Some(reload) = &s.reload_event {
        if !s.gateway.enabled {
            r.errors
                .push("reload_event requires gateway.enabled=true".to_string());
        }
        if matches!(
            reload.action,
            ReloadAction::UpdateTlsProfile | ReloadAction::RotateCert
        ) && reload.payload_file.is_none()
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

fn validate_transport_needs_gateway(interface: Interface, gateway: &Gateway, r: &mut ScenarioReport) {
    if matches!(interface, Interface::Unix | Interface::Shm) && !gateway.enabled {
        r.errors.push(format!(
            "interface={} requires gateway.enabled=true (provisioned via the gRPC management API)",
            interface.label()
        ));
    }
}

fn validate_protocol_transport(s: &Scenario, interface: Interface, r: &mut ScenarioReport) {
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
}

const KNOWN_DSCP: &[&str] = &[
    "EF", "BE", "AF11", "AF12", "AF13", "AF21", "AF22", "AF23", "AF31", "AF32", "AF33", "AF41",
    "AF42", "AF43", "CS0", "CS1", "CS2", "CS3", "CS4", "CS5", "CS6", "CS7",
];

fn validate_dscp(tag: &str, ctx: &str, r: &mut ScenarioReport) {
    if !KNOWN_DSCP.contains(&tag) {
        r.warnings
            .push(format!("{ctx}: unknown DSCP tag '{tag}'"));
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
    fn wireguard_enabled_rejected() {
        let cfg = parse(
            r#"{ "suite": { "name": "t", "version": "1" },
                "scenarios": [
                  { "name": "wg", "protocol": { "type": "wireguard" },
                    "sender": { "interface": "udp", "target_addr": "127.0.0.1:1" } }
                ] }"#,
        );
        let rep = validate(&cfg);
        assert!(!rep.ok());
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
