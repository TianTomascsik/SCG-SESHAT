//! Gateway JSON configuration model (WP2.1).
//!
//! SESHAT does not depend on the `gateway` crate; instead it emits the JSON the
//! `gateway` binary reads via `--config`. These `Serialize` structs mirror the
//! gateway's `GatewayConfig` / `RuleConfig` / `ApiConfig` (see
//! `SCG/gateway/src/management/config.rs`). Only the fields SESHAT sets are
//! emitted; everything else falls back to the gateway's documented defaults.
//!
//! Rules use string values for `direction` / `*_proto` / `security_provider` /
//! `traffic_class` to match the gateway's lowercase serde enums exactly, with
//! typed constructors and a fluent builder to keep call sites readable.
#![allow(dead_code)] // builder surface is consumed across Phase 2 work packages.

use std::collections::BTreeMap;

use serde::Serialize;

/// Top-level gateway configuration document.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    pub rules: Vec<RuleConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
}

impl GatewayConfig {
    /// A config wrapping the given rules with no management API.
    pub fn new(rules: Vec<RuleConfig>) -> Self {
        GatewayConfig {
            log_dir: None,
            run_id: None,
            latency: None,
            log_level: None,
            rules,
            policy: None,
            api: None,
        }
    }

    /// Set the gateway log level (`error|warn|info|debug|trace`).
    pub fn log_level(mut self, level: &str) -> Self {
        self.log_level = Some(level.to_string());
        self
    }

    /// Permit all traffic through the gateway. Without a policy block the
    /// gateway defaults to deny-all, which would reject benchmark traffic.
    pub fn allow_all(mut self) -> Self {
        self.policy = Some(PolicyConfig {
            default_action: "allow".to_string(),
            whitelist: Vec::new(),
        });
        self
    }

    /// Attach a management-API block (required for UDS/SHM endpoint provisioning).
    pub fn api(mut self, api: ApiConfig) -> Self {
        self.api = Some(api);
        self
    }

    /// Serialize to pretty JSON for writing to a config file.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("gateway config serializes")
    }
}

/// Management-API (gRPC over UDS) configuration block.
#[derive(Debug, Clone, Serialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub uds_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_addr: Option<String>,
    pub runtime_dir: String,
    pub shm_ring_capacity: usize,
}

impl ApiConfig {
    /// A management API listening on `uds_path` with endpoint sockets under
    /// `runtime_dir`.
    pub fn new(uds_path: &str, runtime_dir: &str, shm_ring_capacity: usize) -> Self {
        ApiConfig {
            enabled: true,
            uds_path: uds_path.to_string(),
            tcp_addr: None,
            runtime_dir: runtime_dir.to_string(),
            shm_ring_capacity,
        }
    }
}

/// Policy-enforcement block. The gateway defaults to deny-all when this is
/// absent, so benchmark paths emit an explicit allow policy.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyConfig {
    /// `allow` or `deny` when no whitelist entry matches.
    pub default_action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub whitelist: Vec<WhitelistEntry>,
}

/// A single allow-list entry (source/destination address patterns).
#[derive(Debug, Clone, Serialize)]
pub struct WhitelistEntry {
    pub source: String,
    pub destination: String,
}

/// A single proxy rule (one direction of one path).
#[derive(Debug, Clone, Serialize)]
pub struct RuleConfig {
    pub name: String,
    pub direction: String,
    pub listen_addr: String,
    pub listen_proto: String,
    pub upstream_addr: String,
    pub upstream_proto: String,
    pub security_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    pub traffic_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_uids: Vec<u32>,
    /// Provider-specific keys (cert_path, verify, profile, psk_hex, ...) emitted
    /// at the rule's top level via `#[serde(flatten)]`, exactly as the gateway
    /// captures them into its flattened `provider_params` map.
    #[serde(flatten)]
    pub provider_params: BTreeMap<String, serde_json::Value>,
}

impl RuleConfig {
    /// A plaintext `routing` TCP rule (no crypto) — the simplest proxy hop.
    pub fn new(name: &str, direction: &str, listen_addr: &str, upstream_addr: &str) -> Self {
        RuleConfig {
            name: name.to_string(),
            direction: direction.to_string(),
            listen_addr: listen_addr.to_string(),
            listen_proto: "tcp".to_string(),
            upstream_addr: upstream_addr.to_string(),
            upstream_proto: "tcp".to_string(),
            security_provider: "routing".to_string(),
            app_protocol: None,
            protocol_version: None,
            traffic_class: "normal".to_string(),
            app_id: None,
            allowed_uids: Vec::new(),
            provider_params: BTreeMap::new(),
        }
    }

    /// Set the security provider (`routing|tls|ktls|dtls`).
    pub fn security(mut self, provider: &str) -> Self {
        self.security_provider = provider.to_string();
        self
    }

    /// Set the listen protocol (`tcp|udp|uds|shm`).
    pub fn listen_proto(mut self, proto: &str) -> Self {
        self.listen_proto = proto.to_string();
        self
    }

    /// Set the upstream protocol (`tcp|udp|uds|shm`).
    pub fn upstream_proto(mut self, proto: &str) -> Self {
        self.upstream_proto = proto.to_string();
        self
    }

    /// Set both listen and upstream protocol at once.
    pub fn proto(self, proto: &str) -> Self {
        self.listen_proto(proto).upstream_proto(proto)
    }

    /// Set the TLS/DTLS protocol version (`tls1.2|tls1.3|dtls1.0|dtls1.2`).
    pub fn protocol_version(mut self, version: &str) -> Self {
        self.protocol_version = Some(version.to_string());
        self
    }

    /// Set the application protocol (`ale|raw`).
    pub fn app_protocol(mut self, proto: &str) -> Self {
        self.app_protocol = Some(proto.to_string());
        self
    }

    /// Set the traffic class (`normal|safety`).
    pub fn traffic_class(mut self, class: &str) -> Self {
        self.traffic_class = class.to_string();
        self
    }

    /// Set the local-endpoint app id (UDS/SHM rules).
    pub fn app_id(mut self, app_id: &str) -> Self {
        self.app_id = Some(app_id.to_string());
        self
    }

    /// Permit a uid to open local endpoints for this rule (UDS/SHM).
    pub fn allowed_uid(mut self, uid: u32) -> Self {
        self.allowed_uids.push(uid);
        self
    }

    /// Set a flattened provider parameter (e.g. `cert_path`, `verify`, `profile`).
    pub fn param(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.provider_params
            .insert(key.to_string(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_rule_minimal_json() {
        let r = RuleConfig::new("ingress", "encrypt", "127.0.0.1:9000", "127.0.0.1:9001");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["name"], "ingress");
        assert_eq!(v["direction"], "encrypt");
        assert_eq!(v["listen_addr"], "127.0.0.1:9000");
        assert_eq!(v["listen_proto"], "tcp");
        assert_eq!(v["upstream_addr"], "127.0.0.1:9001");
        assert_eq!(v["security_provider"], "routing");
        assert_eq!(v["traffic_class"], "normal");
        // Optional fields omitted when unset.
        assert!(v.get("app_protocol").is_none());
        assert!(v.get("protocol_version").is_none());
        assert!(v.get("allowed_uids").is_none());
    }

    #[test]
    fn tls_rule_flattens_provider_params() {
        let r = RuleConfig::new("dec", "decrypt", "127.0.0.1:7443", "127.0.0.1:7002")
            .security("tls")
            .protocol_version("tls1.3")
            .param("verify", "server")
            .param("cert_path", "/tmp/s.crt")
            .param("key_path", "/tmp/s.key");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["security_provider"], "tls");
        assert_eq!(v["protocol_version"], "tls1.3");
        // provider_params are flattened to the rule's top level.
        assert_eq!(v["verify"], "server");
        assert_eq!(v["cert_path"], "/tmp/s.crt");
        assert_eq!(v["key_path"], "/tmp/s.key");
    }

    #[test]
    fn uds_rule_has_app_id_and_uids() {
        let r = RuleConfig::new("uds", "encrypt", "unused", "127.0.0.1:7777")
            .listen_proto("uds")
            .security("tls")
            .app_id("app-bench")
            .allowed_uid(1000);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["listen_proto"], "uds");
        assert_eq!(v["app_id"], "app-bench");
        assert_eq!(v["allowed_uids"], serde_json::json!([1000]));
    }

    #[test]
    fn gateway_config_with_api_serializes() {
        let cfg = GatewayConfig::new(vec![RuleConfig::new(
            "r",
            "encrypt",
            "127.0.0.1:1",
            "127.0.0.1:2",
        )])
        .log_level("info")
        .api(ApiConfig::new("/run/scg/m.sock", "/run/scg", 1 << 20));
        let v: serde_json::Value = serde_json::to_value(&cfg).unwrap();
        assert_eq!(v["log_level"], "info");
        assert_eq!(v["rules"].as_array().unwrap().len(), 1);
        assert_eq!(v["api"]["enabled"], true);
        assert_eq!(v["api"]["uds_path"], "/run/scg/m.sock");
        // A clean round-trip back to a JSON string works.
        assert!(cfg.to_json().contains("\"rules\""));
    }
}
