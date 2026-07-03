//! Declarative benchmark-matrix expansion.
//!
//! The JSON source deliberately describes compatible *profiles*, rather than a
//! blind Cartesian product.  This keeps generated suites honest: a DTLS row is
//! never emitted for TCP, and a local endpoint is never advertised as a
//! two-gateway topology unless the transport actually supports it.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Map, Value};

/// Summary returned to the CLI after a successful generation.
#[derive(Debug, Clone, Copy)]
pub struct Generated {
    pub files: usize,
    pub scenarios: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixSpec {
    suite: SuiteSpec,
    #[serde(default)]
    defaults: Value,
    dimensions: Dimensions,
    profiles: Vec<Profile>,
    #[serde(default)]
    cipher_matrix: CipherMatrix,
    #[serde(default)]
    hot_reload_profiles: Vec<String>,
    interface_comparison: InterfaceComparison,
    #[serde(default)]
    limitations: Vec<Limitation>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CipherMatrix {
    tls12: Vec<String>,
    tls13: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiteSpec {
    name: String,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    author: String,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dimensions {
    stream_message_sizes: Vec<u32>,
    datagram_message_sizes: Vec<u32>,
    canonical_connections: Vec<u32>,
    nightly_connections: Vec<u32>,
    scalability_connections: Vec<u32>,
    catalog_connections: Vec<u32>,
    canonical_stream_message_size: u32,
    canonical_datagram_message_size: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    protocol: Value,
    interfaces: Vec<String>,
    chains: Vec<String>,
    #[serde(default = "stream_class")]
    message_class: String,
    #[serde(default)]
    tiers: Vec<String>,
    #[serde(default)]
    requirements: Vec<String>,
    /// Explicitly supported connection counts.  Empty means the tier's whole
    /// connection dimension is compatible with this profile.
    #[serde(default)]
    connections: Vec<u32>,
    /// Include the profile in the long connection-scaling sweep in the nightly
    /// output.  This is deliberately opt-in to keep crypto/local-interface
    /// runs from exploding into an impractical suite.
    #[serde(default)]
    scalability: bool,
}

fn stream_class() -> String {
    "stream".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceComparison {
    paths: Vec<ComparisonPath>,
    throughput_message_sizes: Vec<u32>,
    throughput_connections: Vec<u32>,
    latency_message_sizes: Vec<u32>,
    latency_connections: Vec<u32>,
    #[serde(default = "default_latency_fraction")]
    latency_fraction: f64,
}

fn default_latency_fraction() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComparisonPath {
    id: String,
    interface: String,
    gateway: bool,
    #[serde(default = "default_direct_chain")]
    chain: String,
    #[serde(default)]
    requirements: Vec<String>,
    /// Connections explicitly supported by this local interface.  Empty means
    /// every group connection count is emitted.
    #[serde(default)]
    connections: Vec<u32>,
}

fn default_direct_chain() -> String {
    "scg-direct".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limitation {
    name: String,
    reason: String,
    interface: String,
    #[serde(default = "default_direct_chain")]
    chain: String,
    protocol: Value,
}

/// Generate all committed matrix files from `spec_path`.
pub fn generate(spec_path: &Path, out_dir: &Path) -> Result<Generated, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(spec_path)?;
    let spec: MatrixSpec = serde_json::from_str(&text)?;
    validate_spec(&spec)?;
    fs::create_dir_all(out_dir)?;

    let catalog = expand_profiles(&spec, Tier::Catalog)?;
    let full = expand_profiles(&spec, Tier::Nightly)?;
    let canonical = expand_profiles(&spec, Tier::Canonical)?;
    let interface = expand_interface_comparison(&spec)?;
    let hotreload = expand_hotreload(&spec)?;

    let outputs = [
        (
            "matrix_catalog.json",
            suite_document(
                &spec,
                "Benchmark matrix catalog (compatible and blocked combinations)",
                catalog,
            ),
        ),
        (
            "full_matrix.json",
            suite_document(&spec, "Generated executable nightly benchmark matrix", full),
        ),
        (
            "canonical_matrix.json",
            suite_document(
                &spec,
                "Generated compact canonical benchmark matrix",
                canonical,
            ),
        ),
        (
            "interface_comparison.json",
            suite_document(
                &spec,
                "Matched loopback, SCG TCP, TPROXY, UDS, and SHM comparison suite",
                interface,
            ),
        ),
        (
            "hotreload_matrix.json",
            suite_document(
                &spec,
                "Generated compatible hot-reload scenarios (nightly tier)",
                hotreload,
            ),
        ),
    ];

    let mut scenarios = 0usize;
    for (name, scenarios_for_file) in outputs {
        scenarios += scenarios_for_file
            .get("scenarios")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        fs::write(
            out_dir.join(name),
            format!("{}\n", serde_json::to_string_pretty(&scenarios_for_file)?),
        )?;
    }
    Ok(Generated {
        files: 5,
        scenarios,
    })
}

fn expand_hotreload(spec: &MatrixSpec) -> Result<Value, Box<dyn std::error::Error>> {
    let mut scenarios = Vec::new();
    let mut names = BTreeSet::new();
    for profile in spec
        .profiles
        .iter()
        .filter(|profile| spec.hot_reload_profiles.contains(&profile.id))
    {
        // The current hot-reload executor is a TCP gateway path.  Excluding
        // UDP/local profiles here is compatibility filtering, not a coverage
        // claim; their catalog rows remain available in the main matrix.
        if profile.interfaces.len() != 1
            || profile.interfaces[0] != "tcp"
            || !profile.chains.iter().any(|chain| chain == "scg-direct")
        {
            continue;
        }
        // Do not emit a TLS-profile reload scenario yet.  The SCG gateway now
        // restarts a changed same-name data-plane rule (its `diff` gained a
        // `changed` bucket / `reload_differs`), so the changed-rule lifecycle
        // exists.  What is still missing here is the harness side: the reload
        // action must rewrite the config file with a modified same-name rule (and
        // ideally read back a reload-acknowledgement) before this can be measured
        // honestly; until then it stays disabled.
        let actions = ["add_connection", "remove_connection", "invalid_config"];
        for &connections in &[1_u32, 4, 16, 64] {
            for &load in &["sub-saturation", "saturation"] {
                for action in &actions {
                    let name = format!(
                        "hotreload_{}_{}_{}_{}c",
                        profile.id,
                        action,
                        load.replace('-', "_"),
                        connections
                    );
                    let ordinal = scenarios.len();
                    let mut row = scenario(
                        &profile.id,
                        &format!("hotreload-{load}"),
                        "tcp",
                        &profile.protocol,
                        true,
                        "scg-direct",
                        spec.dimensions.canonical_stream_message_size,
                        connections,
                        &profile.requirements,
                        None,
                        ordinal,
                    );
                    let sender = row
                        .get_mut("sender")
                        .and_then(Value::as_object_mut)
                        .expect("matrix scenario sender is object");
                    if load == "sub-saturation" {
                        sender.insert("rate_limit_mbps".to_string(), Value::from(100.0));
                    }
                    row["reload_event"] = json!({
                        "trigger_at_secs": 3,
                        "action": action,
                        "expect_zero_drops": true,
                        "measure_window_before_secs": 2,
                        "measure_window_after_secs": 5,
                    });
                    push_unique(&mut scenarios, &mut names, name, row)?;
                }
            }
        }
    }
    Ok(Value::Array(scenarios))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Catalog,
    Nightly,
    Canonical,
}

fn validate_spec(spec: &MatrixSpec) -> Result<(), Box<dyn std::error::Error>> {
    if spec.profiles.is_empty() || spec.interface_comparison.paths.is_empty() {
        return Err("matrix spec needs protocol profiles and interface-comparison paths".into());
    }
    if !(0.0..=1.0).contains(&spec.interface_comparison.latency_fraction)
        || spec.interface_comparison.latency_fraction == 0.0
    {
        return Err("interface_comparison.latency_fraction must be in (0, 1]".into());
    }
    for profile in &spec.profiles {
        if profile.id.trim().is_empty()
            || profile.interfaces.is_empty()
            || profile.chains.is_empty()
            || !profile.protocol.is_object()
        {
            return Err(format!("invalid matrix profile '{}'", profile.id).into());
        }
    }

    Ok(())
}

fn append_cipher_scenarios(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    spec: &MatrixSpec,
    tier: Tier,
) -> Result<(), Box<dyn std::error::Error>> {
    // Canonical: one representative cipher per version at the canonical size (cheap smoke).
    // Nightly/Catalog: every cipher across a small stream-size grid so the AEAD choice can be
    // compared at more than one payload (F20 — cipher cost vs message size, not a single cell).
    let canonical_size = spec.dimensions.canonical_stream_message_size;
    let sizes: Vec<u32> = if tier == Tier::Canonical {
        vec![canonical_size]
    } else {
        let grid: Vec<u32> = spec
            .dimensions
            .stream_message_sizes
            .iter()
            .copied()
            .filter(|&b| b == 1024 || b == canonical_size || b == 16384)
            .collect();
        if grid.is_empty() {
            vec![canonical_size]
        } else {
            grid
        }
    };
    for (version, suites) in [
        ("1.2", &spec.cipher_matrix.tls12),
        ("1.3", &spec.cipher_matrix.tls13),
    ] {
        let count = if tier == Tier::Canonical {
            1
        } else {
            suites.len()
        };
        for suite in suites.iter().take(count) {
            for &size in &sizes {
                let base = format!(
                    "cipher_tls{}_{}",
                    version.replace('.', ""),
                    sanitize_name(suite)
                );
                // Keep the canonical-size name suffix-free so existing references are stable;
                // other sizes carry a `_<n>B` token (the loader strips it back to the suite).
                let name = if size == canonical_size {
                    base
                } else {
                    format!("{base}_{size}B")
                };
                let ordinal = scenarios.len();
                push_unique(
                    scenarios,
                    names,
                    name,
                    scenario(
                        "cipher",
                        "cipher-matrix",
                        "tcp",
                        &json!({ "type": "tls", "version": version, "cipher_suite": suite }),
                        true,
                        "scg-direct",
                        size,
                        1,
                        &["openssl".to_string()],
                        None,
                        ordinal,
                    ),
                )?;
            }
        }
    }
    Ok(())
}

fn expand_profiles(spec: &MatrixSpec, tier: Tier) -> Result<Value, Box<dyn std::error::Error>> {
    let mut scenarios = Vec::new();
    let mut names = BTreeSet::new();
    for profile in &spec.profiles {
        if tier != Tier::Catalog && !profile.tiers.iter().any(|t| tier_name(tier) == t) {
            continue;
        }
        let sizes = match tier {
            Tier::Catalog | Tier::Nightly => profile_sizes(profile, &spec.dimensions),
            Tier::Canonical => vec![canonical_size(profile, &spec.dimensions)],
        };
        let connections = match tier {
            Tier::Catalog => spec.dimensions.catalog_connections.clone(),
            Tier::Nightly if profile.scalability => union_connections(
                &spec.dimensions.nightly_connections,
                &spec.dimensions.scalability_connections,
            ),
            Tier::Nightly => spec.dimensions.nightly_connections.clone(),
            Tier::Canonical => spec.dimensions.canonical_connections.clone(),
        };
        for interface in &profile.interfaces {
            for chain in &profile.chains {
                for &size in &sizes {
                    for &connections in &connections {
                        if !profile.connections.is_empty()
                            && !profile.connections.contains(&connections)
                        {
                            continue;
                        }
                        let name = format!(
                            "matrix_{}_{}_{}_{}_{}c",
                            profile.id,
                            interface,
                            size_label(size),
                            chain.replace("scg-", ""),
                            connections
                        );
                        let ordinal = scenarios.len();
                        push_unique(
                            &mut scenarios,
                            &mut names,
                            name,
                            scenario(
                                &profile.id,
                                "matrix",
                                interface,
                                &profile.protocol,
                                true,
                                chain,
                                size,
                                connections,
                                &profile.requirements,
                                None,
                                ordinal,
                            ),
                        )?;
                    }
                }
            }
        }
    }

    append_cipher_scenarios(&mut scenarios, &mut names, spec, tier)?;

    if tier == Tier::Catalog {
        for limitation in &spec.limitations {
            let name = format!("blocked_{}", limitation.name);
            let mut row = scenario(
                "blocked",
                "unsupported",
                &limitation.interface,
                &limitation.protocol,
                true,
                &limitation.chain,
                1024,
                1,
                &[],
                None,
                scenarios.len(),
            );
            row["name"] = Value::String(name.clone());
            row["enabled"] = Value::Bool(false);
            row["disabled_reason"] = Value::String(limitation.reason.clone());
            push_unique(&mut scenarios, &mut names, name, row)?;
        }
    }

    Ok(Value::Array(scenarios))
}

fn union_connections(left: &[u32], right: &[u32]) -> Vec<u32> {
    let mut values = left.iter().chain(right).copied().collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn expand_interface_comparison(spec: &MatrixSpec) -> Result<Value, Box<dyn std::error::Error>> {
    let mut scenarios = Vec::new();
    let mut names = BTreeSet::new();
    let comparison = &spec.interface_comparison;
    let direct = comparison
        .paths
        .iter()
        .find(|p| !p.gateway && p.interface == "tcp")
        .ok_or("interface comparison needs a direct TCP loopback path")?;
    let gateway_tcp = comparison
        .paths
        .iter()
        .find(|p| p.gateway && p.interface == "tcp")
        .ok_or("interface comparison needs an SCG TCP routing path")?;

    for &size in &comparison.throughput_message_sizes {
        for &connections in &comparison.throughput_connections {
            let group = format!("iface-throughput-{}-{}c", size_label(size), connections);
            let direct_name = format!(
                "iface_{}_throughput_{}_{}c",
                direct.id,
                size_label(size),
                connections
            );
            let gateway_name = format!(
                "iface_{}_throughput_{}_{}c",
                gateway_tcp.id,
                size_label(size),
                connections
            );
            for path in &comparison.paths {
                if !supports_connections(path, connections) {
                    continue;
                }
                let name = format!(
                    "iface_{}_throughput_{}_{}c",
                    path.id,
                    size_label(size),
                    connections
                );
                let meta = comparison_meta(&group, &direct_name, &gateway_name, None, None);
                let ordinal = scenarios.len();
                push_unique(
                    &mut scenarios,
                    &mut names,
                    name,
                    scenario(
                        "routing",
                        "interface-comparison-throughput",
                        &path.interface,
                        &json!({ "type": "none", "protection_mode": "routing-only" }),
                        path.gateway,
                        &path.chain,
                        size,
                        connections,
                        &path.requirements,
                        Some(meta),
                        ordinal,
                    ),
                )?;
            }
        }
    }

    for &size in &comparison.latency_message_sizes {
        for &connections in &comparison.latency_connections {
            let throughput_group =
                format!("iface-throughput-{}-{}c", size_label(size), connections);
            let group = format!("iface-latency-{}-{}c", size_label(size), connections);
            let direct_name = format!(
                "iface_{}_latency_{}_{}c",
                direct.id,
                size_label(size),
                connections
            );
            let gateway_name = format!(
                "iface_{}_latency_{}_{}c",
                gateway_tcp.id,
                size_label(size),
                connections
            );
            for path in &comparison.paths {
                if !supports_connections(path, connections) {
                    continue;
                }
                let name = format!(
                    "iface_{}_latency_{}_{}c",
                    path.id,
                    size_label(size),
                    connections
                );
                let meta = comparison_meta(
                    &group,
                    &direct_name,
                    &gateway_name,
                    Some(&throughput_group),
                    Some(comparison.latency_fraction),
                );
                let ordinal = scenarios.len();
                let mut row = scenario(
                    "routing",
                    "interface-comparison-latency",
                    &path.interface,
                    &json!({ "type": "none", "protection_mode": "routing-only" }),
                    path.gateway,
                    &path.chain,
                    size,
                    connections,
                    &path.requirements,
                    Some(meta),
                    ordinal,
                );
                let sender = row
                    .get_mut("sender")
                    .and_then(Value::as_object_mut)
                    .expect("matrix scenario sender is object");
                // The runner derives a fixed-rate pacer from the completed
                // throughput comparison group.  A sustained sender with a
                // rate limit supports sub-microsecond pacing, unlike the JSON
                // periodic interval field.
                sender.insert(
                    "pattern".to_string(),
                    Value::String("sustained".to_string()),
                );
                push_unique(&mut scenarios, &mut names, name, row)?;
            }
        }
    }
    Ok(Value::Array(scenarios))
}

fn supports_connections(path: &ComparisonPath, connections: u32) -> bool {
    path.connections.is_empty() || path.connections.contains(&connections)
}

fn comparison_meta(
    group: &str,
    direct: &str,
    gateway: &str,
    calibration_group: Option<&str>,
    calibration_fraction: Option<f64>,
) -> Value {
    let mut value = json!({
        "group": group,
        "reference": direct,
        "gateway_reference": gateway,
    });
    let object = value.as_object_mut().expect("comparison metadata object");
    if let Some(group) = calibration_group {
        object.insert(
            "calibration_group".to_string(),
            Value::String(group.to_string()),
        );
    }
    if let Some(fraction) = calibration_fraction {
        object.insert("calibration_fraction".to_string(), Value::from(fraction));
    }
    value
}

#[allow(clippy::too_many_arguments)]
fn scenario(
    profile: &str,
    category: &str,
    interface: &str,
    protocol: &Value,
    gateway: bool,
    chain: &str,
    size: u32,
    connections: u32,
    requirements: &[String],
    comparison: Option<Value>,
    ordinal: usize,
) -> Value {
    let mut row = json!({
        "name": format!("pending_{ordinal}"),
        "category": category,
        "message_size_bytes": size,
        "connections": connections,
        "gateway": { "enabled": gateway, "chain": chain },
        "protocol": protocol,
        "sender": sender(interface, ordinal),
        "requirements": requirements_json(requirements),
    });
    let object = row.as_object_mut().expect("scenario object");
    object.insert("profile".to_string(), Value::String(profile.to_string()));
    // `profile` is generator-only metadata and not part of the strict runtime
    // schema.  Encode it into the category instead of leaking an unknown key.
    object.remove("profile");
    if let Some(comparison) = comparison {
        object.insert("comparison".to_string(), comparison);
    }
    object.insert(
        "description".to_string(),
        Value::String(matrix_description(
            category,
            interface,
            protocol,
            gateway,
            chain,
            size,
            connections,
        )),
    );
    row
}

/// Compose a one-line, explicit description for a generated scenario from its
/// parameters so every generated suite row carries a human description.
fn matrix_description(
    category: &str,
    interface: &str,
    protocol: &Value,
    gateway: bool,
    chain: &str,
    size: u32,
    connections: u32,
) -> String {
    let path = if gateway {
        format!("SCG {chain}")
    } else {
        "direct loopback".to_string()
    };
    format!(
        "{category}: {path}, {interface}/{}, {}, {} conn{}",
        protocol_summary(protocol),
        size_label(size),
        connections,
        if connections == 1 { "" } else { "s" }
    )
}

/// Short protocol label derived from a generated scenario's protocol JSON.
fn protocol_summary(protocol: &Value) -> String {
    match protocol
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("none")
    {
        "none" => "plain".to_string(),
        "tls" => {
            let v = protocol
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("1.3");
            let base = if protocol
                .get("kernel")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "ktls"
            } else {
                "tls"
            };
            format!("{base}{v}")
        }
        "dtls" => {
            let v = protocol
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("1.2");
            format!("dtls{v}")
        }
        other => other.to_string(),
    }
}

fn sender(interface: &str, ordinal: usize) -> Value {
    let target_addr = match interface {
        "tcp" | "udp" | "tproxy" => format!("127.0.0.1:{}", 18000 + ordinal as u16),
        "unix" => format!("/tmp/seshat-matrix-{ordinal}.sock"),
        "shm" => format!("shm:///seshat-matrix-{ordinal}"),
        other => format!("unsupported://{other}"),
    };
    json!({
        "interface": interface,
        "target_addr": target_addr,
        "pattern": "sustained",
    })
}

fn requirements_json(requirements: &[String]) -> Value {
    let mut map = Map::new();
    for requirement in requirements {
        map.insert(requirement.clone(), Value::Bool(true));
    }
    Value::Object(map)
}

fn profile_sizes(profile: &Profile, dimensions: &Dimensions) -> Vec<u32> {
    if profile.message_class == "datagram" {
        dimensions.datagram_message_sizes.clone()
    } else {
        dimensions.stream_message_sizes.clone()
    }
}

fn canonical_size(profile: &Profile, dimensions: &Dimensions) -> u32 {
    if profile.message_class == "datagram" {
        dimensions.canonical_datagram_message_size
    } else {
        dimensions.canonical_stream_message_size
    }
}

fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Catalog => "catalog",
        Tier::Nightly => "nightly",
        Tier::Canonical => "canonical",
    }
}

fn push_unique(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    name: String,
    mut row: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if !names.insert(name.clone()) {
        return Err(format!("matrix expansion generated duplicate name '{name}'").into());
    }
    row["name"] = Value::String(name);
    scenarios.push(row);
    Ok(())
}

fn size_label(bytes: u32) -> String {
    match bytes {
        1024 => "1KB".to_string(),
        16_384 => "16KB".to_string(),
        65_536 => "64KB".to_string(),
        _ => format!("{bytes}B"),
    }
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn suite_document(spec: &MatrixSpec, description: &str, scenarios: Value) -> Value {
    json!({
        "$schema": "seshat-config-v1",
        "suite": {
            "name": spec.suite.name,
            "description": description,
            "author": spec.suite.author,
            "version": spec.suite.version,
        },
        "defaults": spec.defaults,
        "scenarios": scenarios,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_spec() -> MatrixSpec {
        serde_json::from_str(include_str!("../configs/matrix_spec.json"))
            .expect("production matrix spec parses")
    }

    fn rows(value: &Value) -> &[Value] {
        value
            .as_array()
            .expect("matrix expansion returns a scenario array")
    }

    fn names_are_unique(value: &Value) -> bool {
        let names = rows(value)
            .iter()
            .filter_map(|row| row.get("name").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        names.len() == rows(value).len()
    }

    #[test]
    fn matrix_rejects_invalid_latency_fraction() {
        let spec: MatrixSpec = serde_json::from_value(json!({
            "suite": { "name": "x" },
            "dimensions": {
                "stream_message_sizes": [64], "datagram_message_sizes": [64],
                "canonical_connections": [1], "nightly_connections": [1],
                "scalability_connections": [1], "catalog_connections": [1],
                "canonical_stream_message_size": 64, "canonical_datagram_message_size": 64
            },
            "profiles": [{ "id": "p", "protocol": {"type":"none"}, "interfaces": ["tcp"], "chains": ["scg-direct"] }],
            "interface_comparison": { "paths": [{ "id":"tcp", "interface":"tcp", "gateway":false }, { "id":"scg", "interface":"tcp", "gateway":true }], "throughput_message_sizes": [64], "throughput_connections": [1], "latency_message_sizes": [64], "latency_connections": [1], "latency_fraction": 0.0 }
        }))
        .unwrap();
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn generated_tiers_are_deterministic_unique_and_compatible() {
        let spec = production_spec();
        let first = expand_profiles(&spec, Tier::Nightly).unwrap();
        let second = expand_profiles(&spec, Tier::Nightly).unwrap();
        assert_eq!(first, second, "generation order must be stable");
        assert!(names_are_unique(&first));

        for row in rows(&first) {
            let protocol = row["protocol"]["type"].as_str();
            let interface = row["sender"]["interface"].as_str();
            if protocol == Some("dtls") {
                assert_eq!(interface, Some("udp"));
                assert_eq!(row["connections"].as_u64(), Some(1));
            }
            // Datagram (udp) and transparent (tproxy) transports stay single-connection
            // by design: a UDP "connection" is a flow, and TPROXY interception has no
            // per-connection fan-out here.
            if interface == Some("udp") || interface == Some("tproxy") {
                assert_eq!(row["connections"].as_u64(), Some(1));
            }
            // Stream IPC transports (unix/shm) now sweep the nightly connection ladder —
            // each connection provisions its own endpoint (gRPC + SCM_RIGHTS) — so they can
            // be compared with TCP at matched concurrency, but they do not opt into the
            // scalability tier's 256/1024 fan-out.
            if interface == Some("unix") || interface == Some("shm") {
                let conns = row["connections"].as_u64().unwrap();
                assert!(
                    [1, 4, 16, 64].contains(&conns),
                    "unix/shm connections must stay within the nightly ladder, got {conns}"
                );
            }
        }
    }

    #[test]
    fn catalogued_limitations_are_disabled_with_reasons() {
        let spec = production_spec();
        let catalog = expand_profiles(&spec, Tier::Catalog).unwrap();
        for row in rows(&catalog)
            .iter()
            .filter(|row| row["enabled"] == Value::Bool(false))
        {
            assert!(row["name"].as_str().unwrap().starts_with("blocked_"));
            assert!(row["disabled_reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()));
        }
    }

    #[test]
    fn interface_comparison_groups_have_matched_references() {
        let spec = production_spec();
        let comparison = expand_interface_comparison(&spec).unwrap();
        assert!(names_are_unique(&comparison));
        let group = "iface-throughput-1KB-1c";
        let group_rows = rows(&comparison)
            .iter()
            .filter(|row| row["comparison"]["group"] == group)
            .collect::<Vec<_>>();
        assert_eq!(group_rows.len(), 5);
        for row in group_rows {
            assert_eq!(row["protocol"]["type"], "none");
            assert_eq!(row["protocol"]["protection_mode"], "routing-only");
            assert_eq!(row["message_size_bytes"], 1024);
            assert_eq!(row["connections"], 1);
            assert_eq!(
                row["comparison"]["reference"],
                "iface_tcp_loopback_throughput_1KB_1c"
            );
            assert_eq!(
                row["comparison"]["gateway_reference"],
                "iface_tcp_scg_throughput_1KB_1c"
            );
        }
    }

    #[test]
    fn duplicate_scenario_names_are_rejected() {
        let mut scenarios = Vec::new();
        let mut names = BTreeSet::new();
        let row = json!({ "name": "placeholder" });
        push_unique(
            &mut scenarios,
            &mut names,
            "duplicate".to_string(),
            row.clone(),
        )
        .unwrap();
        assert!(push_unique(&mut scenarios, &mut names, "duplicate".to_string(), row).is_err());
    }
}
