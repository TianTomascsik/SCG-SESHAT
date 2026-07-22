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
    /// SCG optimization flags stamped onto every scenario this profile emits
    /// (e.g. `{ "shm_ring_kind": "slot" }` for the fixed-slot SHM ring variant).
    /// Passed through verbatim and validated against `OptimizationFlags` when the
    /// generated scenario is loaded; empty (the default) leaves rows untouched so
    /// flag-less profiles stay byte-for-byte identical.
    #[serde(default)]
    optimization_flags: Value,
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
            suite_document(
                &spec,
                "Generated executable nightly benchmark matrix (disabled blocked_* rows document deliberate non-coverage)",
                full,
            ),
        ),
        (
            "canonical_matrix.json",
            suite_document(
                &spec,
                "Generated compact canonical benchmark matrix (disabled blocked_* rows document deliberate non-coverage)",
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
        // A TLS-profile reload scenario is still not emitted: that action only
        // SIGHUPs the unchanged file (a harness no-op). rotate_cert IS emitted
        // for cert-bearing profiles — the executor now stages a second identity,
        // rewrites the decrypt rule's cert/key paths (a path change, so the SCG
        // diff's `changed` bucket restarts the rule) and SIGHUPs. The restart
        // severs that rule's established connections by design, so rotate_cert
        // scenarios expect drops rather than asserting zero.
        let mut actions = vec!["add_connection", "remove_connection", "invalid_config"];
        let has_server_cert = profile
            .protocol
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t == "tls");
        if has_server_cert {
            actions.push("rotate_cert");
        }
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
                        // The rotated rule's established connections are severed
                        // by the changed-bucket restart, so drops are expected.
                        "expect_zero_drops": *action != "rotate_cert",
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

/// The message-size grid for a cipher sweep: one canonical size for the smoke tier, otherwise
/// the `preferred` sizes that the dimension actually declares (so the AEAD choice can be compared
/// at more than one payload — F20 renders cost vs message size, not a single cell).
fn cipher_size_grid(tier: Tier, canonical: u32, all: &[u32], preferred: &[u32]) -> Vec<u32> {
    if tier == Tier::Canonical {
        return vec![canonical];
    }
    let grid: Vec<u32> = all
        .iter()
        .copied()
        .filter(|b| preferred.contains(b))
        .collect();
    if grid.is_empty() {
        vec![canonical]
    } else {
        grid
    }
}

/// Push one cipher-sweep scenario (always through the gateway, scg-direct, 1 connection). The
/// canonical-size row is suffix-free so existing references stay stable; other sizes carry a
/// `_<n>B` token (the loader strips it back to the suite).
#[allow(clippy::too_many_arguments)]
fn push_cipher_scenario(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    base: &str,
    interface: &str,
    protocol: Value,
    requirements: &[String],
    size: u32,
    canonical_size: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = if size == canonical_size {
        base.to_string()
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
            interface,
            &protocol,
            true,
            "scg-direct",
            size,
            1,
            requirements,
            None,
            ordinal,
        ),
    )
}

fn append_cipher_scenarios(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    spec: &MatrixSpec,
    tier: Tier,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same AEAD sweep on every path the gateway can carry a chosen cipher on, so F20 can show the
    // AES-NI-vs-software ranking is transport/path-independent: userspace TLS and kernel-offloaded
    // kTLS over TCP (stream sizes), and DTLS 1.2 over UDP (datagram sizes; DTLS 1.2 shares the
    // TLS 1.2 AEAD suite names). Canonical tier keeps one cipher/size per path as a cheap smoke.
    let canonical_stream = spec.dimensions.canonical_stream_message_size;
    let stream_sizes = cipher_size_grid(
        tier,
        canonical_stream,
        &spec.dimensions.stream_message_sizes,
        &[1024, canonical_stream, 16384],
    );
    let canonical_dgram = spec.dimensions.canonical_datagram_message_size;
    // Cap DTLS datagram sizes at the no-fragmentation MTU band so the sweep measures the AEAD, not
    // IP-fragmentation/reassembly cost.
    let dgram_sizes = cipher_size_grid(
        tier,
        canonical_dgram,
        &spec.dimensions.datagram_message_sizes,
        &[256, canonical_dgram, 1400],
    );

    for (version, suites) in [
        ("1.2", &spec.cipher_matrix.tls12),
        ("1.3", &spec.cipher_matrix.tls13),
    ] {
        let count = if tier == Tier::Canonical {
            1
        } else {
            suites.len()
        };
        let vshort = version.replace('.', "");
        for suite in suites.iter().take(count) {
            for &size in &stream_sizes {
                // Userspace TLS.
                push_cipher_scenario(
                    scenarios,
                    names,
                    &format!("cipher_tls{vshort}_{}", sanitize_name(suite)),
                    "tcp",
                    json!({ "type": "tls", "version": version, "cipher_suite": suite }),
                    &["openssl".to_string()],
                    size,
                    canonical_stream,
                )?;
                // Kernel TLS: kTLS offloads whatever cipher OpenSSL negotiated, so the same
                // ciphersuites/cipher_list config selects the kernel AEAD. Only AEAD suites are
                // offloadable; a non-offloadable pick degrades to userspace (logged) rather than
                // failing, so the sweep stays valid.
                push_cipher_scenario(
                    scenarios,
                    names,
                    &format!("cipher_ktls{vshort}_{}", sanitize_name(suite)),
                    "tcp",
                    json!({ "type": "tls", "kernel": true, "version": version, "cipher_suite": suite }),
                    &["openssl".to_string(), "ktls".to_string()],
                    size,
                    canonical_stream,
                )?;
            }
        }
    }

    // DTLS 1.2 over UDP (shares the TLS 1.2 ECDHE-RSA AEAD suite names; DTLS 1.2 uses the
    // TLS-1.2-style cipher-list API the gateway applies via set_dtls_cipher_list).
    let dtls_suites = &spec.cipher_matrix.tls12;
    let dtls_count = if tier == Tier::Canonical {
        1
    } else {
        dtls_suites.len()
    };
    for suite in dtls_suites.iter().take(dtls_count) {
        for &size in &dgram_sizes {
            push_cipher_scenario(
                scenarios,
                names,
                &format!("cipher_dtls12_{}", sanitize_name(suite)),
                "udp",
                json!({ "type": "dtls", "version": "1.2", "cipher_suite": suite }),
                &["openssl".to_string()],
                size,
                canonical_dgram,
            )?;
        }
    }
    Ok(())
}

/// Push one connection-rate handshake row (TLS 1.3, TCP, through the gateway, 64 B). `connrate`
/// mode reports connections/sec + handshake p50/p99. The canonical churn width (4) is suffix-free.
fn push_connrate_handshake(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    base: &str,
    protocol: Value,
    c: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = if c == 4 {
        base.to_string()
    } else {
        format!("{base}_{c}c")
    };
    let ordinal = scenarios.len();
    let mut row = scenario(
        "handshake",
        "handshake-auth",
        "tcp",
        &protocol,
        true,
        "scg-direct",
        64,
        c,
        &["openssl".to_string()],
        None,
        ordinal,
    );
    row.as_object_mut()
        .expect("scenario object")
        .insert("mode".to_string(), Value::String("connrate".to_string()));
    push_unique(scenarios, names, name, row)
}

/// Handshake-algorithm sweep: connection-rate churn at TLS 1.3 over TCP, isolating each asymmetric
/// handshake cost on its own axis (F23). TLS 1.3 is auth-agnostic, so the cipher would not vary
/// either dimension — explicit `cert_key_type` / `kex_group` do.
///   1. **Server auth**: vary the cert signature (RSA-2048 vs ECDSA-P256) at the default KEX group.
///   2. **Key exchange**: vary the ECDHE group (X25519 vs P-256) at a fixed ECDSA cert.
fn append_handshake_scenarios(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    tier: Tier,
) -> Result<(), Box<dyn std::error::Error>> {
    let conns: &[u32] = if tier == Tier::Canonical {
        &[4]
    } else {
        &[1, 4]
    };
    // Axis 1 — server-auth signature algorithm (default KEX group).
    for cert in ["ecdsa", "rsa"] {
        for &c in conns {
            push_connrate_handshake(
                scenarios,
                names,
                &format!("handshake_tls13_{cert}"),
                json!({ "type": "tls", "version": "1.3", "cert_key_type": cert }),
                c,
            )?;
        }
    }
    // Axis 2 — ECDHE key-exchange group (fixed ECDSA cert), gated by the gateway `groups` support
    // added under TRA #84.
    for (label, group) in [("x25519", "X25519"), ("p256", "P-256")] {
        for &c in conns {
            push_connrate_handshake(
                scenarios,
                names,
                &format!("handshake_kex_{label}"),
                json!({ "type": "tls", "version": "1.3", "cert_key_type": "ecdsa", "kex_group": group }),
                c,
            )?;
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
        // Connection ladder per tier. On a single loopback host SHM/UDS gain no aggregate
        // throughput from a longer ladder: the data plane is serial per connection (one relay
        // thread per endpoint) and there is no NIC to bypass, so the box stays largely idle while
        // one thread pegs a core (see docs/methodology.md "Reading the concurrency sweep" and
        // seshat-viz F15). The nightly [1,4,16,64] cap on unix/shm is therefore deliberate — past
        // it the sweep only re-measures the serial ceiling, not fan-out; a bandwidth-bound /
        // real-NIC tier is what would let it scale, not a wider ladder.
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
                        let mut row = scenario(
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
                        );
                        stamp_optimization_flags(&mut row, &profile.optimization_flags);
                        push_unique(&mut scenarios, &mut names, name, row)?;
                    }
                    // Also emit a closed-loop ping-pong LATENCY scenario for this
                    // (protocol, interface, size) at 1 connection on the scg-direct path, so
                    // seshat-viz F4 has a real per-message RTT for every cell — not only the
                    // open-loop blast p99 above, which is queueing-dominated (coordinated
                    // omission). Latency is inherently a 1-connection, single-gateway
                    // measurement; the throughput grid is unchanged. Skip the catalog tier
                    // (reference only) and any profile that pins out 1 connection.
                    if tier != Tier::Catalog
                        && chain == "scg-direct"
                        && (profile.connections.is_empty() || profile.connections.contains(&1))
                    {
                        let lat_name = format!(
                            "matrix_lat_{}_{}_{}_direct_1c",
                            profile.id,
                            interface,
                            size_label(size)
                        );
                        let ordinal = scenarios.len();
                        let mut lat_row = scenario(
                            &profile.id,
                            "matrix-latency",
                            interface,
                            &profile.protocol,
                            true,
                            "scg-direct",
                            size,
                            1,
                            &profile.requirements,
                            None,
                            ordinal,
                        );
                        lat_row["mode"] = Value::String("pingpong".to_string());
                        stamp_optimization_flags(&mut lat_row, &profile.optimization_flags);
                        push_unique(&mut scenarios, &mut names, lat_name, lat_row)?;
                    }
                }
            }
        }
    }

    append_cipher_scenarios(&mut scenarios, &mut names, spec, tier)?;
    append_handshake_scenarios(&mut scenarios, &mut names, tier)?;

    // Emit the catalogued limitations as explicit disabled `blocked_*` rows in
    // *every* generated tier, not only the reference catalog, so a canonical or
    // nightly suite config self-documents what is deliberately not covered
    // (e.g. WireGuard, which is benchmarked only by the privileged
    // scripts/wg_bench.sh orchestration via scripts/perf_gate.sh). This is
    // execution-safe: the runner, the progress/duplicate accounting, and the
    // wall-time estimate all filter on `enabled` (src/commands.rs,
    // config::estimate_total_secs), validation short-circuits disabled rows
    // into a SKIP note, and executed/skipped report totals are rebuilt from
    // on-disk scenario directories that disabled rows never create.
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
                // Measure per-message latency **closed-loop** (ping-pong RTT), not as an
                // open-loop paced blast. The old approach derived the offered rate from the
                // *batched-blast* throughput ceiling (0.5×); on fast local-IPC paths (SHM/UDS)
                // that rate outruns what the one-message-at-a-time paced sender can sustain, so
                // the paced deadline slips behind wall-clock across the window and the
                // coordinated-omission-corrected latency reports seconds of sender backlog
                // (e.g. iface_shm_latency_64B p99 ≈ 2.9 s) instead of real service time. A
                // single-in-flight ping-pong has no sender schedule to fall behind and no ring
                // standing-queue, so it yields true per-message latency — which is the stated
                // intent of this category ("per-message processing latency, not bufferbloat").
                row["mode"] = Value::String("pingpong".to_string());
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

/// Stamp a profile's `optimization_flags` onto a generated scenario row when the
/// profile declares any (a non-empty JSON object). No-op otherwise, so profiles
/// without flags produce byte-for-byte identical rows.
fn stamp_optimization_flags(row: &mut Value, flags: &Value) {
    if let Some(map) = flags.as_object() {
        if !map.is_empty() {
            if let Some(obj) = row.as_object_mut() {
                obj.insert("optimization_flags".to_string(), flags.clone());
            }
        }
    }
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

/// IPv4 UDP payload maximum (16-bit length field, minus the 8-byte UDP header):
/// the largest single datagram the plaintext routing path can relay. It reads a
/// whole datagram (gateway `UDP_BUF_SIZE` = 64 KiB) and re-emits it unchanged, and
/// with no per-datagram crypto it keeps delivering under blast even at this size
/// (the run is flagged harness-limited/overloaded, but still yields a measurement).
const UDP_PAYLOAD_MAX: u32 = 65_507;
/// Largest datagram the *encrypted* UDP paths sweep in the throughput matrix.
/// DTLS is hard-bounded near here — one datagram per record with no application-
/// layer fragmentation. raw/ALE UDP-over-TLS can *carry* far larger datagrams
/// (verified lossless to 64 KiB when the sender is paced; the gateway reassembles
/// datagrams that span multiple TLS records), but a single-connection *blast* of
/// larger encrypted datagrams saturates the relay and delivers zero messages in
/// the measurement window — an invalid, auto-skipped result. That is a harness
/// ceiling, not a gateway limit, so the throughput matrix keeps the encrypted
/// datagram paths in the blast-measurable single-jumbo-frame band.
const ENCRYPTED_DATAGRAM_MAX: u32 = 9_000;

/// Largest datagram (bytes) the size sweep should emit for the given datagram
/// framing, so every generated row yields a valid measurement: plaintext routing
/// runs the full range to the UDP payload maximum; the encrypted paths (DTLS and
/// raw/ALE UDP-over-TLS) stay in the blast-measurable band.
fn datagram_size_cap(protocol: &Value) -> u32 {
    match protocol.get("type").and_then(Value::as_str) {
        Some("none") => UDP_PAYLOAD_MAX,
        _ => ENCRYPTED_DATAGRAM_MAX,
    }
}

fn profile_sizes(profile: &Profile, dimensions: &Dimensions) -> Vec<u32> {
    if profile.message_class == "datagram" {
        let cap = datagram_size_cap(&profile.protocol);
        dimensions
            .datagram_message_sizes
            .iter()
            .copied()
            .filter(|&size| size <= cap)
            .collect()
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
        32_768 => "32KB".to_string(),
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
    fn datagram_sizes_are_capped_per_framing() {
        let spec = production_spec();
        let dims = &spec.dimensions;
        let profile = |proto: Value| -> Profile {
            serde_json::from_value(json!({
                "id": "p", "protocol": proto,
                "interfaces": ["udp"], "chains": ["scg-direct"],
                "message_class": "datagram"
            }))
            .expect("datagram profile parses")
        };

        // Plaintext routing relays a whole datagram and keeps delivering under
        // blast, so it sweeps the full range to the UDP payload maximum.
        let routing = profile_sizes(
            &profile(json!({ "type": "none", "protection_mode": "routing-only" })),
            dims,
        );
        assert!(
            routing.contains(&65_507),
            "plaintext routing reaches the UDP max"
        );
        assert!(routing.iter().all(|&s| s <= UDP_PAYLOAD_MAX));

        // The encrypted datagram paths (DTLS and raw/ALE UDP-over-TLS) stay in the
        // blast-measurable single-jumbo-frame band: a single-connection blast of
        // larger encrypted datagrams saturates and delivers zero (invalid) results.
        for proto in [
            json!({ "type": "dtls", "version": "1.2" }),
            json!({ "type": "tls", "version": "1.3", "app_protocol": "raw" }),
            json!({ "type": "tls", "version": "1.3", "app_protocol": "ale" }),
        ] {
            let sizes = profile_sizes(&profile(proto), dims);
            assert!(sizes.iter().all(|&s| s <= ENCRYPTED_DATAGRAM_MAX));
            assert!(
                !sizes.contains(&16_384),
                "encrypted paths never blast beyond the jumbo band"
            );
            assert_eq!(sizes.last().copied(), Some(9_000));
        }

        // Stream profiles are untouched by the datagram caps.
        let stream: Profile = serde_json::from_value(json!({
            "id": "s", "protocol": { "type": "tls", "version": "1.3" },
            "interfaces": ["tcp"], "chains": ["scg-direct"]
        }))
        .unwrap();
        assert_eq!(profile_sizes(&stream, dims), dims.stream_message_sizes);
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
            // Datagram (udp) transports stay single-connection by design: a UDP "connection"
            // is a flow, and the DTLS/UDP gateway path has one shared backend datagram flow
            // that cannot report independent parallel connections (the `dtls_multi_connection`
            // limitation).
            if interface == Some("udp") {
                assert_eq!(row["connections"].as_u64(), Some(1));
            }
            // Stream transports (unix/shm and transparent tproxy) sweep the nightly connection
            // ladder — each connection is an independent stream (unix/shm provision their own
            // gRPC + SCM_RIGHTS endpoint; tproxy opens a fresh transparent TcpStream per
            // connection through the iptables redirect, see transport::tproxy::loopback_pair) —
            // so they can be compared with TCP at matched concurrency, but they do not opt into
            // the scalability tier's 256/1024 fan-out.
            if interface == Some("unix") || interface == Some("shm") || interface == Some("tproxy")
            {
                let conns = row["connections"].as_u64().unwrap();
                assert!(
                    [1, 4, 16, 64].contains(&conns),
                    "unix/shm/tproxy connections must stay within the nightly ladder, got {conns}"
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
    fn limitations_are_emitted_as_blocked_rows_in_every_tier() {
        let spec = production_spec();
        for tier in [Tier::Catalog, Tier::Nightly, Tier::Canonical] {
            let expanded = expand_profiles(&spec, tier).unwrap();
            let blocked: Vec<&Value> = rows(&expanded)
                .iter()
                .filter(|row| row["enabled"] == Value::Bool(false))
                .collect();
            assert_eq!(
                blocked.len(),
                spec.limitations.len(),
                "every catalogued limitation must surface as a disabled row in {tier:?}"
            );
            for row in &blocked {
                assert!(row["name"].as_str().unwrap().starts_with("blocked_"));
                assert!(row["disabled_reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()));
            }

            // WireGuard is deliberately outside the unified run (privileged
            // scripts/wg_bench.sh orchestration); its blocked row must say so.
            let wg = blocked
                .iter()
                .find(|row| row["name"] == "blocked_wireguard_script_orchestrated")
                .unwrap_or_else(|| panic!("{tier:?} must carry the wireguard blocked row"));
            assert_eq!(wg["protocol"]["type"], "wireguard");
            assert_eq!(wg["sender"]["interface"], "udp");
            assert!(wg["disabled_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("wg_bench.sh")));
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

    #[test]
    fn profile_optimization_flags_are_stamped_only_when_present() {
        // A profile that declares `optimization_flags` (e.g. the fixed-slot SHM
        // ring) stamps them onto every scenario it emits — throughput and
        // latency — while a flag-less profile stays byte-for-byte clean.
        let spec: MatrixSpec = serde_json::from_value(json!({
            "suite": { "name": "x" },
            "dimensions": {
                "stream_message_sizes": [64], "datagram_message_sizes": [64],
                "canonical_connections": [1], "nightly_connections": [1],
                "scalability_connections": [1], "catalog_connections": [1],
                "canonical_stream_message_size": 64, "canonical_datagram_message_size": 64
            },
            "profiles": [
                {
                    "id": "routing_shmslot",
                    "protocol": { "type": "none", "protection_mode": "routing-only" },
                    "interfaces": ["shm"], "chains": ["scg-direct"], "tiers": ["nightly"],
                    "optimization_flags": { "shm_ring_kind": "slot", "shm_g2c_notify": "futex" }
                },
                {
                    "id": "routing_shm",
                    "protocol": { "type": "none", "protection_mode": "routing-only" },
                    "interfaces": ["shm"], "chains": ["scg-direct"], "tiers": ["nightly"]
                }
            ],
            "interface_comparison": { "paths": [{ "id":"tcp", "interface":"tcp", "gateway":false }, { "id":"scg", "interface":"tcp", "gateway":true }], "throughput_message_sizes": [64], "throughput_connections": [1], "latency_message_sizes": [64], "latency_connections": [1] }
        }))
        .unwrap();
        let nightly = expand_profiles(&spec, Tier::Nightly).unwrap();
        let (mut slot_seen, mut plain_seen) = (0, 0);
        for row in rows(&nightly) {
            let name = row["name"].as_str().unwrap_or("");
            if name.contains("shmslot") {
                slot_seen += 1;
                assert_eq!(row["optimization_flags"]["shm_ring_kind"], "slot");
                assert_eq!(row["optimization_flags"]["shm_g2c_notify"], "futex");
            } else if name.contains("routing_shm") {
                plain_seen += 1;
                assert!(
                    row.get("optimization_flags").is_none(),
                    "flag-less profile carries no optimization_flags key: {name}"
                );
            }
        }
        // Both throughput and latency rows for the slot profile must be stamped.
        assert!(
            slot_seen >= 2,
            "slot profile emits stamped throughput + latency rows"
        );
        assert!(plain_seen >= 1, "byte-stream profile emits clean rows");
    }
}
