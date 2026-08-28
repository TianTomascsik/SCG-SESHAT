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
    /// IP address family (`ipv4` / `ipv6`) stamped onto every scenario this
    /// profile emits, threading through to the gateway path's bind/connect
    /// addresses. `ipv4` (the default) leaves rows byte-for-byte unchanged;
    /// `ipv6` stamps `address_family` and rewrites loopback sender targets to
    /// bracketed `[::1]:port` form. Only meaningful for IP interfaces
    /// (tcp/udp/tproxy).
    #[serde(default = "ipv4_family")]
    address_family: String,
}

fn ipv4_family() -> String {
    "ipv4".to_string()
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

/// Build every committed matrix document as an in-memory `(filename, JSON)`
/// pair. Kept separate from disk I/O so a unit test can regenerate the whole set
/// and byte-compare it against the checked-in files (the "codegen --check" guard
/// in `tests::checked_in_generated_files_are_current`).
fn render_documents(
    spec: &MatrixSpec,
) -> Result<Vec<(&'static str, Value)>, Box<dyn std::error::Error>> {
    Ok(vec![
        (
            "matrix_catalog.json",
            suite_document(
                spec,
                "Benchmark matrix catalog (compatible and blocked combinations)",
                expand_profiles(spec, Tier::Catalog)?,
            ),
        ),
        (
            "full_matrix.json",
            suite_document(
                spec,
                "Generated executable nightly benchmark matrix (disabled blocked_* rows document deliberate non-coverage)",
                expand_profiles(spec, Tier::Nightly)?,
            ),
        ),
        (
            "canonical_matrix.json",
            suite_document(
                spec,
                "Generated compact canonical benchmark matrix (disabled blocked_* rows document deliberate non-coverage)",
                expand_profiles(spec, Tier::Canonical)?,
            ),
        ),
        (
            "interface_comparison.json",
            suite_document(
                spec,
                "Matched loopback, SCG TCP, TPROXY, UDS, and SHM comparison suite",
                expand_interface_comparison(spec)?,
            ),
        ),
        (
            "hotreload_matrix.json",
            suite_document(
                spec,
                "Generated compatible hot-reload scenarios (nightly tier)",
                expand_hotreload(spec)?,
            ),
        ),
        (
            "smoke_matrix.json",
            with_default_overrides(
                suite_document(
                    spec,
                    "Generated minimal smoke matrix: every capability path once at the canonical size (no payload-size or connection sweep)",
                    expand_smoke(spec)?,
                ),
                // A smoke pass wants a single short run per path; genuine reload
                // timing rows override this back up per-scenario.
                &[("runs", 1), ("duration_secs", 2), ("warmup_secs", 1), ("cooldown_secs", 0)],
            ),
        ),
        (
            "everything_matrix.json",
            suite_document(
                spec,
                "Generated exhaustive executable matrix: every compatible profile in every valid combination (full message-size range × catalog connection ladder, plus the latency, cipher, and handshake sweeps)",
                expand_profiles(spec, Tier::Everything)?,
            ),
        ),
    ])
}

/// Merge a set of integer `defaults` overrides into a suite document (used to
/// give the smoke matrix its own short-run defaults without editing the spec).
fn with_default_overrides(mut doc: Value, pairs: &[(&str, u64)]) -> Value {
    if let Some(defaults) = doc.get_mut("defaults").and_then(Value::as_object_mut) {
        for (key, value) in pairs {
            defaults.insert((*key).to_string(), Value::from(*value));
        }
    }
    doc
}

/// Generate all committed matrix files from `spec_path`.
pub fn generate(spec_path: &Path, out_dir: &Path) -> Result<Generated, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(spec_path)?;
    let spec: MatrixSpec = serde_json::from_str(&text)?;
    validate_spec(&spec)?;
    fs::create_dir_all(out_dir)?;

    let documents = render_documents(&spec)?;
    let files = documents.len();
    let mut scenarios = 0usize;
    for (name, document) in &documents {
        scenarios += document
            .get("scenarios")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        fs::write(
            out_dir.join(name),
            format!("{}\n", serde_json::to_string_pretty(document)?),
        )?;
    }
    Ok(Generated { files, scenarios })
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
    /// Exhaustive *executable* cross-product: every profile (regardless of its
    /// tier tags, so `tiers: []` profiles are included), swept over the full
    /// message-size range and the catalog connection ladder, plus the latency,
    /// cipher, and handshake sweeps. This is the "test everything in every
    /// combination" tier — the largest suite that still runs end-to-end.
    Everything,
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
        // Catalog (reference) and Everything (exhaustive executable) both ignore
        // per-profile tier tags, so a profile carrying `tiers: []` — one held out
        // of canonical/nightly on purpose, e.g. subset146 keeping the thesis-era
        // tiers byte-identical — still gets full coverage here.
        if !matches!(tier, Tier::Catalog | Tier::Everything)
            && !profile.tiers.iter().any(|t| tier_name(tier) == t)
        {
            continue;
        }
        let sizes = match tier {
            Tier::Catalog | Tier::Nightly | Tier::Everything => {
                profile_sizes(profile, &spec.dimensions)
            }
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
            // Everything sweeps the widest ladder the catalog documents; the
            // per-profile `connections` pinning below still caps UDP→[1] and
            // tproxy→[1,4,16,64].
            Tier::Catalog | Tier::Everything => spec.dimensions.catalog_connections.clone(),
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
                        stamp_address_family(&mut row, &profile.address_family);
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
                        stamp_address_family(&mut lat_row, &profile.address_family);
                        push_unique(&mut scenarios, &mut names, lat_name, lat_row)?;
                    }
                }
            }
        }
    }

    append_cipher_scenarios(&mut scenarios, &mut names, spec, tier)?;
    append_handshake_scenarios(&mut scenarios, &mut names, tier)?;

    append_blocked_rows(&mut scenarios, &mut names, spec)?;

    Ok(Value::Array(scenarios))
}

/// Emit the catalogued limitations as explicit disabled `blocked_*` rows.
///
/// Every generated suite (catalog, nightly, canonical, everything, and the smoke
/// matrix) carries these, not only the reference catalog, so any suite config
/// self-documents what is deliberately not covered (e.g. WireGuard, which is
/// benchmarked only by the privileged scripts/wg_bench.sh orchestration via
/// scripts/perf_gate.sh). This is execution-safe: the runner, the
/// progress/duplicate accounting, and the wall-time estimate all filter on
/// `enabled` (src/commands.rs, config::estimate_total_secs), validation
/// short-circuits disabled rows into a SKIP note, and executed/skipped report
/// totals are rebuilt from on-disk scenario directories that disabled rows never
/// create.
fn append_blocked_rows(
    scenarios: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
    spec: &MatrixSpec,
) -> Result<(), Box<dyn std::error::Error>> {
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
        push_unique(scenarios, names, name, row)?;
    }
    Ok(())
}

/// Minimal per-capability smoke matrix: exercise every profile path once at the
/// canonical message size and a single connection, plus one representative of
/// each cross-cutting dimension (closed-loop latency, cipher override, handshake
/// churn, session resumption, hot-reload, direct-loopback baseline, and
/// multi-stream scheduling). It sweeps **no** payload sizes or connection
/// ladders — its job is "does every path still run end-to-end", not "how fast".
/// Every name is `smoke_`-prefixed so the file composes cleanly with any other
/// config in an ad-hoc `suite --config` run.
fn expand_smoke(spec: &MatrixSpec) -> Result<Value, Box<dyn std::error::Error>> {
    let mut scenarios = Vec::new();
    let mut names = BTreeSet::new();

    // 1. Every profile × chain, once, at the canonical size / 1 connection.
    for profile in &spec.profiles {
        let size = canonical_size(profile, &spec.dimensions);
        for interface in &profile.interfaces {
            for chain in &profile.chains {
                let name = format!(
                    "smoke_{}_{}_{}",
                    profile.id,
                    interface,
                    chain.replace("scg-", "")
                );
                let ordinal = scenarios.len();
                let mut row = scenario(
                    &profile.id,
                    "smoke",
                    interface,
                    &profile.protocol,
                    true,
                    chain,
                    size,
                    1,
                    &profile.requirements,
                    None,
                    ordinal,
                );
                stamp_optimization_flags(&mut row, &profile.optimization_flags);
                stamp_address_family(&mut row, &profile.address_family);
                push_unique(&mut scenarios, &mut names, name, row)?;
            }
        }
    }

    // 2. One closed-loop ping-pong latency rep per plaintext-routing transport
    //    (no DTLS — pingpong + DTLS is auto-skipped by the runner). Look the
    //    profiles up by id so each rep inherits the transport's requirements
    //    (tproxy → cap_net_admin) and optimization flags (shmslot → slot ring).
    for id in [
        "routing_tcp",
        "routing_udp",
        "routing_uds",
        "routing_shm",
        "routing_shmslot",
        "routing_tproxy",
    ] {
        let Some(profile) = spec.profiles.iter().find(|p| p.id == id) else {
            continue;
        };
        let interface = &profile.interfaces[0];
        let size = canonical_size(profile, &spec.dimensions);
        let ordinal = scenarios.len();
        let mut row = scenario(
            &profile.id,
            "smoke-latency",
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
        row["mode"] = Value::String("pingpong".to_string());
        stamp_optimization_flags(&mut row, &profile.optimization_flags);
        stamp_address_family(&mut row, &profile.address_family);
        push_unique(&mut scenarios, &mut names, format!("smoke_lat_{id}"), row)?;
    }

    // 3. One cipher-override rep per TLS/kTLS/DTLS engine (first suite, canonical
    //    size) so the explicit-cipher config path is exercised on every engine.
    let canonical_stream = spec.dimensions.canonical_stream_message_size;
    let canonical_dgram = spec.dimensions.canonical_datagram_message_size;
    if let Some(suite) = spec.cipher_matrix.tls12.first() {
        push_cipher_scenario(
            &mut scenarios,
            &mut names,
            "smoke_cipher_tls12",
            "tcp",
            json!({ "type": "tls", "version": "1.2", "cipher_suite": suite }),
            &["openssl".to_string()],
            canonical_stream,
            canonical_stream,
        )?;
        push_cipher_scenario(
            &mut scenarios,
            &mut names,
            "smoke_cipher_ktls12",
            "tcp",
            json!({ "type": "tls", "kernel": true, "version": "1.2", "cipher_suite": suite }),
            &["openssl".to_string(), "ktls".to_string()],
            canonical_stream,
            canonical_stream,
        )?;
        push_cipher_scenario(
            &mut scenarios,
            &mut names,
            "smoke_cipher_dtls12",
            "udp",
            json!({ "type": "dtls", "version": "1.2", "cipher_suite": suite }),
            &["openssl".to_string()],
            canonical_dgram,
            canonical_dgram,
        )?;
    }
    if let Some(suite) = spec.cipher_matrix.tls13.first() {
        push_cipher_scenario(
            &mut scenarios,
            &mut names,
            "smoke_cipher_tls13",
            "tcp",
            json!({ "type": "tls", "version": "1.3", "cipher_suite": suite }),
            &["openssl".to_string()],
            canonical_stream,
            canonical_stream,
        )?;
        push_cipher_scenario(
            &mut scenarios,
            &mut names,
            "smoke_cipher_ktls13",
            "tcp",
            json!({ "type": "tls", "kernel": true, "version": "1.3", "cipher_suite": suite }),
            &["openssl".to_string(), "ktls".to_string()],
            canonical_stream,
            canonical_stream,
        )?;
    }

    // 4. One handshake-churn rep per auth/kex axis (connrate mode, churn width 4).
    push_connrate_handshake(
        &mut scenarios,
        &mut names,
        "smoke_handshake_ecdsa",
        json!({ "type": "tls", "version": "1.3", "cert_key_type": "ecdsa" }),
        4,
    )?;
    push_connrate_handshake(
        &mut scenarios,
        &mut names,
        "smoke_handshake_rsa",
        json!({ "type": "tls", "version": "1.3", "cert_key_type": "rsa" }),
        4,
    )?;
    push_connrate_handshake(
        &mut scenarios,
        &mut names,
        "smoke_handshake_kex_x25519",
        json!({ "type": "tls", "version": "1.3", "cert_key_type": "ecdsa", "kex_group": "X25519" }),
        4,
    )?;
    push_connrate_handshake(
        &mut scenarios,
        &mut names,
        "smoke_handshake_kex_p256",
        json!({ "type": "tls", "version": "1.3", "cert_key_type": "ecdsa", "kex_group": "P-256" }),
        4,
    )?;

    // 5. TLS session-resumption rep (connrate so the reconnects actually
    //    exercise the ticket path).
    {
        let ordinal = scenarios.len();
        let mut row = scenario(
            "resumption",
            "smoke-resumption",
            "tcp",
            &json!({ "type": "tls", "version": "1.3", "resumption": true }),
            true,
            "scg-direct",
            canonical_stream,
            1,
            &["openssl".to_string()],
            None,
            ordinal,
        );
        row["mode"] = Value::String("connrate".to_string());
        push_unique(
            &mut scenarios,
            &mut names,
            "smoke_resumption_tls13".to_string(),
            row,
        )?;
    }

    // 6. Hot-reload reps: each reload action once on the TLS 1.3 TCP path at a
    //    single sub-saturation connection. The reload timeline needs
    //    trigger_at(3) + after-window(5) inside the measurement phase, so these
    //    rows pin a longer duration than the smoke default (2 s); per-scenario
    //    overrides survive the suite's `--quick`/duration overrides.
    for action in [
        "add_connection",
        "remove_connection",
        "invalid_config",
        "rotate_cert",
    ] {
        let ordinal = scenarios.len();
        let mut row = scenario(
            "tls13_tcp",
            "smoke-hotreload",
            "tcp",
            &json!({ "type": "tls", "version": "1.3" }),
            true,
            "scg-direct",
            canonical_stream,
            1,
            &["openssl".to_string()],
            None,
            ordinal,
        );
        let sender = row
            .get_mut("sender")
            .and_then(Value::as_object_mut)
            .expect("smoke scenario sender is object");
        sender.insert("rate_limit_mbps".to_string(), Value::from(100.0));
        row["reload_event"] = json!({
            "trigger_at_secs": 3,
            "action": action,
            // The rotated rule's established connections are severed by the
            // changed-bucket restart, so drops are expected there.
            "expect_zero_drops": action != "rotate_cert",
            "measure_window_before_secs": 2,
            "measure_window_after_secs": 5,
        });
        let object = row.as_object_mut().expect("scenario object");
        object.insert("duration_secs".to_string(), Value::from(10_u64));
        object.insert("warmup_secs".to_string(), Value::from(1_u64));
        push_unique(
            &mut scenarios,
            &mut names,
            format!("smoke_hotreload_{action}"),
            row,
        )?;
    }

    // 7. Direct-loopback baselines (no gateway) — exercises the non-gateway
    //    measurement engine on both a stream and a datagram transport.
    for (label, interface, size) in [
        ("tcp", "tcp", canonical_stream),
        ("udp", "udp", canonical_dgram),
    ] {
        let ordinal = scenarios.len();
        let row = scenario(
            "loopback",
            "smoke-baseline",
            interface,
            &json!({ "type": "none" }),
            false,
            "scg-direct",
            size,
            1,
            &[],
            None,
            ordinal,
        );
        push_unique(
            &mut scenarios,
            &mut names,
            format!("smoke_loopback_{label}"),
            row,
        )?;
    }

    // 8. Multi-stream scheduling rep (a safety class alongside a bulk class on
    //    the same gateway) so the DSCP-priority scheduler path is covered.
    {
        let mut row = json!({
            "name": "smoke_multistream",
            "category": "smoke-scheduling",
            "message_size_bytes": 1024,
            "connections": 1,
            "gateway": { "enabled": true, "chain": "scg-direct" },
            "protocol": { "type": "none" },
            "streams": [
                {
                    "role": "safety",
                    "interface": "tcp",
                    "target_addr": "127.0.0.1:17990",
                    "message_size_bytes": 256,
                    "pattern": "periodic",
                    "interval_us": 500,
                    "priority": { "dscp_tag": "EF", "traffic_class": "safety" },
                    "protocol": { "type": "none" }
                },
                {
                    "role": "bulk",
                    "interface": "tcp",
                    "target_addr": "127.0.0.1:17990",
                    "message_size_bytes": 4096,
                    "priority": { "dscp_tag": "BE", "traffic_class": "normal" },
                    "protocol": { "type": "none" }
                }
            ],
            "sender": { "interface": "tcp", "target_addr": "127.0.0.1:17990", "pattern": "sustained" },
            "description": "smoke: multi-stream DSCP scheduling (safety + bulk), tcp/plain"
        });
        row["name"] = Value::String("smoke_multistream".to_string());
        push_unique(
            &mut scenarios,
            &mut names,
            "smoke_multistream".to_string(),
            row,
        )?;
    }

    // 9. The catalogued impossibilities, as disabled blocked_* rows, so the smoke
    //    file documents the same gaps every other generated suite does.
    append_blocked_rows(&mut scenarios, &mut names, spec)?;

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

/// Stamp a profile's IP address `family` onto a generated scenario row.
///
/// The default `ipv4` is a no-op so v4 rows stay byte-for-byte identical. For
/// `ipv6` it inserts `"address_family": "ipv6"` and rewrites an IP sender's
/// `127.0.0.1:port` loopback target to bracketed `[::1]:port` form so the loaded
/// scenario validates and drives a v6 path end to end. UDS/SHM targets (which
/// contain no `127.0.0.1:` prefix) are left untouched.
fn stamp_address_family(row: &mut Value, family: &str) {
    if family != "ipv6" {
        return;
    }
    let Some(obj) = row.as_object_mut() else {
        return;
    };
    obj.insert(
        "address_family".to_string(),
        Value::String("ipv6".to_string()),
    );
    if let Some(sender) = obj.get_mut("sender").and_then(Value::as_object_mut) {
        if let Some(target) = sender.get("target_addr").and_then(Value::as_str) {
            if let Some(port) = target.strip_prefix("127.0.0.1:") {
                sender.insert(
                    "target_addr".to_string(),
                    Value::String(format!("[::1]:{port}")),
                );
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
        Tier::Everything => "everything",
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
        // Each generated tier plus the smoke matrix must carry the full set of
        // catalogued impossibilities as disabled rows.
        let tier_expansions = [
            Tier::Catalog,
            Tier::Nightly,
            Tier::Canonical,
            Tier::Everything,
        ]
        .into_iter()
        .map(|tier| (format!("{tier:?}"), expand_profiles(&spec, tier).unwrap()));
        let smoke = std::iter::once(("smoke".to_string(), expand_smoke(&spec).unwrap()));

        for (label, expanded) in tier_expansions.chain(smoke) {
            let blocked: Vec<&Value> = rows(&expanded)
                .iter()
                .filter(|row| row["enabled"] == Value::Bool(false))
                .collect();
            assert_eq!(
                blocked.len(),
                spec.limitations.len(),
                "every catalogued limitation must surface as a disabled row in {label}"
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
                .unwrap_or_else(|| panic!("{label} must carry the wireguard blocked row"));
            assert_eq!(wg["protocol"]["type"], "wireguard");
            assert_eq!(wg["sender"]["interface"], "udp");
            assert!(wg["disabled_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("wg_bench.sh")));
        }
    }

    /// The exact file set `generate` writes. `checked_in_generated_files_are_current`
    /// maps each name to its committed copy; keep the two in lockstep.
    fn checked_in_generated_file(name: &str) -> &'static str {
        match name {
            "matrix_catalog.json" => include_str!("../configs/matrix_catalog.json"),
            "full_matrix.json" => include_str!("../configs/full_matrix.json"),
            "canonical_matrix.json" => include_str!("../configs/canonical_matrix.json"),
            "interface_comparison.json" => include_str!("../configs/interface_comparison.json"),
            "hotreload_matrix.json" => include_str!("../configs/hotreload_matrix.json"),
            "smoke_matrix.json" => include_str!("../configs/smoke_matrix.json"),
            "everything_matrix.json" => include_str!("../configs/everything_matrix.json"),
            other => panic!("no checked-in copy mapped for generated file '{other}'"),
        }
    }

    #[test]
    fn checked_in_generated_files_are_current() {
        // Regenerate every committed matrix in memory and byte-compare it to the
        // file on disk. Generation is deterministic (sorted JSON keys, stable
        // ordering), so any drift means someone edited a generated file by hand
        // or changed matrix_spec.json / the generator without re-running
        // `seshat matrix generate`.
        let spec = production_spec();
        let documents = render_documents(&spec).unwrap();
        assert_eq!(documents.len(), 7, "generate writes exactly seven files");
        for (name, document) in documents {
            let rendered = format!("{}\n", serde_json::to_string_pretty(&document).unwrap());
            assert_eq!(
                rendered,
                checked_in_generated_file(name),
                "{name} is stale — run `seshat matrix generate` and commit the result"
            );
        }
    }

    #[test]
    fn smoke_and_everything_cover_every_profile() {
        // Every declared profile must appear at least once in both the smoke
        // matrix (per-capability verification) and the everything matrix
        // (exhaustive coverage) — the mechanical half of the SESHAT-parity rule.
        let spec = production_spec();
        let smoke = expand_smoke(&spec).unwrap();
        let everything = expand_profiles(&spec, Tier::Everything).unwrap();
        let names_in = |value: &Value| -> Vec<String> {
            rows(value)
                .iter()
                .filter_map(|row| row.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        };
        let smoke_names = names_in(&smoke);
        let everything_names = names_in(&everything);
        for profile in &spec.profiles {
            let token = format!("_{}_", profile.id);
            assert!(
                smoke_names.iter().any(|n| n.contains(&token)),
                "smoke matrix is missing profile '{}'",
                profile.id
            );
            assert!(
                everything_names.iter().any(|n| n.contains(&token)),
                "everything matrix is missing profile '{}'",
                profile.id
            );
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

    #[test]
    fn profile_address_family_is_stamped_only_for_ipv6() {
        // An `ipv6` profile stamps `address_family` and rewrites its IP sender's
        // loopback target to bracketed `[::1]:port`; the default-`ipv4` profile
        // stays byte-for-byte clean (no key, `127.0.0.1` target).
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
                    "id": "routing_tcp_v6",
                    "protocol": { "type": "none", "protection_mode": "routing-only" },
                    "interfaces": ["tcp"], "chains": ["scg-direct"], "tiers": ["nightly"],
                    "address_family": "ipv6"
                },
                {
                    "id": "routing_tcp",
                    "protocol": { "type": "none", "protection_mode": "routing-only" },
                    "interfaces": ["tcp"], "chains": ["scg-direct"], "tiers": ["nightly"]
                }
            ],
            "interface_comparison": { "paths": [{ "id":"tcp", "interface":"tcp", "gateway":false }, { "id":"scg", "interface":"tcp", "gateway":true }], "throughput_message_sizes": [64], "throughput_connections": [1], "latency_message_sizes": [64], "latency_connections": [1] }
        }))
        .unwrap();
        let nightly = expand_profiles(&spec, Tier::Nightly).unwrap();
        let (mut v6_seen, mut v4_seen) = (0, 0);
        for row in rows(&nightly) {
            let name = row["name"].as_str().unwrap_or("");
            let target = row["sender"]["target_addr"].as_str().unwrap_or("");
            if name.contains("_v6") {
                v6_seen += 1;
                assert_eq!(row["address_family"], "ipv6");
                assert!(
                    target.starts_with("[::1]:"),
                    "ipv6 sender target must be bracketed: {target}"
                );
            } else {
                v4_seen += 1;
                assert!(
                    row.get("address_family").is_none(),
                    "ipv4 profile carries no address_family key: {name}"
                );
                assert!(
                    target.starts_with("127.0.0.1:"),
                    "ipv4 sender target stays v4: {target}"
                );
            }
        }
        assert!(
            v6_seen >= 2,
            "ipv6 profile emits stamped throughput + latency rows"
        );
        assert!(v4_seen >= 1, "ipv4 profile emits clean rows");
    }
}
