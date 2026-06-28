//! Subcommand dispatch and handlers.
//!
//! Phase 0 implements `validate`, `list`, and `run --dry-run` (config-driven);
//! `sysinfo` lands in WP0.3 and the remaining commands in later phases.
//! Handlers return a boxed-error result; `main` maps `Err` to a non-zero exit.

use crate::cli::{
    CalibrateArgs, Command, ImpairArgs, ListArgs, MatrixArgs, MatrixCommand, ReceiverArgs,
    ReportArgs, RunArgs, SenderArgs, SetupArgs, SysinfoArgs, SysinfoFormat, TeardownArgs,
    TopologyKind, ValidateArgs,
};
use crate::config::{
    self, AppProtocol, Config, Defaults, GatewayChain, Interface, MetricsBackend, Mode,
    OutlierRemoval, ProtectionMode, ProtocolType, Scenario, TlsVersion, TopologyMode,
    ValidationReport,
};
use crate::console;
use crate::gateway::logscan::{self, Effective};
use crate::gateway::{self, SecuritySpec};
use crate::metrics::app::FlowSummary;
use crate::metrics::system::{self, SystemSampler};
use crate::proto::wire::HEADER_LEN;
use crate::report::csv::{num, Csv};
use crate::report::results::{
    sanitize, ReloadArtifact, ResultDir, ScenarioArtifacts, ScenarioOutcome,
};
use crate::run::affinity;
use crate::run::calibrate::{self, Calibration};
use crate::run::engine::{self, RunMode, RunParams, RunStats};
use crate::run::saturation::{self, SweepPlan, SweepResult};
use crate::transport::gateway::{GatewayDut, GatewayTcpTransport, GatewayUdpTransport};
use crate::transport::shm::GatewayShmTransport;
use crate::transport::uds::GatewayUdsTransport;
use crate::transport::{tcp::TcpTransport, udp::UdpTransport, Transport};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Result type for command handlers.
pub type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// Route a parsed [`Command`] to its handler.
pub fn dispatch(command: Command) -> CmdResult {
    match command {
        Command::Run(args) => run(args),
        Command::Sender(args) => sender(args),
        Command::Receiver(args) => receiver(args),
        Command::Report(args) => report(args),
        Command::Validate(args) => validate(args),
        Command::List(args) => list(args),
        Command::Calibrate(args) => calibrate(args),
        Command::Sysinfo(args) => sysinfo(args),
        Command::Setup(args) => setup(args),
        Command::Teardown(args) => teardown(args),
        Command::Impair(args) => impair(args),
        Command::Matrix(args) => matrix(args),
    }
}

/// Expand the versioned matrix source into the committed benchmark suites.
fn matrix(args: MatrixArgs) -> CmdResult {
    match args.command {
        MatrixCommand::Generate(args) => {
            let generated = crate::matrix::generate(&args.spec, &args.out_dir)?;
            console::line(&format!(
                "generated {} scenario rows across {} suite file(s)",
                generated.scenarios, generated.files
            ));
            Ok(())
        }
    }
}

fn run(args: RunArgs) -> CmdResult {
    let mut cfg = config::load(&args.config)?;
    apply_overrides(&mut cfg, &args)?;

    let report = config::validate(&cfg);

    console::banner();

    if args.dry_run {
        render_dry_run(&args, &cfg, &report);
        if !report.ok() {
            return Err("config invalid \u{2014} see report above".into());
        }
        return Ok(());
    }

    if !report.ok() {
        render_validation(&args.config.display().to_string(), &cfg, &report);
        return Err("config invalid \u{2014} fix errors before running".into());
    }

    log::info!(
        "config valid: {} enabled scenario(s); estimated wall time {}",
        report.enabled_count(),
        config::human_secs(config::estimate_total_secs(&cfg))
    );

    execute_suite(&args, &cfg)
}

/// Run every enabled scenario the Phase 1 engine can drive on a local loopback
/// pair; scenarios needing gateway/crypto/topology features are skipped with a
/// notice until the relevant phase lands. Results are written to a timestamped
/// directory under `--output-dir` (default `./results`).
fn execute_suite(args: &RunArgs, cfg: &Config) -> CmdResult {
    let base = args
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("results"));
    let mut rdir = ResultDir::create(&base)?;
    let host = crate::sysinfo::SysInfo::collect();
    // Reproducibility preflight: warn (don't block) when the host is not in a
    // controlled state, so results are interpreted with that caveat in mind.
    for w in crate::sysinfo::preflight_warnings(&host) {
        log::warn!("preflight: {w}");
    }
    if host.wsl && !host.ktls_usable {
        log::warn!(
            "host is WSL with kTLS unavailable; any kTLS scenario runs as userspace TLS \
             (the effective_protocol column records the actual protocol per scenario)"
        );
    }
    if cfg.defaults.collect_system_metrics
        && cfg.defaults.metrics_backend == MetricsBackend::Perf
        && !system::PerfSampler::available()
    {
        log::warn!(
            "perf backend requested but `perf` is unavailable; perf_* result fields will be empty"
        );
    }
    if cfg.defaults.collect_system_metrics
        && cfg.defaults.metrics_backend == MetricsBackend::Ebpf
        && !system::MemCopySampler::available()
    {
        log::warn!(
            "ebpf backend requested but bpftrace is unavailable or unprivileged (needs root); \
             mem_* result fields will be empty"
        );
    }
    rdir.write_sysinfo(&host)?;

    // Resolve sender/receiver/gateway CPU pools once for the whole suite.
    let cores = resolve_core_plan(&cfg.defaults);

    // Cache harness ceilings by (transport, on-wire size, connections) so the
    // NFR-PERF headroom probe runs at most once per distinct scenario shape.
    let mut ceilings: HashMap<(String, u32, usize), f64> = HashMap::new();
    // Interface-latency rows use a shared fraction of the lowest successful
    // throughput in their preceding comparison group.  This prevents one
    // interface from being measured in queueing saturation while another is
    // mostly idle.
    let mut comparison_ceilings: HashMap<String, f64> = HashMap::new();
    let mut skipped = 0usize;

    // Per-SCG-PID `/proc` sampling rate (F-13b), or None when disabled.
    let sys_rate = system_metrics_rate(&cfg.defaults);

    // Probe a working gateway binary once, if any scenario needs the SCG.
    let needs_gateway = cfg
        .scenarios
        .iter()
        .filter(|s| s.enabled)
        .any(|s| gateway_plan(s).is_some());
    let gateway_binary = if needs_gateway {
        let probe_dir = base.join("gateway");
        let found = gateway::locate_working_binary(&probe_dir);
        if let Some(bin) = &found {
            log::info!("gateway binary: {}", bin.display());
        } else {
            log::warn!(
                "no gateway binary supports the required providers; SCG scenarios will be skipped"
            );
        }
        found
    } else {
        None
    };

    for scenario in cfg.scenarios.iter().filter(|s| s.enabled) {
        if let Some(reason) = unmet_requirements(scenario, &host) {
            log::warn!("scenario '{}': {reason}; skipping", scenario.name);
            rdir.record_skipped(scenario, &reason)?;
            skipped += 1;
            continue;
        }
        if let Some(transport) = loopback_transport(scenario) {
            let mut params = build_run_params(scenario, &cfg.defaults, &cores);
            apply_comparison_rate(scenario, &mut params, &comparison_ceilings);
            render_scenario_header(scenario, &params, &scenario_interface(scenario));
            if params.mode == RunMode::PingPong {
                // Closed-loop RTT: no calibration/saturation (those measure
                // bandwidth, which is not the point of a ping-pong scenario).
                let stats = engine::run_scenario(transport.as_ref(), &params, |i, s| {
                    render_pingpong_run_line(i, params.runs, s);
                })?;
                render_pingpong_result(&stats);
                rdir.record_scenario(
                    scenario,
                    &params,
                    &stats,
                    &ScenarioArtifacts {
                        loss_threshold_pct: cfg.defaults.loss_threshold_pct,
                        ..Default::default()
                    },
                )?;
                capture_comparison_ceiling(
                    scenario,
                    rdir.outcomes(),
                    cfg.defaults.loss_threshold_pct,
                    &mut comparison_ceilings,
                );
                continue;
            }
            if params.mode == RunMode::Connrate {
                // Connection churn: report rate + handshake latency; skip the
                // bandwidth-oriented calibration and saturation sweep.
                let stats = engine::run_scenario(transport.as_ref(), &params, |i, s| {
                    render_connrate_run_line(i, params.runs, s);
                })?;
                render_connrate_result(&stats);
                rdir.record_scenario(
                    scenario,
                    &params,
                    &stats,
                    &ScenarioArtifacts {
                        loss_threshold_pct: cfg.defaults.loss_threshold_pct,
                        ..Default::default()
                    },
                )?;
                capture_comparison_ceiling(
                    scenario,
                    rdir.outcomes(),
                    cfg.defaults.loss_threshold_pct,
                    &mut comparison_ceilings,
                );
                continue;
            }
            let stats = engine::run_scenario(transport.as_ref(), &params, |i, s| {
                render_run_line(i, params.runs, s);
            })?;
            render_scenario_result(&stats);

            let cal = calibrate_scenario(
                transport.as_ref(),
                &params,
                stats.throughput_gbps.mean,
                &mut ceilings,
                false,
                None,
            )?;
            render_calibration(&cal);

            let sweep = run_saturation_if_requested(
                scenario,
                transport.as_ref(),
                &params,
                cfg.defaults.loss_threshold_pct,
            )?;
            warn_if_overloaded(scenario, &stats, cfg.defaults.loss_threshold_pct);
            rdir.record_scenario(
                scenario,
                &params,
                &stats,
                &ScenarioArtifacts {
                    cal: Some(&cal),
                    sweep: sweep.as_ref(),
                    loss_threshold_pct: cfg.defaults.loss_threshold_pct,
                    ..Default::default()
                },
            )?;
            capture_comparison_ceiling(
                scenario,
                rdir.outcomes(),
                cfg.defaults.loss_threshold_pct,
                &mut comparison_ceilings,
            );
        } else if let Some(plan) = gateway_plan(scenario) {
            match gateway_binary.as_deref() {
                Some(binary) => {
                    let ran = if !scenario.streams.is_empty() {
                        run_multistream_scenario(
                            scenario,
                            &cfg.defaults,
                            &plan,
                            binary,
                            &mut rdir,
                            sys_rate,
                            &cores,
                        )?
                    } else if scenario.reload_event.is_some() {
                        run_hotreload_scenario(
                            scenario,
                            &cfg.defaults,
                            &plan,
                            binary,
                            &mut rdir,
                            sys_rate,
                            &cores,
                        )?
                    } else {
                        run_gateway_scenario(
                            scenario,
                            &cfg.defaults,
                            &plan,
                            binary,
                            &mut rdir,
                            &mut ceilings,
                            sys_rate,
                            &cores,
                            comparison_rate(scenario, &comparison_ceilings),
                        )?
                    };
                    if !ran {
                        rdir.record_skipped(
                            scenario,
                            "gateway path could not be provisioned or completed on this host",
                        )?;
                        skipped += 1;
                    } else {
                        capture_comparison_ceiling(
                            scenario,
                            rdir.outcomes(),
                            cfg.defaults.loss_threshold_pct,
                            &mut comparison_ceilings,
                        );
                    }
                }
                None => {
                    log::warn!(
                        "scenario '{}' [{} / {}] needs the SCG but no gateway binary is available; skipping",
                        scenario.name,
                        plan.transport_name,
                        scenario.protocol_label()
                    );
                    rdir.record_skipped(scenario, "no compatible SCG gateway binary found")?;
                    skipped += 1;
                }
            }
        } else {
            log::warn!(
                "scenario '{}' [{} / {}] needs features not yet implemented; skipping",
                scenario.name,
                scenario_interface(scenario),
                scenario.protocol_label()
            );
            rdir.record_skipped(scenario, "scenario path is not implemented by this harness")?;
            skipped += 1;
        }
    }

    let executed = rdir.outcomes().len();
    rdir.finish(cfg, &args.config, executed, skipped, &host)?;
    render_suite_summary(rdir.outcomes(), skipped, rdir.root());

    if executed == 0 {
        log::warn!("no scenarios were executable");
    }
    Ok(())
}

/// Return a common offered rate (Mbit/s) for a generated comparison latency
/// row.  The corresponding throughput group is executed first by the matrix
/// generator, so every available path contributes to the lowest ceiling.
fn comparison_rate(scenario: &Scenario, ceilings: &HashMap<String, f64>) -> Option<f64> {
    let comparison = scenario.comparison.as_ref()?;
    let group = comparison.calibration_group.as_ref()?;
    let fraction = comparison.calibration_fraction?;
    ceilings
        .get(group)
        .copied()
        .map(|gbps| gbps * 1_000.0 * fraction)
        .filter(|mbps| *mbps > 0.0)
}

fn apply_comparison_rate(
    scenario: &Scenario,
    params: &mut RunParams,
    ceilings: &HashMap<String, f64>,
) {
    if let Some(rate_mbps) = comparison_rate(scenario, ceilings) {
        params.sender.pattern = config::Pattern::Sustained;
        params.sender.rate_limit_mbps = Some(rate_mbps);
        params.sender.interval_us = None;
        log::info!(
            "scenario '{}': interface comparison latency rate {:.3} Mbit/s",
            scenario.name,
            rate_mbps
        );
    }
}

fn capture_comparison_ceiling(
    scenario: &Scenario,
    outcomes: &[ScenarioOutcome],
    loss_threshold_pct: f64,
    ceilings: &mut HashMap<String, f64>,
) {
    let Some(comparison) = &scenario.comparison else {
        return;
    };
    if scenario.category.as_deref() != Some("interface-comparison-throughput") {
        return;
    }
    let Some(outcome) = outcomes
        .last()
        .filter(|outcome| outcome.name == scenario.name)
    else {
        return;
    };
    if outcome.loss_pct > loss_threshold_pct || outcome.throughput_gbps <= 0.0 {
        return;
    }
    ceilings
        .entry(comparison.group.clone())
        .and_modify(|ceiling| *ceiling = ceiling.min(outcome.throughput_gbps))
        .or_insert(outcome.throughput_gbps);
}

/// Return a human-readable preflight failure for a generated scenario.  The
/// checks intentionally err on the side of a recorded skip: an optional host
/// capability must never turn into an unlabelled userspace fallback.
fn unmet_requirements(scenario: &Scenario, host: &crate::sysinfo::SysInfo) -> Option<String> {
    let requirements = &scenario.requirements;
    let mut missing = Vec::new();
    if requirements.openssl && !crate::pki::openssl_available() {
        missing.push("openssl CLI unavailable");
    }
    if requirements.ktls && !host.ktls_usable {
        missing.push("usable kTLS unavailable");
    }
    if requirements.dtls10 && !dtls10_available() {
        missing.push("DTLS 1.0 unavailable in the local OpenSSL policy");
    }
    if let Some(cipher) = scenario.protocol.cipher_suite.as_deref() {
        if !cipher_suite_available(scenario.protocol.version, cipher) {
            missing.push("configured OpenSSL cipher suite unavailable");
        }
    }
    if requirements.cap_net_admin && !has_cap_net_admin() {
        missing.push("CAP_NET_ADMIN unavailable");
    }
    if requirements.perf && !perf_available_for_current_process() {
        missing.push("perf events unavailable or not permitted");
    }
    if requirements.ebpf && !std::path::Path::new("/sys/fs/bpf").is_dir() {
        missing.push("eBPF filesystem unavailable");
    }
    (!missing.is_empty()).then(|| missing.join("; "))
}

fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            })
        })
        .map(|effective| effective & (1_u64 << CAP_NET_ADMIN) != 0)
        .unwrap_or(false)
}

fn perf_available_for_current_process() -> bool {
    system::PerfSampler::available()
        && std::process::Command::new("perf")
            .args(["stat", "-x,", "-e", "task-clock", "--", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}

fn dtls10_available() -> bool {
    // OpenSSL 3 can compile DTLS 1.0 out through its security policy.  Its
    // cipher listing is a cheap preflight; the actual gateway setup remains
    // authoritative and is also recorded as a skip if it fails.
    crate::pki::openssl_available()
        && std::process::Command::new("openssl")
            .args(["ciphers", "-v", "ALL:@SECLEVEL=0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}

fn cipher_suite_available(version: TlsVersion, cipher: &str) -> bool {
    if !crate::pki::openssl_available() || cipher.trim().is_empty() {
        return false;
    }
    let args: Vec<&str> = match version {
        TlsVersion::V1_3 => vec!["ciphers", "-s", "-tls1_3", "-ciphersuites", cipher],
        TlsVersion::V1_2 | TlsVersion::V1_0 => vec!["ciphers", "-s", cipher],
    };
    std::process::Command::new("openssl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Return a loopback transport if the scenario is executable without the
/// gateway: single TCP/UDP sender, no crypto, no gateway chaining, no streams.
fn loopback_transport(s: &Scenario) -> Option<Box<dyn Transport>> {
    if !s.streams.is_empty() || s.gateway.enabled || s.protocol.kind != ProtocolType::None {
        return None;
    }
    let sender = s.sender.as_ref()?;
    match sender.interface {
        Interface::Tcp => Some(Box::new(TcpTransport)),
        Interface::Udp => Some(Box::new(UdpTransport)),
        // UDS/SHM/TPROXY require the gateway.
        Interface::Unix | Interface::Shm | Interface::Tproxy => None,
    }
}

/// Security choice for a gateway-backed scenario (certs are generated at run
/// time, so this only records the protocol decision).
#[derive(Debug, Clone, Copy)]
enum GwSecurity {
    /// Plaintext L4 routing (no crypto).
    Routing,
    /// TLS, optionally kernel-offloaded (kTLS), at the given gateway version.
    Tls { version: &'static str, ktls: bool },
    /// Mutual TLS: both peers present a certificate verified against a CA.
    Mtls { version: &'static str, ktls: bool },
    /// Integrity-only TLS: authenticated but unencrypted (NULL cipher).
    IntegrityOnly { version: &'static str },
    /// DTLS over UDP, optionally mutually authenticated.
    Dtls { version: &'static str, mutual: bool },
}

/// Convert the validated SESHAT version into SCG's TLS spelling.  Validation
/// rejects TLS 1.0 before this dispatch path is reachable.
fn tls_version(version: TlsVersion) -> &'static str {
    match version {
        TlsVersion::V1_0 => "tls1.0",
        TlsVersion::V1_2 => "tls1.2",
        TlsVersion::V1_3 => "tls1.3",
    }
}

/// Convert the validated SESHAT version into SCG's DTLS spelling.  Validation
/// rejects DTLS 1.3 before a gateway plan can be executed.
fn dtls_version(version: TlsVersion) -> &'static str {
    match version {
        TlsVersion::V1_0 => "dtls1.0",
        TlsVersion::V1_2 => "dtls1.2",
        TlsVersion::V1_3 => "dtls1.3",
    }
}

/// Cipher configuration is version-specific in OpenSSL: TLS 1.2 uses the
/// legacy cipher-list API whereas TLS 1.3 uses the ciphersuites API.  Supplying
/// a TLS 1.3 suite to both used to make otherwise valid generated rows fail
/// before the benchmark started.
fn apply_cipher_override(spec: SecuritySpec, scenario: &Scenario) -> SecuritySpec {
    let Some(cipher) = scenario.protocol.cipher_suite.as_deref() else {
        return spec;
    };
    match scenario.protocol.version {
        TlsVersion::V1_2 | TlsVersion::V1_0 => spec.with_cipher_list(cipher),
        TlsVersion::V1_3 => spec.with_ciphersuites(cipher),
    }
}

/// A resolved plan to run a scenario through the SCG over TCP.
#[derive(Debug, Clone, Copy)]
struct GatewayPlan {
    security: GwSecurity,
    topology: gateway::Topology,
    transport_name: &'static str,
}

/// Map a scenario's protocol configuration to the appropriate `GwSecurity`. Used
/// by interface-agnostic dispatch (UDS, SHM) where the transport is orthogonal
/// to the security layer.
fn resolve_security(s: &Scenario) -> GwSecurity {
    if s.protocol.kind == ProtocolType::None
        || s.protocol.protection_mode == ProtectionMode::RoutingOnly
    {
        return GwSecurity::Routing;
    }
    match s.protocol.kind {
        ProtocolType::Tls => {
            let version = tls_version(s.protocol.version);
            let ktls = s.protocol.kernel;
            if s.protocol.protection_mode == ProtectionMode::IntegrityOnly {
                GwSecurity::IntegrityOnly { version }
            } else if s.protocol.mutual_auth {
                GwSecurity::Mtls { version, ktls }
            } else {
                GwSecurity::Tls { version, ktls }
            }
        }
        ProtocolType::Dtls => {
            let mutual = s.protocol.mutual_auth;
            GwSecurity::Dtls {
                version: dtls_version(s.protocol.version),
                mutual,
            }
        }
        _ => GwSecurity::Routing,
    }
}

fn selected_server_identity(s: &Scenario) -> Option<crate::pki::Identity> {
    let certs = &s.protocol.certificates;
    Some(crate::pki::Identity {
        cert: certs.server_cert.as_ref()?.clone(),
        key: certs.server_key.as_ref()?.clone(),
    })
}

fn selected_mtls_bundle(s: &Scenario) -> Option<crate::pki::CaBundle> {
    let certs = &s.protocol.certificates;
    Some(crate::pki::CaBundle {
        ca_cert: certs.ca_cert.as_ref()?.clone(),
        server: crate::pki::Identity {
            cert: certs.server_cert.as_ref()?.clone(),
            key: certs.server_key.as_ref()?.clone(),
        },
        client: crate::pki::Identity {
            cert: certs.client_cert.as_ref()?.clone(),
            key: certs.client_key.as_ref()?.clone(),
        },
    })
}

fn server_identity_for_scenario(
    scenario: &Scenario,
    work_dir: &Path,
    purpose: &str,
) -> Result<crate::pki::Identity, Box<dyn std::error::Error>> {
    if let Some(identity) = selected_server_identity(scenario) {
        return Ok(identity);
    }
    if !crate::pki::openssl_available() {
        return Err(format!(
            "scenario '{}' needs {purpose} certificates but the openssl CLI is unavailable",
            scenario.name
        )
        .into());
    }
    Ok(crate::pki::generate_self_signed(work_dir, 2)?)
}

fn mtls_bundle_for_scenario(
    scenario: &Scenario,
    work_dir: &Path,
    purpose: &str,
) -> Result<crate::pki::CaBundle, Box<dyn std::error::Error>> {
    if let Some(bundle) = selected_mtls_bundle(scenario) {
        return Ok(bundle);
    }
    if !crate::pki::openssl_available() {
        return Err(format!(
            "scenario '{}' needs a {purpose} CA bundle but the openssl CLI is unavailable",
            scenario.name
        )
        .into());
    }
    Ok(crate::pki::generate_mtls_bundle(work_dir, 2)?)
}

fn apply_protocol_security_overrides(mut spec: SecuritySpec, scenario: &Scenario) -> SecuritySpec {
    spec = apply_cipher_override(spec, scenario);
    spec = match (&scenario.protocol.psk_identity, &scenario.protocol.psk_hex) {
        (Some(identity), Some(hex_key)) => spec.with_psk(identity, hex_key),
        _ => spec,
    };
    if let Some(ref profile) = scenario.protocol.profile {
        spec = spec.with_profile(profile);
    }
    spec.with_resumption(scenario.protocol.resumption)
        .with_certificate_selection(&scenario.protocol.certificates)
}

fn build_security_spec(
    plan: &GatewayPlan,
    scenario: &Scenario,
    work_dir: &Path,
) -> Result<SecuritySpec, Box<dyn std::error::Error>> {
    let spec = match plan.security {
        GwSecurity::Routing => SecuritySpec::routing_tcp(),
        GwSecurity::Tls { version, ktls } => {
            let id = server_identity_for_scenario(scenario, work_dir, "TLS")?;
            let mut s = SecuritySpec::tls_server(version, &id.cert, &id.key);
            if ktls {
                s = s.provider("ktls");
            }
            s
        }
        GwSecurity::Mtls { version, ktls } => {
            let bundle = mtls_bundle_for_scenario(scenario, work_dir, "TLS")?;
            let mut s = SecuritySpec::tls_mutual(version, &bundle);
            if ktls {
                s = s.provider("ktls");
            }
            s
        }
        GwSecurity::IntegrityOnly { version } => {
            let id = server_identity_for_scenario(scenario, work_dir, "TLS integrity-only")?;
            SecuritySpec::tls_server(version, &id.cert, &id.key).with_profile("integrity-only")
        }
        GwSecurity::Dtls { version, mutual } => {
            if mutual {
                let bundle = mtls_bundle_for_scenario(scenario, work_dir, "DTLS")?;
                SecuritySpec::dtls_mutual(version, &bundle)
            } else {
                let id = server_identity_for_scenario(scenario, work_dir, "DTLS")?;
                SecuritySpec::dtls_server(version, &id.cert, &id.key)
            }
        }
    };

    Ok(apply_protocol_security_overrides(spec, scenario))
}

/// Build a `SecuritySpec` for multi-stream scenarios. Uses routing by default
/// (each stream routes through the same gateway rules), but honors the scenario-
/// level protocol selection when specified.
fn build_multistream_spec(
    plan: &GatewayPlan,
    scenario: &Scenario,
    work_dir: &Path,
) -> Result<SecuritySpec, Box<dyn std::error::Error>> {
    build_security_spec(plan, scenario, work_dir)
}

/// Decide whether a scenario can be driven through the gateway in this slice and
/// how. Returns `None` for paths still pending later work packages (WireGuard/
/// IPSec).
fn gateway_plan(s: &Scenario) -> Option<GatewayPlan> {
    if !s.gateway.enabled {
        return None;
    }

    // Non-loopback topologies and network impairment are allowed; they require
    // CAP_NET_ADMIN which is checked at runtime (the scenario is skipped with a
    // warning if capabilities are missing).

    // Multi-stream and hot-reload scenarios are handled by dedicated execution
    // paths; they still need a gateway plan to know the security/topology.
    let sender = if !s.streams.is_empty() {
        // Multi-stream: derive interface from first stream.
        None
    } else {
        s.sender.as_ref()
    };

    let topology = match s.gateway.chain {
        GatewayChain::ScgDirect => gateway::Topology::SingleGateway,
        GatewayChain::ScgScg => gateway::Topology::ScgToScg,
    };

    // Multi-stream scenarios: we just need routing through the gateway. The
    // per-stream transport pairs are provisioned separately.
    if !s.streams.is_empty() {
        return Some(GatewayPlan {
            security: GwSecurity::Routing,
            topology,
            transport_name: "scg-multistream",
        });
    }

    let sender = sender?;

    // DTLS runs over UDP datagrams. The two-rule path converges every flow onto
    // one backend address, so it models a single logical flow only.
    if s.protocol.kind == ProtocolType::Dtls {
        if sender.interface != Interface::Udp {
            return None;
        }
        let version = dtls_version(s.protocol.version);
        let mutual = s.protocol.mutual_auth;
        return Some(GatewayPlan {
            security: GwSecurity::Dtls { version, mutual },
            topology,
            transport_name: if mutual { "scg-dtls-mtls" } else { "scg-dtls" },
        });
    }

    // UDS/SHM endpoints are provisioned via the gateway's gRPC management API.
    // They only support routing (the crypto is handled gateway-internally
    // regardless of the interface).
    if sender.interface == Interface::Unix {
        return Some(GatewayPlan {
            security: resolve_security(s),
            topology,
            transport_name: "scg-uds",
        });
    }
    if sender.interface == Interface::Shm {
        return Some(GatewayPlan {
            security: resolve_security(s),
            topology,
            transport_name: "scg-shm",
        });
    }

    // TPROXY transparent interception. Requires CAP_NET_ADMIN; the transport
    // will skip gracefully at runtime if capabilities are absent.
    if sender.interface == Interface::Tproxy {
        return Some(GatewayPlan {
            security: resolve_security(s),
            topology,
            transport_name: "scg-tproxy",
        });
    }

    // UDP-over-TLS (ALE/RAW framing): tunnels UDP datagrams through a TLS TCP
    // stream using the gateway's `ale` or `raw` app_protocol.
    if sender.interface == Interface::Udp && s.protocol.kind == ProtocolType::Tls {
        if s.protocol.app_protocol == AppProtocol::None {
            // Plain UDP through TLS needs an explicit framing protocol.
            return None;
        }
        let version = tls_version(s.protocol.version);
        let ktls = s.protocol.kernel;
        let mutual = s.protocol.mutual_auth;
        let security = if mutual {
            GwSecurity::Mtls { version, ktls }
        } else {
            GwSecurity::Tls { version, ktls }
        };
        let transport_name = match s.protocol.app_protocol {
            AppProtocol::Ale => "scg-udp-ale",
            AppProtocol::Raw => "scg-udp-raw",
            AppProtocol::None => unreachable!(),
        };
        return Some(GatewayPlan {
            security,
            topology,
            transport_name,
        });
    }

    if sender.interface != Interface::Tcp {
        return None;
    }

    // Routing short-circuits any crypto decision.
    if s.protocol.kind == ProtocolType::None
        || s.protocol.protection_mode == ProtectionMode::RoutingOnly
    {
        return Some(GatewayPlan {
            security: GwSecurity::Routing,
            topology,
            transport_name: "scg-tcp",
        });
    }

    match s.protocol.kind {
        ProtocolType::Tls => {
            let version = tls_version(s.protocol.version);
            let ktls = s.protocol.kernel;
            // Integrity-only is a userspace, server-auth NULL-cipher path.
            if s.protocol.protection_mode == ProtectionMode::IntegrityOnly {
                return Some(GatewayPlan {
                    security: GwSecurity::IntegrityOnly { version },
                    topology,
                    transport_name: "scg-tls-integrity",
                });
            }
            if s.protocol.mutual_auth {
                return Some(GatewayPlan {
                    security: GwSecurity::Mtls { version, ktls },
                    topology,
                    transport_name: if ktls { "scg-ktls-mtls" } else { "scg-mtls" },
                });
            }
            let (security, transport_name) = if ktls {
                (
                    GwSecurity::Tls {
                        version,
                        ktls: true,
                    },
                    "scg-ktls",
                )
            } else {
                (
                    GwSecurity::Tls {
                        version,
                        ktls: false,
                    },
                    "scg-tls",
                )
            };
            Some(GatewayPlan {
                security,
                topology,
                transport_name,
            })
        }
        // DTLS is handled above (UDP); WireGuard and IPSec are disabled paths.
        _ => None,
    }
}

/// Run one scenario through the SCG. Returns `Ok(true)` when the scenario was
/// measured and recorded, `Ok(false)` when it had to be skipped (e.g. missing
/// certificate tooling or a gateway that failed to start).
#[allow(clippy::too_many_arguments)] // cohesive per-scenario driver: suite caches + core plan.
fn run_gateway_scenario(
    scenario: &Scenario,
    defaults: &Defaults,
    plan: &GatewayPlan,
    binary: &Path,
    rdir: &mut ResultDir,
    ceilings: &mut HashMap<(String, u32, usize), f64>,
    sys_rate: Option<u32>,
    cores: &CorePlan,
    comparison_rate_mbps: Option<f64>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Ping-pong RTT needs a duplex echo path. The DTLS/UDP gateway converges
    // every flow onto one backend over a single one-way rule pair, so it cannot
    // bounce datagrams back to the client; skip those scenarios with a notice.
    if scenario.mode == Mode::Pingpong && matches!(plan.security, GwSecurity::Dtls { .. }) {
        log::warn!(
            "scenario '{}': ping-pong RTT over the DTLS/UDP gateway path is not supported; skipping",
            scenario.name
        );
        return Ok(false);
    }
    let work_dir = rdir.root().join("gateway").join(sanitize(&scenario.name));
    std::fs::create_dir_all(&work_dir)?;

    // Provision non-loopback topology if requested (E1).
    let _provisioned_topology = match scenario.topology.mode {
        TopologyMode::Loopback => None,
        TopologyMode::Veth => {
            match crate::topology::setup_veth(
                &scenario.topology.left_ip,
                &scenario.topology.right_ip,
                scenario.topology.subnet_mask,
            ) {
                Ok(topo) => Some(topo),
                Err(e) => {
                    log::warn!(
                        "scenario '{}': veth topology setup failed ({e}); skipping",
                        scenario.name
                    );
                    return Ok(false);
                }
            }
        }
        TopologyMode::Netns => {
            match crate::topology::setup_netns(
                &scenario.topology.left_namespace,
                &scenario.topology.right_namespace,
                &scenario.topology.left_ip,
                &scenario.topology.right_ip,
                scenario.topology.subnet_mask,
            ) {
                Ok(topo) => Some(topo),
                Err(e) => {
                    log::warn!(
                        "scenario '{}': netns topology setup failed ({e}); skipping",
                        scenario.name
                    );
                    return Ok(false);
                }
            }
        }
        _ => {
            log::warn!(
                "scenario '{}': topology mode {:?} not yet supported; skipping",
                scenario.name,
                scenario.topology.mode
            );
            return Ok(false);
        }
    };

    // Apply network impairment via tc netem if configured (E2).
    let _applied_impairment = if let Some(ref imp) = scenario.network_impairment {
        if imp.enabled {
            use crate::topology::impair::{self, Impairment};
            let netem = Impairment {
                delay_ms: if imp.latency_ms > 0.0 {
                    Some(imp.latency_ms as u32)
                } else {
                    None
                },
                jitter_ms: if imp.jitter_ms > 0.0 {
                    Some(imp.jitter_ms as u32)
                } else {
                    None
                },
                loss_pct: if imp.loss_percent > 0.0 {
                    Some(imp.loss_percent)
                } else {
                    None
                },
                bandwidth_mbit: if imp.bandwidth_limit_mbps > 0 {
                    Some(imp.bandwidth_limit_mbps)
                } else {
                    None
                },
                reorder_pct: if imp.reorder_percent > 0.0 {
                    Some(imp.reorder_percent)
                } else {
                    None
                },
                duplicate_pct: if imp.duplicate_percent > 0.0 {
                    Some(imp.duplicate_percent)
                } else {
                    None
                },
            };
            match impair::apply_impairment(&imp.apply_to, &netem) {
                Ok(applied) => Some(applied),
                Err(e) => {
                    log::warn!(
                        "scenario '{}': network impairment setup failed ({e}); skipping",
                        scenario.name
                    );
                    return Ok(false);
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let spec = match build_security_spec(plan, scenario, &work_dir) {
        Ok(spec) => spec,
        Err(e) => {
            log::warn!("scenario '{}': {e}; skipping", scenario.name);
            return Ok(false);
        }
    };

    // Apply ALE/RAW asymmetric framing for UDP-over-TLS scenarios.
    let spec = match scenario.protocol.app_protocol {
        AppProtocol::Ale => spec.with_asymmetric_ale("ale"),
        AppProtocol::Raw => spec.with_asymmetric_ale("raw"),
        AppProtocol::None => spec,
    };

    // Apply optimization flags (F1 zero_copy, F2 spin_wait_us).
    let spec = spec.with_optimizations(&scenario.optimization_flags);

    let mut params = build_run_params(scenario, defaults, cores);
    if let Some(rate_mbps) = comparison_rate_mbps {
        params.sender.pattern = config::Pattern::Sustained;
        params.sender.rate_limit_mbps = Some(rate_mbps);
        params.sender.interval_us = None;
        log::info!(
            "scenario '{}': interface comparison latency rate {:.3} Mbit/s",
            scenario.name,
            rate_mbps
        );
    }
    render_scenario_header(scenario, &params, plan.transport_name);

    // DTLS runs over UDP datagrams; UDS/SHM use gRPC-provisioned local
    // endpoints; everything else over TCP. All wrap into a `GatewayDut` so PID
    // sampling, the run engine, and shutdown stay uniform. The gateway is pinned
    // to its own core pool so it never contends with the harness sender/receiver.
    let is_udp = matches!(plan.security, GwSecurity::Dtls { .. });
    let is_uds = plan.transport_name == "scg-uds";
    let is_shm = plan.transport_name == "scg-shm";
    let is_tproxy = plan.transport_name == "scg-tproxy";
    let is_ale_raw = matches!(plan.transport_name, "scg-udp-ale" | "scg-udp-raw");

    let dut = if is_uds {
        let app_id = format!("seshat-{}", sanitize(&scenario.name));
        match GatewayUdsTransport::start(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
            &app_id,
        ) {
            Ok(t) => GatewayDut::Uds(t),
            Err(e) => {
                log::warn!(
                    "scenario '{}': UDS gateway failed to start ({e}); skipping",
                    scenario.name
                );
                return Ok(false);
            }
        }
    } else if is_shm {
        let app_id = format!("seshat-{}", sanitize(&scenario.name));
        // Ring capacity: scenario override, else 1 MiB. Enlarging the ring is
        // opt-in (via optimization_flags.shm_ring_capacity) because a deeper
        // ring inflates queueing latency for open-loop "sustained" senders.
        let ring_capacity = scenario
            .optimization_flags
            .shm_ring_capacity
            .unwrap_or(1024 * 1024) as u64;
        let shm_tuning = crate::gateway::config::ShmTuning {
            ring_kind: scenario.optimization_flags.shm_ring_kind.clone(),
            segment_size: scenario.optimization_flags.shm_segment_size,
            num_segments: scenario.optimization_flags.shm_num_segments,
            g2c_notify: scenario.optimization_flags.shm_g2c_notify.clone(),
        };
        match GatewayShmTransport::start(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
            &app_id,
            ring_capacity,
            &shm_tuning,
        ) {
            Ok(t) => GatewayDut::Shm(t),
            Err(e) => {
                log::warn!(
                    "scenario '{}': SHM gateway failed to start ({e}); skipping",
                    scenario.name
                );
                return Ok(false);
            }
        }
    } else if is_tproxy {
        use crate::transport::tproxy::TproxyTransport;
        match TproxyTransport::start(plan.transport_name, binary, &work_dir) {
            Ok(t) => GatewayDut::Tproxy(t),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    log::warn!(
                        "scenario '{}': TPROXY requires CAP_NET_ADMIN; skipping",
                        scenario.name
                    );
                } else {
                    log::warn!(
                        "scenario '{}': TPROXY gateway failed to start ({e}); skipping",
                        scenario.name
                    );
                }
                return Ok(false);
            }
        }
    } else if is_udp || is_ale_raw {
        match GatewayUdpTransport::start(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
        ) {
            Ok(t) => GatewayDut::Udp(t),
            Err(e) => {
                log::warn!(
                    "scenario '{}': gateway failed to start ({e}); skipping",
                    scenario.name
                );
                return Ok(false);
            }
        }
    } else {
        match GatewayTcpTransport::start(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
        ) {
            Ok(t) => GatewayDut::Tcp(t),
            Err(e) => {
                log::warn!(
                    "scenario '{}': gateway failed to start ({e}); skipping",
                    scenario.name
                );
                return Ok(false);
            }
        }
    };

    // Sample the live gateway PID(s) for the duration of the runs (F-13b).
    let sampler = sys_rate
        .filter(|_| !dut.pids().is_empty())
        .map(|hz| SystemSampler::start(dut.pids(), hz));

    let perf_sampler = start_perf_sampler(defaults, scenario, &dut, &work_dir);
    let mem_copy_sampler = start_mem_copy_sampler(defaults, scenario, &dut, &work_dir);

    let run_result = engine::run_scenario(dut.as_transport(), &params, |i, s| {
        if params.mode == RunMode::Connrate {
            render_connrate_run_line(i, params.runs, s);
        } else {
            render_run_line(i, params.runs, s);
        }
    });

    // Stop sampling immediately once the runs finish (before any teardown or
    // calibration probe), regardless of whether the runs succeeded.
    let system_samples = sampler.map(SystemSampler::stop);
    let perf_result = perf_sampler.map(system::PerfSampler::stop);
    let mem_copy_result = mem_copy_sampler.map(system::MemCopySampler::stop);
    if let Some(ref perf) = perf_result {
        if let Some(ipc) = perf.ipc {
            log::debug!("perf: IPC={ipc:.2}, cache-misses={:?}", perf.cache_misses);
        }
    }
    // Roll the gateway CPU timeseries up so the calibrator can tell SCG-bound
    // results (trustworthy) from harness-bound ones (suspect).
    let sys_agg = system_samples.as_deref().and_then(system::aggregate);

    let stats = match run_result {
        Ok(stats) => stats,
        Err(e) => {
            log::warn!("scenario '{}': run failed ({e}); skipping", scenario.name);
            let _ = dut.shutdown();
            return Ok(false);
        }
    };
    if !has_measurements(&stats) {
        log::warn!(
            "scenario '{}': no messages reached the receiver; skipping invalid zero-metric result",
            scenario.name
        );
        let _ = dut.shutdown();
        return Ok(false);
    }

    if scenario.mode == Mode::Connrate {
        render_connrate_result(&stats);
        if let Some(samples) = system_samples {
            rdir.record_system_metrics(scenario, &samples)?;
        }
        let kernel_requested = matches!(
            plan.security,
            GwSecurity::Tls { ktls: true, .. } | GwSecurity::Mtls { ktls: true, .. }
        );
        let log_paths = dut.log_paths();
        dut.shutdown()?;
        let effective = logscan::scan_effective(&log_paths, kernel_requested);
        warn_if_protocol_fallback(scenario, &effective);
        rdir.record_scenario(
            scenario,
            &params,
            &stats,
            &ScenarioArtifacts {
                sys: sys_agg.as_ref(),
                perf: perf_result.as_ref(),
                mem_copies: mem_copy_result.as_ref(),
                effective: Some(&effective),
                loss_threshold_pct: defaults.loss_threshold_pct,
                ..Default::default()
            },
        )?;
        return Ok(true);
    }

    // Closed-loop RTT path: report round-trip time and record the effective
    // protocol, but skip the throughput-oriented calibration and saturation
    // sweep (they measure bandwidth, not latency).
    if scenario.mode == Mode::Pingpong {
        render_pingpong_result(&stats);
        if let Some(samples) = system_samples {
            rdir.record_system_metrics(scenario, &samples)?;
        }
        let kernel_requested = matches!(
            plan.security,
            GwSecurity::Tls { ktls: true, .. } | GwSecurity::Mtls { ktls: true, .. }
        );
        let log_paths = dut.log_paths();
        dut.shutdown()?;
        let effective = logscan::scan_effective(&log_paths, kernel_requested);
        warn_if_protocol_fallback(scenario, &effective);
        rdir.record_scenario(
            scenario,
            &params,
            &stats,
            &ScenarioArtifacts {
                sys: sys_agg.as_ref(),
                perf: perf_result.as_ref(),
                mem_copies: mem_copy_result.as_ref(),
                effective: Some(&effective),
                loss_threshold_pct: defaults.loss_threshold_pct,
                ..Default::default()
            },
        )?;
        return Ok(true);
    }

    render_scenario_result(&stats);

    // Persist the per-PID system-metrics timeseries captured during the runs.
    if let Some(samples) = system_samples {
        rdir.record_system_metrics(scenario, &samples)?;
    }

    // The headroom ceiling is the harness's own loopback capacity for this shape
    // (loopback UDP for the DTLS path, loopback TCP otherwise), not the SCG path,
    // so a low ratio flags a harness-limited result — unless the gateway's cores
    // are saturated, in which case the SCG genuinely *is* the bottleneck.
    let gw_core_count = if cores.gateway.is_empty() {
        crate::sysinfo::cpu_logical()
    } else {
        cores.gateway.len()
    };
    let gw_cpu = sys_agg.as_ref().map(|a| (a.cpu_pct_peak, gw_core_count));
    let cal = if is_udp {
        calibrate_scenario(
            &UdpTransport,
            &params,
            stats.throughput_gbps.mean,
            ceilings,
            true,
            gw_cpu,
        )?
    } else {
        calibrate_scenario(
            &TcpTransport,
            &params,
            stats.throughput_gbps.mean,
            ceilings,
            true,
            gw_cpu,
        )?
    };
    render_calibration(&cal);

    let sweep = run_saturation_if_requested(
        scenario,
        dut.as_transport(),
        &params,
        defaults.loss_threshold_pct,
    )?;
    warn_if_overloaded(scenario, &stats, defaults.loss_threshold_pct);

    // Capture the gateway logs, tear it down so they flush, then scan them for an
    // effective-protocol fallback (e.g. kTLS that silently ran in userspace).
    let kernel_requested = matches!(
        plan.security,
        GwSecurity::Tls { ktls: true, .. } | GwSecurity::Mtls { ktls: true, .. }
    );
    let log_paths = dut.log_paths();
    dut.shutdown()?;
    let effective = logscan::scan_effective(&log_paths, kernel_requested);
    warn_if_protocol_fallback(scenario, &effective);

    rdir.record_scenario(
        scenario,
        &params,
        &stats,
        &ScenarioArtifacts {
            cal: Some(&cal),
            sweep: sweep.as_ref(),
            sys: sys_agg.as_ref(),
            perf: perf_result.as_ref(),
            mem_copies: mem_copy_result.as_ref(),
            effective: Some(&effective),
            loss_threshold_pct: defaults.loss_threshold_pct,
        },
    )?;
    Ok(true)
}

// ─── F-10: Multi-Stream Execution ───────────────────────────────────────────

/// Run a multi-stream scheduling scenario through the gateway.
///
/// Each stream in the config becomes a separate transport pair through the same
/// gateway instance, running concurrently. Per-stream metrics are collected and
/// the aggregate result (fairness, safety starvation) is recorded.
#[allow(clippy::too_many_arguments)]
fn run_multistream_scenario(
    scenario: &Scenario,
    defaults: &Defaults,
    plan: &GatewayPlan,
    binary: &Path,
    rdir: &mut ResultDir,
    sys_rate: Option<u32>,
    cores: &CorePlan,
) -> Result<bool, Box<dyn std::error::Error>> {
    use crate::workload::streams::{self, MultiStreamResult, StreamConfig};

    let work_dir = rdir.root().join("gateway").join(sanitize(&scenario.name));
    std::fs::create_dir_all(&work_dir)?;

    // Build the gateway SecuritySpec from the plan (respects per-scenario
    // protocol selection instead of always hardcoding routing).
    let spec = build_multistream_spec(plan, scenario, &work_dir)?;
    let dut = match GatewayTcpTransport::start(
        plan.transport_name,
        &spec,
        plan.topology,
        binary,
        &work_dir,
        &cores.gateway,
    ) {
        Ok(t) => GatewayDut::Tcp(t),
        Err(e) => {
            log::warn!(
                "scenario '{}': gateway failed to start ({e}); skipping",
                scenario.name
            );
            return Ok(false);
        }
    };

    // Convert config streams → workload StreamConfigs + transport pairs.
    let warmup = Duration::from_secs(scenario.warmup_secs.unwrap_or(defaults.warmup_secs));
    let measure = Duration::from_secs(
        scenario
            .duration_secs
            .unwrap_or(defaults.duration_secs)
            .max(1),
    );

    let mut configs = Vec::with_capacity(scenario.streams.len());
    let mut pairs = Vec::with_capacity(scenario.streams.len());

    for (i, stream) in scenario.streams.iter().enumerate() {
        let msg_bytes = stream.message_size_bytes.max(HEADER_LEN as u32);
        let rate_limit = match stream.pattern {
            config::Pattern::Periodic => stream.interval_us.map(|iv| {
                let bits_per_msg = msg_bytes as f64 * 8.0;
                let msgs_per_sec = 1_000_000.0 / iv as f64;
                (bits_per_msg * msgs_per_sec) / 1_000_000.0
            }),
            _ => None,
        };

        configs.push(StreamConfig {
            name: format!("{:?}-{}", stream.role, i),
            traffic_class: stream.priority.traffic_class.clone(),
            priority: i as i32,
            dscp_tag: dscp_from_tag(&stream.priority.dscp_tag),
            message_bytes: msg_bytes,
            rate_limit_mbps: rate_limit,
            sender_cores: cores.sender.clone(),
            receiver_cores: cores.receiver.clone(),
        });

        // Create a transport pair through the gateway for this stream, keeping
        // the declared traffic class for transports that provision class-
        // specific local endpoints.
        let pair = dut
            .as_transport()
            .loopback_pair_for_class(msg_bytes, &stream.priority.traffic_class)?;
        pairs.push(pair);
    }

    console::rule(&format!("Scenario: {} (multi-stream)", scenario.name));
    console::kv("Streams", &scenario.streams.len().to_string(), 10);
    console::kv(
        "Schedule",
        &format!(
            "{}s warmup / {}s measure",
            warmup.as_secs(),
            measure.as_secs()
        ),
        10,
    );

    // Sample system metrics during the run.
    let sampler = sys_rate
        .filter(|_| !dut.pids().is_empty())
        .map(|hz| SystemSampler::start(dut.pids(), hz));
    let perf_sampler = start_perf_sampler(defaults, scenario, &dut, &work_dir);

    let result: MultiStreamResult = streams::run_multi_stream(&configs, pairs, warmup, measure)?;

    let system_samples = sampler.map(SystemSampler::stop);
    let perf_result = perf_sampler.map(system::PerfSampler::stop);
    if let Some(samples) = &system_samples {
        let _ = rdir.record_system_metrics(scenario, samples);
    }
    rdir.record_stream_results(scenario, &result)?;

    // Render results.
    console::line("");
    for sr in &result.streams {
        console::kv(
            &format!("  {}", sr.name),
            &format!(
                "{:.3} Gbit/s  p99={:.0}µs  loss={}",
                sr.summary.throughput_gbps, sr.summary.latency_us.p99, sr.summary.integrity.lost
            ),
            16,
        );
    }
    console::kv("  Fairness", &format!("{:.3}", result.fairness_ratio), 16);
    console::kv(
        "  Safety loss-free",
        if result.safety_loss_free {
            "PASS"
        } else {
            "FAIL"
        },
        16,
    );
    if let Some(p99) = result.safety_p99_us {
        console::kv("  Safety p99", &format!("{:.0} µs", p99), 16);
    }

    // Build a synthetic FlowSummary from the best-performing stream for recording.
    let best = result
        .streams
        .iter()
        .max_by(|a, b| {
            a.summary
                .throughput_gbps
                .partial_cmp(&b.summary.throughput_gbps)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| s.summary.clone());

    let stats = if let Some(best) = best {
        if best.messages == 0 {
            log::warn!(
                "scenario '{}': no multi-stream messages reached a receiver; skipping invalid zero-metric result",
                scenario.name
            );
            dut.shutdown()?;
            return Ok(false);
        }
        use crate::metrics::stats::summarize;
        RunStats {
            runs: vec![best.clone()],
            throughput_gbps: summarize(&[best.throughput_gbps]),
            latency_mean_us: summarize(&[best.latency_us.mean]),
            latency_p99_us: summarize(&[best.latency_us.p99]),
            handshake_us: summarize(&[0.0]),
            total_lost: best.integrity.lost,
            loss_pct: best.loss_pct,
            mode: RunMode::Throughput,
            rtt: None,
            conn: None,
            // The multi-stream senders stamp actual send time (not the scheduled
            // one), so their per-stream latency is not coordinated-omission-
            // corrected. Report that honestly rather than overclaiming.
            co_corrected: false,
            send_lag_mean_us: 0.0,
            send_lag_max_us: 0.0,
        }
    } else {
        log::warn!("scenario '{}': no stream results; skipping", scenario.name);
        dut.shutdown()?;
        return Ok(false);
    };

    let log_paths = dut.log_paths();
    dut.shutdown()?;
    let effective = logscan::scan_effective(&log_paths, false);

    // Build a RunParams suitable for recording (multi-stream doesn't use the
    // standard single-sender model, so we construct a minimal params).
    let first_stream = &scenario.streams[0];
    let record_params = RunParams {
        message_bytes: first_stream.message_size_bytes.max(HEADER_LEN as u32),
        connections: scenario.streams.len(),
        runs: 1,
        warmup,
        measure,
        cooldown: Duration::from_secs(scenario.cooldown_secs.unwrap_or(defaults.cooldown_secs)),
        remove_outliers: matches!(defaults.outlier_removal, OutlierRemoval::Iqr),
        sender_cores: cores.sender.clone(),
        receiver_cores: cores.receiver.clone(),
        sender: config::Sender {
            interface: first_stream.interface,
            target_addr: first_stream.target_addr.clone(),
            pattern: first_stream.pattern,
            rate_limit_mbps: None,
            interval_us: first_stream.interval_us,
            burst_count: None,
            burst_pause_us: None,
            ramp_start_mbps: None,
            ramp_step_mbps: None,
            ramp_step_interval_secs: None,
        },
        mode: RunMode::Throughput,
    };

    rdir.record_scenario(
        scenario,
        &record_params,
        &stats,
        &ScenarioArtifacts {
            effective: Some(&effective),
            sys: system_samples
                .as_deref()
                .and_then(system::aggregate)
                .as_ref(),
            perf: perf_result.as_ref(),
            loss_threshold_pct: defaults.loss_threshold_pct,
            ..Default::default()
        },
    )?;
    Ok(true)
}

// ─── F-11: Hot-Reload Execution ─────────────────────────────────────────────

/// Whether a reload action is a no-op *as currently driven by this harness*.
///
/// The gateway itself now applies same-name field changes: `GatewayConfig::diff`
/// has a `changed` bucket (`RuleConfig::reload_differs`) that restarts a listener
/// whose provider/upstream/profile/`verify`/cert/class/QoS changed. But SESHAT's
/// `UpdateTlsProfile`/`RotateCert` actions only send SIGHUP *without rewriting the
/// config file*, so no diff is produced and nothing is re-applied — a harness-side
/// no-op. A "zero drops" result for these actions therefore still proves nothing
/// (the config never changed). Add/remove connection (gRPC) and invalid-config
/// rollback do take effect and must stay zero-drop. To actually exercise the
/// gateway's new in-place reload, the action must write a modified same-name rule.
fn reload_is_noop_on_scg(action: config::ReloadAction) -> bool {
    matches!(
        action,
        config::ReloadAction::UpdateTlsProfile | config::ReloadAction::RotateCert
    )
}

/// Run a hot-reload scenario: measure before, inject reload, measure after.
///
/// This fires a config reload (SIGHUP) at the configured offset into the
/// measurement phase and compares throughput/latency/drops before vs after.
#[allow(clippy::too_many_arguments)]
fn run_hotreload_scenario(
    scenario: &Scenario,
    defaults: &Defaults,
    plan: &GatewayPlan,
    binary: &Path,
    rdir: &mut ResultDir,
    sys_rate: Option<u32>,
    cores: &CorePlan,
) -> Result<bool, Box<dyn std::error::Error>> {
    let reload_event = scenario.reload_event.as_ref().unwrap();
    let work_dir = rdir.root().join("gateway").join(sanitize(&scenario.name));
    std::fs::create_dir_all(&work_dir)?;

    // Build the security spec normally.
    let spec = match build_security_spec(plan, scenario, &work_dir) {
        Ok(spec) => spec,
        Err(e) => {
            log::warn!("scenario '{}': {e}; skipping", scenario.name);
            return Ok(false);
        }
    };

    let params = build_run_params(scenario, defaults, cores);

    // Start the gateway. Dynamic endpoint actions need an explicit management
    // API plus a matching UDS endpoint template; ordinary signal-based reloads
    // use the lean TCP-only data path.
    let needs_management_endpoint = matches!(
        reload_event.action,
        config::ReloadAction::AddConnection | config::ReloadAction::RemoveConnection
    );
    let start_transport = if needs_management_endpoint {
        GatewayTcpTransport::start_with_management_endpoint(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
            "hotreload-probe",
        )
    } else {
        GatewayTcpTransport::start(
            plan.transport_name,
            &spec,
            plan.topology,
            binary,
            &work_dir,
            &cores.gateway,
        )
    };
    let dut = match start_transport {
        Ok(t) => GatewayDut::Tcp(t),
        Err(e) => {
            log::warn!(
                "scenario '{}': gateway failed to start ({e}); skipping",
                scenario.name
            );
            return Ok(false);
        }
    };

    console::rule(&format!("Scenario: {} (hot-reload)", scenario.name));
    console::kv("Action", &format!("{:?}", reload_event.action), 10);
    console::kv(
        "Trigger",
        &format!("{}s into measurement", reload_event.trigger_at_secs),
        10,
    );

    // Sample system metrics.
    let sampler = sys_rate
        .filter(|_| !dut.pids().is_empty())
        .map(|hz| SystemSampler::start(dut.pids(), hz));
    let perf_sampler = start_perf_sampler(defaults, scenario, &dut, &work_dir);

    // Run the measurement with a reload injected mid-flight.
    // We extend the measurement window to include both pre- and post-reload windows.
    let trigger_secs = reload_event.trigger_at_secs;
    let post_window = reload_event.measure_window_after_secs.max(5);
    let total_measure_secs = trigger_secs + post_window + 2; // extra buffer

    let extended_params = RunParams {
        measure: Duration::from_secs(total_measure_secs),
        ..params.clone()
    };

    // Spawn the run engine in a thread so we can inject the reload at the right time.
    let transport: &dyn Transport = dut.as_transport();
    let reload_trigger_dur = Duration::from_secs(trigger_secs) + extended_params.warmup; // trigger offset from thread start

    // Get process info for reload injection before entering the run.
    let process_ref = dut.first_process();
    let config_paths = dut.config_paths();
    let gw_pid = process_ref.map(|p| p.pid());

    // We run the engine on the main thread and inject reload from a spawned timer thread.
    let reload_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_fired_clone = reload_fired.clone();
    let reload_succeeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_succeeded_clone = reload_succeeded.clone();
    let reload_duration_us = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reload_duration_us_clone = reload_duration_us.clone();

    // Timer thread: sleep until trigger point, then execute the reload action.
    let config_path = config_paths.first().cloned();
    let pid_for_reload = gw_pid;
    let action = reload_event.action;
    let mgmt_socket = dut.mgmt_socket_path();
    let reload_thread = std::thread::spawn(move || {
        use crate::config::ReloadAction;
        std::thread::sleep(reload_trigger_dur);
        let action_started = std::time::Instant::now();

        let succeeded = match action {
            ReloadAction::AddConnection | ReloadAction::RemoveConnection => {
                // gRPC-based reload: add or remove a UDS endpoint mid-run.
                if let Some(mgmt_path) = mgmt_socket {
                    use crate::gateway::grpc_client::{Direction, MgmtClient, TrafficClass};
                    let mgmt = MgmtClient::new(&mgmt_path);
                    match action {
                        ReloadAction::AddConnection => {
                            match mgmt.create_uds(
                                "hotreload-probe",
                                TrafficClass::Normal,
                                Direction::Encrypt,
                            ) {
                                Ok(ep) => {
                                    log::info!(
                                        "hot-reload: added endpoint via gRPC at {}s",
                                        trigger_secs
                                    );
                                    // Close it after a brief pause to exercise remove.
                                    std::thread::sleep(Duration::from_millis(500));
                                    match mgmt.close_endpoint(ep.endpoint_id) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            log::warn!(
                                                "hot-reload: gRPC remove after add failed: {e}"
                                            );
                                            false
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("hot-reload: gRPC add_connection failed: {e}");
                                    false
                                }
                            }
                        }
                        ReloadAction::RemoveConnection => {
                            // Create then immediately remove — exercises the close path.
                            match mgmt.create_uds(
                                "hotreload-remove",
                                TrafficClass::Normal,
                                Direction::Encrypt,
                            ) {
                                Ok(ep) => match mgmt.close_endpoint(ep.endpoint_id) {
                                    Ok(()) => {
                                        log::info!(
                                            "hot-reload: removed endpoint via gRPC at {}s",
                                            trigger_secs
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "hot-reload: gRPC remove_connection failed: {e}"
                                        );
                                        false
                                    }
                                },
                                Err(e) => {
                                    log::warn!("hot-reload: gRPC remove_connection failed: {e}");
                                    false
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                } else {
                    log::warn!("hot-reload: no management socket for gRPC reload");
                    false
                }
            }
            ReloadAction::InvalidConfig => {
                // Write an invalid config and SIGHUP — gateway should reject and keep running.
                if let (Some(path), Some(pid)) = (&config_path, pid_for_reload) {
                    let backup = std::fs::read_to_string(path).ok();
                    let _ = std::fs::write(path, "{ invalid json!!!");
                    // SAFETY: `kill` is an FFI call with no memory-safety
                    // preconditions; `pid` is the PID of the live gateway child
                    // process spawned and owned by `dut` (from
                    // `dut.first_process().map(|p| p.pid())`), and `libc::SIGHUP`
                    // is a valid signal number. The return value is intentionally
                    // discarded — a failed signal only means the reload was not
                    // delivered, which is handled by the gateway staying running.
                    let _ = unsafe { libc::kill(pid, libc::SIGHUP) };
                    log::info!(
                        "hot-reload: pushed invalid config + SIGHUP at {}s (expect rollback)",
                        trigger_secs
                    );
                    // Restore valid config after a brief delay so subsequent scenarios work.
                    std::thread::sleep(Duration::from_millis(500));
                    if let Some(valid) = backup {
                        let _ = std::fs::write(path, valid);
                    }
                    true
                } else {
                    false
                }
            }
            ReloadAction::UpdateTlsProfile | ReloadAction::RotateCert => {
                // Config-swap + SIGHUP: new connections get new config.
                if let (Some(_path), Some(pid)) = (config_path, pid_for_reload) {
                    // SAFETY: `kill` is an FFI call with no memory-safety
                    // preconditions; `pid` is the PID of the live gateway child
                    // process spawned and owned by `dut` (from
                    // `dut.first_process().map(|p| p.pid())`), and `libc::SIGHUP`
                    // is a valid signal number. The return value is intentionally
                    // discarded — a failed signal only means the reload SIGHUP was
                    // not delivered, which the caller treats as a best-effort path.
                    let _ = unsafe { libc::kill(pid, libc::SIGHUP) };
                    log::info!(
                        "hot-reload: SIGHUP sent to gateway (pid={pid}) at {}s (action={:?})",
                        trigger_secs,
                        action
                    );
                    true
                } else {
                    false
                }
            }
        };

        reload_succeeded_clone.store(succeeded, std::sync::atomic::Ordering::Relaxed);
        reload_duration_us_clone.store(
            u64::try_from(action_started.elapsed().as_micros()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        reload_fired_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let run_result = engine::run_scenario(transport, &extended_params, |i, s| {
        render_run_line(i, extended_params.runs, s);
    });

    let system_samples = sampler.map(SystemSampler::stop);
    let perf_result = perf_sampler.map(system::PerfSampler::stop);
    let sys_agg = system_samples.as_deref().and_then(system::aggregate);

    let stats = match run_result {
        Ok(stats) => stats,
        Err(e) => {
            log::warn!("scenario '{}': run failed ({e}); skipping", scenario.name);
            dut.shutdown()?;
            return Ok(false);
        }
    };
    // The expanded measurement duration always extends beyond the trigger;
    // join before reading action status so hotreload.csv cannot race a timer.
    let _ = reload_thread.join();
    if !has_measurements(&stats) {
        log::warn!(
            "scenario '{}': no messages reached the receiver; skipping invalid zero-metric result",
            scenario.name
        );
        dut.shutdown()?;
        return Ok(false);
    }

    // Report hot-reload specific metrics.
    let reload_actually_fired = reload_fired.load(std::sync::atomic::Ordering::Relaxed);
    let reload_action_succeeded = reload_succeeded.load(std::sync::atomic::Ordering::Relaxed);
    let reload_elapsed_us = reload_duration_us.load(std::sync::atomic::Ordering::Relaxed);
    if needs_management_endpoint && !reload_action_succeeded {
        log::warn!(
            "scenario '{}': management hot-reload action did not complete; skipping",
            scenario.name
        );
        dut.shutdown()?;
        return Ok(false);
    }
    console::line("");
    console::kv(
        "  Reload fired",
        if reload_actually_fired { "yes" } else { "no" },
        16,
    );
    console::kv(
        "  Reload action",
        if reload_action_succeeded {
            "succeeded"
        } else {
            "failed"
        },
        16,
    );
    // The harness's TLS-profile / cert reload only SIGHUPs the *unchanged* file, so
    // no config diff is produced — a no-op. (The gateway itself now applies
    // same-name field changes via the `changed` diff bucket, but this action does
    // not rewrite the file to trigger it.) Report honestly: a zero-drop result
    // here is not proof of seamless reload. `change_applied = Some(false)` flags it.
    let noop_on_scg = reload_is_noop_on_scg(reload_event.action);
    let change_applied = if noop_on_scg { Some(false) } else { None };
    if let Some(run) = stats.runs.first() {
        let drops = run.integrity.lost;
        console::kv("  Drops", &drops.to_string(), 16);
        let verdict = if noop_on_scg {
            "N/A (SCG diff is name-keyed; same-name rule change not applied)".to_string()
        } else if drops == 0 {
            "PASS".to_string()
        } else if reload_event.expect_zero_drops {
            "FAIL (drops > 0)".to_string()
        } else {
            "PASS (drops tolerated)".to_string()
        };
        console::kv("  VERDICT", &verdict, 16);
    }
    render_scenario_result(&stats);

    if let Some(samples) = &system_samples {
        let _ = rdir.record_system_metrics(scenario, samples);
    }

    let log_paths = dut.log_paths();
    dut.shutdown()?;
    let kernel_requested = matches!(
        plan.security,
        GwSecurity::Tls { ktls: true, .. } | GwSecurity::Mtls { ktls: true, .. }
    );
    let effective = logscan::scan_effective(&log_paths, kernel_requested);

    rdir.record_scenario(
        scenario,
        &params,
        &stats,
        &ScenarioArtifacts {
            sys: sys_agg.as_ref(),
            perf: perf_result.as_ref(),
            effective: Some(&effective),
            loss_threshold_pct: defaults.loss_threshold_pct,
            ..Default::default()
        },
    )?;
    rdir.record_reload_artifact(
        scenario,
        &ReloadArtifact {
            action: format!("{:?}", reload_event.action),
            fired: reload_actually_fired,
            action_succeeded: reload_action_succeeded,
            reload_duration_us: reload_elapsed_us,
            connections_before: params.connections,
            connections_after: params.connections,
            inflight_packets_lost: stats.total_lost,
            latency_p99_us: stats.latency_p99_us.mean,
            throughput_gbps: stats.throughput_gbps.mean,
            rollback_continuity_passed: matches!(
                reload_event.action,
                config::ReloadAction::InvalidConfig
            )
            .then_some(reload_action_succeeded && stats.total_lost == 0),
            change_applied,
        },
    )?;
    Ok(true)
}

/// Resolved CPU core pools for the sender, receiver, and gateway.
struct CorePlan {
    sender: Vec<usize>,
    receiver: Vec<usize>,
    gateway: Vec<usize>,
}

/// Resolve the sender/receiver/gateway core pools for the suite.
///
/// Explicit config always wins. When `auto_affinity` is set *and* no pool is
/// configured, the host's logical cores are split into three disjoint pools
/// (gateway : sender : receiver = 2 : 1 : 1, core 0 reserved for the OS) so the
/// harness sender/receiver never share cores with the SCG and the measurement
/// reflects the gateway's limit, not scheduler contention (NFR-PERF).
fn resolve_core_plan(d: &Defaults) -> CorePlan {
    let sender = d.cpu_affinity_sender.clone();
    let receiver = d.cpu_affinity_receiver.clone();
    let gateway = d.cpu_affinity_gateway.clone();
    let all_empty = sender.is_empty() && receiver.is_empty() && gateway.is_empty();
    if d.auto_affinity && all_empty {
        let total = crate::sysinfo::cpu_logical();
        let parts = affinity::partition_cores(total, &[2, 1, 1]);
        let gateway = parts.first().cloned().unwrap_or_default();
        let sender = parts.get(1).cloned().unwrap_or_default();
        let receiver = parts.get(2).cloned().unwrap_or_default();
        if gateway.is_empty() {
            log::warn!("auto-affinity: only {total} logical core(s) available; running unpinned");
        } else {
            log::info!(
                "auto-affinity: gateway={gateway:?} sender={sender:?} receiver={receiver:?}"
            );
        }
        return CorePlan {
            sender,
            receiver,
            gateway,
        };
    }
    CorePlan {
        sender,
        receiver,
        gateway,
    }
}

/// Build engine [`RunParams`] from a scenario plus suite defaults and the
/// resolved core pools.
fn build_run_params(s: &Scenario, d: &Defaults, cores: &CorePlan) -> RunParams {
    let message_bytes = s
        .message_size_bytes
        .unwrap_or(DEFAULT_MESSAGE_BYTES)
        .max(HEADER_LEN as u32);
    RunParams {
        message_bytes,
        connections: s.connections.max(1) as usize,
        runs: config::scenario_runs(s, d).max(1) as usize,
        warmup: Duration::from_secs(s.warmup_secs.unwrap_or(d.warmup_secs)),
        measure: Duration::from_secs(s.duration_secs.unwrap_or(d.duration_secs).max(1)),
        cooldown: Duration::from_secs(s.cooldown_secs.unwrap_or(d.cooldown_secs)),
        remove_outliers: matches!(d.outlier_removal, OutlierRemoval::Iqr),
        sender_cores: cores.sender.clone(),
        receiver_cores: cores.receiver.clone(),
        sender: s.sender.clone().expect("loopback scenario has a sender"),
        mode: match s.mode {
            Mode::Throughput => RunMode::Throughput,
            Mode::Pingpong => RunMode::PingPong,
            Mode::Connrate => RunMode::Connrate,
        },
    }
}

/// Resolve the per-PID system-metrics sample rate (Hz) for the suite, or `None`
/// when collection is disabled (by `--no-system-metrics` or `backend=none`).
fn system_metrics_rate(d: &Defaults) -> Option<u32> {
    if d.collect_system_metrics && d.metrics_backend != MetricsBackend::None {
        Some(d.metrics_sample_rate_hz.max(1))
    } else {
        None
    }
}

/// A transport that completed without any received messages did not produce a
/// usable benchmark measurement. Treat it as a skipped scenario rather than
/// reporting zero throughput/latency as a successful result.
fn has_measurements(stats: &RunStats) -> bool {
    stats.runs.iter().any(|run| run.messages > 0)
}

/// Start a per-gateway `perf stat` sampler for every gateway-backed execution
/// path.  Multi-stream and hot-reload used to omit this even when the caller
/// explicitly selected the perf backend, which made their `perf_*` summaries
/// silently incomplete.
fn start_perf_sampler(
    defaults: &Defaults,
    scenario: &Scenario,
    dut: &GatewayDut,
    work_dir: &Path,
) -> Option<system::PerfSampler> {
    if !defaults.collect_system_metrics || defaults.metrics_backend != MetricsBackend::Perf {
        return None;
    }
    let pids = dut.pids();
    match system::PerfSampler::start(&pids, work_dir) {
        Some(sampler) => Some(sampler),
        None => {
            log::warn!(
                "scenario '{}': perf backend requested but perf stat could not attach; perf_* result fields will be empty",
                scenario.name
            );
            None
        }
    }
}

/// Start a `bpftrace` memory-copy sampler for the gateway PID(s) when the
/// `ebpf` metrics backend is selected. Returns `None` (with a warning) when
/// unavailable — unprivileged or no `bpftrace` — so the run still proceeds, just
/// without the memory-copy columns.
fn start_mem_copy_sampler(
    defaults: &Defaults,
    scenario: &Scenario,
    dut: &GatewayDut,
    work_dir: &Path,
) -> Option<system::MemCopySampler> {
    if !defaults.collect_system_metrics || defaults.metrics_backend != MetricsBackend::Ebpf {
        return None;
    }
    let pids = dut.pids();
    match system::MemCopySampler::start(&pids, work_dir) {
        Some(sampler) => Some(sampler),
        None => {
            log::warn!(
                "scenario '{}': ebpf backend requested but bpftrace could not attach \
                 (needs root + bpftrace); mem_* result fields will be empty",
                scenario.name
            );
            None
        }
    }
}

/// Default on-wire message size when a scenario omits `message_size_bytes`.
const DEFAULT_MESSAGE_BYTES: u32 = 1024;

fn render_scenario_header(s: &Scenario, params: &RunParams, transport_label: &str) {
    console::section(&format!("Scenario: {}", s.name));
    console::card(
        "",
        &[
            ("Transport", transport_label.to_string()),
            ("Message", human_bytes(params.message_bytes)),
            ("Connections", params.connections.to_string()),
            (
                "Schedule",
                format!(
                    "{} run(s) × {}s warmup / {}s measure / {}s cooldown",
                    params.runs,
                    params.warmup.as_secs(),
                    params.measure.as_secs(),
                    params.cooldown.as_secs()
                ),
            ),
        ],
    );
}

fn render_run_line(index: usize, total: usize, s: &FlowSummary) {
    let line = format!(
        "  run {:>2}/{:<2}  {:>9.3} Gbit/s    p99 {:>9.1} µs    loss {:>6.3} %",
        index + 1,
        total,
        s.throughput_gbps,
        s.latency_us.p99,
        s.loss_pct
    );
    console::line(&console::dim(&line));
}

fn render_scenario_result(stats: &RunStats) {
    let thr = &stats.throughput_gbps;
    let lat = &stats.latency_mean_us;
    let p99 = &stats.latency_p99_us;
    console::card(
        "Result",
        &[
            (
                "Throughput",
                format!("{:.3} ± {:.3} Gbit/s", thr.mean, thr.ci95),
            ),
            (
                "Latency",
                format!(
                    "mean {:.1} ± {:.1} µs    p99 {:.1} ± {:.1} µs",
                    lat.mean, lat.ci95, p99.mean, p99.ci95
                ),
            ),
            (
                "Loss",
                format!("{:.3} % ({} msg)", stats.loss_pct, stats.total_lost),
            ),
        ],
    );
}

/// Per-run progress line for a closed-loop ping-pong scenario: RTT, not Gbit/s.
fn render_pingpong_run_line(index: usize, total: usize, s: &FlowSummary) {
    let line = format!(
        "  run {:>2}/{:<2}  rtt mean {:>8.1} µs    p50 {:>8.1} µs    p99 {:>8.1} µs",
        index + 1,
        total,
        s.latency_us.mean,
        s.latency_us.p50,
        s.latency_us.p99,
    );
    console::line(&console::dim(&line));
}

/// Cross-run result block for a closed-loop ping-pong scenario.
fn render_pingpong_result(stats: &RunStats) {
    match stats.rtt {
        Some(rtt) => {
            console::card(
                "Result — Round-Trip Time",
                &[
                    (
                        "RTT",
                        format!(
                            "mean {:.1} ± {:.1} µs    p50 {:.1} µs    p99 {:.1} µs",
                            rtt.mean_us, rtt.mean_ci95, rtt.p50_us, rtt.p99_us
                        ),
                    ),
                    ("Samples", rtt.samples.to_string()),
                ],
            );
        }
        None => render_scenario_result(stats),
    }
}

/// Per-run progress line for a connection-rate scenario: conns/s and handshake.
fn render_connrate_run_line(index: usize, total: usize, s: &FlowSummary) {
    let line = format!(
        "  run {:>2}/{:<2}  {:>10.0} conn/s    hs p50 {:>7.1} µs    p99 {:>7.1} µs",
        index + 1,
        total,
        s.message_rate,
        s.latency_us.p50,
        s.latency_us.p99,
    );
    console::line(&console::dim(&line));
}

/// Cross-run result block for a connection-rate scenario.
fn render_connrate_result(stats: &RunStats) {
    match stats.conn {
        Some(conn) => {
            console::card(
                "Result — Connection Rate",
                &[
                    (
                        "Rate",
                        format!(
                            "{:.0} ± {:.0} conn/s",
                            conn.conns_per_sec, conn.conns_per_sec_ci95
                        ),
                    ),
                    (
                        "Handshake",
                        format!(
                            "p50 {:.1} µs    p99 {:.1} µs",
                            conn.handshake_p50_us, conn.handshake_p99_us
                        ),
                    ),
                    ("Connections", conn.total_conns.to_string()),
                ],
            );
        }
        None => render_scenario_result(stats),
    }
}

/// Run a saturation sweep when the scenario requests one (Phase D), reusing its
/// transport and run parameters. Returns `None` when no sweep is configured.
fn run_saturation_if_requested(
    scenario: &Scenario,
    transport: &dyn Transport,
    params: &RunParams,
    loss_threshold_pct: f64,
) -> Result<Option<SweepResult>, Box<dyn std::error::Error>> {
    let Some(sat) = scenario.saturation else {
        return Ok(None);
    };
    let plan = SweepPlan {
        start_mbps: sat.start_mbps,
        step_mbps: sat.step_mbps,
        max_mbps: sat.max_mbps,
        loss_threshold_pct,
    };
    let result = saturation::sweep_saturation(transport, params, &plan)?;
    render_saturation_result(&result, loss_threshold_pct);
    Ok(Some(result))
}

/// Flag (console) any run whose loss blew through the budget, so an overloaded
/// blast number is never silently trusted as a capacity figure (Phase D).
fn warn_if_overloaded(scenario: &Scenario, stats: &RunStats, loss_threshold_pct: f64) {
    if stats.loss_pct > loss_threshold_pct {
        log::warn!(
            "scenario '{}' overloaded: {:.2}% loss exceeds the {:.2}% budget; the \
             throughput reflects an overloaded path, not its capacity (see \
             max_lossfree_gbps / saturation.csv for the sustainable rate)",
            scenario.name,
            stats.loss_pct,
            loss_threshold_pct
        );
    }
}

/// Warn (console) when the gateway did not deliver the configured protocol — the
/// canonical case being kTLS requested but run in userspace (e.g. on WSL2). The
/// `effective_protocol` column records the same fact for the report (Phase E).
fn warn_if_protocol_fallback(scenario: &Scenario, effective: &Effective) {
    if !effective.is_fallback() {
        return;
    }
    let configured = scenario.protocol_label();
    log::warn!(
        "scenario '{}': configured {configured} but the gateway ran {} (kTLS \
         unavailable on this host); the numbers reflect userspace TLS",
        scenario.name,
        logscan::effective_protocol_label(&configured, effective),
    );
    for note in &effective.notes {
        log::debug!("scenario '{}': gateway log: {note}", scenario.name);
    }
}

fn render_saturation_result(result: &SweepResult, loss_threshold_pct: f64) {
    console::card(
        "Saturation Sweep",
        &[
            ("Ceiling", format!("{:.3} Gbit/s", result.saturation_gbps)),
            (
                "Loss-free",
                format!(
                    "{:.3} Gbit/s (≤{:.1} % loss) @ {:.0} Mbit/s offered",
                    result.max_lossfree_gbps, loss_threshold_pct, result.knee_offered_mbps
                ),
            ),
            ("Points", result.points.len().to_string()),
        ],
    );
}

/// On-loopback (no SCG) ceiling probe duration per distinct scenario shape.
const CEILING_PROBE: Duration = Duration::from_millis(500);

/// Measure (or reuse a cached) harness ceiling for a scenario's shape and
/// compute its headroom. The ceiling is always the harness's null-loopback
/// capacity for this shape; `is_scg` selects whether the result is a Phase-1
/// baseline (never flagged) or an SCG measurement (flagged when headroom drops
/// below the gate).
fn calibrate_scenario(
    ceiling_transport: &dyn Transport,
    params: &RunParams,
    measured_gbps: f64,
    cache: &mut HashMap<(String, u32, usize), f64>,
    is_scg: bool,
    gw_cpu: Option<(f64, usize)>,
) -> Result<Calibration, Box<dyn std::error::Error>> {
    let key = (
        ceiling_transport.name().to_string(),
        params.message_bytes,
        params.connections,
    );
    let ceiling = match cache.get(&key) {
        Some(c) => *c,
        None => {
            let c = calibrate::measure_ceiling(
                ceiling_transport,
                params.message_bytes,
                params.connections,
                CEILING_PROBE,
            )?;
            cache.insert(key, c.throughput_gbps);
            c.throughput_gbps
        }
    };
    Ok(if is_scg {
        match gw_cpu {
            Some((peak_pct, cores)) => {
                Calibration::for_scg_with_cpu(ceiling, measured_gbps, peak_pct, cores)
            }
            None => Calibration::for_scg(ceiling, measured_gbps),
        }
    } else {
        Calibration::baseline(ceiling, measured_gbps)
    })
}

fn render_calibration(cal: &Calibration) {
    let mut value = format!(
        "ceiling {:.3} Gbit/s    headroom {:.1}×    dut: {}    bottleneck: {}",
        cal.ceiling_gbps, cal.headroom, cal.dut, cal.bottleneck
    );
    if cal.harness_limited {
        value.push_str(&format!("  {}", console::yellow("⚠ HARNESS-LIMITED (<3×)")));
    } else if cal.bottleneck == "scg-cpu" {
        value.push_str(&format!("  {}", console::dim("[SCG CPU-bound]")));
    }
    console::kv("Headroom", &value, 12);
}

fn render_suite_summary(outcomes: &[ScenarioOutcome], skipped: usize, root: &Path) {
    console::section("SUITE COMPLETE");
    println!(
        "  {} scenarios executed, {} skipped",
        outcomes.len(),
        skipped
    );
    println!("  Results: {}\n", root.display());

    // Build a table sorted by throughput descending
    let mut sorted: Vec<&ScenarioOutcome> = outcomes.iter().collect();
    sorted.sort_by(|a, b| b.throughput_gbps.total_cmp(&a.throughput_gbps));

    let headers = &["#", "Scenario", "Throughput", "p99 Latency", "Loss"];
    let rows: Vec<Vec<String>> = sorted
        .iter()
        .enumerate()
        .map(|(i, o)| {
            vec![
                format!("{}", i + 1),
                o.name.clone(),
                format!("{:.3} Gbit/s", o.throughput_gbps),
                format!("{:.1} µs", o.latency_p99_us),
                format!("{:.3} %", o.loss_pct),
            ]
        })
        .collect();

    console::table(headers, &rows, b"rlrrr");

    if let (Some(best), Some(worst)) = (best_by_throughput(outcomes), worst_by_throughput(outcomes))
    {
        println!();
        console::kv(
            "Best",
            &format!("{} ({:.3} Gbit/s)", best.name, best.throughput_gbps),
            10,
        );
        console::kv(
            "Worst",
            &format!("{} ({:.3} Gbit/s)", worst.name, worst.throughput_gbps),
            10,
        );
    }
    console::end_rule();
}

/// Scenario with the highest mean throughput.
fn best_by_throughput(o: &[ScenarioOutcome]) -> Option<&ScenarioOutcome> {
    o.iter()
        .max_by(|a, b| a.throughput_gbps.total_cmp(&b.throughput_gbps))
}

/// Scenario with the lowest mean throughput.
fn worst_by_throughput(o: &[ScenarioOutcome]) -> Option<&ScenarioOutcome> {
    o.iter()
        .min_by(|a, b| a.throughput_gbps.total_cmp(&b.throughput_gbps))
}

/// Apply CLI flag overrides onto the loaded config.
fn apply_overrides(cfg: &mut Config, args: &RunArgs) -> CmdResult {
    if let Some(r) = args.runs {
        cfg.defaults.runs = r;
    }
    if let Some(d) = args.duration {
        cfg.defaults.duration_secs = d.as_secs();
    }
    if let Some(w) = args.warmup {
        cfg.defaults.warmup_secs = w.as_secs();
    }
    if let Some(c) = args.cooldown {
        cfg.defaults.cooldown_secs = c.as_secs();
    }
    if let Some(name) = &args.scenario {
        let before = cfg.scenarios.len();
        cfg.scenarios.retain(|s| &s.name == name);
        if cfg.scenarios.is_empty() {
            return Err(
                format!("no scenario named '{name}' (config has {before} scenario(s))").into(),
            );
        }
    }
    if let Some(backend) = args.metrics_backend {
        cfg.defaults.metrics_backend = backend.into();
        cfg.defaults.collect_system_metrics = cfg.defaults.metrics_backend != MetricsBackend::None;
    }
    if args.no_system_metrics {
        cfg.defaults.collect_system_metrics = false;
        cfg.defaults.metrics_backend = MetricsBackend::None;
    }
    Ok(())
}

fn render_dry_run(args: &RunArgs, cfg: &Config, report: &ValidationReport) {
    console::rule("DRY RUN");
    let valid = if report.ok() {
        console::check()
    } else {
        console::cross()
    };
    console::kv("Config", &format!("{} {valid}", args.config.display()), 10);
    console::kv(
        "Scenarios",
        &format!(
            "{} enabled / {} total",
            report.enabled_count(),
            report.total_count()
        ),
        10,
    );
    console::kv("Runs/scn", &cfg.defaults.runs.to_string(), 10);
    console::kv(
        "Duration",
        &format!(
            "{}s measure + {}s warmup + {}s cooldown = {}s/run",
            cfg.defaults.duration_secs,
            cfg.defaults.warmup_secs,
            cfg.defaults.cooldown_secs,
            cfg.defaults.duration_secs + cfg.defaults.warmup_secs + cfg.defaults.cooldown_secs
        ),
        10,
    );
    console::kv(
        "Est. time",
        &config::human_secs(config::estimate_total_secs(cfg)),
        10,
    );
    let output = args
        .output_dir
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "./results/<timestamp>".to_string());
    console::kv("Output", &output, 10);
    console::kv("Tag", args.tag.as_deref().unwrap_or("(none)"), 10);
    console::kv(
        "Metrics",
        &format!(
            "{} ({})",
            if cfg.defaults.collect_system_metrics {
                "on"
            } else {
                "off"
            },
            cfg.defaults.metrics_backend.label()
        ),
        10,
    );
    console::kv(
        "CPU pin",
        &format!(
            "sender={:?} receiver={:?}",
            cfg.defaults.cpu_affinity_sender, cfg.defaults.cpu_affinity_receiver
        ),
        10,
    );
    console::end_rule();

    if report.ok() {
        println!(
            "  {} All scenarios validated. Ready to execute.",
            console::check()
        );
        println!("  {} Not executing (--dry-run).", console::cross());
    } else {
        render_validation(&args.config.display().to_string(), cfg, report);
    }
}

fn sender(args: SenderArgs) -> CmdResult {
    log::info!("sender: scenario={}, target={}", args.scenario, args.target);

    let cfg = config::load(&args.config)?;
    let scenario = cfg
        .scenarios
        .iter()
        .find(|s| s.name == args.scenario)
        .ok_or_else(|| format!("scenario '{}' not found in config", args.scenario))?;

    let sender_spec = scenario.sender.clone().unwrap_or_else(|| config::Sender {
        interface: Interface::Tcp,
        target_addr: args.target.clone(),
        pattern: config::Pattern::Sustained,
        rate_limit_mbps: None,
        interval_us: None,
        burst_count: None,
        burst_pause_us: None,
        ramp_start_mbps: None,
        ramp_step_mbps: None,
        ramp_step_interval_secs: None,
    });

    let params = engine::DistributedParams {
        message_bytes: scenario
            .message_size_bytes
            .unwrap_or(1024)
            .max(HEADER_LEN as u32),
        connections: scenario.connections.max(1) as usize,
        warmup: Duration::from_secs(scenario.warmup_secs.unwrap_or(cfg.defaults.warmup_secs)),
        measure: Duration::from_secs(
            scenario
                .duration_secs
                .unwrap_or(cfg.defaults.duration_secs)
                .max(1),
        ),
        cooldown: Duration::from_secs(scenario.cooldown_secs.unwrap_or(cfg.defaults.cooldown_secs)),
        cores: args.cpu_affinity,
        sender: sender_spec,
        remove_outliers: matches!(cfg.defaults.outlier_removal, OutlierRemoval::Iqr),
    };

    console::banner();
    console::rule(&format!("Distributed Sender: {}", args.scenario));
    console::kv("Target", &args.target, 10);
    console::kv("Message", &human_bytes(params.message_bytes), 10);
    console::kv("Connections", &params.connections.to_string(), 10);

    let sent = engine::run_distributed_sender(&params, &args.target)
        .map_err(|e| format!("sender failed: {e}"))?;
    console::kv("Sent (measure)", &sent.to_string(), 10);
    Ok(())
}

fn receiver(args: ReceiverArgs) -> CmdResult {
    log::info!("receiver: scenario={}, bind={}", args.scenario, args.bind);

    let cfg = config::load(&args.config)?;
    let scenario = cfg
        .scenarios
        .iter()
        .find(|s| s.name == args.scenario)
        .ok_or_else(|| format!("scenario '{}' not found in config", args.scenario))?;

    let sender_spec = scenario.sender.clone().unwrap_or_else(|| config::Sender {
        interface: Interface::Tcp,
        target_addr: args.bind.clone(),
        pattern: config::Pattern::Sustained,
        rate_limit_mbps: None,
        interval_us: None,
        burst_count: None,
        burst_pause_us: None,
        ramp_start_mbps: None,
        ramp_step_mbps: None,
        ramp_step_interval_secs: None,
    });

    let params = engine::DistributedParams {
        message_bytes: scenario
            .message_size_bytes
            .unwrap_or(1024)
            .max(HEADER_LEN as u32),
        connections: scenario.connections.max(1) as usize,
        warmup: Duration::from_secs(scenario.warmup_secs.unwrap_or(cfg.defaults.warmup_secs)),
        measure: Duration::from_secs(
            scenario
                .duration_secs
                .unwrap_or(cfg.defaults.duration_secs)
                .max(1),
        ),
        cooldown: Duration::from_secs(scenario.cooldown_secs.unwrap_or(cfg.defaults.cooldown_secs)),
        cores: args.cpu_affinity,
        sender: sender_spec,
        remove_outliers: matches!(cfg.defaults.outlier_removal, OutlierRemoval::Iqr),
    };

    console::banner();
    console::rule(&format!("Distributed Receiver: {}", args.scenario));
    console::kv("Bind", &args.bind, 10);
    console::kv("Message", &human_bytes(params.message_bytes), 10);

    let summary = engine::run_distributed_receiver(&params, &args.bind)
        .map_err(|e| format!("receiver failed: {e}"))?;
    console::kv(
        "Throughput",
        &format!("{:.3} Gbit/s", summary.throughput_gbps),
        10,
    );
    console::kv(
        "Latency p99",
        &format!("{:.0} µs", summary.latency_us.p99),
        10,
    );
    console::kv("Lost", &summary.integrity.lost.to_string(), 10);
    Ok(())
}

fn report(args: ReportArgs) -> CmdResult {
    log::info!(
        "report: input={}, format={:?}",
        args.input.display(),
        args.format
    );

    if !args.input.is_dir() {
        return Err(format!("results directory not found: {}", args.input.display()).into());
    }

    // Walk the result directory structure and regenerate the summary CSV.
    let scenarios_dir = args.input.join("scenarios");
    if !scenarios_dir.is_dir() {
        return Err(format!("no scenarios/ subdirectory in {}", args.input.display()).into());
    }

    let mut summary_rows = Vec::new();
    summary_rows.push(
        "scenario,protocol,topology,messages,throughput_gbps,latency_p50_us,\
         latency_p99_us,loss_pct,jitter_us"
            .to_string(),
    );

    let mut entries: Vec<_> = std::fs::read_dir(&scenarios_dir)
        .map_err(|e| format!("read scenarios/: {e}"))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let scenario_name = entry.file_name().to_string_lossy().to_string();
        let summary_path = entry.path().join("summary.json");
        if !summary_path.exists() {
            log::warn!("skipping {scenario_name}: no summary.json");
            continue;
        }
        let json = std::fs::read_to_string(&summary_path)
            .map_err(|e| format!("read {}: {e}", summary_path.display()))?;
        let val: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| format!("parse {}: {e}", summary_path.display()))?;

        let protocol = val["protocol"].as_str().unwrap_or("unknown");
        let topology = val["topology"].as_str().unwrap_or("unknown");
        let messages = val["messages"].as_u64().unwrap_or(0);
        let throughput = val["throughput_gbps"].as_f64().unwrap_or(0.0);
        let p50 = val["latency_us"]["p50"].as_f64().unwrap_or(0.0);
        let p99 = val["latency_us"]["p99"].as_f64().unwrap_or(0.0);
        let loss = val["loss_pct"].as_f64().unwrap_or(0.0);
        let jitter = val["jitter_us"].as_f64().unwrap_or(0.0);

        summary_rows.push(format!(
            "{scenario_name},{protocol},{topology},{messages},{throughput:.4},{p50:.1},{p99:.1},{loss:.3},{jitter:.1}"
        ));
    }

    // Write the regenerated summary.
    let output_path = args.input.join("summary.csv");
    std::fs::write(&output_path, summary_rows.join("\n") + "\n")
        .map_err(|e| format!("write {}: {e}", output_path.display()))?;
    log::info!("wrote {}", output_path.display());
    println!("{}", output_path.display());
    Ok(())
}

fn validate(args: ValidateArgs) -> CmdResult {
    let cfg = config::load(&args.config)?;
    let report = config::validate(&cfg);
    render_validation(&args.config.display().to_string(), &cfg, &report);

    if report.ok() {
        Ok(())
    } else {
        let n = report.suite_errors.len()
            + report
                .scenarios
                .iter()
                .map(|s| s.errors.len())
                .sum::<usize>();
        Err(format!("config invalid: {n} error(s)").into())
    }
}

fn render_validation(path: &str, cfg: &Config, report: &ValidationReport) {
    console::rule(&format!("Validating: {path}"));
    let schema = cfg.schema.as_deref().unwrap_or("(none)");
    console::kv("Schema", schema, 10);
    console::kv(
        "Suite",
        &format!("\"{}\" (v{})", cfg.suite.name, cfg.suite.version),
        10,
    );
    console::kv(
        "Defaults",
        &format!(
            "{} runs, {}s duration, {}s warmup",
            cfg.defaults.runs, cfg.defaults.duration_secs, cfg.defaults.warmup_secs
        ),
        10,
    );
    console::kv(
        "Scenarios",
        &format!(
            "{} defined, {} enabled",
            report.total_count(),
            report.enabled_count()
        ),
        10,
    );

    for se in &report.suite_errors {
        println!("  {} {}", console::cross(), console::red(se));
    }

    for sr in &report.scenarios {
        let status = if !sr.enabled {
            console::dim("SKIP")
        } else if sr.ok() {
            console::check()
        } else {
            console::cross()
        };
        println!("  \u{251c}\u{2500} {:<40} {}", sr.name, status);
        for note in &sr.notes {
            println!("  \u{2502}    \u{2514}\u{2500} {}", console::dim(note));
        }
        for warn in &sr.warnings {
            println!(
                "  \u{2502}    \u{2514}\u{2500} {} {}",
                console::warn(),
                console::yellow(warn)
            );
        }
        for err in &sr.errors {
            println!(
                "  \u{2502}    \u{2514}\u{2500} {} {}",
                console::cross(),
                console::red(err)
            );
        }
    }

    console::end_rule();
    if report.ok() {
        println!(
            "  {} Config valid. {} scenario(s) ready.",
            console::check(),
            report.enabled_count()
        );
    } else {
        println!("  {} Config invalid.", console::cross());
    }
}

fn list(args: ListArgs) -> CmdResult {
    let cfg = config::load(&args.config)?;
    let report = config::validate(&cfg);
    let enabled = cfg.scenarios.iter().filter(|s| s.enabled).count();

    console::section(&format!("Suite: {}", cfg.suite.name));
    println!(
        "  {} scenarios enabled / {} total\n",
        enabled,
        cfg.scenarios.len()
    );

    let headers = &[
        "#",
        "Name",
        "Category",
        "Interface",
        "Protocol",
        "Conns",
        "MsgSize",
    ];
    let rows: Vec<Vec<String>> = cfg
        .scenarios
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let marker = if s.enabled {
                format!("{:02}", i + 1)
            } else {
                "×".to_string()
            };
            vec![
                marker,
                s.name.clone(),
                s.category.clone().unwrap_or_else(|| "-".to_string()),
                scenario_interface(s),
                s.protocol_label(),
                scenario_conns(s),
                scenario_msgsize(s),
            ]
        })
        .collect();

    console::table(headers, &rows, b"rllllrl");
    console::end_rule();

    if !report.ok() {
        log::warn!("config has validation errors; run `seshat validate` for details");
    }
    Ok(())
}

fn scenario_interface(s: &Scenario) -> String {
    if let Some(sender) = &s.sender {
        sender.interface.label().to_string()
    } else if !s.streams.is_empty() {
        let mut labels: Vec<&str> = s.streams.iter().map(|st| st.interface.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        labels.join("+")
    } else {
        "-".to_string()
    }
}

fn scenario_conns(s: &Scenario) -> String {
    if s.sender.is_some() {
        s.connections.to_string()
    } else if !s.streams.is_empty() {
        s.streams
            .iter()
            .map(|st| st.connections)
            .sum::<u32>()
            .to_string()
    } else {
        "-".to_string()
    }
}

fn scenario_msgsize(s: &Scenario) -> String {
    if let Some(size) = s.message_size_bytes {
        return human_bytes(size);
    }
    if !s.streams.is_empty() {
        let mut sizes: Vec<u32> = s.streams.iter().map(|st| st.message_size_bytes).collect();
        sizes.sort_unstable();
        sizes.dedup();
        return sizes
            .iter()
            .map(|b| human_bytes(*b))
            .collect::<Vec<_>>()
            .join("+");
    }
    "-".to_string()
}

fn human_bytes(n: u32) -> String {
    if n >= 1024 && n.is_multiple_of(1024) {
        format!("{} KB", n / 1024)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

/// Parse a DSCP tag name (e.g. "EF", "AF41", "BE", "CS3") to its numeric value.
fn dscp_from_tag(tag: &str) -> Option<u8> {
    match tag.to_uppercase().as_str() {
        "BE" | "CS0" => Some(0),
        "CS1" => Some(8),
        "AF11" => Some(10),
        "AF12" => Some(12),
        "AF13" => Some(14),
        "CS2" => Some(16),
        "AF21" => Some(18),
        "AF22" => Some(20),
        "AF23" => Some(22),
        "CS3" => Some(24),
        "AF31" => Some(26),
        "AF32" => Some(28),
        "AF33" => Some(30),
        "CS4" => Some(32),
        "AF41" => Some(34),
        "AF42" => Some(36),
        "AF43" => Some(38),
        "CS5" => Some(40),
        "EF" => Some(46),
        "CS6" => Some(48),
        "CS7" => Some(56),
        _ => tag.parse().ok(),
    }
}

fn sysinfo(args: SysinfoArgs) -> CmdResult {
    let info = crate::sysinfo::SysInfo::collect();
    match args.format {
        SysinfoFormat::Table => info.render_table(),
        SysinfoFormat::Json => println!("{}", info.to_json()),
    }
    Ok(())
}

/// Sweep the harness's null-loopback throughput ceiling across message sizes
/// (NFR-PERF reference) and report the per-sample statistics overhead.
fn calibrate(args: CalibrateArgs) -> CmdResult {
    console::banner();
    console::rule("HARNESS CALIBRATION");

    let overhead = calibrate::record_overhead_ns(200_000);
    console::kv("Stats cost", &format!("{overhead:.1} ns/sample"), 13);
    console::kv(
        "Headroom min",
        &format!("{:.1}x", calibrate::HEADROOM_MIN),
        13,
    );
    console::kv(
        "Probe",
        &format!(
            "{} conn, {:.2}s each",
            args.connections,
            args.duration.as_secs_f64()
        ),
        13,
    );
    console::line("");

    let mut transports: Vec<(&str, Box<dyn Transport>)> = Vec::new();
    if args.tcp {
        transports.push(("tcp", Box::new(TcpTransport)));
    }
    if args.udp {
        transports.push(("udp", Box::new(UdpTransport)));
    }
    if transports.is_empty() {
        return Err("nothing to probe: enable at least one of --tcp/--udp".into());
    }

    console::line(&console::bold(&format!(
        "  {:<6} {:>10} {:>16} {:>16}",
        "proto", "msg_bytes", "throughput", "msg_rate"
    )));

    let mut csv = Csv::new(&[
        "transport",
        "message_bytes",
        "connections",
        "throughput_gbps",
        "message_rate",
    ]);
    for size in &args.message_sizes {
        let msg = (*size).max(HEADER_LEN as u32);
        for (label, transport) in &transports {
            let c = calibrate::measure_ceiling(
                transport.as_ref(),
                msg,
                args.connections as usize,
                args.duration,
            )?;
            console::line(&format!(
                "  {:<6} {:>10} {:>11.3} Gbit/s {:>11.0} m/s",
                label, msg, c.throughput_gbps, c.message_rate
            ));
            csv.row(vec![
                (*label).to_string(),
                msg.to_string(),
                args.connections.to_string(),
                num(c.throughput_gbps, 4),
                num(c.message_rate, 1),
            ]);
        }
    }
    console::end_rule();

    if let Some(dir) = &args.output_dir {
        let path = dir.join("calibration.csv");
        csv.write(&path)?;
        log::info!("wrote {}", path.display());
    }
    Ok(())
}

fn setup(args: SetupArgs) -> CmdResult {
    log::info!("setup: topology={:?}", args.topology);
    use crate::topology;

    if !topology::has_net_admin() {
        log::error!("setup requires CAP_NET_ADMIN — run with sudo or appropriate capabilities");
        return Err("CAP_NET_ADMIN required".into());
    }

    match args.topology {
        TopologyKind::Veth => {
            let topo = topology::setup_veth(&args.left_ip, &args.right_ip, args.subnet_mask)
                .map_err(|e| format!("veth setup failed: {e}"))?;
            // Prevent drop from tearing it down (user manages lifecycle manually).
            std::mem::forget(topo);
            log::info!(
                "veth topology created: {} ↔ {} (prefix /{})",
                args.left_ip,
                args.right_ip,
                args.subnet_mask
            );
        }
        TopologyKind::Netns => {
            let topo = topology::setup_netns(
                &args.left_namespace,
                &args.right_namespace,
                &args.left_ip,
                &args.right_ip,
                args.subnet_mask,
            )
            .map_err(|e| format!("netns setup failed: {e}"))?;
            std::mem::forget(topo);
            log::info!(
                "netns topology created: {}({}) ↔ {}({})",
                args.left_namespace,
                args.left_ip,
                args.right_namespace,
                args.right_ip
            );
        }
    }
    Ok(())
}

fn teardown(args: TeardownArgs) -> CmdResult {
    log::info!("teardown: topology={:?}", args.topology);
    use crate::topology::{self, ProvisionedTopology};

    if !topology::has_net_admin() {
        log::error!("teardown requires CAP_NET_ADMIN");
        return Err("CAP_NET_ADMIN required".into());
    }

    let mode = match args.topology {
        TopologyKind::Veth => crate::topology::TopologyMode::Veth,
        TopologyKind::Netns => crate::topology::TopologyMode::Netns,
    };

    let topo = ProvisionedTopology {
        mode,
        namespaces: vec![args.left_namespace, args.right_namespace],
        veth_pair: Some(("seshat-a".to_string(), "seshat-b".to_string())),
        addrs: (String::new(), String::new()),
    };
    topology::teardown_topology(&topo).map_err(|e| format!("teardown failed: {e}"))?;
    log::info!("topology torn down");
    Ok(())
}

fn impair(args: ImpairArgs) -> CmdResult {
    log::info!(
        "impair: interface={}, latency={}ms, loss={}%",
        args.interface,
        args.latency,
        args.loss
    );
    use crate::topology::impair::{self, Impairment};

    let imp = Impairment {
        delay_ms: if args.latency > 0.0 {
            Some(args.latency as u32)
        } else {
            None
        },
        jitter_ms: if args.jitter > 0.0 {
            Some(args.jitter as u32)
        } else {
            None
        },
        loss_pct: if args.loss > 0.0 {
            Some(args.loss)
        } else {
            None
        },
        bandwidth_mbit: if args.bandwidth > 0 {
            Some(args.bandwidth)
        } else {
            None
        },
        reorder_pct: if args.reorder > 0.0 {
            Some(args.reorder)
        } else {
            None
        },
        duplicate_pct: if args.duplicate > 0.0 {
            Some(args.duplicate)
        } else {
            None
        },
    };

    let applied = impair::apply_impairment(&args.interface, &imp)
        .map_err(|e| format!("impairment failed: {e}"))?;
    // Forget so it persists (user removes via teardown or `tc qdisc del`).
    std::mem::forget(applied);
    log::info!("impairment applied to {}", args.interface);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::MetricsBackendArg;
    use crate::config::Suite;

    #[test]
    fn reload_noop_classification_matches_scg_name_keyed_diff() {
        use crate::config::ReloadAction;
        // Same-name parameter changes the SCG diff ignores (no-op).
        assert!(reload_is_noop_on_scg(ReloadAction::UpdateTlsProfile));
        assert!(reload_is_noop_on_scg(ReloadAction::RotateCert));
        // Actions that genuinely take effect must stay zero-drop, not no-op.
        assert!(!reload_is_noop_on_scg(ReloadAction::AddConnection));
        assert!(!reload_is_noop_on_scg(ReloadAction::RemoveConnection));
        assert!(!reload_is_noop_on_scg(ReloadAction::InvalidConfig));
    }

    fn base_config() -> Config {
        Config {
            schema: None,
            suite: Suite {
                name: "suite".to_string(),
                description: String::new(),
                author: String::new(),
                version: "1.0.0".to_string(),
            },
            defaults: Defaults::default(),
            scenarios: Vec::new(),
        }
    }

    fn base_args() -> RunArgs {
        RunArgs {
            config: PathBuf::from("./cfg.json"),
            output_dir: None,
            runs: None,
            duration: None,
            warmup: None,
            cooldown: None,
            scenario: None,
            tag: None,
            cpu_affinity: Vec::new(),
            no_system_metrics: false,
            metrics_backend: None,
            scg_pid: None,
            dry_run: false,
        }
    }

    #[test]
    fn metrics_backend_override_updates_defaults() {
        let mut cfg = base_config();
        let mut args = base_args();
        args.metrics_backend = Some(MetricsBackendArg::Perf);

        apply_overrides(&mut cfg, &args).unwrap();

        assert_eq!(cfg.defaults.metrics_backend, MetricsBackend::Perf);
        assert!(cfg.defaults.collect_system_metrics);
    }

    #[test]
    fn no_system_metrics_disables_backend() {
        let mut cfg = base_config();
        let mut args = base_args();
        args.metrics_backend = Some(MetricsBackendArg::Perf);
        args.no_system_metrics = true;

        apply_overrides(&mut cfg, &args).unwrap();

        assert_eq!(cfg.defaults.metrics_backend, MetricsBackend::None);
        assert!(!cfg.defaults.collect_system_metrics);
    }
}
