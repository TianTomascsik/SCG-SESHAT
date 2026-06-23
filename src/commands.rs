//! Subcommand dispatch and handlers.
//!
//! Phase 0 implements `validate`, `list`, and `run --dry-run` (config-driven);
//! `sysinfo` lands in WP0.3 and the remaining commands in later phases.
//! Handlers return a boxed-error result; `main` maps `Err` to a non-zero exit.

use crate::cli::{
    CalibrateArgs, Command, ImpairArgs, ListArgs, ReceiverArgs, ReportArgs, RunArgs, SenderArgs,
    SetupArgs, SysinfoArgs, SysinfoFormat, TeardownArgs, TopologyKind, ValidateArgs,
};
use crate::config::{
    self, Config, Defaults, GatewayChain, Interface, MetricsBackend, Mode, OutlierRemoval,
    ProtectionMode, ProtocolType, Scenario, TlsVersion, TopologyMode, ValidationReport,
};
use crate::console;
use crate::gateway::logscan::{self, Effective};
use crate::gateway::{self, SecuritySpec};
use crate::metrics::app::FlowSummary;
use crate::metrics::system::{self, SystemSampler};
use crate::proto::wire::HEADER_LEN;
use crate::report::csv::{num, Csv};
use crate::report::results::{sanitize, ResultDir, ScenarioArtifacts, ScenarioOutcome};
use crate::run::affinity;
use crate::run::calibrate::{self, Calibration};
use crate::run::engine::{self, RunMode, RunParams, RunStats};
use crate::run::saturation::{self, SweepPlan, SweepResult};
use crate::transport::gateway::{GatewayDut, GatewayTcpTransport, GatewayUdpTransport};
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
    if host.wsl && !host.ktls_usable {
        log::warn!(
            "host is WSL with kTLS unavailable; any kTLS scenario runs as userspace TLS \
             (the effective_protocol column records the actual protocol per scenario)"
        );
    }
    rdir.write_sysinfo(&host)?;

    // Resolve sender/receiver/gateway CPU pools once for the whole suite.
    let cores = resolve_core_plan(&cfg.defaults);

    // Cache harness ceilings by (transport, on-wire size, connections) so the
    // NFR-PERF headroom probe runs at most once per distinct scenario shape.
    let mut ceilings: HashMap<(String, u32, usize), f64> = HashMap::new();
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
            log::warn!("no gateway binary supports the required providers; SCG scenarios will be skipped");
        }
        found
    } else {
        None
    };

    for scenario in cfg.scenarios.iter().filter(|s| s.enabled) {
        if let Some(transport) = loopback_transport(scenario) {
            let params = build_run_params(scenario, &cfg.defaults, &cores);
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
                        )?
                    };
                    if !ran {
                        skipped += 1;
                    }
                }
                None => {
                    log::warn!(
                        "scenario '{}' [{} / {}] needs the SCG but no gateway binary is available; skipping",
                        scenario.name,
                        plan.transport_name,
                        scenario.protocol_label()
                    );
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
        // unix/shm endpoints are provisioned by the gateway (Phase 2).
        Interface::Unix | Interface::Shm => None,
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

/// A resolved plan to run a scenario through the SCG over TCP.
#[derive(Debug, Clone, Copy)]
struct GatewayPlan {
    security: GwSecurity,
    topology: gateway::Topology,
    transport_name: &'static str,
}

/// Decide whether a scenario can be driven through the gateway in this slice and
/// how. Returns `None` for paths still pending later work packages (UDS/SHM,
/// DTLS/UDP, WireGuard/IPSec, or a non-loopback network topology).
fn gateway_plan(s: &Scenario) -> Option<GatewayPlan> {
    if !s.gateway.enabled
        || s.network_impairment.is_some()
        || s.topology.mode != TopologyMode::Loopback
    {
        return None;
    }

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
        if sender.interface != Interface::Udp || s.connections.max(1) > 1 {
            return None;
        }
        // The gateway's DTLS provider tops out at DTLS 1.2; map 1.3 down.
        let version = "dtls1.2";
        let mutual = s.protocol.mutual_auth;
        return Some(GatewayPlan {
            security: GwSecurity::Dtls { version, mutual },
            topology,
            transport_name: if mutual { "scg-dtls-mtls" } else { "scg-dtls" },
        });
    }

    if sender.interface != Interface::Tcp {
        // UDS/SHM gateway endpoints and the UDP-over-TLS (ALE/RAW) paths land in
        // later work packages.
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
            let version = match s.protocol.version {
                TlsVersion::V1_2 => "tls1.2",
                TlsVersion::V1_3 => "tls1.3",
            };
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
                (GwSecurity::Tls { version, ktls: true }, "scg-ktls")
            } else {
                (GwSecurity::Tls { version, ktls: false }, "scg-tls")
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
    // Connection-rate churn through the gateway is not wired yet (it needs a
    // dedicated ingress connect/teardown harness); skip with a notice so the
    // loopback connrate scenarios still run.
    if scenario.mode == Mode::Connrate {
        log::warn!(
            "scenario '{}': connection-rate benchmarking through the gateway is not supported yet; skipping",
            scenario.name
        );
        return Ok(false);
    }
    let work_dir = rdir.root().join("gateway").join(sanitize(&scenario.name));
    std::fs::create_dir_all(&work_dir)?;

    let spec = match plan.security {
        GwSecurity::Routing => SecuritySpec::routing_tcp(),
        GwSecurity::Tls { version, ktls } => {
            if !crate::pki::openssl_available() {
                log::warn!(
                    "scenario '{}' needs TLS certificates but the openssl CLI is unavailable; skipping",
                    scenario.name
                );
                return Ok(false);
            }
            let id = crate::pki::generate_self_signed(&work_dir, 2)?;
            let mut spec = SecuritySpec::tls_server(version, &id.cert, &id.key);
            if ktls {
                spec = spec.provider("ktls");
            }
            spec
        }
        GwSecurity::Mtls { version, ktls } => {
            if !crate::pki::openssl_available() {
                log::warn!(
                    "scenario '{}' needs a TLS CA bundle but the openssl CLI is unavailable; skipping",
                    scenario.name
                );
                return Ok(false);
            }
            let bundle = crate::pki::generate_mtls_bundle(&work_dir, 2)?;
            let mut spec = SecuritySpec::tls_mutual(version, &bundle);
            if ktls {
                spec = spec.provider("ktls");
            }
            spec
        }
        GwSecurity::IntegrityOnly { version } => {
            if !crate::pki::openssl_available() {
                log::warn!(
                    "scenario '{}' needs TLS certificates but the openssl CLI is unavailable; skipping",
                    scenario.name
                );
                return Ok(false);
            }
            let id = crate::pki::generate_self_signed(&work_dir, 2)?;
            SecuritySpec::tls_server(version, &id.cert, &id.key).with_profile("integrity-only")
        }
        GwSecurity::Dtls { version, mutual } => {
            if !crate::pki::openssl_available() {
                log::warn!(
                    "scenario '{}' needs DTLS certificates but the openssl CLI is unavailable; skipping",
                    scenario.name
                );
                return Ok(false);
            }
            if mutual {
                let bundle = crate::pki::generate_mtls_bundle(&work_dir, 2)?;
                SecuritySpec::dtls_mutual(version, &bundle)
            } else {
                let id = crate::pki::generate_self_signed(&work_dir, 2)?;
                SecuritySpec::dtls_server(version, &id.cert, &id.key)
            }
        }
    };

    let params = build_run_params(scenario, defaults, cores);
    render_scenario_header(scenario, &params, plan.transport_name);

    // DTLS runs over UDP datagrams; everything else over TCP. Both wrap into a
    // `GatewayDut` so PID sampling, the run engine, and shutdown stay uniform.
    // The gateway is pinned to its own core pool so it never contends with the
    // harness sender/receiver.
    let is_udp = matches!(plan.security, GwSecurity::Dtls { .. });
    let dut = if is_udp {
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

    // F-13b perf backend: attach `perf stat` when configured.
    let perf_sampler = if defaults.metrics_backend == MetricsBackend::Perf {
        dut.pids().first().and_then(|&pid| {
            system::PerfSampler::start(pid, &work_dir)
        })
    } else {
        None
    };

    let run_result = engine::run_scenario(dut.as_transport(), &params, |i, s| {
        render_run_line(i, params.runs, s);
    });

    // Stop sampling immediately once the runs finish (before any teardown or
    // calibration probe), regardless of whether the runs succeeded.
    let system_samples = sampler.map(SystemSampler::stop);
    let perf_result = perf_sampler.map(system::PerfSampler::stop);
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
            let _ = dut.shutdown();
            return Err(e.into());
        }
    };

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

    // Start the gateway with a routing config (each stream gets its own
    // connection through the same rule set).
    let spec = SecuritySpec::routing_tcp();
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
    let warmup = Duration::from_secs(
        scenario.warmup_secs.unwrap_or(defaults.warmup_secs),
    );
    let measure = Duration::from_secs(
        scenario.duration_secs.unwrap_or(defaults.duration_secs).max(1),
    );

    let mut configs = Vec::with_capacity(scenario.streams.len());
    let mut pairs = Vec::with_capacity(scenario.streams.len());

    for (i, stream) in scenario.streams.iter().enumerate() {
        let msg_bytes = stream.message_size_bytes.max(HEADER_LEN as u32);
        let rate_limit = match stream.pattern {
            config::Pattern::Periodic => stream
                .interval_us
                .map(|iv| {
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

        // Create a transport pair through the gateway for this stream.
        let pair = dut.as_transport().loopback_pair(msg_bytes)?;
        pairs.push(pair);
    }

    console::rule(&format!("Scenario: {} (multi-stream)", scenario.name));
    console::kv("Streams", &scenario.streams.len().to_string(), 10);
    console::kv(
        "Schedule",
        &format!("{}s warmup / {}s measure", warmup.as_secs(), measure.as_secs()),
        10,
    );

    // Sample system metrics during the run.
    let sampler = sys_rate
        .filter(|_| !dut.pids().is_empty())
        .map(|hz| SystemSampler::start(dut.pids(), hz));

    let result: MultiStreamResult = streams::run_multi_stream(&configs, pairs, warmup, measure)?;

    let system_samples = sampler.map(SystemSampler::stop);
    if let Some(samples) = &system_samples {
        let _ = rdir.record_system_metrics(scenario, samples);
    }

    // Render results.
    console::line("");
    for sr in &result.streams {
        console::kv(
            &format!("  {}", sr.name),
            &format!(
                "{:.3} Gbit/s  p99={:.0}µs  loss={}",
                sr.summary.throughput_gbps,
                sr.summary.latency_us.p99,
                sr.summary.integrity.lost
            ),
            16,
        );
    }
    console::kv("  Fairness", &format!("{:.3}", result.fairness_ratio), 16);
    console::kv(
        "  Safety loss-free",
        if result.safety_loss_free { "PASS" } else { "FAIL" },
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
        cooldown: Duration::from_secs(
            scenario.cooldown_secs.unwrap_or(defaults.cooldown_secs),
        ),
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
            sys: system_samples.as_deref().and_then(system::aggregate).as_ref(),
            loss_threshold_pct: defaults.loss_threshold_pct,
            ..Default::default()
        },
    )?;
    Ok(true)
}

// ─── F-11: Hot-Reload Execution ─────────────────────────────────────────────

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
    let spec = match plan.security {
        GwSecurity::Routing => SecuritySpec::routing_tcp(),
        GwSecurity::Tls { version, ktls } => {
            if !crate::pki::openssl_available() {
                log::warn!("scenario '{}': openssl unavailable; skipping", scenario.name);
                return Ok(false);
            }
            let id = crate::pki::generate_self_signed(&work_dir, 2)?;
            let mut spec = SecuritySpec::tls_server(version, &id.cert, &id.key);
            if ktls { spec = spec.provider("ktls"); }
            spec
        }
        GwSecurity::Mtls { version, ktls } => {
            if !crate::pki::openssl_available() {
                log::warn!("scenario '{}': openssl unavailable; skipping", scenario.name);
                return Ok(false);
            }
            let bundle = crate::pki::generate_mtls_bundle(&work_dir, 2)?;
            let mut spec = SecuritySpec::tls_mutual(version, &bundle);
            if ktls { spec = spec.provider("ktls"); }
            spec
        }
        GwSecurity::IntegrityOnly { version } => {
            if !crate::pki::openssl_available() {
                log::warn!("scenario '{}': openssl unavailable; skipping", scenario.name);
                return Ok(false);
            }
            let id = crate::pki::generate_self_signed(&work_dir, 2)?;
            SecuritySpec::tls_server(version, &id.cert, &id.key).with_profile("integrity-only")
        }
        GwSecurity::Dtls { version, mutual } => {
            if !crate::pki::openssl_available() {
                log::warn!("scenario '{}': openssl unavailable; skipping", scenario.name);
                return Ok(false);
            }
            if mutual {
                let bundle = crate::pki::generate_mtls_bundle(&work_dir, 2)?;
                SecuritySpec::dtls_mutual(version, &bundle)
            } else {
                let id = crate::pki::generate_self_signed(&work_dir, 2)?;
                SecuritySpec::dtls_server(version, &id.cert, &id.key)
            }
        }
    };

    let params = build_run_params(scenario, defaults, cores);

    // Start the gateway.
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
    let reload_trigger_dur = Duration::from_secs(trigger_secs)
        + extended_params.warmup; // trigger offset from thread start

    // Get process info for reload injection before entering the run.
    let process_ref = dut.first_process();
    let config_paths = dut.config_paths();
    let gw_pid = process_ref.map(|p| p.pid());

    // We run the engine on the main thread and inject reload from a spawned timer thread.
    let reload_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_fired_clone = reload_fired.clone();

    // Timer thread: sleep until trigger point, then SIGHUP.
    let config_path = config_paths.first().cloned();
    let pid_for_reload = gw_pid;
    let _reload_thread = std::thread::spawn(move || {
        std::thread::sleep(reload_trigger_dur);
        if let (Some(path), Some(pid)) = (config_path, pid_for_reload) {
            // Re-write the same config (simulates a no-op reload that still
            // exercises the full reload code path in the gateway).
            let _ = unsafe { libc::kill(pid, libc::SIGHUP) };
            log::info!("hot-reload: SIGHUP sent to gateway (pid={pid}) at {}s", trigger_secs);
            let _ = path; // config_path available for future swap variants
        }
        reload_fired_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let run_result = engine::run_scenario(transport, &extended_params, |i, s| {
        render_run_line(i, extended_params.runs, s);
    });

    let system_samples = sampler.map(SystemSampler::stop);
    let sys_agg = system_samples.as_deref().and_then(system::aggregate);

    let stats = match run_result {
        Ok(stats) => stats,
        Err(e) => {
            log::warn!(
                "scenario '{}': run failed ({e}); skipping",
                scenario.name
            );
            dut.shutdown()?;
            return Ok(false);
        }
    };

    // Report hot-reload specific metrics.
    let reload_actually_fired = reload_fired.load(std::sync::atomic::Ordering::Relaxed);
    console::line("");
    console::kv("  Reload fired", if reload_actually_fired { "yes" } else { "no" }, 16);
    if let Some(run) = stats.runs.first() {
        let drops = run.integrity.lost;
        console::kv("  Drops", &drops.to_string(), 16);
        if reload_event.expect_zero_drops && drops > 0 {
            console::kv("  VERDICT", "FAIL (drops > 0)", 16);
        } else {
            console::kv("  VERDICT", "PASS", 16);
        }
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
            effective: Some(&effective),
            loss_threshold_pct: defaults.loss_threshold_pct,
            ..Default::default()
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
            log::warn!(
                "auto-affinity: only {total} logical core(s) available; running unpinned"
            );
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

/// Default on-wire message size when a scenario omits `message_size_bytes`.
const DEFAULT_MESSAGE_BYTES: u32 = 1024;

fn render_scenario_header(s: &Scenario, params: &RunParams, transport_label: &str) {
    console::section(&format!("Scenario: {}", s.name));
    console::card("", &[
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
    ]);
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
    console::card("Result", &[
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
        ("Loss", format!("{:.3} % ({} msg)", stats.loss_pct, stats.total_lost)),
    ]);
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
            console::card("Result — Round-Trip Time", &[
                (
                    "RTT",
                    format!(
                        "mean {:.1} ± {:.1} µs    p50 {:.1} µs    p99 {:.1} µs",
                        rtt.mean_us, rtt.mean_ci95, rtt.p50_us, rtt.p99_us
                    ),
                ),
                ("Samples", rtt.samples.to_string()),
            ]);
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
            console::card("Result — Connection Rate", &[
                (
                    "Rate",
                    format!("{:.0} ± {:.0} conn/s", conn.conns_per_sec, conn.conns_per_sec_ci95),
                ),
                (
                    "Handshake",
                    format!("p50 {:.1} µs    p99 {:.1} µs", conn.handshake_p50_us, conn.handshake_p99_us),
                ),
                ("Connections", conn.total_conns.to_string()),
            ]);
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
    console::card("Saturation Sweep", &[
        (
            "Ceiling",
            format!("{:.3} Gbit/s", result.saturation_gbps),
        ),
        (
            "Loss-free",
            format!(
                "{:.3} Gbit/s (≤{:.1} % loss) @ {:.0} Mbit/s offered",
                result.max_lossfree_gbps, loss_threshold_pct, result.knee_offered_mbps
            ),
        ),
        ("Points", result.points.len().to_string()),
    ]);
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
        value.push_str(&format!(
            "  {}",
            console::yellow("⚠ HARNESS-LIMITED (<3×)")
        ));
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

    if let (Some(best), Some(worst)) = (
        best_by_throughput(outcomes),
        worst_by_throughput(outcomes),
    ) {
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
            return Err(format!(
                "no scenario named '{name}' (config has {before} scenario(s))"
            )
            .into());
        }
    }
    if args.no_system_metrics {
        cfg.defaults.collect_system_metrics = false;
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
    log::info!(
        "sender: scenario={}, target={}",
        args.scenario,
        args.target
    );

    let cfg = config::load(&args.config)?;
    let scenario = cfg
        .scenarios
        .iter()
        .find(|s| s.name == args.scenario)
        .ok_or_else(|| format!("scenario '{}' not found in config", args.scenario))?;

    let sender_spec = scenario
        .sender
        .clone()
        .unwrap_or_else(|| config::Sender {
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
        warmup: Duration::from_secs(
            scenario.warmup_secs.unwrap_or(cfg.defaults.warmup_secs),
        ),
        measure: Duration::from_secs(
            scenario
                .duration_secs
                .unwrap_or(cfg.defaults.duration_secs)
                .max(1),
        ),
        cooldown: Duration::from_secs(
            scenario.cooldown_secs.unwrap_or(cfg.defaults.cooldown_secs),
        ),
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

    let sender_spec = scenario
        .sender
        .clone()
        .unwrap_or_else(|| config::Sender {
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
        warmup: Duration::from_secs(
            scenario.warmup_secs.unwrap_or(cfg.defaults.warmup_secs),
        ),
        measure: Duration::from_secs(
            scenario
                .duration_secs
                .unwrap_or(cfg.defaults.duration_secs)
                .max(1),
        ),
        cooldown: Duration::from_secs(
            scenario.cooldown_secs.unwrap_or(cfg.defaults.cooldown_secs),
        ),
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
    console::kv("Throughput", &format!("{:.3} Gbit/s", summary.throughput_gbps), 10);
    console::kv("Latency p99", &format!("{:.0} µs", summary.latency_us.p99), 10);
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
        return Err(format!(
            "no scenarios/ subdirectory in {}",
            args.input.display()
        ).into());
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
            println!("  \u{2502}    \u{2514}\u{2500} {} {}", console::warn(), console::yellow(warn));
        }
        for err in &sr.errors {
            println!("  \u{2502}    \u{2514}\u{2500} {} {}", console::cross(), console::red(err));
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

    let headers = &["#", "Name", "Category", "Interface", "Protocol", "Conns", "MsgSize"];
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
    console::kv("Headroom min", &format!("{:.1}x", calibrate::HEADROOM_MIN), 13);
    console::kv(
        "Probe",
        &format!("{} conn, {:.2}s each", args.connections, args.duration.as_secs_f64()),
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
                args.left_ip, args.right_ip, args.subnet_mask
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
                args.left_namespace, args.left_ip,
                args.right_namespace, args.right_ip
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
    topology::teardown_topology(&topo)
        .map_err(|e| format!("teardown failed: {e}"))?;
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
