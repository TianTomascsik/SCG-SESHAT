//! Self-contained result directory tree (F-18) and the suite-complete summary
//! (F-20). Every benchmark invocation writes a timestamped directory:
//!
//! ```text
//! results/<YYYYMMDD-HHMMSS>/
//!   meta.csv                       suite + run metadata
//!   sysinfo.csv                    host fingerprint snapshot (F-19)
//!   summary.csv                    one columnar row per executed scenario
//!   scenarios/<name>/
//!     config.csv                   resolved scenario configuration
//!     summary.csv                  cross-run aggregated metrics (key/value)
//!     runs.csv                     one row per measurement run
//!     system_metrics/              per-SCG-PID `/proc` timeseries (F-13b)
//! ```
//!
//! Output is CSV-only by design; the tree is portable and opens directly in a
//! spreadsheet.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::{Config, Interface, ProtocolType, Scenario, TlsVersion};
use crate::gateway::logscan::{effective_protocol_label, Effective};
use crate::metrics::app::FlowSummary;
use crate::metrics::overhead::{compute as compute_overhead, EncapProfile};
use crate::metrics::system::{MemCopyResult, PerfResult, SysAgg, SystemSample};
use crate::proto::wire::HEADER_LEN;
use crate::run::calibrate::Calibration;
use crate::run::engine::RunParams;
use crate::run::engine::RunStats;
use crate::run::saturation::SweepResult;
use crate::sysinfo::SysInfo;
use crate::time::realtime_ns;
use crate::workload::streams::MultiStreamResult;

use super::csv::{num, Csv};

/// Columnar header for the top-level cross-scenario `summary.csv`.
const SUMMARY_HEADERS: &[&str] = &[
    "scenario",
    "transport",
    "protocol",
    "message_bytes",
    "connections",
    "runs",
    "throughput_gbps_mean",
    "throughput_gbps_ci95",
    "throughput_gbps_min",
    "throughput_gbps_max",
    "latency_mean_us",
    "latency_mean_ci95",
    "latency_p99_us_mean",
    "latency_p99_us_ci95",
    "jitter_us_mean",
    "handshake_us_mean",
    "loss_pct",
    "total_lost",
    "integrity_failures",
    "boundary_violations",
    "encapsulation_overhead_bytes_analytical",
    "encapsulation_overhead_capture_verified",
    "ceiling_gbps",
    "headroom",
    "harness_limited",
    "dut",
    "saturation_gbps",
    "max_lossfree_gbps",
    "overloaded",
    "effective_protocol",
    "cpu_pct_peak",
    "cpu_pct_mean",
    "rss_peak_kib",
    "pss_peak_kib",
    "gbps_per_core",
    "bottleneck",
    "rtt_us_mean",
    "rtt_us_ci95",
    "rtt_us_p50",
    "rtt_us_p99",
    "conns_per_sec",
    "conns_per_sec_ci95",
    "conn_handshake_p50_us",
    "conn_handshake_p99_us",
    "perf_cycles",
    "perf_instructions",
    "perf_ipc",
    "perf_cache_references",
    "perf_cache_misses",
    "perf_context_switches",
    "perf_syscalls",
    "perf_task_clock_ms",
    "perf_duration_s",
    "co_corrected",
    "send_lag_mean_us",
    "send_lag_max_us",
    "ctx_switches_total",
    "ctx_switches_per_s",
    "cpu_seconds_total",
    "mem_copies_per_msg",
    "mem_copy_to_user",
    "mem_copy_from_user",
    "mem_splice_syscalls",
    "resumed_fraction",
    "cpu_hot_thread_pct_p95",
    "host_busy_frac_p95",
    "ceiling_transport",
];

/// Per-run header for each scenario's `runs.csv`.
const RUNS_HEADERS: &[&str] = &[
    "run",
    "throughput_gbps",
    "message_rate",
    "messages",
    "bytes",
    "duration_s",
    "latency_mean_us",
    "latency_p50_us",
    "latency_p90_us",
    "latency_p95_us",
    "latency_p99_us",
    "latency_p999_us",
    "latency_min_us",
    "latency_max_us",
    "jitter_us",
    "loss_pct",
    "lost",
    "duplicate",
    "reordered",
    "integrity_failures",
    "boundary_violations",
    "outliers_removed",
];

/// A summary row distilled for the console suite report (F-20).
#[derive(Debug, Clone)]
pub struct ScenarioOutcome {
    pub name: String,
    pub throughput_gbps: f64,
    pub loss_pct: f64,
    /// Pre-formatted, mode-aware one-line metric for the compact progress view
    /// (throughput, round-trip, or connection-rate depending on the run mode).
    pub headline: String,
}

/// Build the compact, mode-aware headline metric shown in the live progress
/// view: round-trip time for ping-pong, connection rate for connrate, otherwise
/// throughput with p99 latency and loss.
fn outcome_headline(stats: &RunStats) -> String {
    if let Some(rtt) = &stats.rtt {
        format!("rtt {:.1} µs  p99 {:.1} µs", rtt.p50_us, rtt.p99_us)
    } else if let Some(conn) = &stats.conn {
        format!(
            "{:.0} conn/s  hs p99 {:.1} µs",
            conn.conns_per_sec, conn.handshake_p99_us
        )
    } else {
        format!(
            "{:.3} Gbit/s  p99 {:.1} µs  loss {:.3} %",
            stats.throughput_gbps.mean, stats.latency_p99_us.mean, stats.loss_pct
        )
    }
}

/// One completed row belonging to a generated interface-comparison group.
#[derive(Debug, Clone)]
struct ComparisonOutcome {
    group: String,
    scenario: String,
    transport: String,
    reference: String,
    gateway_reference: Option<String>,
    throughput_gbps: f64,
    latency_mean_us: f64,
    latency_p99_us: f64,
    jitter_us: f64,
    loss_pct: f64,
    cpu_pct_peak: Option<f64>,
    rss_peak_kib: Option<u64>,
    pss_peak_kib: Option<u64>,
}

/// Optional analysis artifacts attached to a recorded scenario: the calibration
/// outcome, the saturation sweep (Phase D), gateway `/proc` CPU aggregates,
/// optional `perf stat` counters, and the effective-protocol scan (Phase E).
/// All are absent for a plain loopback run, so each is an `Option`;
/// `loss_threshold_pct` drives the `overloaded` flag.
#[derive(Clone, Copy, Default)]
pub struct ScenarioArtifacts<'a> {
    pub cal: Option<&'a Calibration>,
    pub sweep: Option<&'a SweepResult>,
    pub sys: Option<&'a SysAgg>,
    pub perf: Option<&'a PerfResult>,
    pub mem_copies: Option<&'a MemCopyResult>,
    pub effective: Option<&'a Effective>,
    pub loss_threshold_pct: f64,
}

/// Observations from one hot-reload injection.  These are deliberately a
/// separate artifact because reload windows do not map cleanly onto the normal
/// cross-run throughput aggregate.
#[derive(Debug, Clone)]
pub struct ReloadArtifact {
    pub action: String,
    pub fired: bool,
    pub action_succeeded: bool,
    pub reload_duration_us: u64,
    pub connections_before: usize,
    pub connections_after: usize,
    pub inflight_packets_lost: u64,
    pub latency_p99_us: f64,
    pub throughput_gbps: f64,
    pub rollback_continuity_passed: Option<bool>,
    /// Whether the requested change actually took effect. `Some(false)` for a
    /// same-name TLS-profile / cert reload, because the harness only SIGHUPs the
    /// *unchanged* config file (no diff is produced). The gateway itself now
    /// applies same-name field changes (`diff`'s `changed` bucket), but this
    /// action does not rewrite the file to trigger it — so a zero-drop result is
    /// a no-op, not proof of seamless in-place reload. `None` when not classified
    /// (add/remove connection, invalid-config rollback).
    pub change_applied: Option<bool>,
}

/// A timestamped result directory being populated during a run.
pub struct ResultDir {
    root: PathBuf,
    summary: Csv,
    skipped: Csv,
    comparisons: Vec<ComparisonOutcome>,
    started_unix: u64,
    outcomes: Vec<ScenarioOutcome>,
}

impl ResultDir {
    /// Create `base/<timestamp>/` and seed the cross-scenario summary table.
    pub fn create(base: &Path) -> io::Result<Self> {
        let started_unix = realtime_ns() / 1_000_000_000;
        let stamp = format_timestamp(started_unix);
        let mut root = base.join(&stamp);
        // Avoid clobbering an existing directory from the same second.
        let mut suffix = 1;
        while root.exists() {
            root = base.join(format!("{stamp}-{suffix}"));
            suffix += 1;
        }
        fs::create_dir_all(&root)?;
        Ok(ResultDir {
            root,
            summary: Csv::new(SUMMARY_HEADERS),
            skipped: Csv::new(&["scenario", "reason"]),
            comparisons: Vec::new(),
            started_unix,
            outcomes: Vec::new(),
        })
    }

    /// The absolute path of this result directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist the host fingerprint as `sysinfo.csv`.
    pub fn write_sysinfo(&self, info: &SysInfo) -> io::Result<()> {
        sysinfo_csv(info).write(&self.root.join("sysinfo.csv"))
    }

    /// Write a scenario's per-run artifacts and append its summary row.
    ///
    /// `art` bundles the optional calibration, saturation sweep (Phase D),
    /// gateway CPU aggregates, optional `perf stat` counters, and the
    /// effective-protocol scan (Phase E). The sweep, when present, is written
    /// as `saturation.csv`; `loss_threshold_pct` flags the run as `overloaded`
    /// when its measured loss exceeds the budget.
    pub fn record_scenario(
        &mut self,
        scenario: &Scenario,
        params: &RunParams,
        stats: &RunStats,
        art: &ScenarioArtifacts,
    ) -> io::Result<()> {
        let ScenarioArtifacts {
            cal,
            sweep,
            sys,
            perf,
            mem_copies,
            effective,
            loss_threshold_pct,
        } = *art;
        let dir = self.root.join("scenarios").join(sanitize(&scenario.name));
        fs::create_dir_all(dir.join("system_metrics"))?;

        let overloaded = stats.loss_pct > loss_threshold_pct;
        let protocol = scenario.protocol_label();
        let effective_protocol = match effective {
            Some(e) => effective_protocol_label(&protocol, e),
            None => protocol.clone(),
        };

        let analytical_overhead = analytical_overhead(scenario, params);
        scenario_config_csv(scenario, params, analytical_overhead)
            .write(&dir.join("config.csv"))?;
        scenario_summary_csv(
            stats,
            art,
            overloaded,
            &effective_protocol,
            analytical_overhead,
        )
        .write(&dir.join("summary.csv"))?;
        runs_csv(stats).write(&dir.join("runs.csv"))?;
        if let Some(sweep) = sweep {
            saturation_csv(sweep).write(&dir.join("saturation.csv"))?;
        }

        let transport = params.sender.interface.label().to_string();
        let jitter_mean = mean_jitter(stats);
        let (ceiling_s, headroom_s, limited_s, dut_s) = calibration_cells(cal);
        let (saturation_s, lossfree_s) = match sweep {
            Some(s) => (num(s.saturation_gbps, 4), num(s.max_lossfree_gbps, 4)),
            None => (String::new(), String::new()),
        };
        let (cpu_peak_s, cpu_mean_s, rss_peak_s, pss_peak_s, per_core_s) =
            cpu_cells(sys, stats.throughput_gbps.mean);
        let bottleneck_s = cal.map(|c| c.bottleneck.to_string()).unwrap_or_default();
        let (rtt_mean_s, rtt_ci_s, rtt_p50_s, rtt_p99_s) = rtt_cells(stats);
        let (cps_s, cps_ci_s, hs_p50_s, hs_p99_s) = conn_cells(stats);
        let (
            perf_cycles_s,
            perf_instructions_s,
            perf_ipc_s,
            perf_cache_refs_s,
            perf_cache_misses_s,
            perf_ctx_switches_s,
            perf_syscalls_s,
            perf_task_clock_s,
            perf_duration_s,
        ) = perf_cells(perf);
        self.summary.row(vec![
            scenario.name.clone(),
            transport,
            protocol,
            params.message_bytes.to_string(),
            params.connections.to_string(),
            stats.runs.len().to_string(),
            num(stats.throughput_gbps.mean, 4),
            num(stats.throughput_gbps.ci95, 4),
            num(stats.throughput_gbps.min, 4),
            num(stats.throughput_gbps.max, 4),
            num(stats.latency_mean_us.mean, 3),
            num(stats.latency_mean_us.ci95, 3),
            num(stats.latency_p99_us.mean, 3),
            num(stats.latency_p99_us.ci95, 3),
            num(jitter_mean, 3),
            num(stats.handshake_us.mean, 3),
            num(stats.loss_pct, 4),
            stats.total_lost.to_string(),
            stats
                .runs
                .iter()
                .map(|run| run.integrity_failures)
                .sum::<u64>()
                .to_string(),
            stats
                .runs
                .iter()
                .map(|run| run.boundary_violations)
                .sum::<u64>()
                .to_string(),
            analytical_overhead
                .map(|bytes| bytes.to_string())
                .unwrap_or_default(),
            "false".to_string(),
            ceiling_s,
            headroom_s,
            limited_s,
            dut_s,
            saturation_s,
            lossfree_s,
            overloaded.to_string(),
            effective_protocol,
            cpu_peak_s,
            cpu_mean_s,
            rss_peak_s,
            pss_peak_s,
            per_core_s,
            bottleneck_s,
            rtt_mean_s,
            rtt_ci_s,
            rtt_p50_s,
            rtt_p99_s,
            cps_s,
            cps_ci_s,
            hs_p50_s,
            hs_p99_s,
            perf_cycles_s,
            perf_instructions_s,
            perf_ipc_s,
            perf_cache_refs_s,
            perf_cache_misses_s,
            perf_ctx_switches_s,
            perf_syscalls_s,
            perf_task_clock_s,
            perf_duration_s,
            stats.co_corrected.to_string(),
            num(stats.send_lag_mean_us, 3),
            num(stats.send_lag_max_us, 3),
            sys.map(|a| a.ctx_switches_total.to_string())
                .unwrap_or_default(),
            sys.map(|a| num(a.ctx_switches_per_s, 1))
                .unwrap_or_default(),
            sys.map(|a| num(a.cpu_seconds_total, 4)).unwrap_or_default(),
            mem_copies
                .and_then(|m| m.copies_per_msg(total_messages(stats)))
                .map(|v| num(v, 3))
                .unwrap_or_default(),
            mem_copies
                .and_then(|m| m.copy_to_user)
                .map(|v| v.to_string())
                .unwrap_or_default(),
            mem_copies
                .and_then(|m| m.copy_from_user)
                .map(|v| v.to_string())
                .unwrap_or_default(),
            mem_copies
                .and_then(|m| m.splice)
                .map(|v| v.to_string())
                .unwrap_or_default(),
            effective
                .and_then(|e| e.resumed_fraction())
                .map(|v| num(v, 3))
                .unwrap_or_default(),
            sys.map(|a| num(a.cpu_hot_thread_pct_p95, 1))
                .unwrap_or_default(),
            sys.map(|a| num(a.host_busy_frac_p95, 3))
                .unwrap_or_default(),
            cal.map(|c| c.ceiling_transport.to_string())
                .unwrap_or_default(),
        ]);

        self.outcomes.push(ScenarioOutcome {
            name: scenario.name.clone(),
            throughput_gbps: stats.throughput_gbps.mean,
            loss_pct: stats.loss_pct,
            headline: outcome_headline(stats),
        });
        if let Some(comparison) = &scenario.comparison {
            self.comparisons.push(ComparisonOutcome {
                group: comparison.group.clone(),
                scenario: scenario.name.clone(),
                transport: params.sender.interface.label().to_string(),
                reference: comparison.reference.clone(),
                gateway_reference: comparison.gateway_reference.clone(),
                throughput_gbps: stats.throughput_gbps.mean,
                latency_mean_us: stats.latency_mean_us.mean,
                latency_p99_us: stats.latency_p99_us.mean,
                jitter_us: mean_jitter(stats),
                loss_pct: stats.loss_pct,
                cpu_pct_peak: sys.map(|a| a.cpu_pct_peak),
                rss_peak_kib: sys.map(|a| a.rss_peak_kib),
                pss_peak_kib: sys.map(|a| a.pss_peak_kib),
            });
        }
        Ok(())
    }

    /// Write per-PID system-metrics timeseries (F-13b) for a scenario under
    /// `scenarios/<name>/system_metrics/`. A no-op when `samples` is empty.
    pub fn record_system_metrics(
        &self,
        scenario: &Scenario,
        samples: &[SystemSample],
    ) -> io::Result<()> {
        let dir = self
            .root
            .join("scenarios")
            .join(sanitize(&scenario.name))
            .join("system_metrics");
        crate::metrics::system::write_csv(&dir, samples)
    }

    /// Persist per-stream scheduling results rather than reducing a scheduling
    /// run to a synthetic best-flow summary.  The normal `summary.csv` remains
    /// compatible while this artifact carries the evidence for safety/bulk
    /// isolation and DSCP checks.
    pub fn record_stream_results(
        &self,
        scenario: &Scenario,
        result: &MultiStreamResult,
    ) -> io::Result<()> {
        let dir = self.root.join("scenarios").join(sanitize(&scenario.name));
        let mut streams = Csv::new(&[
            "stream",
            "traffic_class",
            "priority",
            "throughput_gbps",
            "latency_mean_us",
            "latency_p50_us",
            "latency_p95_us",
            "latency_p99_us",
            "jitter_us",
            "loss_pct",
            "lost",
            "duplicate",
            "reordered",
            "dscp_preserved",
        ]);
        for stream in &result.streams {
            streams.row(vec![
                stream.name.clone(),
                stream.traffic_class.clone(),
                stream.priority.to_string(),
                num(stream.summary.throughput_gbps, 4),
                num(stream.summary.latency_us.mean, 3),
                num(stream.summary.latency_us.p50, 3),
                num(stream.summary.latency_us.p95, 3),
                num(stream.summary.latency_us.p99, 3),
                num(stream.summary.jitter_us, 3),
                num(stream.summary.loss_pct, 4),
                stream.summary.integrity.lost.to_string(),
                stream.summary.integrity.duplicate.to_string(),
                stream.summary.integrity.reordered.to_string(),
                stream
                    .dscp_preserved
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ]);
        }
        streams.write(&dir.join("streams.csv"))?;
        let mut summary = Csv::key_value();
        summary
            .kv("fairness_ratio", num(result.fairness_ratio, 4))
            .kv("safety_loss_free", result.safety_loss_free.to_string())
            .kv(
                "safety_p99_us",
                result
                    .safety_p99_us
                    .map(|value| num(value, 3))
                    .unwrap_or_default(),
            );
        summary.write(&dir.join("stream_summary.csv"))
    }

    /// Persist hot-reload control-plane timing and traffic-continuity evidence.
    pub fn record_reload_artifact(
        &self,
        scenario: &Scenario,
        artifact: &ReloadArtifact,
    ) -> io::Result<()> {
        let dir = self.root.join("scenarios").join(sanitize(&scenario.name));
        let mut csv = Csv::key_value();
        csv.kv("action", artifact.action.clone())
            .kv("reload_fired", artifact.fired.to_string())
            .kv("action_succeeded", artifact.action_succeeded.to_string())
            .kv(
                "reload_duration_us",
                artifact.reload_duration_us.to_string(),
            )
            .kv(
                "connections_before",
                artifact.connections_before.to_string(),
            )
            .kv("connections_after", artifact.connections_after.to_string())
            .kv(
                "inflight_packets_lost",
                artifact.inflight_packets_lost.to_string(),
            )
            .kv("latency_p99_us", num(artifact.latency_p99_us, 3))
            .kv(
                "throughput_during_reload_gbps",
                num(artifact.throughput_gbps, 4),
            )
            .kv(
                "rollback_continuity_passed",
                artifact
                    .rollback_continuity_passed
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            )
            .kv(
                "change_applied",
                artifact
                    .change_applied
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            );
        csv.write(&dir.join("hotreload.csv"))
    }

    /// Persist an explicit capability/setup skip.  A skipped scenario must be
    /// visible to downstream analysis; silently omitting it would make a
    /// generated matrix look more complete than the host permitted.
    pub fn record_skipped(&mut self, scenario: &Scenario, reason: &str) -> io::Result<()> {
        let dir = self.root.join("scenarios").join(sanitize(&scenario.name));
        let mut detail = Csv::key_value();
        detail
            .kv("scenario", scenario.name.clone())
            .kv("reason", reason.to_string());
        detail.write(&dir.join("skip.csv"))?;
        self.skipped
            .row(vec![scenario.name.clone(), reason.to_string()]);
        Ok(())
    }

    /// Write `meta.csv` and the top-level `summary.csv`, finishing the tree.
    pub fn finish(
        &self,
        cfg: &Config,
        config_path: &Path,
        executed: usize,
        skipped: usize,
        host: &SysInfo,
    ) -> io::Result<()> {
        let mut meta = Csv::key_value();
        meta.kv("tool", "seshat")
            .kv("version", env!("CARGO_PKG_VERSION"))
            .kv("config", config_path.display().to_string())
            .kv("suite_name", cfg.suite.name.clone())
            .kv("suite_version", cfg.suite.version.clone())
            .kv("started_unix", self.started_unix.to_string())
            .kv("started_utc", format_datetime(self.started_unix))
            .kv("scenarios_executed", executed.to_string())
            .kv("scenarios_skipped", skipped.to_string())
            .kv(
                "collect_system_metrics",
                cfg.defaults.collect_system_metrics.to_string(),
            )
            .kv("metrics_backend", cfg.defaults.metrics_backend.label())
            .kv("host_wsl", host.wsl.to_string())
            .kv("ktls_usable", host.ktls_usable.to_string());
        meta.write(&self.root.join("meta.csv"))?;

        self.summary.write(&self.root.join("summary.csv"))?;
        self.skipped.write(&self.root.join("skipped.csv"))?;
        self.write_interface_comparison()
    }

    /// Outcomes for the console suite summary, in execution order.
    pub fn outcomes(&self) -> &[ScenarioOutcome] {
        &self.outcomes
    }

    /// Consolidate matched interface rows and calculate end-to-end and
    /// gateway-normalized deltas.  References that were skipped remain blank,
    /// which preserves the fact that an unavailable capability cannot support
    /// a valid comparison on that host.
    fn write_interface_comparison(&self) -> io::Result<()> {
        if self.comparisons.is_empty() {
            return Ok(());
        }
        use std::collections::HashMap;
        let by_scenario = self
            .comparisons
            .iter()
            .map(|row| (row.scenario.as_str(), row))
            .collect::<HashMap<_, _>>();
        let mut csv = Csv::new(&[
            "group",
            "scenario",
            "transport",
            "reference_scenario",
            "gateway_reference_scenario",
            "throughput_gbps",
            "latency_mean_us",
            "latency_p99_us",
            "jitter_us",
            "loss_pct",
            "cpu_pct_peak",
            "rss_peak_kib",
            "pss_peak_kib",
            "throughput_delta_vs_direct_gbps",
            "latency_p99_delta_vs_direct_us",
            "throughput_delta_vs_gateway_gbps",
            "latency_p99_delta_vs_gateway_us",
        ]);
        for row in &self.comparisons {
            let direct = by_scenario.get(row.reference.as_str()).copied();
            let gateway = row
                .gateway_reference
                .as_deref()
                .and_then(|name| by_scenario.get(name).copied());
            csv.row(vec![
                row.group.clone(),
                row.scenario.clone(),
                row.transport.clone(),
                row.reference.clone(),
                row.gateway_reference.clone().unwrap_or_default(),
                num(row.throughput_gbps, 4),
                num(row.latency_mean_us, 3),
                num(row.latency_p99_us, 3),
                num(row.jitter_us, 3),
                num(row.loss_pct, 4),
                row.cpu_pct_peak.map(|v| num(v, 1)).unwrap_or_default(),
                row.rss_peak_kib.map(|v| v.to_string()).unwrap_or_default(),
                row.pss_peak_kib.map(|v| v.to_string()).unwrap_or_default(),
                direct
                    .map(|r| num(row.throughput_gbps - r.throughput_gbps, 4))
                    .unwrap_or_default(),
                direct
                    .map(|r| num(row.latency_p99_us - r.latency_p99_us, 3))
                    .unwrap_or_default(),
                gateway
                    .map(|r| num(row.throughput_gbps - r.throughput_gbps, 4))
                    .unwrap_or_default(),
                gateway
                    .map(|r| num(row.latency_p99_us - r.latency_p99_us, 3))
                    .unwrap_or_default(),
            ]);
        }
        csv.write(&self.root.join("interface_comparison.csv"))
    }
}

/// Mean per-run jitter across a scenario's runs.
fn mean_jitter(stats: &RunStats) -> f64 {
    if stats.runs.is_empty() {
        return 0.0;
    }
    let sum: f64 = stats.runs.iter().map(|r| r.jitter_us).sum();
    sum / stats.runs.len() as f64
}

/// Estimate the per-message protocol overhead from the configured endpoint
/// path.  This is intentionally marked analytical: TCP options, TLS record
/// coalescing, and the actual on-wire packetisation require a packet capture
/// before they can be claimed as observed bytes.
fn analytical_overhead(scenario: &Scenario, params: &RunParams) -> Option<u32> {
    let profile = match params.sender.interface {
        Interface::Unix => EncapProfile::Uds,
        Interface::Shm => EncapProfile::Shm,
        Interface::Udp => match scenario.protocol.kind {
            ProtocolType::Dtls => EncapProfile::Dtls12Gcm,
            _ => EncapProfile::Udp,
        },
        Interface::Tcp | Interface::Tproxy => match scenario.protocol.kind {
            ProtocolType::Tls => match scenario.protocol.version {
                TlsVersion::V1_3 => EncapProfile::Tls13Aead,
                TlsVersion::V1_0 | TlsVersion::V1_2 => EncapProfile::Tls12Gcm,
            },
            ProtocolType::Dtls => return None,
            ProtocolType::None | ProtocolType::Wireguard | ProtocolType::Ipsec => EncapProfile::Tcp,
        },
    };
    Some(compute_overhead(profile).total)
}

/// Resolved scenario configuration as a `key,value` table.
fn scenario_config_csv(s: &Scenario, params: &RunParams, analytical_overhead: Option<u32>) -> Csv {
    let payload = params.message_bytes.saturating_sub(HEADER_LEN as u32);
    let mut c = Csv::key_value();
    c.kv("name", s.name.clone())
        .kv("category", s.category.clone().unwrap_or_default())
        .kv("transport", params.sender.interface.label())
        .kv("protocol", s.protocol_label())
        .kv(
            "pattern",
            format!("{:?}", params.sender.pattern).to_lowercase(),
        )
        .kv("message_bytes", params.message_bytes.to_string())
        .kv("payload_bytes", payload.to_string())
        .kv(
            "encapsulation_overhead_bytes_analytical",
            analytical_overhead
                .map(|bytes| bytes.to_string())
                .unwrap_or_default(),
        )
        .kv("encapsulation_overhead_capture_verified", "false")
        .kv("connections", params.connections.to_string())
        .kv("gateway_enabled", s.gateway.enabled.to_string())
        .kv("runs", params.runs.to_string())
        .kv("warmup_secs", params.warmup.as_secs().to_string())
        .kv("measure_secs", params.measure.as_secs().to_string())
        .kv("cooldown_secs", params.cooldown.as_secs().to_string())
        .kv("outlier_removal", params.remove_outliers.to_string());
    c
}

/// Cross-run aggregated metrics as a `key,value` table.
fn scenario_summary_csv(
    stats: &RunStats,
    art: &ScenarioArtifacts,
    overloaded: bool,
    effective_protocol: &str,
    analytical_overhead: Option<u32>,
) -> Csv {
    let thr = &stats.throughput_gbps;
    let lat = &stats.latency_mean_us;
    let p99 = &stats.latency_p99_us;
    let mut c = Csv::key_value();
    c.kv("runs", stats.runs.len().to_string())
        .kv("throughput_gbps_mean", num(thr.mean, 4))
        .kv("throughput_gbps_ci95", num(thr.ci95, 4))
        .kv("throughput_gbps_stddev", num(thr.stddev, 4))
        .kv("throughput_gbps_min", num(thr.min, 4))
        .kv("throughput_gbps_max", num(thr.max, 4))
        .kv("throughput_gbps_cov", num(thr.cov, 4))
        .kv("latency_mean_us", num(lat.mean, 3))
        .kv("latency_mean_ci95", num(lat.ci95, 3))
        .kv("latency_p99_us_mean", num(p99.mean, 3))
        .kv("latency_p99_us_ci95", num(p99.ci95, 3))
        .kv("handshake_us_mean", num(stats.handshake_us.mean, 3))
        .kv("loss_pct", num(stats.loss_pct, 4))
        .kv("total_lost", stats.total_lost.to_string())
        .kv(
            "integrity_failures",
            stats
                .runs
                .iter()
                .map(|run| run.integrity_failures)
                .sum::<u64>()
                .to_string(),
        )
        .kv(
            "boundary_violations",
            stats
                .runs
                .iter()
                .map(|run| run.boundary_violations)
                .sum::<u64>()
                .to_string(),
        )
        .kv("overloaded", overloaded.to_string())
        .kv("effective_protocol", effective_protocol.to_string())
        .kv(
            "encapsulation_overhead_bytes_analytical",
            analytical_overhead
                .map(|bytes| bytes.to_string())
                .unwrap_or_default(),
        )
        .kv("encapsulation_overhead_capture_verified", "false");
    if let Some(cal) = art.cal {
        c.kv("ceiling_gbps", num(cal.ceiling_gbps, 4))
            .kv("headroom", num(cal.headroom, 2))
            .kv("harness_limited", cal.harness_limited.to_string())
            .kv("dut", cal.dut)
            .kv("bottleneck", cal.bottleneck)
            .kv("ceiling_transport", cal.ceiling_transport);
    }
    if let Some(a) = art.sys {
        c.kv("cpu_pct_peak", num(a.cpu_pct_peak, 1))
            .kv("cpu_pct_mean", num(a.cpu_pct_mean, 1))
            .kv("cpu_pct_p95", num(a.cpu_pct_p95, 1))
            .kv("cpu_hot_thread_pct_p95", num(a.cpu_hot_thread_pct_p95, 1))
            .kv("host_busy_frac_p95", num(a.host_busy_frac_p95, 3))
            .kv("cpu_seconds_total", num(a.cpu_seconds_total, 4))
            .kv("ctx_switches_total", a.ctx_switches_total.to_string())
            .kv("ctx_switches_per_s", num(a.ctx_switches_per_s, 1))
            .kv("rss_peak_kib", a.rss_peak_kib.to_string())
            .kv("pss_peak_kib", a.pss_peak_kib.to_string());
        if a.cpu_pct_peak > 0.0 {
            c.kv("gbps_per_core", num(thr.mean / (a.cpu_pct_peak / 100.0), 4));
        }
    }
    if let Some(p) = art.perf {
        if let Some(v) = p.cycles {
            c.kv("perf_cycles", v.to_string());
        }
        if let Some(v) = p.instructions {
            c.kv("perf_instructions", v.to_string());
        }
        if let Some(v) = p.ipc {
            c.kv("perf_ipc", num(v, 3));
        }
        if let Some(v) = p.cache_references {
            c.kv("perf_cache_references", v.to_string());
        }
        if let Some(v) = p.cache_misses {
            c.kv("perf_cache_misses", v.to_string());
        }
        if let Some(v) = p.context_switches {
            c.kv("perf_context_switches", v.to_string());
        }
        if let Some(v) = p.syscalls {
            c.kv("perf_syscalls", v.to_string());
        }
        if let Some(v) = p.task_clock_ms {
            c.kv("perf_task_clock_ms", num(v, 3));
        }
        if let Some(v) = p.duration_s {
            c.kv("perf_duration_s", num(v, 6));
        }
    }
    if let Some(m) = art.mem_copies {
        if let Some(cpm) = m.copies_per_msg(total_messages(stats)) {
            c.kv("mem_copies_per_msg", num(cpm, 3));
        }
        if let Some(v) = m.copy_to_user {
            c.kv("mem_copy_to_user", v.to_string());
        }
        if let Some(v) = m.copy_from_user {
            c.kv("mem_copy_from_user", v.to_string());
        }
        if let Some(v) = m.splice {
            c.kv("mem_splice_syscalls", v.to_string());
        }
    }
    if let Some(s) = art.sweep {
        c.kv("saturation_gbps", num(s.saturation_gbps, 4))
            .kv("max_lossfree_gbps", num(s.max_lossfree_gbps, 4))
            .kv("knee_offered_mbps", num(s.knee_offered_mbps, 3));
    }
    if let Some(r) = stats.rtt {
        c.kv("rtt_us_mean", num(r.mean_us, 3))
            .kv("rtt_us_ci95", num(r.mean_ci95, 3))
            .kv("rtt_us_p50", num(r.p50_us, 3))
            .kv("rtt_us_p99", num(r.p99_us, 3))
            .kv("rtt_samples", r.samples.to_string());
    }
    if let Some(cn) = stats.conn {
        c.kv("conns_per_sec", num(cn.conns_per_sec, 1))
            .kv("conns_per_sec_ci95", num(cn.conns_per_sec_ci95, 1))
            .kv("conn_handshake_p50_us", num(cn.handshake_p50_us, 3))
            .kv("conn_handshake_p99_us", num(cn.handshake_p99_us, 3))
            .kv("conn_total", cn.total_conns.to_string());
    }
    if let Some(eff) = art.effective {
        if let Some(frac) = eff.resumed_fraction() {
            c.kv("resumed_fraction", num(frac, 3))
                .kv("resumed_handshakes", eff.resumed_handshakes.to_string())
                .kv("full_handshakes", eff.full_handshakes.to_string());
        }
    }
    c
}

/// Round-trip summary cells (Phase F) for the top-level `summary.csv`: mean,
/// CI95, p50, and p99 in microseconds. Empty for throughput scenarios, which
/// carry no [`RunStats::rtt`].
fn rtt_cells(stats: &RunStats) -> (String, String, String, String) {
    match stats.rtt {
        Some(r) => (
            num(r.mean_us, 3),
            num(r.mean_ci95, 3),
            num(r.p50_us, 3),
            num(r.p99_us, 3),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    }
}

/// Connection-rate cells (Phase G) for the top-level `summary.csv`: rate, its
/// CI95 (connections/second), and the p50/p99 handshake latency (µs). Empty for
/// non-connrate scenarios, which carry no [`RunStats::conn`].
fn conn_cells(stats: &RunStats) -> (String, String, String, String) {
    match stats.conn {
        Some(c) => (
            num(c.conns_per_sec, 1),
            num(c.conns_per_sec_ci95, 1),
            num(c.handshake_p50_us, 3),
            num(c.handshake_p99_us, 3),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    }
}

/// Gateway CPU summary cells: peak %, mean %, and Gbit/s per fully-loaded core
/// (throughput divided by the peak core-equivalents). Empty when no gateway CPU
/// timeseries was captured (e.g. a plain loopback run).
fn cpu_cells(
    sys: Option<&SysAgg>,
    throughput_gbps: f64,
) -> (String, String, String, String, String) {
    match sys {
        Some(a) => {
            let per_core = if a.cpu_pct_peak > 0.0 {
                num(throughput_gbps / (a.cpu_pct_peak / 100.0), 4)
            } else {
                String::new()
            };
            (
                num(a.cpu_pct_peak, 1),
                num(a.cpu_pct_mean, 1),
                a.rss_peak_kib.to_string(),
                a.pss_peak_kib.to_string(),
                per_core,
            )
        }
        None => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
    }
}

/// Perf-stat summary cells: raw counters plus IPC/task-clock/duration.
fn perf_cells(
    perf: Option<&PerfResult>,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
) {
    match perf {
        Some(p) => (
            p.cycles.map(|v| v.to_string()).unwrap_or_default(),
            p.instructions.map(|v| v.to_string()).unwrap_or_default(),
            p.ipc.map(|v| num(v, 3)).unwrap_or_default(),
            p.cache_references
                .map(|v| v.to_string())
                .unwrap_or_default(),
            p.cache_misses.map(|v| v.to_string()).unwrap_or_default(),
            p.context_switches
                .map(|v| v.to_string())
                .unwrap_or_default(),
            p.syscalls.map(|v| v.to_string()).unwrap_or_default(),
            p.task_clock_ms.map(|v| num(v, 3)).unwrap_or_default(),
            p.duration_s.map(|v| num(v, 6)).unwrap_or_default(),
        ),
        None => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
    }
}

/// The per-point saturation-sweep curve as a columnar `saturation.csv`.
fn saturation_csv(sweep: &SweepResult) -> Csv {
    // The per-load-point series *is* the degradation curve: each row is a point
    // on the offered-load axis. The annotation columns make it self-describing —
    // `pct_of_peak_throughput` traces the plateau/roll-off and `past_lossfree_knee`
    // marks where loss/latency begin to climb (the saturation point).
    const HEADERS: &[&str] = &[
        "point",
        "offered_mbps",
        "throughput_gbps",
        "loss_pct",
        "latency_p99_us",
        "pct_of_peak_throughput",
        "past_lossfree_knee",
    ];
    let mut c = Csv::new(HEADERS);
    let peak = sweep.saturation_gbps;
    for (i, p) in sweep.points.iter().enumerate() {
        let pct_of_peak = if peak > 0.0 {
            p.throughput_gbps / peak * 100.0
        } else {
            0.0
        };
        let past_knee = sweep.knee_offered_mbps > 0.0 && p.offered_mbps > sweep.knee_offered_mbps;
        c.row(vec![
            (i + 1).to_string(),
            num(p.offered_mbps, 3),
            num(p.throughput_gbps, 4),
            num(p.loss_pct, 4),
            num(p.latency_p99_us, 3),
            num(pct_of_peak, 1),
            past_knee.to_string(),
        ]);
    }
    c
}

/// Render a calibration outcome as the four summary cells (or empty strings).
fn calibration_cells(cal: Option<&Calibration>) -> (String, String, String, String) {
    match cal {
        Some(c) => (
            num(c.ceiling_gbps, 4),
            num(c.headroom, 2),
            c.harness_limited.to_string(),
            c.dut.to_string(),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    }
}

/// One row per measurement run.
fn runs_csv(stats: &RunStats) -> Csv {
    let mut c = Csv::new(RUNS_HEADERS);
    for (i, r) in stats.runs.iter().enumerate() {
        c.row(run_row(i, r));
    }
    c
}

/// Build the columnar row for a single run.
fn run_row(index: usize, r: &FlowSummary) -> Vec<String> {
    let l = &r.latency_us;
    vec![
        (index + 1).to_string(),
        num(r.throughput_gbps, 4),
        num(r.message_rate, 1),
        r.messages.to_string(),
        r.bytes.to_string(),
        num(r.duration_s, 4),
        num(l.mean, 3),
        num(l.p50, 3),
        num(l.p90, 3),
        num(l.p95, 3),
        num(l.p99, 3),
        num(l.p999, 3),
        num(l.min, 3),
        num(l.max, 3),
        num(r.jitter_us, 3),
        num(r.loss_pct, 4),
        r.integrity.lost.to_string(),
        r.integrity.duplicate.to_string(),
        r.integrity.reordered.to_string(),
        r.integrity_failures.to_string(),
        r.boundary_violations.to_string(),
        r.outliers_removed.to_string(),
    ]
}

/// Host fingerprint snapshot as a `key,value` table (F-19).
fn sysinfo_csv(info: &SysInfo) -> Csv {
    let mut c = Csv::key_value();
    c.kv("hostname", info.hostname.clone())
        .kv("os", info.os.clone())
        .kv("kernel", info.kernel.clone())
        .kv("arch", info.arch.clone())
        .kv("cpu_model", info.cpu_model.clone())
        .kv("cpu_logical", info.cpu_logical.to_string())
        .kv("cpu_physical", opt(info.cpu_physical))
        .kv(
            "cpu_mhz",
            info.cpu_mhz.map(|v| num(v, 1)).unwrap_or_default(),
        )
        .kv("governor", info.governor.clone().unwrap_or_default())
        .kv("turbo", opt(info.turbo))
        .kv("smt", opt(info.smt))
        .kv(
            "isolated_cpus",
            info.isolated_cpus.clone().unwrap_or_default(),
        )
        .kv("numa_nodes", opt(info.numa_nodes))
        .kv("mem_total_kb", opt(info.mem_total_kb))
        .kv("thp", info.thp.clone().unwrap_or_default())
        .kv("ktls", info.ktls.to_string())
        .kv("ktls_usable", info.ktls_usable.to_string())
        .kv("wsl", info.wsl.to_string())
        .kv("io_uring", opt(info.io_uring))
        .kv("seshat_version", info.seshat_version.clone())
        .kv("seshat_git", info.seshat_git.clone().unwrap_or_default())
        .kv("scg_git", info.scg_git.clone().unwrap_or_default())
        .kv("nic_count", info.nics.len().to_string());
    for nic in &info.nics {
        let detail = format!(
            "speed_mbps={} mtu={} state={}",
            nic.speed_mbps.map(|v| v.to_string()).unwrap_or_default(),
            nic.mtu.map(|v| v.to_string()).unwrap_or_default(),
            nic.operstate.clone().unwrap_or_default(),
        );
        c.kv(&format!("nic.{}", nic.name), detail);
    }
    c
}

/// Render an `Option<T: ToString>` as its value or empty string.
fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

/// Total messages measured across all runs (the denominator for per-message
/// metrics such as memory copies per message).
fn total_messages(stats: &RunStats) -> u64 {
    stats.runs.iter().map(|r| r.messages).sum()
}

/// Replace characters unsafe for a path segment with `_`.
pub(crate) fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `YYYYMMDD-HHMMSS` (UTC) directory stamp from a Unix timestamp.
fn format_timestamp(unix_secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix(unix_secs);
    format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}")
}

/// `YYYY-MM-DD HH:MM:SS UTC` human form for metadata.
fn format_datetime(unix_secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix(unix_secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Convert a Unix timestamp to civil `(year, month, day, hour, min, sec)` (UTC)
/// using Howard Hinnant's `civil_from_days` algorithm (no external deps).
fn civil_from_unix(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix_secs / 86_400) as i64;
    let rem = (unix_secs % 86_400) as u32;
    let hh = rem / 3_600;
    let mm = (rem % 3_600) / 60;
    let ss = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::stats::Summary;
    use crate::run::engine::{RunMode, RunStats};

    fn empty_run_stats() -> RunStats {
        RunStats {
            runs: Vec::new(),
            throughput_gbps: Summary::empty(),
            latency_mean_us: Summary::empty(),
            latency_p99_us: Summary::empty(),
            handshake_us: Summary::empty(),
            total_lost: 0,
            loss_pct: 0.0,
            mode: RunMode::Throughput,
            rtt: None,
            conn: None,
            co_corrected: false,
            send_lag_mean_us: 0.0,
            send_lag_max_us: 0.0,
        }
    }

    #[test]
    fn timestamp_epoch_is_known() {
        // 0 → 1970-01-01 00:00:00 UTC.
        assert_eq!(format_timestamp(0), "19700101-000000");
        // 1_700_000_000 → 2023-11-14 22:13:20 UTC (verified externally).
        assert_eq!(format_timestamp(1_700_000_000), "20231114-221320");
        assert_eq!(format_datetime(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn sanitize_keeps_safe_chars() {
        assert_eq!(sanitize("perf_tcp-1.4KB"), "perf_tcp-1.4KB");
        assert_eq!(sanitize("a/b c:d"), "a_b_c_d");
    }

    #[test]
    fn scenario_summary_includes_perf_metrics() {
        let stats = empty_run_stats();
        let perf = PerfResult {
            cycles: Some(123),
            instructions: Some(456),
            ipc: Some(3.5),
            cache_references: Some(789),
            cache_misses: Some(12),
            context_switches: Some(34),
            syscalls: Some(56),
            task_clock_ms: Some(56.789),
            duration_s: Some(1.234567),
        };

        let csv = scenario_summary_csv(
            &stats,
            &ScenarioArtifacts {
                perf: Some(&perf),
                ..Default::default()
            },
            false,
            "ktls/1.3",
            Some(74),
        )
        .render();

        assert!(csv.contains("perf_cycles,123\r\n"));
        assert!(csv.contains("perf_instructions,456\r\n"));
        assert!(csv.contains("perf_ipc,3.500\r\n"));
        assert!(csv.contains("perf_syscalls,56\r\n"));
        assert!(csv.contains("perf_duration_s,1.234567\r\n"));
        assert!(csv.contains("encapsulation_overhead_bytes_analytical,74\r\n"));
        assert!(csv.contains("encapsulation_overhead_capture_verified,false\r\n"));
    }

    #[test]
    fn analytical_overhead_is_not_packet_capture_measurement() {
        let scenario: Scenario = serde_json::from_value(serde_json::json!({
            "name": "tls13",
            "sender": { "interface": "tcp", "target_addr": "127.0.0.1:1" },
            "protocol": { "type": "tls", "version": "1.3" }
        }))
        .unwrap();
        let params = RunParams {
            message_bytes: 1024,
            connections: 1,
            runs: 1,
            warmup: std::time::Duration::ZERO,
            measure: std::time::Duration::from_secs(1),
            cooldown: std::time::Duration::ZERO,
            remove_outliers: false,
            sender_cores: Vec::new(),
            receiver_cores: Vec::new(),
            sender: scenario.sender.clone().unwrap(),
            mode: RunMode::Throughput,
        };
        assert_eq!(analytical_overhead(&scenario, &params), Some(74));
    }
}
