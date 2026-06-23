//! Command-line interface (F-01 subcommands, F-02 global flags).
//!
//! Defines the full `seshat` CLI surface with `clap`. Global flags that apply
//! everywhere (`--log-level`, `--quiet`) live on the top-level [`Cli`]; flags
//! that only make sense for a particular workflow live on that subcommand's
//! argument struct.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

/// SESHAT — the SCG benchmark harness.
#[derive(Debug, Parser)]
#[command(
    name = "seshat",
    version,
    about = "SESHAT — SCG Evaluation, Stress & Harness Analysis Toolkit",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Logging verbosity.
    #[arg(long, value_enum, default_value_t = LogLevel::Info, global = true)]
    pub log_level: LogLevel,

    /// Suppress the banner and live console output.
    #[arg(long, default_value_t = false, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Logging verbosity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

/// Output format for the `report` subcommand. Only CSV is produced (locked
/// decision); the enum is kept for forward compatibility and clear errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Csv,
}

/// Output format for the `sysinfo` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SysinfoFormat {
    Table,
    Json,
}

/// CLI override for the suite-level system-metrics backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MetricsBackendArg {
    Procfs,
    Perf,
    Ebpf,
    None,
}

impl From<MetricsBackendArg> for crate::config::MetricsBackend {
    fn from(value: MetricsBackendArg) -> Self {
        match value {
            MetricsBackendArg::Procfs => crate::config::MetricsBackend::Procfs,
            MetricsBackendArg::Perf => crate::config::MetricsBackend::Perf,
            MetricsBackendArg::Ebpf => crate::config::MetricsBackend::Ebpf,
            MetricsBackendArg::None => crate::config::MetricsBackend::None,
        }
    }
}

/// Virtual network topology kind for `setup`/`teardown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TopologyKind {
    Veth,
    Netns,
}

/// The set of SESHAT subcommands (F-01).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a full benchmark suite.
    Run(RunArgs),
    /// Run only the sender side (distributed mode).
    Sender(SenderArgs),
    /// Run only the receiver side (distributed mode).
    Receiver(ReceiverArgs),
    /// Re-generate reports from existing result files.
    Report(ReportArgs),
    /// Validate a config file without executing.
    Validate(ValidateArgs),
    /// List all scenarios with their parameters.
    List(ListArgs),
    /// Measure the harness's null-loopback throughput ceiling (NFR-PERF).
    Calibrate(CalibrateArgs),
    /// Dump system hardware/kernel info.
    Sysinfo(SysinfoArgs),
    /// Auto-create a virtual network topology.
    Setup(SetupArgs),
    /// Remove a virtual network topology.
    Teardown(TeardownArgs),
    /// Apply `tc netem` impairment to an interface.
    Impair(ImpairArgs),
}

/// Arguments shared by `run` (the bulk of the F-02 reproducibility controls).
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    pub config: PathBuf,

    /// Result output directory (default: ./results/<timestamp>).
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Override the number of repetitions per scenario.
    #[arg(long)]
    pub runs: Option<u32>,

    /// Override the measurement phase length (e.g. 30s, 500ms, 2m).
    #[arg(long, value_parser = parse_duration)]
    pub duration: Option<Duration>,

    /// Override the warmup phase length.
    #[arg(long, value_parser = parse_duration)]
    pub warmup: Option<Duration>,

    /// Override the pause between runs.
    #[arg(long, value_parser = parse_duration)]
    pub cooldown: Option<Duration>,

    /// Run only one scenario by name.
    #[arg(long)]
    pub scenario: Option<String>,

    /// Custom label written into result metadata.
    #[arg(long)]
    pub tag: Option<String>,

    /// Pin SESHAT threads to specific CPU cores (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub cpu_affinity: Vec<usize>,

    /// Skip `/proc`/`perf` system-metric collection.
    #[arg(long, default_value_t = false)]
    pub no_system_metrics: bool,

    /// Override the suite's system-metrics backend.
    #[arg(long, value_enum)]
    pub metrics_backend: Option<MetricsBackendArg>,

    /// PID of the SCG process for system metrics (default: auto-detect).
    #[arg(long)]
    pub scg_pid: Option<u32>,

    /// Parse + validate config, print the plan, but do not execute.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// Arguments for `sender` (distributed mode).
#[derive(Debug, clap::Args)]
pub struct SenderArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    pub config: PathBuf,

    /// Scenario to run.
    #[arg(long)]
    pub scenario: String,

    /// Receiver address to send to.
    #[arg(long)]
    pub target: String,

    /// Pin sender threads to specific CPU cores (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub cpu_affinity: Vec<usize>,
}

/// Arguments for `receiver` (distributed mode).
#[derive(Debug, clap::Args)]
pub struct ReceiverArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    pub config: PathBuf,

    /// Scenario to run.
    #[arg(long)]
    pub scenario: String,

    /// Local address to bind and listen on.
    #[arg(long)]
    pub bind: String,

    /// Pin receiver threads to specific CPU cores (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub cpu_affinity: Vec<usize>,
}

/// Arguments for `report`.
#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Directory of existing result files to regenerate reports from.
    #[arg(long)]
    pub input: PathBuf,

    /// Output format (CSV only).
    #[arg(long, value_enum, default_value_t = ReportFormat::Csv)]
    pub format: ReportFormat,
}

/// Arguments for `validate`.
#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    pub config: PathBuf,
}

/// Arguments for `list`.
#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Path to the JSON config file.
    #[arg(long)]
    pub config: PathBuf,
}

/// Arguments for `calibrate` (harness null-loopback ceiling sweep).
#[derive(Debug, clap::Args)]
pub struct CalibrateArgs {
    /// Message sizes (on-wire bytes) to probe (comma-separated).
    #[arg(
        long,
        value_delimiter = ',',
        default_values_t = [64u32, 128, 256, 1024, 1400, 4096, 16384, 65536]
    )]
    pub message_sizes: Vec<u32>,

    /// Parallel connections per probe.
    #[arg(long, default_value_t = 1)]
    pub connections: u32,

    /// Measurement duration per probe.
    #[arg(long, value_parser = parse_duration, default_value = "1s")]
    pub duration: Duration,

    /// Probe TCP loopback.
    #[arg(long, default_value_t = true)]
    pub tcp: bool,

    /// Probe UDP loopback.
    #[arg(long, default_value_t = true)]
    pub udp: bool,

    /// Optional directory to write a `calibration.csv` into.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,
}

/// Arguments for `sysinfo`.
#[derive(Debug, clap::Args)]
pub struct SysinfoArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = SysinfoFormat::Table)]
    pub format: SysinfoFormat,
}

/// Arguments for `setup`.
#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// Topology kind to create.
    #[arg(long, value_enum)]
    pub topology: TopologyKind,

    /// Left-side namespace name.
    #[arg(long, default_value = "scg_left")]
    pub left_namespace: String,

    /// Right-side namespace name.
    #[arg(long, default_value = "scg_right")]
    pub right_namespace: String,

    /// Left-side IP address.
    #[arg(long, default_value = "10.0.0.1")]
    pub left_ip: String,

    /// Right-side IP address.
    #[arg(long, default_value = "10.0.0.2")]
    pub right_ip: String,

    /// Subnet mask (prefix length).
    #[arg(long, default_value_t = 24)]
    pub subnet_mask: u8,

    /// Link MTU.
    #[arg(long, default_value_t = 1500)]
    pub mtu: u32,
}

/// Arguments for `teardown`.
#[derive(Debug, clap::Args)]
pub struct TeardownArgs {
    /// Topology kind to remove.
    #[arg(long, value_enum)]
    pub topology: TopologyKind,

    /// Left-side namespace name.
    #[arg(long, default_value = "scg_left")]
    pub left_namespace: String,

    /// Right-side namespace name.
    #[arg(long, default_value = "scg_right")]
    pub right_namespace: String,
}

/// Arguments for `impair`.
#[derive(Debug, clap::Args)]
pub struct ImpairArgs {
    /// Interface to apply impairment to.
    #[arg(long)]
    pub interface: String,

    /// Added latency in milliseconds.
    #[arg(long, default_value_t = 0.0)]
    pub latency: f64,

    /// Latency jitter in milliseconds.
    #[arg(long, default_value_t = 0.0)]
    pub jitter: f64,

    /// Packet loss percentage.
    #[arg(long, default_value_t = 0.0)]
    pub loss: f64,

    /// Bandwidth limit in Mbit/s (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    pub bandwidth: u32,

    /// Packet reorder percentage.
    #[arg(long, default_value_t = 0.0)]
    pub reorder: f64,

    /// Packet duplication percentage.
    #[arg(long, default_value_t = 0.0)]
    pub duplicate: f64,
}

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Accepted forms: a bare integer (seconds), or an integer/decimal suffixed
/// with `ms`, `s`, `m`, or `h`. Examples: `30s`, `500ms`, `2m`, `1h`, `45`.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let (value_str, unit, to_secs): (&str, &str, f64) = if let Some(v) = s.strip_suffix("ms") {
        (v, "ms", 0.001)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, "s", 1.0)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, "m", 60.0)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, "h", 3600.0)
    } else {
        (s, "s", 1.0)
    };

    let value: f64 = value_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration '{input}' (unit '{unit}')"))?;
    if value < 0.0 || !value.is_finite() {
        return Err(format!(
            "duration '{input}' must be non-negative and finite"
        ));
    }

    Ok(Duration::from_secs_f64(value * to_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_seconds() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parses_unit_suffixes() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("-5s").is_err());
    }

    #[test]
    fn verifies_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_metrics_backend_override() {
        let cli = Cli::parse_from([
            "seshat",
            "run",
            "--config",
            "./cfg.json",
            "--metrics-backend",
            "perf",
        ]);
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(args.metrics_backend, Some(MetricsBackendArg::Perf));
    }
}
