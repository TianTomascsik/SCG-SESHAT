//! Host hardware/kernel fingerprint (F-19).
//!
//! Captures a snapshot of the machine a benchmark runs on so results are
//! reproducible and comparable: CPU model/topology, frequency governor, SMT,
//! isolated CPUs, RAM, kernel, transparent-huge-page policy, NICs, and whether
//! kTLS / io_uring are available. Everything is read best-effort from `/proc`,
//! `/sys`, and `uname`; missing values degrade to `None` / "unknown" rather
//! than failing, because this also runs inside minimal containers.
//!
//! The same [`SysInfo`] is rendered as a human table for the `sysinfo`
//! subcommand and serialized into each result directory in later phases.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::console;

/// A single network interface as seen under `/sys/class/net`.
#[derive(Debug, Clone, Serialize)]
pub struct Nic {
    pub name: String,
    pub mac: Option<String>,
    pub speed_mbps: Option<i64>,
    pub mtu: Option<u32>,
    pub operstate: Option<String>,
}

/// A best-effort fingerprint of the host.
#[derive(Debug, Clone, Serialize)]
pub struct SysInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: String,
    pub cpu_logical: usize,
    pub cpu_physical: Option<usize>,
    pub cpu_mhz: Option<f64>,
    pub governor: Option<String>,
    /// Whether turbo/boost is enabled (`intel_pstate/no_turbo` or `cpufreq/boost`).
    /// `Some(true)` means clock-boosting is on — a reproducibility hazard for
    /// benchmarking, since per-run frequency then depends on thermal headroom.
    pub turbo: Option<bool>,
    pub smt: Option<bool>,
    pub isolated_cpus: Option<String>,
    /// Number of online NUMA nodes (`/sys/devices/system/node`). >1 means
    /// cross-socket memory latency can perturb results without explicit pinning.
    pub numa_nodes: Option<usize>,
    pub mem_total_kb: Option<u64>,
    pub thp: Option<String>,
    pub ktls: bool,
    /// kTLS can actually be attached to a socket here (`TCP_ULP=tls` probe), not
    /// merely that the `tls` module is present. `false` on WSL2 and the like.
    pub ktls_usable: bool,
    /// Running under WSL (kernel advertises `microsoft`/`WSL`), where kTLS and
    /// some `/proc` counters behave differently from native Linux.
    pub wsl: bool,
    pub io_uring: Option<bool>,
    pub nics: Vec<Nic>,
    /// Version of the SESHAT harness binary (`CARGO_PKG_VERSION`).
    pub seshat_version: String,
    /// Short git commit of the SESHAT source tree, best-effort (`None` if the
    /// tree is not a git checkout). Pins exactly which harness produced a result.
    pub seshat_git: Option<String>,
    /// Short git commit of the sibling SCG gateway source tree, best-effort, so a
    /// result records which gateway build it measured.
    pub scg_git: Option<String>,
}

impl SysInfo {
    /// Read the host fingerprint. Never fails; unknown fields fall back.
    pub fn collect() -> Self {
        let kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into());
        SysInfo {
            hostname: read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into()),
            os: os_pretty_name(),
            io_uring: io_uring_available(&kernel),
            wsl: is_wsl(&kernel),
            kernel,
            arch: std::env::consts::ARCH.to_string(),
            cpu_model: cpu_model(),
            cpu_logical: cpu_logical(),
            cpu_physical: cpu_physical(),
            cpu_mhz: cpu_mhz(),
            governor: read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            turbo: turbo_enabled(),
            smt: read_trim("/sys/devices/system/cpu/smt/active").map(|v| v == "1"),
            isolated_cpus: read_trim("/sys/devices/system/cpu/isolated").filter(|s| !s.is_empty()),
            numa_nodes: numa_nodes(),
            mem_total_kb: mem_total_kb(),
            thp: thp_policy(),
            ktls: Path::new("/sys/module/tls").exists(),
            ktls_usable: ktls_usable(),
            nics: collect_nics(),
            seshat_version: env!("CARGO_PKG_VERSION").to_string(),
            // CARGO_MANIFEST_DIR is the SESHAT crate root baked in at build time;
            // the gateway is its sibling under the Janus tree. Both are best-effort.
            seshat_git: git_short_hash(env!("CARGO_MANIFEST_DIR")),
            scg_git: git_short_hash(concat!(env!("CARGO_MANIFEST_DIR"), "/../SCG")),
        }
    }

    /// Render as a human-readable table to stdout.
    pub fn render_table(&self) {
        console::banner();
        console::rule("System Information");

        console::kv("Hostname", &self.hostname, 12);
        console::kv("OS", &self.os, 12);
        console::kv("Kernel", &format!("{} ({})", self.kernel, self.arch), 12);
        console::end_rule();

        console::rule("CPU");
        console::kv("Model", &self.cpu_model, 12);
        let topo = match self.cpu_physical {
            Some(p) => format!("{} logical / {} physical", self.cpu_logical, p),
            None => format!("{} logical", self.cpu_logical),
        };
        console::kv("Topology", &topo, 12);
        if let Some(mhz) = self.cpu_mhz {
            console::kv("Frequency", &format!("{mhz:.0} MHz"), 12);
        }
        console::kv(
            "Governor",
            self.governor.as_deref().unwrap_or("unknown"),
            12,
        );
        console::kv("Turbo", fmt_bool(self.turbo), 12);
        console::kv("SMT/HT", fmt_bool(self.smt), 12);
        console::kv(
            "Isolated",
            self.isolated_cpus.as_deref().unwrap_or("(none)"),
            12,
        );
        console::kv(
            "NUMA nodes",
            &self
                .numa_nodes
                .map(|n| n.to_string())
                .unwrap_or_else(|| "1".into()),
            12,
        );
        console::end_rule();

        console::rule("Memory & Kernel");
        console::kv("RAM", &fmt_mem(self.mem_total_kb), 12);
        console::kv("THP", self.thp.as_deref().unwrap_or("unknown"), 12);
        let ktls = if self.ktls_usable {
            console::green("usable")
        } else if self.ktls {
            console::yellow("loaded (not attachable)")
        } else {
            console::yellow("not loaded")
        };
        console::kv("kTLS", &ktls, 12);
        console::kv("io_uring", fmt_bool(self.io_uring), 12);
        if self.wsl {
            console::kv(
                "Platform",
                &console::yellow("WSL (kTLS offload unavailable)"),
                12,
            );
        }
        console::end_rule();

        console::rule("Network Interfaces");
        if self.nics.is_empty() {
            console::kv("NICs", "(none found)", 12);
        } else {
            for nic in &self.nics {
                let speed = match nic.speed_mbps {
                    Some(s) if s > 0 => format!("{s} Mbps"),
                    _ => "?".to_string(),
                };
                let state = nic.operstate.as_deref().unwrap_or("?");
                let mtu = nic.mtu.map(|m| m.to_string()).unwrap_or_else(|| "?".into());
                let detail = format!(
                    "{:<8} {:<6} mtu={:<5} {}",
                    speed,
                    state,
                    mtu,
                    nic.mac.as_deref().unwrap_or("")
                );
                console::kv(&nic.name, detail.trim_end(), 12);
            }
        }
        console::end_rule();

        console::rule("Provenance");
        console::kv("SESHAT", &format!("v{}", self.seshat_version), 12);
        console::kv(
            "SESHAT git",
            self.seshat_git.as_deref().unwrap_or("unknown"),
            12,
        );
        console::kv("SCG git", self.scg_git.as_deref().unwrap_or("unknown"), 12);
        console::end_rule();
    }

    /// Render as pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

fn fmt_bool(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn fmt_mem(kb: Option<u64>) -> String {
    match kb {
        Some(kb) => {
            let gib = kb as f64 / (1024.0 * 1024.0);
            format!("{gib:.1} GiB ({kb} kB)")
        }
        None => "unknown".to_string(),
    }
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn os_pretty_name() -> String {
    if let Ok(text) = fs::read_to_string("/etc/os-release") {
        for line in text.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    "unknown".to_string()
}

fn cpu_model() -> String {
    if let Ok(text) = fs::read_to_string("/proc/cpuinfo") {
        for line in text.lines() {
            // x86 uses "model name", aarch64 often only exposes "Model" or none.
            if let Some(val) = line.strip_prefix("model name") {
                if let Some((_, v)) = val.split_once(':') {
                    return v.trim().to_string();
                }
            }
        }
        for line in text.lines() {
            if let Some(val) = line.strip_prefix("Model") {
                if let Some((_, v)) = val.split_once(':') {
                    return v.trim().to_string();
                }
            }
        }
    }
    "unknown".to_string()
}

pub fn cpu_logical() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or_else(|_| {
            fs::read_to_string("/proc/cpuinfo")
                .map(|t| t.lines().filter(|l| l.starts_with("processor")).count())
                .unwrap_or(1)
                .max(1)
        })
}

fn cpu_physical() -> Option<usize> {
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut pairs = std::collections::HashSet::new();
    let mut phys: Option<String> = None;
    let mut core: Option<String> = None;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim() {
                "physical id" => phys = Some(v.trim().to_string()),
                "core id" => core = Some(v.trim().to_string()),
                _ => {}
            }
        }
        if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (phys.take(), core.take()) {
                pairs.insert((p, c));
            }
        }
    }
    if let (Some(p), Some(c)) = (phys, core) {
        pairs.insert((p, c));
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.len())
    }
}

fn cpu_mhz() -> Option<f64> {
    // Prefer the advertised max frequency; fall back to the live cpuinfo value.
    if let Some(khz) = read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")
        .and_then(|s| s.parse::<f64>().ok())
    {
        return Some(khz / 1000.0);
    }
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in text.lines() {
        if let Some(val) = line.strip_prefix("cpu MHz") {
            if let Some((_, v)) = val.split_once(':') {
                return v.trim().parse::<f64>().ok();
            }
        }
    }
    None
}

fn mem_total_kb() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return rest.trim().trim_end_matches(" kB").trim().parse().ok();
        }
    }
    None
}

/// Whether CPU turbo/boost is enabled. Prefers the `intel_pstate` driver's
/// `no_turbo` flag (`0` = turbo on), falling back to the generic `cpufreq/boost`
/// (`1` = on). `None` when neither knob is exposed (e.g. in a VM/container).
fn turbo_enabled() -> Option<bool> {
    if let Some(v) = read_trim("/sys/devices/system/cpu/intel_pstate/no_turbo") {
        return Some(v.trim() == "0");
    }
    if let Some(v) = read_trim("/sys/devices/system/cpu/cpufreq/boost") {
        return Some(v.trim() == "1");
    }
    None
}

/// Count online NUMA nodes from `/sys/devices/system/node/online` (a range list
/// such as `0-1`). `None` when the file is absent (single-node / no NUMA sysfs).
fn numa_nodes() -> Option<usize> {
    parse_cpu_range_count(&read_trim("/sys/devices/system/node/online")?)
}

/// Count the entries in a sysfs range list like `0-1,4,8-11` (used for NUMA
/// nodes and CPU masks). `None` when nothing parses.
fn parse_cpu_range_count(raw: &str) -> Option<usize> {
    let mut count = 0usize;
    for part in raw.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (
                    a.trim().parse::<usize>().ok()?,
                    b.trim().parse::<usize>().ok()?,
                );
                count += b.saturating_sub(a) + 1;
            }
            None if !part.trim().is_empty() => count += 1,
            None => {}
        }
    }
    (count > 0).then_some(count)
}

/// Best-effort short git commit of the tree at `dir` (`git -C dir rev-parse
/// --short HEAD`). Returns `None` if `git` is missing, `dir` is not a checkout,
/// or the command fails — never blocks reproducibility capture.
fn git_short_hash(dir: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", dir, "rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!hash.is_empty()).then_some(hash)
}

/// Reproducibility/measurement-quality warnings for the current host. Empty when
/// the environment is well-controlled. Surfaced as `WARN` logs before a run so a
/// thesis result is never silently taken on a turbo-enabled, on-demand-governed
/// box where per-run clocks (and thus latency/throughput) drift.
pub fn preflight_warnings(info: &SysInfo) -> Vec<String> {
    let mut warns = Vec::new();
    if let Some(gov) = &info.governor {
        if gov != "performance" {
            warns.push(format!(
                "CPU governor is '{gov}', not 'performance' — clock scaling will \
                 add run-to-run variance. Pin it: \
                 `sudo cpupower frequency-set -g performance`."
            ));
        }
    }
    if info.turbo == Some(true) {
        warns.push(
            "CPU turbo/boost is enabled — per-run frequency depends on thermal \
             headroom. Disable for stable numbers (intel_pstate: \
             `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`)."
                .to_string(),
        );
    }
    if info.smt == Some(true) {
        warns.push(
            "SMT/Hyper-Threading is active — sibling-thread contention can perturb \
             pinned-core results; consider isolating physical cores."
                .to_string(),
        );
    }
    if info.numa_nodes.unwrap_or(1) > 1 && info.isolated_cpus.is_none() {
        warns.push(
            "Multi-node NUMA host with no isolated CPUs — cross-socket memory \
             latency may leak into results; pin with `isolcpus=`/`taskset` and \
             keep sender, gateway, and receiver on one node."
                .to_string(),
        );
    }
    warns
}

fn thp_policy() -> Option<String> {
    // The file looks like "always [madvise] never"; extract the active token.
    let raw = read_trim("/sys/kernel/mm/transparent_hugepage/enabled")?;
    if let (Some(a), Some(b)) = (raw.find('['), raw.find(']')) {
        if a < b {
            return Some(raw[a + 1..b].to_string());
        }
    }
    Some(raw)
}

/// io_uring has no stable userspace probe without attempting the syscall, so we
/// use a kernel-version heuristic (merged in 5.1) — good enough for a report.
fn io_uring_available(kernel: &str) -> Option<bool> {
    let mut parts = kernel.split(['.', '-', '_']);
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some(major > 5 || (major == 5 && minor >= 1))
}

/// Whether the host is WSL: the kernel release string advertises `microsoft`
/// (WSL2) or `WSL`. kTLS offload and some `/proc` counters differ there.
fn is_wsl(kernel: &str) -> bool {
    let k = kernel.to_ascii_lowercase();
    k.contains("microsoft") || k.contains("wsl")
}

/// Probe whether kernel TLS can actually be attached to a socket here.
///
/// Unlike [`SysInfo::ktls`] (which only checks the `tls` module is present),
/// this performs the `TCP_ULP=tls` `setsockopt` the gateway needs, on a live
/// loopback connection. Returns `false` on WSL2 and other hosts lacking kTLS,
/// driving the auto-detect/labelling so a userspace fallback is never reported
/// as kernel offload. The probe is read-only and tears its socket down at once.
fn ktls_usable() -> bool {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;

    // `TCP_ULP` is a stable Linux constant but is not exported by libc on every
    // target; the level is `IPPROTO_TCP` (6).
    const TCP_ULP: libc::c_int = 31;

    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return false;
    };
    let Ok(addr) = listener.local_addr() else {
        return false;
    };
    let Ok(client) = TcpStream::connect(addr) else {
        return false;
    };
    // Complete the handshake so the socket is ESTABLISHED (TCP_ULP requirement).
    let _server = listener.accept();
    let name = b"tls";
    // SAFETY: `client.as_raw_fd()` is a valid, open, ESTABLISHED TCP descriptor
    // owned by `client` and kept alive for the whole call; `name` is a live,
    // fully-initialised `b"tls"` byte slice, so `name.as_ptr()`/`name.len()`
    // form a valid pointer/length pair for an `optval` of that length; the
    // return value is checked on the next line (`ret == 0`).
    let ret = unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_ULP,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    ret == 0
}

fn collect_nics() -> Vec<Nic> {
    let mut nics = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return nics;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "lo")
        .collect();
    names.sort();
    for name in names {
        let base = format!("/sys/class/net/{name}");
        nics.push(Nic {
            mac: read_trim(&format!("{base}/address")).filter(|s| s != "00:00:00:00:00:00"),
            speed_mbps: read_trim(&format!("{base}/speed"))
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|&s| s > 0),
            mtu: read_trim(&format!("{base}/mtu")).and_then(|s| s.parse().ok()),
            operstate: read_trim(&format!("{base}/operstate")),
            name,
        });
    }
    nics
}

/// Compact one-line summary used in run headers and CSV metadata.
// Consumed by the run engine / reporting in a later phase (WP1.6).
#[allow(dead_code)]
pub fn summary_line(info: &SysInfo) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "{} | {} | {} cores | {}",
        info.cpu_model,
        info.kernel,
        info.cpu_logical,
        fmt_mem(info.mem_total_kb)
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_range_count_handles_lists_and_ranges() {
        assert_eq!(parse_cpu_range_count("0"), Some(1));
        assert_eq!(parse_cpu_range_count("0-1"), Some(2));
        assert_eq!(parse_cpu_range_count("0-3,8,10-11"), Some(7));
        assert_eq!(parse_cpu_range_count(""), None);
    }

    #[test]
    fn preflight_flags_uncontrolled_environment() {
        let mut info = SysInfo::collect();
        info.governor = Some("powersave".into());
        info.turbo = Some(true);
        info.smt = Some(false);
        info.numa_nodes = Some(1);
        let warns = preflight_warnings(&info);
        assert!(warns.iter().any(|w| w.contains("governor")));
        assert!(warns.iter().any(|w| w.contains("turbo")));
    }

    #[test]
    fn preflight_clean_on_controlled_host() {
        let mut info = SysInfo::collect();
        info.governor = Some("performance".into());
        info.turbo = Some(false);
        info.smt = Some(false);
        info.numa_nodes = Some(1);
        assert!(preflight_warnings(&info).is_empty());
    }
}
