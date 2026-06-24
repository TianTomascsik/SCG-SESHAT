//! Per-PID system-metrics sampling (F-13b).
//!
//! While a gateway scenario runs, a background thread reads the SCG process(es)'
//! `/proc/<pid>/{stat,status,io}` counters at a configured rate and records a
//! timeseries (CPU%, RSS, thread count, context switches, block I/O). The PIDs
//! come straight from the running gateway transport, so no auto-detection or
//! `--scg-pid` guesswork is needed for the standard path.
//!
//! Sampling is deliberately lightweight: three small `/proc` reads per PID per
//! tick, parsed without allocation-heavy helpers, off the measurement hot path
//! (a separate thread), so it never perturbs the throughput/latency figures.
#![allow(dead_code)] // wired in from the run command; some fields are report-only.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::report::csv::{num, Csv};

/// Cap on how long the sampler thread sleeps between stop-flag checks, so
/// [`SystemSampler::stop`] returns promptly even at low sample rates.
const MAX_SLEEP: Duration = Duration::from_millis(100);

/// CSV schema for a per-PID timeseries file.
const HEADERS: &[&str] = &[
    "elapsed_ms",
    "cpu_pct",
    "rss_kib",
    "threads",
    "utime_ticks",
    "stime_ticks",
    "voluntary_ctxt_switches",
    "nonvoluntary_ctxt_switches",
    "read_bytes",
    "write_bytes",
];

/// One snapshot of a single PID's `/proc` counters.
#[derive(Debug, Clone)]
pub struct SystemSample {
    /// Milliseconds since sampling started (for correlating the timeseries).
    pub elapsed_ms: u64,
    /// The sampled process id.
    pub pid: u32,
    /// Resident set size in kibibytes (`/proc/<pid>/status` VmRSS).
    pub rss_kib: u64,
    /// Thread count (`/proc/<pid>/stat` field 20).
    pub threads: u64,
    /// Cumulative user-mode CPU ticks (`stat` utime).
    pub utime_ticks: u64,
    /// Cumulative kernel-mode CPU ticks (`stat` stime).
    pub stime_ticks: u64,
    /// Cumulative voluntary context switches (`status`).
    pub voluntary_ctxt: u64,
    /// Cumulative involuntary context switches (`status`).
    pub nonvoluntary_ctxt: u64,
    /// Cumulative bytes read from the block layer (`io`, 0 if unreadable).
    pub read_bytes: u64,
    /// Cumulative bytes written to the block layer (`io`, 0 if unreadable).
    pub write_bytes: u64,
}

/// A running background sampler. Started before a scenario's runs and consumed
/// by [`stop`](Self::stop) afterwards to retrieve the captured timeseries.
pub struct SystemSampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Vec<SystemSample>>,
}

impl SystemSampler {
    /// Spawn a sampler that polls `pids` at `rate_hz` (clamped to ≥1).
    pub fn start(pids: Vec<i32>, rate_hz: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let hz = rate_hz.max(1);
        let handle = thread::spawn(move || sample_loop(&pids, hz, &stop_thread));
        SystemSampler { stop, handle }
    }

    /// Signal the sampler to stop and return everything it captured.
    pub fn stop(self) -> Vec<SystemSample> {
        self.stop.store(true, Ordering::Release);
        self.handle.join().unwrap_or_default()
    }
}

// ─── F-13b: `perf stat` Backend ─────────────────────────────────────────────

/// Result of a `perf stat` run against a process.
#[derive(Debug, Clone, Default)]
pub struct PerfResult {
    /// CPU cycles (hardware counter).
    pub cycles: Option<u64>,
    /// Instructions retired.
    pub instructions: Option<u64>,
    /// Instructions per cycle (IPC).
    pub ipc: Option<f64>,
    /// Cache references.
    pub cache_references: Option<u64>,
    /// Cache misses.
    pub cache_misses: Option<u64>,
    /// Context switches (perf-counted, may differ from /proc).
    pub context_switches: Option<u64>,
    /// System calls (raw_syscalls:sys_enter tracepoint or syscalls event).
    pub syscalls: Option<u64>,
    /// Task-clock in milliseconds.
    pub task_clock_ms: Option<f64>,
    /// Wall-clock duration in seconds.
    pub duration_s: Option<f64>,
}

/// A `perf stat` process attached to a running PID. Collects hardware counters
/// for the full lifetime of the sampler.
pub struct PerfSampler {
    child: Option<std::process::Child>,
    stderr_path: std::path::PathBuf,
}

impl PerfSampler {
    /// Start `perf stat -p <pid[,pid...]>` collecting standard counters.
    /// Returns `None` if `perf` is not available.
    pub fn start(pids: &[i32], work_dir: &std::path::Path) -> Option<Self> {
        use std::process::{Command, Stdio};

        if pids.is_empty() {
            return None;
        }

        let pid_list = pids
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let stderr_path = work_dir.join(format!("perf_stat_{}.txt", pid_list.replace(',', "-")));
        let stderr_file = fs::File::create(&stderr_path).ok()?;

        let child = Command::new("perf")
            .args(["stat", "-p"])
            .arg(&pid_list)
            .args([
                "-e",
                "cycles,instructions,cache-references,cache-misses,context-switches,raw_syscalls:sys_enter,task-clock",
                "--log-fd",
                "2",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .ok()?;

        Some(PerfSampler {
            child: Some(child),
            stderr_path,
        })
    }

    /// Stop perf (SIGINT) and parse the results.
    pub fn stop(mut self) -> PerfResult {
        if let Some(mut child) = self.child.take() {
            // Send SIGINT so perf writes its summary.
            unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
            let _ = child.wait();
        }
        parse_perf_output(&self.stderr_path)
    }

    /// Check if `perf` is available on this system.
    pub fn available() -> bool {
        std::process::Command::new("perf")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Drop for PerfSampler {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

/// Parse `perf stat` output for known counters.
fn parse_perf_output(path: &std::path::Path) -> PerfResult {
    let mut result = PerfResult::default();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return result,
    };
    for line in content.lines() {
        let line = line.trim();
        // perf stat output format: "  1,234,567      cycles"
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() < 2 {
            continue;
        }
        let value_str = parts[0].replace(',', "");
        let label = parts[1].trim();

        if label.contains("cycles") && !label.contains("instructions") {
            result.cycles = value_str.parse().ok();
        } else if label.contains("instructions") {
            result.instructions = value_str.parse().ok();
            // Look for IPC in the same line: "# 1.23 insn per cycle"
            if let Some(ipc_pos) = line.find('#') {
                let ipc_str = &line[ipc_pos + 1..];
                let ipc_val: f64 = ipc_str
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                if ipc_val > 0.0 {
                    result.ipc = Some(ipc_val);
                }
            }
        } else if label.contains("cache-references") {
            result.cache_references = value_str.parse().ok();
        } else if label.contains("cache-misses") {
            result.cache_misses = value_str.parse().ok();
        } else if label.contains("context-switches") || label.contains("cs") {
            result.context_switches = value_str.parse().ok();
        } else if label.contains("raw_syscalls:sys_enter") || label.contains("syscalls") {
            result.syscalls = value_str.parse().ok();
        } else if label.contains("task-clock") {
            // task-clock is in ms (float format: "123.456 msec task-clock")
            result.task_clock_ms = parts[0].replace(',', "").parse().ok();
        } else if label.contains("seconds time elapsed") {
            result.duration_s = parts[0].replace(',', "").parse().ok();
        }
    }
    result
}

/// Sampling loop: emit one sample per PID per tick until the stop flag is set.
fn sample_loop(pids: &[i32], rate_hz: u32, stop: &AtomicBool) -> Vec<SystemSample> {
    let interval = Duration::from_secs_f64(1.0 / rate_hz as f64);
    let start = Instant::now();
    let mut next = start;
    let mut out = Vec::new();
    while !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if now >= next {
            let elapsed_ms = now.duration_since(start).as_millis() as u64;
            for &pid in pids {
                if let Some(sample) = sample_pid(pid, elapsed_ms) {
                    out.push(sample);
                }
            }
            // Advance to the next tick; if we fell behind, resync to now.
            next += interval;
            if next <= now {
                next = now + interval;
            }
        }
        let wait = next
            .saturating_duration_since(Instant::now())
            .min(MAX_SLEEP);
        if !wait.is_zero() {
            thread::sleep(wait);
        }
    }
    out
}

/// Read and parse one PID's counters. Returns `None` if the process is gone
/// (its `stat` file vanished), so a mid-run exit just truncates the series.
fn sample_pid(pid: i32, elapsed_ms: u64) -> Option<SystemSample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (utime_ticks, stime_ticks, threads) = parse_stat(&stat)?;
    let (rss_kib, voluntary_ctxt, nonvoluntary_ctxt) = parse_status(pid);
    let (read_bytes, write_bytes) = parse_io(pid);
    Some(SystemSample {
        elapsed_ms,
        pid: pid as u32,
        rss_kib,
        threads,
        utime_ticks,
        stime_ticks,
        voluntary_ctxt,
        nonvoluntary_ctxt,
        read_bytes,
        write_bytes,
    })
}

/// Parse `utime`, `stime`, and `num_threads` from a `/proc/<pid>/stat` line.
///
/// Field 2 (`comm`) is parenthesised and may itself contain spaces or `)`, so
/// we split after the **last** `)` and index the remaining whitespace-separated
/// fields, where `stat` field _K_ maps to remainder index _K − 3_.
fn parse_stat(line: &str) -> Option<(u64, u64, u64)> {
    let rparen = line.rfind(')')?;
    let rest = line.get(rparen + 1..)?.trim();
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime = f.get(11)?.parse().ok()?; // field 14
    let stime = f.get(12)?.parse().ok()?; // field 15
    let threads = f.get(17)?.parse().ok()?; // field 20
    Some((utime, stime, threads))
}

/// Parse VmRSS (kiB) and the two context-switch counters from `status`.
fn parse_status(pid: i32) -> (u64, u64, u64) {
    let mut rss = 0;
    let mut vol = 0;
    let mut nonvol = 0;
    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("VmRSS:") {
                rss = first_u64(v);
            } else if let Some(v) = line.strip_prefix("voluntary_ctxt_switches:") {
                vol = first_u64(v);
            } else if let Some(v) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
                nonvol = first_u64(v);
            }
        }
    }
    (rss, vol, nonvol)
}

/// Parse `read_bytes`/`write_bytes` from `/proc/<pid>/io` (0 if unavailable).
fn parse_io(pid: i32) -> (u64, u64) {
    let mut r = 0;
    let mut w = 0;
    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/io")) {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("read_bytes:") {
                r = first_u64(v);
            } else if let Some(v) = line.strip_prefix("write_bytes:") {
                w = first_u64(v);
            }
        }
    }
    (r, w)
}

/// First whitespace-separated `u64` token of `s`, or 0.
fn first_u64(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

/// Clock ticks per second (`_SC_CLK_TCK`), used to turn CPU ticks into seconds.
fn clk_tck() -> f64 {
    // SAFETY: sysconf with a constant name has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as f64
    } else {
        100.0
    }
}

/// CPU% over the interval between two consecutive samples of the same PID.
fn cpu_percent(prev: &SystemSample, cur: &SystemSample, tck: f64) -> f64 {
    let dt = cur.elapsed_ms.saturating_sub(prev.elapsed_ms) as f64 / 1000.0;
    if dt <= 0.0 {
        return 0.0;
    }
    let prev_ticks = prev.utime_ticks + prev.stime_ticks;
    let cur_ticks = cur.utime_ticks + cur.stime_ticks;
    let delta = cur_ticks.saturating_sub(prev_ticks) as f64;
    delta / tck / dt * 100.0
}

/// Run-level rollup of a per-PID system-metrics timeseries.
///
/// CPU figures are **summed across all sampled PIDs at the same tick** (the
/// sampler stamps every PID in a tick with the same `elapsed_ms`), so `100.0`
/// means one fully-busy core and a value near `cores * 100` means the gateway's
/// core pool is saturated — the signal the calibrator uses to decide the SCG
/// (not the harness) is the bottleneck.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysAgg {
    /// Number of distinct PIDs sampled (1 for single gateway, 2 for scg↔scg).
    pub n_pids: usize,
    /// Peak summed CPU% across PIDs over the run (100% == one core).
    pub cpu_pct_peak: f64,
    /// Mean summed CPU% across PIDs over the measured ticks.
    pub cpu_pct_mean: f64,
    /// Peak summed resident set size across PIDs (kiB).
    pub rss_peak_kib: u64,
    /// Total context switches per second across PIDs over the run.
    pub ctx_switches_per_s: f64,
}

/// Roll a flat per-PID sample series up into a [`SysAgg`], or `None` if empty.
pub fn aggregate(samples: &[SystemSample]) -> Option<SysAgg> {
    if samples.is_empty() {
        return None;
    }
    let tck = clk_tck();

    // Distinct PIDs in first-seen order.
    let mut pids: Vec<u32> = Vec::new();
    for s in samples {
        if !pids.contains(&s.pid) {
            pids.push(s.pid);
        }
    }

    // Summed-across-PIDs CPU% and RSS, keyed by tick (`elapsed_ms`).
    use std::collections::BTreeMap;
    let mut cpu_by_time: BTreeMap<u64, f64> = BTreeMap::new();
    let mut rss_by_time: BTreeMap<u64, u64> = BTreeMap::new();
    let mut ctx_total: u64 = 0;
    let mut span_s: f64 = 0.0;
    for &pid in &pids {
        let series: Vec<&SystemSample> = samples.iter().filter(|s| s.pid == pid).collect();
        let mut prev: Option<&SystemSample> = None;
        for s in &series {
            let cpu = match prev {
                Some(p) => cpu_percent(p, s, tck),
                None => 0.0,
            };
            *cpu_by_time.entry(s.elapsed_ms).or_insert(0.0) += cpu;
            *rss_by_time.entry(s.elapsed_ms).or_insert(0) += s.rss_kib;
            prev = Some(s);
        }
        if let (Some(first), Some(last)) = (series.first(), series.last()) {
            let dctx = (last.voluntary_ctxt + last.nonvoluntary_ctxt)
                .saturating_sub(first.voluntary_ctxt + first.nonvoluntary_ctxt);
            ctx_total += dctx;
            let s = last.elapsed_ms.saturating_sub(first.elapsed_ms) as f64 / 1000.0;
            span_s = span_s.max(s);
        }
    }

    // Skip the first tick (its per-PID CPU% is 0 for want of a prior delta).
    let times: Vec<u64> = cpu_by_time.keys().copied().collect();
    let measured = if times.len() > 1 {
        &times[1..]
    } else {
        &times[..]
    };
    let mut peak = 0.0_f64;
    let mut sum = 0.0_f64;
    for t in measured {
        let v = cpu_by_time[t];
        peak = peak.max(v);
        sum += v;
    }
    let cpu_pct_mean = if measured.is_empty() {
        0.0
    } else {
        sum / measured.len() as f64
    };
    let rss_peak_kib = rss_by_time.values().copied().max().unwrap_or(0);
    let ctx_switches_per_s = if span_s > 0.0 {
        ctx_total as f64 / span_s
    } else {
        0.0
    };

    Some(SysAgg {
        n_pids: pids.len(),
        cpu_pct_peak: peak,
        cpu_pct_mean,
        rss_peak_kib,
        ctx_switches_per_s,
    })
}

/// Write one `gateway_pid_<pid>.csv` timeseries per sampled PID into `dir`.
pub fn write_csv(dir: &Path, samples: &[SystemSample]) -> io::Result<()> {
    if samples.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    let tck = clk_tck();

    // Distinct PIDs in first-seen order (scg↔scg has two gateway processes).
    let mut pids: Vec<u32> = Vec::new();
    for s in samples {
        if !pids.contains(&s.pid) {
            pids.push(s.pid);
        }
    }

    for pid in pids {
        let mut csv = Csv::new(HEADERS);
        let mut prev: Option<&SystemSample> = None;
        for s in samples.iter().filter(|s| s.pid == pid) {
            let cpu = match prev {
                Some(p) => cpu_percent(p, s, tck),
                None => 0.0,
            };
            csv.row(vec![
                s.elapsed_ms.to_string(),
                num(cpu, 2),
                s.rss_kib.to_string(),
                s.threads.to_string(),
                s.utime_ticks.to_string(),
                s.stime_ticks.to_string(),
                s.voluntary_ctxt.to_string(),
                s.nonvoluntary_ctxt.to_string(),
                s.read_bytes.to_string(),
                s.write_bytes.to_string(),
            ]);
            prev = Some(s);
        }
        csv.write(&dir.join(format!("gateway_pid_{pid}.csv")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_handles_comm_with_spaces_and_parens() {
        // comm = "(weird ) name)" exercises the last-')' split.
        let line = "1234 (weird ) name) S 1 1 1 0 -1 4194304 100 0 0 0 \
            42 7 0 0 20 0 9 0 1000 0 0";
        let (utime, stime, threads) = parse_stat(line).unwrap();
        assert_eq!(utime, 42);
        assert_eq!(stime, 7);
        assert_eq!(threads, 9);
    }

    #[test]
    fn first_u64_extracts_leading_number() {
        assert_eq!(first_u64("   12345 kB"), 12345);
        assert_eq!(first_u64("nope"), 0);
        assert_eq!(first_u64(""), 0);
    }

    #[test]
    fn cpu_percent_is_one_core_when_ticks_match_wall() {
        let tck = 100.0;
        let a = SystemSample {
            elapsed_ms: 0,
            pid: 1,
            rss_kib: 0,
            threads: 1,
            utime_ticks: 0,
            stime_ticks: 0,
            voluntary_ctxt: 0,
            nonvoluntary_ctxt: 0,
            read_bytes: 0,
            write_bytes: 0,
        };
        let mut b = a.clone();
        b.elapsed_ms = 1000; // 1s wall
        b.utime_ticks = 100; // 100 ticks == 1s of CPU at 100 Hz
        assert!((cpu_percent(&a, &b, tck) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn samples_self_process() {
        let pid = std::process::id() as i32;
        let s = sample_pid(pid, 0).expect("self /proc/<pid>/stat readable");
        assert_eq!(s.pid, pid as u32);
        assert!(s.threads >= 1);
        assert!(s.rss_kib > 0);
    }

    #[test]
    fn parse_perf_output_extracts_counters() {
        let dir = std::env::temp_dir().join(format!("seshat-perf-{}", monotonic_tag()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("perf.txt");
        fs::write(
            &path,
            "  1,234      cycles
  2,468      instructions              # 2.00 insn per cycle
  3,579      cache-references
  246      cache-misses
  12      context-switches
  45.678      task-clock
  0.123456      seconds time elapsed
",
        )
        .unwrap();

        let perf = parse_perf_output(&path);
        assert_eq!(perf.cycles, Some(1234));
        assert_eq!(perf.instructions, Some(2468));
        assert_eq!(perf.ipc, Some(2.0));
        assert_eq!(perf.cache_references, Some(3579));
        assert_eq!(perf.cache_misses, Some(246));
        assert_eq!(perf.context_switches, Some(12));
        assert_eq!(perf.task_clock_ms, Some(45.678));
        assert_eq!(perf.duration_s, Some(0.123456));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sampler_captures_timeseries_and_writes_csv() {
        let pid = std::process::id() as i32;
        let sampler = SystemSampler::start(vec![pid], 50);
        thread::sleep(Duration::from_millis(140));
        let samples = sampler.stop();
        assert!(
            samples.len() >= 2,
            "expected several samples, got {}",
            samples.len()
        );

        let dir = std::env::temp_dir().join(format!("seshat-sys-{pid}-{}", monotonic_tag()));
        write_csv(&dir, &samples).unwrap();
        let csv = dir.join(format!("gateway_pid_{pid}.csv"));
        let body = fs::read_to_string(&csv).unwrap();
        assert!(body.starts_with("elapsed_ms,cpu_pct,rss_kib"));
        // header + at least two data rows.
        assert!(body.lines().count() >= 3);
        let _ = fs::remove_dir_all(&dir);
    }

    fn monotonic_tag() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
