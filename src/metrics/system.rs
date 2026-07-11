//! Per-PID system-metrics sampling (F-13b).
//!
//! While a gateway scenario runs, a background thread reads the SCG process(es)'
//! `/proc/<pid>/{stat,status,io,smaps_rollup}` counters at a configured rate and records a
//! timeseries (CPU%, RSS/PSS, thread count, context switches, block I/O). The PIDs
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
    "hot_thread_cpu_pct",
    "rss_kib",
    "pss_kib",
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
    /// Proportional set size in kibibytes (`/proc/<pid>/smaps_rollup` Pss).
    /// Zero means the kernel denied or did not expose the optional file.
    pub pss_kib: u64,
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
    /// Cumulative per-thread CPU ticks (`utime+stime` from
    /// `/proc/<pid>/task/<tid>/stat`), keyed by tid. Lets the aggregator find
    /// the hottest single thread — the signal that a serial data plane is
    /// pegged even when the process-wide total looks idle.
    pub thread_ticks: Vec<(u32, u64)>,
    /// Whole-host busy CPU ticks at this instant (`/proc/stat` aggregate `cpu`
    /// line, total − idle − iowait). Zero if unreadable.
    pub host_busy_ticks: u64,
    /// Whole-host total CPU ticks at this instant. Zero if unreadable.
    pub host_total_ticks: u64,
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
            .args(["stat", "-x,", "--no-big-num", "-p"])
            .arg(&pid_list)
            .args([
                "-e",
                // Keep the default set to events available to unprivileged perf
                // users. Optional tracepoints such as raw_syscalls can make
                // perf abort the whole group on locked-down hosts.
                "cycles,instructions,cache-references,cache-misses,context-switches,task-clock",
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
            // SAFETY: `libc::kill` is a plain syscall with no memory-safety
            // preconditions; `child.id()` is the PID of the perf child this
            // `PerfSampler` owns and has not yet reaped (it was `take`n above and
            // is `wait`ed for right below), and `SIGINT` is a valid signal number.
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
            // SAFETY: `libc::kill` is a plain syscall with no memory-safety
            // preconditions; `child.id()` is the PID of the perf child this
            // `PerfSampler` owns and has not yet reaped (it was `take`n above and
            // is `wait`ed for right below), and `SIGKILL` is a valid signal number.
            unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

/// Parse `perf stat` output for known counters.
///
/// New runs use `perf stat -x,`, whose CSV fields are stable across perf
/// versions.  Keep the whitespace parser as a fallback so older result
/// artifacts remain readable too.
fn parse_perf_output(path: &std::path::Path) -> PerfResult {
    let mut result = PerfResult::default();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return result,
    };
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        // `perf stat -x,` emits value,unit,event,... .  An unavailable event
        // uses strings such as `<not counted>`; leave only that field empty
        // instead of discarding the other counters from the same run.
        if let Some((value, label)) = perf_csv_fields(line) {
            record_perf_counter(&mut result, value, label, line);
            continue;
        }

        // Human-readable perf output: `1,234 cycles` (after trimming leading
        // spaces). `split_whitespace` deliberately avoids the old leading-space
        // split bug that made every value parse as an empty string.
        let mut fields = line.split_whitespace();
        let Some(value) = fields.next() else {
            continue;
        };
        let label = fields.collect::<Vec<_>>().join(" ");
        if !label.is_empty() {
            record_perf_counter(&mut result, value, &label, line);
        }
    }

    // CSV perf output does not consistently include the derived IPC annotation
    // that the human formatter prints, so compute it when both raw counters
    // were successfully collected.
    if result.ipc.is_none() {
        if let (Some(instructions), Some(cycles)) = (result.instructions, result.cycles) {
            if cycles > 0 {
                result.ipc = Some(instructions as f64 / cycles as f64);
            }
        }
    }
    result
}

/// Extract `(value, event)` from one `perf stat -x,` line.
fn perf_csv_fields(line: &str) -> Option<(&str, &str)> {
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 3 {
        return None;
    }
    let event = fields[2].trim();
    if event.is_empty() {
        return None;
    }
    Some((fields[0].trim(), event))
}

/// Record one known perf counter from either CSV or human-readable output.
fn record_perf_counter(result: &mut PerfResult, raw_value: &str, label: &str, line: &str) {
    let integer = || parse_perf_u64(raw_value);
    let decimal = || parse_perf_f64(raw_value);
    if label.contains("cycles") && !label.contains("instructions") {
        result.cycles = integer();
    } else if label.contains("instructions") {
        result.instructions = integer();
        // The human formatter may append `# 1.23 insn per cycle`.
        if let Some(ipc_pos) = line.find('#') {
            result.ipc = line[ipc_pos + 1..]
                .split_whitespace()
                .next()
                .and_then(parse_perf_f64);
        }
    } else if label.contains("cache-references") {
        result.cache_references = integer();
    } else if label.contains("cache-misses") {
        result.cache_misses = integer();
    } else if label.contains("context-switches") || label == "cs" {
        result.context_switches = integer();
    } else if label.contains("raw_syscalls:sys_enter") || label.contains("syscalls") {
        result.syscalls = integer();
    } else if label.contains("task-clock") {
        result.task_clock_ms = decimal();
    } else if label.contains("seconds time elapsed") {
        result.duration_s = decimal();
    }
}

fn parse_perf_u64(value: &str) -> Option<u64> {
    value.trim().replace(',', "").parse::<u64>().ok()
}

fn parse_perf_f64(value: &str) -> Option<f64> {
    value.trim().replace(',', "").parse::<f64>().ok()
}

// ─── F-13b: eBPF memory-copy backend (`bpftrace`) ───────────────────────────

/// The embedded `mem_copies.bt` program (kept in `scripts/` for standalone use
/// and documentation, embedded here so the binary is self-contained). Attaches
/// only the copy kprobes.
const MEM_COPIES_BT: &str = include_str!("../../scripts/mem_copies.bt");

/// The embedded `mem_syscalls.bt` program: the payload-moving syscall counters,
/// run as an independent bpftrace job so a kernel with non-attachable copy
/// kprobes (which abort their own script) still yields these counts.
const MEM_SYSCALLS_BT: &str = include_str!("../../scripts/mem_syscalls.bt");

/// Result of a `bpftrace` memory-copy run against the gateway PID(s).
#[derive(Debug, Clone, Default)]
pub struct MemCopyResult {
    /// `_copy_to_user` invocations (kernel→user payload copies).
    pub copy_to_user: Option<u64>,
    /// `_copy_from_user` invocations (user→kernel payload copies).
    pub copy_from_user: Option<u64>,
    /// `sendmsg` syscalls entered.
    pub sendmsg: Option<u64>,
    /// `recvmsg` syscalls entered.
    pub recvmsg: Option<u64>,
    /// `splice` syscalls entered (the poll+splice zero-copy relay path).
    pub splice: Option<u64>,
    /// `poll` syscalls entered (poll+splice relay readiness waits).
    pub poll: Option<u64>,
    /// `ppoll` syscalls entered (poll+splice relay readiness waits).
    pub ppoll: Option<u64>,
    /// `io_uring_enter` syscalls entered (the io_uring relay backend).
    pub io_uring_enter: Option<u64>,
}

impl MemCopyResult {
    /// Total user<->kernel payload copies (`copy_to_user + copy_from_user`),
    /// `None` unless at least one counter was collected.
    pub fn total_copies(&self) -> Option<u64> {
        match (self.copy_to_user, self.copy_from_user) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
        }
    }

    /// Memory copies per delivered message, given the total messages measured.
    pub fn copies_per_msg(&self, messages: u64) -> Option<f64> {
        if messages == 0 {
            return None;
        }
        self.total_copies().map(|c| c as f64 / messages as f64)
    }
}

/// A running `bpftrace` job: its child process and the file its map output is
/// written to.
struct BpfJob {
    child: std::process::Child,
    stdout_path: std::path::PathBuf,
}

/// One or more `bpftrace` processes counting payload copies and payload-moving
/// syscalls for the gateway PID(s) over the run. Like [`PerfSampler`] the jobs
/// attach for the full sampler lifetime.
///
/// The copy kprobes and the syscall tracepoints run as **independent** jobs
/// because bpftrace aborts a whole script when any single probe fails to attach,
/// and the copy kprobes are non-attachable on some kernels. Splitting them means
/// a kernel without attachable copy kprobes still yields the syscall counts.
pub struct MemCopySampler {
    jobs: Vec<BpfJob>,
}

impl MemCopySampler {
    /// Start `bpftrace` with the embedded programs, filtered to `pids`. Returns
    /// `None` if `bpftrace` is unavailable, the caller is unprivileged, or both
    /// spawns fail — so an unprivileged run degrades to "no memory-copy data".
    pub fn start(pids: &[i32], work_dir: &std::path::Path) -> Option<Self> {
        if pids.is_empty() || !Self::available() {
            return None;
        }

        let filter = pids
            .iter()
            .map(|p| format!("pid == {p}"))
            .collect::<Vec<_>>()
            .join(" || ");

        // Syscall tracepoints first (attach on every modern kernel), then the
        // copy kprobes (may be non-attachable and abort their own job only).
        let mut jobs = Vec::new();
        if let Some(job) = spawn_bpftrace(
            &MEM_SYSCALLS_BT.replace("__PID_FILTER__", &filter),
            work_dir,
            "mem_syscalls.bt",
            "mem_syscalls_out.txt",
            "mem_syscalls_err.txt",
        ) {
            jobs.push(job);
        }
        if let Some(job) = spawn_bpftrace(
            &MEM_COPIES_BT.replace("__PID_FILTER__", &filter),
            work_dir,
            "mem_copies.bt",
            "mem_copies_out.txt",
            "mem_copies_err.txt",
        ) {
            jobs.push(job);
        }

        if jobs.is_empty() {
            return None;
        }
        Some(MemCopySampler { jobs })
    }

    /// Stop the bpftrace jobs (SIGINT, which makes them print their maps) and
    /// parse the merged result across every job's output.
    pub fn stop(mut self) -> MemCopyResult {
        let mut result = MemCopyResult::default();
        for mut job in std::mem::take(&mut self.jobs) {
            // SAFETY: `libc::kill` is a plain syscall with no memory-safety
            // preconditions; `job.child.id()` is the PID of a bpftrace child this
            // sampler owns and has not yet reaped (moved out above, `wait`ed
            // below), and `SIGINT` is a valid signal number.
            unsafe { libc::kill(job.child.id() as i32, libc::SIGINT) };
            let _ = job.child.wait();
            parse_mem_copies_into(&job.stdout_path, &mut result);
        }
        result
    }

    /// Whether memory-copy sampling can run here: `bpftrace` present and the
    /// process is privileged enough to load BPF (root, or holding CAP_BPF —
    /// approximated by an effective-uid-0 check, which is the common case).
    pub fn available() -> bool {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return false;
        }
        std::process::Command::new("bpftrace")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Drop for MemCopySampler {
    fn drop(&mut self) {
        for job in &mut self.jobs {
            // SAFETY: see `stop`; each owned, unreaped bpftrace child PID is
            // killed and immediately waited for.
            unsafe { libc::kill(job.child.id() as i32, libc::SIGKILL) };
            let _ = job.child.wait();
        }
    }
}

/// Spawn one `bpftrace` job for `program`, writing its script, map output, and
/// stderr into `work_dir`. Returns `None` if writing the script or spawning
/// fails. Capturing stderr matters because bpftrace aborts a whole script if any
/// single probe fails to attach, and a silent null stderr made that undiagnosable.
fn spawn_bpftrace(
    program: &str,
    work_dir: &std::path::Path,
    script_name: &str,
    stdout_name: &str,
    stderr_name: &str,
) -> Option<BpfJob> {
    use std::process::{Command, Stdio};

    let script_path = work_dir.join(script_name);
    fs::write(&script_path, program).ok()?;

    let stdout_path = work_dir.join(stdout_name);
    let stdout_file = fs::File::create(&stdout_path).ok()?;
    let stderr_file = fs::File::create(work_dir.join(stderr_name)).ok();

    let child = Command::new("bpftrace")
        .arg(&script_path)
        .stdin(Stdio::null())
        .stdout(stdout_file)
        .stderr(match stderr_file {
            Some(f) => Stdio::from(f),
            None => Stdio::null(),
        })
        .spawn()
        .ok()?;

    Some(BpfJob { child, stdout_path })
}

/// Parse `bpftrace` map output lines such as `@copy_to_user: 12345`.
#[cfg(test)]
fn parse_mem_copies(path: &std::path::Path) -> MemCopyResult {
    let mut result = MemCopyResult::default();
    parse_mem_copies_into(path, &mut result);
    result
}

/// Merge `bpftrace` map output at `path` into `result` (each split job's output
/// contributes only the counters it collected, so later jobs never clobber
/// earlier ones).
fn parse_mem_copies_into(path: &std::path::Path, result: &mut MemCopyResult) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    for line in content.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(n) = value.trim().parse::<u64>().ok() else {
            continue;
        };
        match key.trim() {
            "@copy_to_user" => result.copy_to_user = Some(n),
            "@copy_from_user" => result.copy_from_user = Some(n),
            "@sendmsg" => result.sendmsg = Some(n),
            "@recvmsg" => result.recvmsg = Some(n),
            "@splice" => result.splice = Some(n),
            "@poll" => result.poll = Some(n),
            "@ppoll" => result.ppoll = Some(n),
            "@io_uring_enter" => result.io_uring_enter = Some(n),
            _ => {}
        }
    }
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
            // One host-wide reading per tick, stamped into every PID's sample
            // of that tick (the aggregator dedupes by `elapsed_ms`).
            let (host_busy, host_total) = read_host_stat();
            for &pid in pids {
                if let Some(sample) = sample_pid(pid, elapsed_ms, host_busy, host_total) {
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
fn sample_pid(
    pid: i32,
    elapsed_ms: u64,
    host_busy_ticks: u64,
    host_total_ticks: u64,
) -> Option<SystemSample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (utime_ticks, stime_ticks, threads) = parse_stat(&stat)?;
    let rss_kib = parse_rss(pid);
    // CPU ticks (above) are process-wide, but `/proc/<pid>/status` context-switch
    // counters are the thread-group *leader's* only — ~0 for a gateway whose
    // workers run in spawned threads. Sum the per-thread counters so the totals
    // reflect the whole process.
    let (voluntary_ctxt, nonvoluntary_ctxt) = sum_thread_ctxt_switches(pid);
    let (read_bytes, write_bytes) = parse_io(pid);
    let pss_kib = parse_pss(pid);
    let thread_ticks = read_thread_ticks(pid);
    Some(SystemSample {
        elapsed_ms,
        pid: pid as u32,
        rss_kib,
        pss_kib,
        threads,
        utime_ticks,
        stime_ticks,
        voluntary_ctxt,
        nonvoluntary_ctxt,
        read_bytes,
        write_bytes,
        thread_ticks,
        host_busy_ticks,
        host_total_ticks,
    })
}

/// Cumulative CPU ticks (`utime+stime`) per thread of `pid`, from
/// `/proc/<pid>/task/<tid>/stat`. Threads that exit between ticks simply drop
/// out of later samples; the aggregator only diffs tids present in consecutive
/// samples. Empty if the `task` dir is unreadable.
fn read_thread_ticks(pid: i32) -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Ok(tid) = name.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let path = format!("/proc/{pid}/task/{tid}/stat");
            if let Some((utime, stime, _threads)) = fs::read_to_string(&path)
                .ok()
                .as_deref()
                .and_then(parse_stat)
            {
                out.push((tid, utime + stime));
            }
        }
    }
    out
}

/// Whole-host `(busy, total)` CPU ticks from the aggregate `cpu ` line of
/// `/proc/stat` (busy = total − idle − iowait). `(0, 0)` if unreadable.
fn read_host_stat() -> (u64, u64) {
    let Ok(s) = fs::read_to_string("/proc/stat") else {
        return (0, 0);
    };
    parse_host_cpu_line(&s)
}

/// Parse the aggregate `cpu ` line of a `/proc/stat` body.
fn parse_host_cpu_line(body: &str) -> (u64, u64) {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            let fields: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|f| f.parse().ok())
                .collect();
            if fields.len() < 5 {
                return (0, 0);
            }
            let total: u64 = fields.iter().sum();
            // fields: user nice system idle iowait irq softirq steal ...
            let idle = fields[3] + fields[4];
            return (total.saturating_sub(idle), total);
        }
    }
    (0, 0)
}

/// Parse `Pss:` from `/proc/<pid>/smaps_rollup`; a kernel may hide it from an
/// unprivileged reader, in which case the scenario still records RSS.
fn parse_pss(pid: i32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("Pss:").map(first_u64))
        })
        .unwrap_or(0)
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

/// Parse VmRSS (kiB) from `/proc/<pid>/status` (process-wide; 0 if unreadable).
fn parse_rss(pid: i32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("VmRSS:").map(first_u64))
        })
        .unwrap_or(0)
}

/// Sum voluntary + involuntary context switches across every thread of the
/// process by walking `/proc/<pid>/task/<tid>/status`. `/proc/<pid>/status`
/// alone reports only the group leader's counters, which understates a
/// multi-threaded gateway; per-thread aggregation gives the process total.
/// Returns the leader-only count as a fallback if the `task` dir is unreadable.
fn sum_thread_ctxt_switches(pid: i32) -> (u64, u64) {
    let mut vol = 0u64;
    let mut nonvol = 0u64;
    let mut any = false;
    if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in entries.flatten() {
            let tid = entry.file_name();
            let path = format!("/proc/{pid}/task/{}/status", tid.to_string_lossy());
            if let Ok(s) = fs::read_to_string(&path) {
                any = true;
                for line in s.lines() {
                    if let Some(v) = line.strip_prefix("voluntary_ctxt_switches:") {
                        vol += first_u64(v);
                    } else if let Some(v) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
                        nonvol += first_u64(v);
                    }
                }
            }
        }
    }
    if any {
        return (vol, nonvol);
    }
    // Fallback: the group leader's own counters.
    let mut lvol = 0u64;
    let mut lnonvol = 0u64;
    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/status")) {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("voluntary_ctxt_switches:") {
                lvol = first_u64(v);
            } else if let Some(v) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
                lnonvol = first_u64(v);
            }
        }
    }
    (lvol, lnonvol)
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
    /// Peak summed CPU% across PIDs over the run (100% == one core). Derived
    /// from the per-tick timeseries, so it sees sub-second spikes.
    pub cpu_pct_peak: f64,
    /// Mean summed CPU% across PIDs over the sampled span (100% == one core).
    /// Derived from the **exact** cumulative CPU-tick delta over the span, so it
    /// is independent of the sample rate (no per-tick averaging error).
    pub cpu_pct_mean: f64,
    /// p95 of the per-tick summed CPU% series. The classification input: unlike
    /// `cpu_pct_peak` it ignores a single-tick burst, and unlike `cpu_pct_mean`
    /// it is not diluted by warmup/cooldown ticks inside the sampler window.
    pub cpu_pct_p95: f64,
    /// Peak CPU% of the hottest single thread across all sampled PIDs
    /// (100% == one core). Report-only.
    pub cpu_hot_thread_pct_peak: f64,
    /// p95 of the per-tick hottest-thread CPU%. A value near 100 means one
    /// thread is pegged — a serial data plane at its limit even when the
    /// process-wide pool looks idle. Classification input.
    pub cpu_hot_thread_pct_p95: f64,
    /// p95 of the per-tick whole-host busy fraction (0..1). Near 1.0 means the
    /// host itself is saturated (loopback co-saturation): the measurement is a
    /// lower bound imposed by single-host physics. Classification input.
    pub host_busy_frac_p95: f64,
    /// Peak summed resident set size across PIDs (kiB).
    pub rss_peak_kib: u64,
    /// Peak summed proportional set size across PIDs (kiB), when readable.
    pub pss_peak_kib: u64,
    /// Context switches per second across PIDs, from the exact cumulative delta
    /// over the sampled span.
    pub ctx_switches_per_s: f64,
    /// Exact total CPU seconds consumed across all sampled PIDs over the span
    /// (cumulative `utime+stime` delta ÷ `_SC_CLK_TCK`). Rate-independent.
    pub cpu_seconds_total: f64,
    /// Exact total voluntary+involuntary context switches across PIDs over the
    /// span. Rate-independent (a spec headline metric).
    pub ctx_switches_total: u64,
    /// Wall-clock span the exact totals cover (first→last sample), in seconds.
    pub window_s: f64,
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
    let mut pss_by_time: BTreeMap<u64, u64> = BTreeMap::new();
    // Hottest single thread across all PIDs per tick (100% == one core).
    let mut hot_by_time: BTreeMap<u64, f64> = BTreeMap::new();
    // Whole-host (busy, total) tick counters per tick — every PID's sample in a
    // tick carries the same host reading, so first-write wins.
    let mut host_by_time: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    // Exact, rate-independent totals: the `/proc` counters are cumulative, so a
    // first→last delta is the true count over the sampled span no matter how
    // many ticks fell in between. The per-tick series is used only for the peak.
    let mut ctx_total: u64 = 0;
    let mut cpu_ticks_total: u64 = 0;
    let mut span_s: f64 = 0.0;
    for &pid in &pids {
        let series: Vec<&SystemSample> = samples.iter().filter(|s| s.pid == pid).collect();
        let mut prev: Option<&SystemSample> = None;
        for s in &series {
            let cpu = match prev {
                Some(p) => cpu_percent(p, s, tck),
                None => 0.0,
            };
            let hot = match prev {
                Some(p) => hot_thread_percent(p, s, tck),
                None => 0.0,
            };
            *cpu_by_time.entry(s.elapsed_ms).or_insert(0.0) += cpu;
            *rss_by_time.entry(s.elapsed_ms).or_insert(0) += s.rss_kib;
            *pss_by_time.entry(s.elapsed_ms).or_insert(0) += s.pss_kib;
            let slot = hot_by_time.entry(s.elapsed_ms).or_insert(0.0);
            *slot = slot.max(hot);
            host_by_time
                .entry(s.elapsed_ms)
                .or_insert((s.host_busy_ticks, s.host_total_ticks));
            prev = Some(s);
        }
        if let (Some(first), Some(last)) = (series.first(), series.last()) {
            let dctx = (last.voluntary_ctxt + last.nonvoluntary_ctxt)
                .saturating_sub(first.voluntary_ctxt + first.nonvoluntary_ctxt);
            ctx_total += dctx;
            let dticks = (last.utime_ticks + last.stime_ticks)
                .saturating_sub(first.utime_ticks + first.stime_ticks);
            cpu_ticks_total += dticks;
            let s = last.elapsed_ms.saturating_sub(first.elapsed_ms) as f64 / 1000.0;
            span_s = span_s.max(s);
        }
    }

    // Peak: the highest summed per-tick CPU% seen (spike-sensitive). Skip the
    // first tick, whose per-PID CPU% is 0 for want of a prior delta.
    let times: Vec<u64> = cpu_by_time.keys().copied().collect();
    let measured = if times.len() > 1 {
        &times[1..]
    } else {
        &times[..]
    };
    let mut peak = 0.0_f64;
    let mut hot_peak = 0.0_f64;
    let mut cpu_series: Vec<f64> = Vec::with_capacity(measured.len());
    let mut hot_series: Vec<f64> = Vec::with_capacity(measured.len());
    for t in measured {
        peak = peak.max(cpu_by_time[t]);
        cpu_series.push(cpu_by_time[t]);
        if let Some(h) = hot_by_time.get(t) {
            hot_peak = hot_peak.max(*h);
            hot_series.push(*h);
        }
    }
    // Whole-host busy fraction between consecutive ticks.
    let mut host_series: Vec<f64> = Vec::new();
    let mut prev_host: Option<(u64, u64)> = None;
    for (_, &(busy, total)) in host_by_time.iter() {
        if let Some((pb, pt)) = prev_host {
            let dtotal = total.saturating_sub(pt);
            if dtotal > 0 {
                host_series.push(busy.saturating_sub(pb) as f64 / dtotal as f64);
            }
        }
        prev_host = Some((busy, total));
    }

    let cpu_seconds_total = cpu_ticks_total as f64 / tck;
    let rss_peak_kib = rss_by_time.values().copied().max().unwrap_or(0);
    let pss_peak_kib = pss_by_time.values().copied().max().unwrap_or(0);
    // Mean CPU% and context-switch rate from the exact totals over the exact
    // span — no sampling error, unlike averaging per-tick percentages.
    let (cpu_pct_mean, ctx_switches_per_s) = if span_s > 0.0 {
        (
            cpu_seconds_total / span_s * 100.0,
            ctx_total as f64 / span_s,
        )
    } else {
        (0.0, 0.0)
    };

    Some(SysAgg {
        n_pids: pids.len(),
        cpu_pct_peak: peak,
        cpu_pct_mean,
        cpu_pct_p95: percentile(&mut cpu_series, 0.95),
        cpu_hot_thread_pct_peak: hot_peak,
        cpu_hot_thread_pct_p95: percentile(&mut hot_series, 0.95),
        host_busy_frac_p95: percentile(&mut host_series, 0.95),
        rss_peak_kib,
        pss_peak_kib,
        ctx_switches_per_s,
        cpu_seconds_total,
        ctx_switches_total: ctx_total,
        window_s: span_s,
    })
}

/// CPU% of the hottest single thread between two consecutive samples of the
/// same PID (100% == one core). Only tids present in both samples are diffed,
/// so thread churn between ticks cannot manufacture a spike.
fn hot_thread_percent(prev: &SystemSample, cur: &SystemSample, tck: f64) -> f64 {
    let dt = cur.elapsed_ms.saturating_sub(prev.elapsed_ms) as f64 / 1000.0;
    if dt <= 0.0 {
        return 0.0;
    }
    let mut hottest_delta = 0u64;
    for &(tid, cur_ticks) in &cur.thread_ticks {
        if let Some(&(_, prev_ticks)) = prev.thread_ticks.iter().find(|&&(t, _)| t == tid) {
            hottest_delta = hottest_delta.max(cur_ticks.saturating_sub(prev_ticks));
        }
    }
    hottest_delta as f64 / tck / dt * 100.0
}

/// In-place p95-style percentile of an unsorted series (0.0 if empty). Uses
/// the nearest-rank method: small series simply yield their maximum.
fn percentile(values: &mut [f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = ((values.len() as f64) * p.clamp(0.0, 1.0)).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
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
            let hot = match prev {
                Some(p) => hot_thread_percent(p, s, tck),
                None => 0.0,
            };
            csv.row(vec![
                s.elapsed_ms.to_string(),
                num(cpu, 2),
                num(hot, 2),
                s.rss_kib.to_string(),
                s.pss_kib.to_string(),
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
            pss_kib: 0,
            threads: 1,
            utime_ticks: 0,
            stime_ticks: 0,
            voluntary_ctxt: 0,
            nonvoluntary_ctxt: 0,
            read_bytes: 0,
            write_bytes: 0,
            thread_ticks: Vec::new(),
            host_busy_ticks: 0,
            host_total_ticks: 0,
        };
        let mut b = a.clone();
        b.elapsed_ms = 1000; // 1s wall
        b.utime_ticks = 100; // 100 ticks == 1s of CPU at 100 Hz
        assert!((cpu_percent(&a, &b, tck) - 100.0).abs() < 1e-9);
    }

    #[test]
    fn aggregate_exact_totals_are_rate_independent() {
        let tck = clk_tck();
        let mk = |elapsed_ms, ut, st, vol, nonvol| SystemSample {
            elapsed_ms,
            pid: 1,
            rss_kib: 1000,
            pss_kib: 0,
            threads: 1,
            utime_ticks: ut,
            stime_ticks: st,
            voluntary_ctxt: vol,
            nonvoluntary_ctxt: nonvol,
            read_bytes: 0,
            write_bytes: 0,
            thread_ticks: Vec::new(),
            host_busy_ticks: 0,
            host_total_ticks: 0,
        };
        // Over a 1 s span, CPU ticks grow by exactly `_SC_CLK_TCK` (= 1 CPU-second
        // = one fully-busy core), and 8 context switches occur. The exact totals
        // must reflect the cumulative deltas regardless of how many samples landed
        // in between — here just the two endpoints.
        let ticks = tck as u64;
        let agg = aggregate(&[mk(0, 0, 0, 0, 0), mk(1000, ticks, 0, 5, 3)]).unwrap();
        assert!((agg.window_s - 1.0).abs() < 1e-9);
        assert!((agg.cpu_seconds_total - 1.0).abs() < 1e-6);
        assert!((agg.cpu_pct_mean - 100.0).abs() < 1e-6);
        assert_eq!(agg.ctx_switches_total, 8);
        assert!((agg.ctx_switches_per_s - 8.0).abs() < 1e-6);
    }

    #[test]
    fn samples_self_process() {
        let pid = std::process::id() as i32;
        let (busy, total) = read_host_stat();
        let s = sample_pid(pid, 0, busy, total).expect("self /proc/<pid>/stat readable");
        assert_eq!(s.pid, pid as u32);
        assert!(s.threads >= 1);
        assert!(s.rss_kib > 0);
        // The per-thread walker must at least see this thread, with ticks that
        // never exceed the process-wide total.
        assert!(!s.thread_ticks.is_empty());
        let process_ticks = s.utime_ticks + s.stime_ticks;
        let thread_sum: u64 = s.thread_ticks.iter().map(|&(_, t)| t).sum();
        assert!(
            thread_sum <= process_ticks + 2,
            "threads {thread_sum} vs process {process_ticks}"
        );
        // Host counters are readable and monotone-consistent.
        assert!(s.host_total_ticks >= s.host_busy_ticks);
        assert!(s.host_total_ticks > 0);
    }

    #[test]
    fn host_cpu_line_parses_busy_and_total() {
        // user nice system idle iowait irq softirq steal
        let body = "cpu  100 0 50 800 50 0 0 0\ncpu0 25 0 12 200 12 0 0 0\n";
        let (busy, total) = parse_host_cpu_line(body);
        assert_eq!(total, 1000);
        assert_eq!(busy, 150); // total − idle(800) − iowait(50)
        assert_eq!(parse_host_cpu_line("intr 1 2 3"), (0, 0));
        assert_eq!(parse_host_cpu_line("cpu  1 2"), (0, 0));
    }

    #[test]
    fn hot_thread_and_host_percentiles_aggregate() {
        let tck = clk_tck();
        let ticks_1s = tck as u64; // one fully-busy core for one second
        let mk =
            |elapsed_ms: u64, total: u64, hot_tid_ticks: u64, host_busy: u64, host_total: u64| {
                SystemSample {
                    elapsed_ms,
                    pid: 1,
                    rss_kib: 0,
                    pss_kib: 0,
                    threads: 2,
                    utime_ticks: total,
                    stime_ticks: 0,
                    voluntary_ctxt: 0,
                    nonvoluntary_ctxt: 0,
                    read_bytes: 0,
                    write_bytes: 0,
                    // tid 10 is the hot relay thread; tid 11 idles. tid 12 exists
                    // only in later samples (thread churn must not fabricate load).
                    thread_ticks: vec![(10, hot_tid_ticks), (11, 1), (12, 999)],
                    host_busy_ticks: host_busy,
                    host_total_ticks: host_total,
                }
            };
        // Three ticks, 1 s apart: the hot thread burns a full core each second,
        // and the host is 95% busy in each interval.
        let samples = vec![
            mk(0, 0, 0, 0, 0),
            mk(1000, ticks_1s, ticks_1s, 950, 1000),
            mk(2000, 2 * ticks_1s, 2 * ticks_1s, 1900, 2000),
        ];
        let agg = aggregate(&samples).unwrap();
        assert!((agg.cpu_hot_thread_pct_peak - 100.0).abs() < 1.0);
        assert!((agg.cpu_hot_thread_pct_p95 - 100.0).abs() < 1.0);
        assert!((agg.host_busy_frac_p95 - 0.95).abs() < 1e-6);
        assert!(agg.cpu_pct_p95 > 0.0);
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
  78      raw_syscalls:sys_enter
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
        assert_eq!(perf.syscalls, Some(78));
        assert_eq!(perf.task_clock_ms, Some(45.678));
        assert_eq!(perf.duration_s, Some(0.123456));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_perf_csv_extracts_every_requested_counter() {
        let dir = std::env::temp_dir().join(format!("seshat-perf-csv-{}", monotonic_tag()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("perf.csv");
        fs::write(
            &path,
            "1234,,cycles,100.00,\n2468,,instructions,100.00,\n3579,,cache-references,100.00,\n246,,cache-misses,100.00,\n12,,context-switches,100.00,\n78,,raw_syscalls:sys_enter,100.00,\n45.678,msec,task-clock,100.00,\n0.123456,,seconds time elapsed,,,,\n",
        )
        .unwrap();

        let perf = parse_perf_output(&path);
        assert_eq!(perf.cycles, Some(1234));
        assert_eq!(perf.instructions, Some(2468));
        assert_eq!(perf.ipc, Some(2.0));
        assert_eq!(perf.cache_references, Some(3579));
        assert_eq!(perf.cache_misses, Some(246));
        assert_eq!(perf.context_switches, Some(12));
        assert_eq!(perf.syscalls, Some(78));
        assert_eq!(perf.task_clock_ms, Some(45.678));
        assert_eq!(perf.duration_s, Some(0.123456));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_mem_copies_reads_bpftrace_maps() {
        let dir = std::env::temp_dir().join(format!("seshat-memcopy-{}", monotonic_tag()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.txt");
        fs::write(
            &path,
            "Attaching 8 probes...\n\n@copy_from_user: 2048\n@copy_to_user: 1024\n@recvmsg: 500\n@sendmsg: 500\n@splice: 0\n@poll: 12\n@io_uring_enter: 340\n",
        )
        .unwrap();
        let r = parse_mem_copies(&path);
        assert_eq!(r.copy_to_user, Some(1024));
        assert_eq!(r.copy_from_user, Some(2048));
        assert_eq!(r.total_copies(), Some(3072));
        assert_eq!(r.sendmsg, Some(500));
        assert_eq!(r.splice, Some(0));
        assert_eq!(r.poll, Some(12));
        assert_eq!(r.io_uring_enter, Some(340));
        assert_eq!(r.ppoll, None);
        // 3072 copies over 1024 messages = 3 copies/message.
        assert_eq!(r.copies_per_msg(1024), Some(3.0));
        assert_eq!(r.copies_per_msg(0), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mem_copies_total_is_none_without_counters() {
        assert_eq!(MemCopyResult::default().total_copies(), None);
        assert_eq!(MemCopyResult::default().copies_per_msg(100), None);
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
        assert!(body.starts_with("elapsed_ms,cpu_pct,hot_thread_cpu_pct,rss_kib"));
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
