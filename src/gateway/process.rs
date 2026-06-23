//! Gateway child-process lifecycle (WP2.1).
//!
//! [`GatewayProcess`] spawns the real `gateway` binary against a generated JSON
//! config, waits for its listeners to come up (by polling the sockets — not by
//! scraping logs), captures stdout/stderr to a log file, and tears the process
//! down with `SIGTERM` (escalating to `SIGKILL`). The [`Drop`] impl guarantees
//! the child is killed and the config file removed even on panic.
#![allow(dead_code)] // lifecycle surface is consumed across Phase 2 work packages.

use std::fs::{File, OpenOptions};
use std::io::{self};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::config::GatewayConfig;

/// How often readiness/teardown polls the child while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// How long to wait for graceful `SIGTERM` shutdown before `SIGKILL`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Per-connect timeout when probing a TCP listener for readiness.
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// All `gateway` binaries that exist, in preference order: `SCG_GATEWAY_BIN`
/// first, then the sibling `SCG` checkout's build outputs (optimized first).
pub fn candidate_gateway_binaries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = std::env::var_os("SCG_GATEWAY_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            out.push(p);
        }
    }
    let candidates = [
        "../SCG/target/release/gateway",
        "../SCG/target/debug/gateway",
        "SCG/target/release/gateway",
        "SCG/target/debug/gateway",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Locate the preferred `gateway` binary (the first [`candidate_gateway_binaries`]).
pub fn locate_gateway_binary() -> Option<PathBuf> {
    candidate_gateway_binaries().into_iter().next()
}

/// A running `gateway` process tied to a generated config file.
pub struct GatewayProcess {
    label: String,
    child: Child,
    pid: i32,
    config_path: PathBuf,
    /// Captured stdout+stderr log file (scanned post-run for kTLS fallback etc.).
    log_path: PathBuf,
    /// TCP `IP:port` listeners to poll before declaring readiness.
    tcp_listeners: Vec<String>,
    /// Management UDS path to poll before declaring readiness, if any.
    mgmt_socket: Option<PathBuf>,
    /// Whether the process has already been reaped by `shutdown`.
    finished: bool,
}

impl GatewayProcess {
    /// Write `config` to `work_dir/<label>.config.json`, spawn the gateway with
    /// logs captured to `work_dir/<label>.log`, and return the handle. Call
    /// [`GatewayProcess::wait_ready`] before driving traffic.
    pub fn spawn(
        binary: &Path,
        config: &GatewayConfig,
        work_dir: &Path,
        label: &str,
        log_level: &str,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;
        let config_path = work_dir.join(format!("{label}.config.json"));
        std::fs::write(&config_path, config.to_json())?;

        let log_path = work_dir.join(format!("{label}.log"));
        let stdout = create_log(&log_path)?;
        let stderr = stdout.try_clone()?;

        let child = Command::new(binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--log-dir")
            .arg(work_dir)
            .arg("--log-level")
            .arg(log_level)
            .arg("--log-stdout")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let pid = child.id() as i32;

        let tcp_listeners = config
            .rules
            .iter()
            .filter(|r| r.listen_proto == "tcp" && r.listen_addr != "unused")
            .map(|r| normalize_probe_addr(&r.listen_addr))
            .collect();
        let mgmt_socket = config
            .api
            .as_ref()
            .map(|a| PathBuf::from(&a.uds_path));

        Ok(GatewayProcess {
            label: label.to_string(),
            child,
            pid,
            config_path,
            log_path,
            tcp_listeners,
            mgmt_socket,
            finished: false,
        })
    }

    /// The OS process id of the gateway (for `/proc/<pid>` system metrics).
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Path to the captured stdout+stderr log (scanned for the effective
    /// protocol — e.g. kTLS->userspace fallback — after the run).
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// The management UDS socket path, if the gateway was started with an API
    /// block. Used by UDS/SHM transports to provision endpoints.
    pub fn mgmt_socket_path(&self) -> Option<&Path> {
        self.mgmt_socket.as_deref()
    }

    /// Path to the generated JSON config file driving this gateway instance.
    /// Used by hot-reload injection to atomically swap the config.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Block until every TCP listener (and the management socket, if any) accepts
    /// a connection, or `timeout` elapses. Fails fast if the child exits early.
    pub fn wait_ready(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "gateway '{}' exited during startup with {status}",
                    self.label
                )));
            }
            if self.all_listeners_up() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "gateway '{}' not ready within {:?}",
                    self.label, timeout
                )));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn all_listeners_up(&self) -> bool {
        for addr in &self.tcp_listeners {
            let Ok(socket) = addr.parse() else {
                continue;
            };
            if TcpStream::connect_timeout(&socket, PROBE_TIMEOUT).is_err() {
                return false;
            }
        }
        if let Some(sock) = &self.mgmt_socket {
            if UnixStream::connect(sock).is_err() {
                return false;
            }
        }
        true
    }

    /// Gracefully stop the gateway: `SIGTERM`, wait up to [`SHUTDOWN_GRACE`],
    /// then `SIGKILL`. Reaps the child and removes the generated config file.
    pub fn shutdown(mut self) -> io::Result<()> {
        self.terminate()
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if self.child.try_wait()?.is_none() {
            signal(self.pid, libc::SIGTERM);
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline {
                if self.child.try_wait()?.is_some() {
                    break;
                }
                thread::sleep(POLL_INTERVAL);
            }
            if self.child.try_wait()?.is_none() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        self.finished = true;
        let _ = std::fs::remove_file(&self.config_path);
        if let Some(sock) = &self.mgmt_socket {
            let _ = std::fs::remove_file(sock);
        }
        Ok(())
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        // Best-effort: never panic in Drop. Force-kill if shutdown was skipped.
        if !self.finished {
            signal(self.pid, libc::SIGKILL);
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.config_path);
            if let Some(sock) = &self.mgmt_socket {
                let _ = std::fs::remove_file(sock);
            }
        }
    }
}

/// Send `sig` to `pid`, ignoring errors (e.g. the process already exited).
fn signal(pid: i32, sig: libc::c_int) {
    // SAFETY: `kill(2)` with a previously valid pid is sound; failure is ignored.
    unsafe {
        libc::kill(pid, sig);
    }
}

/// Truncate any previous log, then reopen in append mode so the cloned stderr
/// handle shares the write position (append writes are atomic at EOF).
fn create_log(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    OpenOptions::new().create(true).append(true).open(path)
}

/// Map a wildcard bind (`0.0.0.0:port` / `[::]:port`) to a connectable loopback
/// address for readiness probing.
fn normalize_probe_addr(listen_addr: &str) -> String {
    if let Some(port) = listen_addr.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{port}")
    } else if let Some(port) = listen_addr.strip_prefix("[::]:") {
        format!("127.0.0.1:{port}")
    } else {
        listen_addr.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_wildcard_to_loopback() {
        assert_eq!(normalize_probe_addr("0.0.0.0:9100"), "127.0.0.1:9100");
        assert_eq!(normalize_probe_addr("[::]:9100"), "127.0.0.1:9100");
        assert_eq!(normalize_probe_addr("127.0.0.1:9100"), "127.0.0.1:9100");
    }
}
