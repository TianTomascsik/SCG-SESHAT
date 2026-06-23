//! Hot-reload event injection for mid-run config changes (WP3.4).
//!
//! The SCG gateway supports two hot-reload mechanisms:
//!   1. **SIGHUP + file-watch**: rewrite the JSON config file and send SIGHUP (or
//!      rely on `--watch` polling every 2s). The gateway re-validates and swaps
//!      atomically; new connections use the new config, in-flight ones drain.
//!   2. **gRPC endpoint management**: `CreateUdsEndpoint` / `CreateShmEndpoint` /
//!      `CloseEndpoint` — add/remove local interface endpoints at runtime. This
//!      is zero-drop for well-behaved clients (they re-provision).
//!
//! A `ReloadEvent` is injected at a specific time offset during the measurement
//! window. The run engine records three windows:
//!   - **before**: steady-state metrics pre-reload.
//!   - **during**: the reload moment + immediate aftermath.
//!   - **after**: recovered steady-state post-reload.
//!
//! CSV columns added: `reload_drops`, `reload_latency_spike_us`, `reload_recovery_ms`.
#![allow(dead_code)]

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::gateway::config::GatewayConfig;
use crate::gateway::grpc_client::MgmtClient;
use crate::gateway::process::GatewayProcess;

/// The type of reload event to inject.
#[derive(Debug, Clone)]
pub enum ReloadAction {
    /// Rewrite the config file with `new_config` and send SIGHUP.
    ConfigSwap { new_config: GatewayConfig },
    /// Write an invalid config and send SIGHUP (should be rejected by gateway).
    InvalidConfig { bad_json: String },
    /// Add a UDS endpoint via gRPC (zero-drop hot-add).
    AddEndpoint { app_id: String },
    /// Remove an endpoint via gRPC (graceful close).
    RemoveEndpoint { endpoint_id: u32 },
}

/// Metrics captured during and after a reload event.
#[derive(Debug, Clone, Default)]
pub struct ReloadMetrics {
    /// Messages lost during the reload window.
    pub drops: u64,
    /// Peak latency spike during reload (microseconds).
    pub latency_spike_us: u64,
    /// Time from reload signal to recovery of steady-state throughput (ms).
    pub recovery_ms: u64,
    /// Whether the reload was accepted (false for invalid config).
    pub accepted: bool,
}

/// Inject a SIGHUP-based config reload on a running gateway.
///
/// Atomically writes `new_config` over the gateway's config file path, then
/// signals the process. The gateway will preflight-validate and swap (or reject
/// if invalid). Returns immediately — the caller should measure the impact.
pub fn inject_config_reload(
    process: &GatewayProcess,
    config_path: &Path,
    new_config: &GatewayConfig,
) -> io::Result<()> {
    // Write the new config to a temp file, then atomically rename over the
    // target path (prevents partial reads by the gateway's file-watch).
    let dir = config_path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(".seshat-reload.tmp.json");
    std::fs::write(&tmp, new_config.to_json())?;
    std::fs::rename(&tmp, config_path)?;

    // Send SIGHUP.
    send_sighup(process.pid())?;
    Ok(())
}

/// Inject an invalid config (should be rejected; gateway keeps old config).
pub fn inject_invalid_reload(
    process: &GatewayProcess,
    config_path: &Path,
    bad_json: &str,
) -> io::Result<()> {
    let dir = config_path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(".seshat-reload.tmp.json");
    std::fs::write(&tmp, bad_json)?;
    std::fs::rename(&tmp, config_path)?;
    send_sighup(process.pid())?;
    Ok(())
}

/// Add a UDS endpoint via the gRPC management API (zero-drop hot-add).
pub fn inject_add_endpoint(mgmt: &MgmtClient, app_id: &str) -> Result<u32, String> {
    use crate::gateway::grpc_client::{Direction, TrafficClass};
    let ep = mgmt.create_uds(app_id, TrafficClass::Normal, Direction::Encrypt)?;
    Ok(ep.endpoint_id)
}

/// Remove an endpoint via the gRPC management API.
pub fn inject_remove_endpoint(mgmt: &MgmtClient, endpoint_id: u32) -> Result<(), String> {
    mgmt.close_endpoint(endpoint_id)
}

/// Wait for the gateway to finish processing a reload. We check by verifying
/// the gateway is still healthy (responds to gRPC health) after the signal.
pub fn wait_reload_settled(mgmt: &MgmtClient, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    // Give the gateway a moment to process the signal.
    std::thread::sleep(Duration::from_millis(100));
    while Instant::now() < deadline {
        if mgmt.health() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn send_sighup(pid: i32) -> io::Result<()> {
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
