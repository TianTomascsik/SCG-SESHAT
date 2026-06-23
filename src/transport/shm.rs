//! SHM transport via the SCG gateway's gRPC-provisioned shared-memory interface
//! (WP2.4).
//!
//! The gateway exposes shared-memory ring endpoints that are dynamically created
//! through the management API. A client connects via a control socket, presents
//! the capability token, and receives `memfd`/`eventfd` descriptors over
//! `SCM_RIGHTS`. Data then flows through lock-free SPSC rings with `eventfd`
//! wakeups — the lowest-latency path the SCG offers.
//!
//! This transport exercises the full real-world SHM path:
//!   1. SESHAT creates two endpoints (encrypt + decrypt) via gRPC.
//!   2. The sender writes framed messages into the encrypt ring.
//!   3. The gateway applies the configured security internally.
//!   4. The receiver reads framed messages from the decrypt ring.
//!
//! For high-throughput benchmarking, the ring_capacity can be tuned per-scenario
//! (default 1 MiB; sweep 4/16 MiB for optimization studies).
#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use scg_client::ScgClient;

use super::{DataSink, DataSource, RecvOutcome, Transport, RECV_POLL_TIMEOUT};
use crate::gateway::grpc_client::{Direction, MgmtClient, TrafficClass};
use crate::gateway::{self, RunningPath, SecuritySpec, Topology};

/// How long to wait for each gateway process to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Default ring capacity per direction (1 MiB).
const DEFAULT_RING_CAPACITY: u64 = 1024 * 1024;

/// Sender side wrapping an `ScgClient` connected to the encrypt SHM endpoint.
struct ShmSink {
    client: ScgClient,
    traffic_id: u32,
}

impl DataSink for ShmSink {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.client
            .send(self.traffic_id, buf)
            .map_err(|e| io::Error::other(format!("SHM send: {e}")))
    }

    fn close(&mut self) {
        // ScgClient deregisters on drop.
    }
}

/// Receiver side wrapping an `ScgClient` connected to the decrypt SHM endpoint.
struct ShmSource {
    client: ScgClient,
    timeout: Duration,
}

impl DataSource for ShmSource {
    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        match self.client.recv_timeout(Some(self.timeout)) {
            Ok(Some((_traffic_id, data))) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(RecvOutcome::Message(len))
            }
            Ok(None) => Ok(RecvOutcome::Timeout),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("closed") || msg.contains("EOF") {
                    Ok(RecvOutcome::Closed)
                } else {
                    Err(io::Error::other(format!("SHM recv: {e}")))
                }
            }
        }
    }

    fn close(&mut self) {
        // ScgClient deregisters on drop.
    }
}

/// A benchmark transport that drives traffic through the gateway's shared-memory
/// local interface, provisioned via the gRPC management API.
pub struct GatewayShmTransport {
    name: &'static str,
    mgmt_socket: PathBuf,
    app_id: String,
    ring_capacity: u64,
    running: Option<RunningPath>,
}

impl GatewayShmTransport {
    /// Start a gateway configured for SHM endpoints and provision the management
    /// API.
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
        ring_capacity: u64,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;

        let backend_addr = format!("127.0.0.1:{}", gateway::reserve_local_port()?);
        let plan = gateway::build_path(spec, topology, &backend_addr)?;

        let running =
            gateway::start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

        let mgmt_socket = running.mgmt_socket_path().ok_or_else(|| {
            io::Error::other("gateway has no management socket path for SHM provisioning")
        })?;

        let capacity = if ring_capacity == 0 {
            DEFAULT_RING_CAPACITY
        } else {
            ring_capacity
        };

        Ok(GatewayShmTransport {
            name,
            mgmt_socket,
            app_id: app_id.to_string(),
            ring_capacity: capacity,
            running: Some(running),
        })
    }

    /// OS pids of the gateway process(es).
    pub fn pids(&self) -> Vec<i32> {
        self.running
            .as_ref()
            .map(RunningPath::pids)
            .unwrap_or_default()
    }

    /// Captured gateway log files.
    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.running
            .as_ref()
            .map(RunningPath::log_paths)
            .unwrap_or_default()
    }

    /// Gracefully stop the gateway process(es).
    pub fn shutdown(mut self) -> io::Result<()> {
        if let Some(running) = self.running.take() {
            running.shutdown()?;
        }
        Ok(())
    }
}

impl Transport for GatewayShmTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn loopback_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let mgmt = MgmtClient::new(&self.mgmt_socket);

        // Create an encrypt endpoint (sender → gateway encrypts).
        let encrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Encrypt,
                self.ring_capacity,
            )
            .map_err(io::Error::other)?;

        // Create a decrypt endpoint (gateway decrypts → receiver).
        let decrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Decrypt,
                self.ring_capacity,
            )
            .map_err(io::Error::other)?;

        let sink = Box::new(ShmSink {
            client: encrypt_ep.client,
            traffic_id: 1,
        });
        let source = Box::new(ShmSource {
            client: decrypt_ep.client,
            timeout: RECV_POLL_TIMEOUT,
        });

        Ok((sink, source))
    }
}
