//! UDS transport via the SCG gateway's gRPC-provisioned local interface (WP2.3).
//!
//! The gateway exposes Unix-domain socket endpoints that are dynamically created
//! through the management API. A client connects with a single-use capability
//! token and then sends/receives framed messages over the socket.
//!
//! This transport exercises the full real-world path:
//!   1. SESHAT creates two endpoints (encrypt + decrypt) via gRPC.
//!   2. The sender writes framed plaintext to the encrypt UDS endpoint.
//!   3. The gateway applies the configured security (TLS/kTLS/routing) internally.
//!   4. The receiver reads framed plaintext from the decrypt UDS endpoint.
//!
//! The `ScgClient` from `scg-client` handles the gRPC provisioning, token
//! handshake, and framed I/O internally. We wrap it into the SESHAT `Transport`
//! trait.
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

/// Sender side wrapping an `ScgClient` connected to the encrypt endpoint.
struct UdsSink {
    client: ScgClient,
    traffic_id: u32,
}

impl DataSink for UdsSink {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.client
            .send(self.traffic_id, buf)
            .map_err(|e| io::Error::other(format!("UDS send: {e}")))
    }

    fn close(&mut self) {
        // ScgClient deregisters on drop.
    }
}

/// Receiver side wrapping an `ScgClient` connected to the decrypt endpoint.
struct UdsSource {
    client: ScgClient,
    timeout: Duration,
}

impl DataSource for UdsSource {
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
                    Err(io::Error::other(format!("UDS recv: {e}")))
                }
            }
        }
    }

    fn close(&mut self) {
        // ScgClient deregisters on drop.
    }
}

/// A benchmark transport that drives traffic through the gateway's UDS local
/// interface, provisioned via the gRPC management API.
pub struct GatewayUdsTransport {
    name: &'static str,
    mgmt_socket: PathBuf,
    app_id: String,
    running: Option<RunningPath>,
}

impl GatewayUdsTransport {
    /// Start a gateway configured for UDS endpoints and provision the management
    /// API.
    ///
    /// The gateway must have rules with `listen_proto: "uds"` so that UDS
    /// endpoint creation maps to a pipeline. The `spec` and `topology` describe
    /// the security layer applied between the encrypt and decrypt rules.
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;

        // For UDS transport, the gateway rules use listen_proto=uds. The backend
        // address is unused (UDS traffic goes through the local interface, not a
        // TCP upstream). We set a dummy backend address.
        let backend_addr = format!("127.0.0.1:{}", gateway::reserve_local_port()?);
        let plan = gateway::build_path(spec, topology, &backend_addr)?;

        let running =
            gateway::start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

        // Discover the management socket path from the running gateway.
        let mgmt_socket = running.mgmt_socket_path().ok_or_else(|| {
            io::Error::other("gateway has no management socket path for UDS provisioning")
        })?;

        Ok(GatewayUdsTransport {
            name,
            mgmt_socket,
            app_id: app_id.to_string(),
            running: Some(running),
        })
    }

    /// OS pids of the gateway process(es), for `/proc/<pid>` system metrics.
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

impl Transport for GatewayUdsTransport {
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
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Encrypt)
            .map_err(io::Error::other)?;

        // Create a decrypt endpoint (gateway decrypts → receiver).
        let decrypt_ep = mgmt
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Decrypt)
            .map_err(io::Error::other)?;

        let sink = Box::new(UdsSink {
            client: encrypt_ep.client,
            traffic_id: 1,
        });
        let source = Box::new(UdsSource {
            client: decrypt_ep.client,
            timeout: RECV_POLL_TIMEOUT,
        });

        Ok((sink, source))
    }
}
