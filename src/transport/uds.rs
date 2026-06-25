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

use super::{DataSink, DataSource, DuplexEnd, RecvOutcome, Transport, RECV_POLL_TIMEOUT};
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

/// Client-side full-duplex end for the closed-loop ping-pong RTT mode.
///
/// Mirrors the SHM duplex client: send on the encrypt endpoint, read the same
/// framed message back off the decrypt endpoint once the gateway has relayed it.
/// One message in flight yields a true closed-loop gateway latency.
struct UdsDuplexClient {
    tx: ScgClient,
    rx: ScgClient,
    traffic_id: u32,
    timeout: Duration,
}

impl DuplexEnd for UdsDuplexClient {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        self.tx
            .send(self.traffic_id, buf)
            .map_err(|e| io::Error::other(format!("UDS send: {e}")))
    }

    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        match self.rx.recv_timeout(Some(self.timeout)) {
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
        // ScgClients deregister on drop.
    }
}

/// Server-side stub for UDS ping-pong: the gateway relays encrypt→decrypt, so
/// this end just idles until the run completes.
struct UdsNullServer;

impl DuplexEnd for UdsNullServer {
    fn send_msg(&mut self, _buf: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn recv_msg(&mut self, _buf: &mut [u8]) -> io::Result<RecvOutcome> {
        std::thread::sleep(Duration::from_millis(5));
        Ok(RecvOutcome::Timeout)
    }

    fn close(&mut self) {}
}

/// A benchmark transport that drives traffic through the gateway's UDS local
/// interface, provisioned via the gRPC management API.
pub struct GatewayUdsTransport {
    name: &'static str,
    pub(crate) mgmt_socket: PathBuf,
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
        use crate::gateway::config::{ApiConfig, GatewayConfig, RuleConfig};
        use crate::gateway::NamedGateway;
        use std::sync::atomic::{AtomicU64, Ordering};
        static UDS_MGMT_ID: AtomicU64 = AtomicU64::new(0);

        std::fs::create_dir_all(work_dir)?;

        let uid = unsafe { libc::getuid() };

        // Build UDS rules: the gateway needs `listen_proto: "uds"` rules with an
        // `app_id` so that the management API can create endpoints for this app.
        // A dummy upstream_addr is still needed for the security pipeline.
        // NB: apply_encrypt/apply_decrypt call .proto() which resets listen_proto,
        // so we must set listen_proto("uds") AFTER applying the security spec.
        let upstream_addr = format!("127.0.0.1:{}", gateway::reserve_local_port()?);
        let encrypt = spec.apply_encrypt(
            RuleConfig::new("seshat-encrypt", "encrypt", "unused", &upstream_addr)
                .app_id(app_id)
                .traffic_class("normal")
                .allowed_uid(uid),
        ).listen_proto("uds");
        let decrypt = spec.apply_decrypt(
            RuleConfig::new("seshat-decrypt", "decrypt", "unused", &upstream_addr)
                .app_id(app_id)
                .traffic_class("normal")
                .allowed_uid(uid),
        ).listen_proto("uds");

        // Build plan with API config (required for UDS endpoint provisioning).
        let id = UDS_MGMT_ID.fetch_add(1, Ordering::Relaxed);
        let runtime_dir = gateway::short_runtime_dir("su", id)?;
        let sock = runtime_dir.join("mgmt.sock");
        let api = ApiConfig::new(
            &sock.to_string_lossy(),
            &runtime_dir.to_string_lossy(),
            1024 * 1024,
        );

        let gateways = match topology {
            Topology::SingleGateway => vec![NamedGateway {
                label: "scg".to_string(),
                config: GatewayConfig::new(vec![encrypt, decrypt])
                    .log_level("info")
                    .allow_all()
                    .api(api),
            }],
            Topology::ScgToScg => {
                let id2 = UDS_MGMT_ID.fetch_add(1, Ordering::Relaxed);
                let runtime_dir2 = gateway::short_runtime_dir("su", id2)?;
                let sock2 = runtime_dir2.join("mgmt.sock");
                let api2 = ApiConfig::new(
                    &sock2.to_string_lossy(),
                    &runtime_dir2.to_string_lossy(),
                    1024 * 1024,
                );
                vec![
                    NamedGateway {
                        label: "scg-a".to_string(),
                        config: GatewayConfig::new(vec![encrypt])
                            .log_level("info")
                            .allow_all()
                            .api(api),
                    },
                    NamedGateway {
                        label: "scg-b".to_string(),
                        config: GatewayConfig::new(vec![decrypt])
                            .log_level("info")
                            .allow_all()
                            .api(api2),
                    },
                ]
            }
        };

        let plan = gateway::PathPlan {
            ingress_addr: "unused".to_string(),
            backend_addr: upstream_addr,
            gateways,
        };

        let running = gateway::start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

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

        // Bring up the decrypt listener first. The encrypt endpoint dials it as
        // part of its initial TLS handshake; provisioning encrypt first makes
        // its first connect race a closed port and adds a one-second retry,
        // which used to consume an entire short benchmark window.
        let decrypt_ep = mgmt
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Decrypt)
            .map_err(io::Error::other)?;

        let encrypt_ep = mgmt
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Encrypt)
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

    fn pingpong_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let mgmt = MgmtClient::new(&self.mgmt_socket);

        let decrypt_ep = mgmt
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Decrypt)
            .map_err(io::Error::other)?;

        let encrypt_ep = mgmt
            .create_uds(&self.app_id, TrafficClass::Normal, Direction::Encrypt)
            .map_err(io::Error::other)?;

        // The client sends on encrypt and reads the echo off decrypt; the
        // gateway relays between them, so the server end is a no-op stub.
        let client = Box::new(UdsDuplexClient {
            tx: encrypt_ep.client,
            rx: decrypt_ep.client,
            traffic_id: 1,
            timeout: RECV_POLL_TIMEOUT,
        });
        let server = Box::new(UdsNullServer);

        Ok((client, server))
    }
}
