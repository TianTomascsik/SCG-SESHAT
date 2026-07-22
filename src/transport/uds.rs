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

fn class_label(class: TrafficClass) -> &'static str {
    match class {
        TrafficClass::Normal => "normal",
        TrafficClass::Safety => "safety",
    }
}

fn traffic_class_from_label(label: &str) -> io::Result<TrafficClass> {
    match label {
        "normal" | "non-safety" | "bulk" | "best-effort" => Ok(TrafficClass::Normal),
        "safety" | "safety-critical" => Ok(TrafficClass::Safety),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported UDS traffic class '{other}'"),
        )),
    }
}

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

    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        // One vectored writev per ≤512 frames instead of two write syscalls
        // per message (frame header + payload).
        self.client
            .try_send_batch(self.traffic_id, msgs)
            .map_err(|e| io::Error::other(format!("UDS send: {e}")))
    }

    fn preferred_batch(&self, message_bytes: u32) -> usize {
        crate::transport::stream_batch_size(message_bytes)
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

    fn recv_batch(
        &mut self,
        buf: &mut [u8],
        stride: usize,
        max: usize,
        lens: &mut [usize],
    ) -> io::Result<crate::transport::BatchOutcome> {
        use crate::transport::BatchOutcome;
        if max == 0 || stride == 0 || buf.len() < stride || lens.is_empty() {
            return Ok(BatchOutcome::Timeout);
        }
        let cap = max.min(lens.len());
        match self
            .client
            .recv_batch_into(buf, stride, &mut lens[..cap], Some(self.timeout))
        {
            Ok(Some(count)) => Ok(BatchOutcome::Messages(count)),
            Ok(None) => Ok(BatchOutcome::Timeout),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("closed") || msg.contains("EOF") {
                    Ok(BatchOutcome::Closed)
                } else {
                    Err(io::Error::other(format!("UDS recv: {e}")))
                }
            }
        }
    }

    fn preferred_batch(&self, message_bytes: u32) -> usize {
        crate::transport::stream_batch_size(message_bytes)
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
    /// Management socket of the encrypt gateway (also the single-gateway socket;
    /// used by the hot-reload accessor).
    pub(crate) mgmt_socket: PathBuf,
    /// Management socket of the decrypt gateway. Equals `mgmt_socket` in the
    /// single-gateway topology; distinct in scg-scg where encrypt (scg-a) and
    /// decrypt (scg-b) run as separate processes and each direction must be
    /// provisioned on its own gateway's socket.
    decrypt_mgmt_socket: PathBuf,
    /// Base management app-id; connection `i` provisions under `conn_app_id(app_id, i)`.
    app_id: String,
    /// Number of independent pipelines provisioned at start. Sized by the
    /// caller as connections × runs, since every repetition of the engine's
    /// runs loop opens a fresh set of pairs (`next_conn` never resets).
    connections: usize,
    /// Hands out the next connection index to `loopback_pair`/`pingpong_pair`, so each
    /// call provisions its own `(app_id, upstream port)` pair and the gateway does not
    /// evict siblings that share one app_id (multi-connection zero-metric fix).
    next_conn: std::sync::atomic::AtomicUsize,
    running: Option<RunningPath>,
}

impl GatewayUdsTransport {
    /// Start a gateway configured for UDS endpoints and provision the management
    /// API.
    ///
    /// The gateway must have rules with `listen_proto: "uds"` so that UDS
    /// endpoint creation maps to a pipeline. The `spec` and `topology` describe
    /// the security layer applied between the encrypt and decrypt rules.
    #[allow(clippy::too_many_arguments)] // cohesive constructor; mirrors `shm.rs::start`.
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
        connections: usize,
    ) -> io::Result<Self> {
        Self::start_with_classes(
            name,
            spec,
            topology,
            binary,
            work_dir,
            gateway_cores,
            app_id,
            connections,
            &[TrafficClass::Normal],
        )
    }

    /// Start a gateway with UDS endpoint templates for the requested traffic
    /// classes.
    #[allow(clippy::too_many_arguments)] // cohesive constructor; mirrors `shm.rs::start_with_classes`.
    pub fn start_with_classes(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
        connections: usize,
        classes: &[TrafficClass],
    ) -> io::Result<Self> {
        use crate::gateway::config::{ApiConfig, GatewayConfig};
        use crate::gateway::NamedGateway;
        use std::sync::atomic::{AtomicU64, Ordering};
        static UDS_MGMT_ID: AtomicU64 = AtomicU64::new(0);

        std::fs::create_dir_all(work_dir)?;

        // SAFETY: `getuid()` is an always-successful POSIX syscall that takes no
        // arguments, dereferences no pointers, and cannot fail; it returns the
        // real user ID of the calling process with no preconditions.
        let uid = unsafe { libc::getuid() };
        let classes = normalize_classes(classes);
        let connections = connections.max(1);

        // Build UDS rules: the gateway needs `listen_proto: "uds"` rules with an
        // `app_id` so that the management API can create endpoints for this app.
        // Each connection gets its OWN rule pair (distinct app_id + upstream port):
        // the gateway keys endpoints by (uid, app_id, class, direction) with no
        // per-connection component, so reusing one app_id across N connections would
        // evict all but the last (the multi-connection zero-metric bug). Reserve one
        // upstream port per connection so the N encrypt→decrypt TLS legs don't
        // contend on a single bound port either.
        // NB: apply_encrypt/apply_decrypt call .proto() which resets listen_proto,
        // so we must set listen_proto("uds") AFTER applying the security spec.
        let upstream_addrs: Vec<String> = (0..connections)
            .map(|_| Ok(format!("127.0.0.1:{}", gateway::reserve_local_port()?)))
            .collect::<io::Result<Vec<_>>>()?;
        let rules = build_rules_for_classes(spec, app_id, uid, &upstream_addrs, &classes);
        // Representative backend addr for the plan (informational for UDS: readiness
        // is gated on the management socket, not this port).
        let upstream_addr = upstream_addrs[0].clone();

        // Build plan with API config (required for UDS endpoint provisioning).
        let id = UDS_MGMT_ID.fetch_add(1, Ordering::Relaxed);
        let runtime_dir = gateway::short_runtime_dir("su", id)?;
        let sock = runtime_dir.join("mgmt.sock");
        let api = ApiConfig::new(
            &sock.to_string_lossy(),
            &runtime_dir.to_string_lossy(),
            1024 * 1024,
        );

        // Encrypt endpoints are provisioned via `sock` (the encrypt gateway),
        // decrypt endpoints via `decrypt_sock`. In the single-gateway topology
        // both rules live in one process, so the two sockets coincide. In scg-scg
        // the encrypt rule runs on scg-a (`sock`) and the decrypt rule on scg-b
        // (`sock2`), so each direction MUST be provisioned on its own gateway's
        // socket — provisioning the encrypt endpoint on the decrypt-only process
        // fails `not_found` (that process carries no encrypt rule).
        let (gateways, decrypt_sock) = match topology {
            Topology::SingleGateway => (
                vec![NamedGateway {
                    label: "scg".to_string(),
                    config: GatewayConfig::new(rules)
                        .log_level("info")
                        .allow_all()
                        .api(api),
                }],
                sock.clone(),
            ),
            Topology::ScgToScg => {
                let id2 = UDS_MGMT_ID.fetch_add(1, Ordering::Relaxed);
                let runtime_dir2 = gateway::short_runtime_dir("su", id2)?;
                let sock2 = runtime_dir2.join("mgmt.sock");
                let api2 = ApiConfig::new(
                    &sock2.to_string_lossy(),
                    &runtime_dir2.to_string_lossy(),
                    1024 * 1024,
                );
                let (encrypt_rules, decrypt_rules): (Vec<_>, Vec<_>) = rules
                    .into_iter()
                    .partition(|rule| rule.direction == "encrypt");
                (
                    vec![
                        NamedGateway {
                            label: "scg-a".to_string(),
                            config: GatewayConfig::new(encrypt_rules)
                                .log_level("info")
                                .allow_all()
                                .api(api),
                        },
                        NamedGateway {
                            label: "scg-b".to_string(),
                            config: GatewayConfig::new(decrypt_rules)
                                .log_level("info")
                                .allow_all()
                                .api(api2),
                        },
                    ],
                    sock2,
                )
            }
        };

        let plan = gateway::PathPlan {
            ingress_addr: "unused".to_string(),
            backend_addr: upstream_addr,
            gateways,
        };

        let running = gateway::start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

        Ok(GatewayUdsTransport {
            name,
            mgmt_socket: sock,
            decrypt_mgmt_socket: decrypt_sock,
            app_id: app_id.to_string(),
            connections,
            next_conn: std::sync::atomic::AtomicUsize::new(0),
            running: Some(running),
        })
    }

    /// The base app-id for the next connection to provision, or an error once every
    /// pre-provisioned connection has been handed out (a caller bug — the engine opens
    /// exactly `connections` pipelines).
    fn next_conn_app_id(&self) -> io::Result<String> {
        let i = self
            .next_conn
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if i >= self.connections {
            return Err(io::Error::other(format!(
                "UDS: connection {i} requested but only {} pipeline(s) provisioned",
                self.connections
            )));
        }
        Ok(super::conn_app_id(&self.app_id, i))
    }

    pub fn loopback_pair_for_class(
        &self,
        _message_bytes: u32,
        class: TrafficClass,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        // Provision each direction on its own gateway's management socket; the
        // two coincide for single-gateway and differ for scg-scg.
        let decrypt_mgmt = MgmtClient::new(&self.decrypt_mgmt_socket);
        let encrypt_mgmt = MgmtClient::new(&self.mgmt_socket);
        let app_id = self.next_conn_app_id()?;

        // Bring up the decrypt listener first. The encrypt endpoint dials it as
        // part of its initial TLS handshake; provisioning encrypt first makes
        // its first connect race a closed port and adds a one-second retry,
        // which used to consume an entire short benchmark window.
        let decrypt_ep = decrypt_mgmt
            .create_uds(&app_id, class, Direction::Decrypt)
            .map_err(io::Error::other)?;

        let encrypt_ep = encrypt_mgmt
            .create_uds(&app_id, class, Direction::Encrypt)
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

    pub fn pingpong_pair_for_class(
        &self,
        _message_bytes: u32,
        class: TrafficClass,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let decrypt_mgmt = MgmtClient::new(&self.decrypt_mgmt_socket);
        let encrypt_mgmt = MgmtClient::new(&self.mgmt_socket);
        let app_id = self.next_conn_app_id()?;

        let decrypt_ep = decrypt_mgmt
            .create_uds(&app_id, class, Direction::Decrypt)
            .map_err(io::Error::other)?;

        let encrypt_ep = encrypt_mgmt
            .create_uds(&app_id, class, Direction::Encrypt)
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

fn normalize_classes(classes: &[TrafficClass]) -> Vec<TrafficClass> {
    let mut out = Vec::new();
    for class in classes {
        if !out.contains(class) {
            out.push(*class);
        }
    }
    if out.is_empty() {
        out.push(TrafficClass::Normal);
    }
    out
}

/// Build the UDS rule set: one encrypt+decrypt pair per (connection, class).
///
/// Each connection `i` gets a distinct `app_id` (`conn_app_id(base, i)`) and its own
/// `upstream_addrs[i]` (encrypt dials it, decrypt listens on it), so the N pipelines are
/// independent — no gateway owner-key eviction and no shared-port contention. Rule names
/// are suffixed `-c{i}` to stay unique. `upstream_addrs.len()` is the connection count.
fn build_rules_for_classes(
    spec: &SecuritySpec,
    app_id: &str,
    uid: u32,
    upstream_addrs: &[String],
    classes: &[TrafficClass],
) -> Vec<crate::gateway::config::RuleConfig> {
    use crate::gateway::config::RuleConfig;

    let mut rules = Vec::with_capacity(upstream_addrs.len() * classes.len() * 2);
    for (i, upstream_addr) in upstream_addrs.iter().enumerate() {
        let conn_app_id = super::conn_app_id(app_id, i);
        for class in classes {
            let label = class_label(*class);
            let encrypt = spec
                .apply_encrypt(
                    RuleConfig::new(
                        &format!("seshat-encrypt-{label}-c{i}"),
                        "encrypt",
                        "unused",
                        upstream_addr,
                    )
                    .app_id(&conn_app_id)
                    .traffic_class(label)
                    .allowed_uid(uid),
                )
                .traffic_class(label)
                .listen_proto("uds");
            let decrypt = spec
                .apply_decrypt(
                    RuleConfig::new(
                        &format!("seshat-decrypt-{label}-c{i}"),
                        "decrypt",
                        "unused",
                        upstream_addr,
                    )
                    .app_id(&conn_app_id)
                    .traffic_class(label)
                    .allowed_uid(uid),
                )
                .traffic_class(label)
                .listen_proto("uds");
            rules.push(encrypt);
            rules.push(decrypt);
        }
    }
    rules
}

impl Transport for GatewayUdsTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        self.loopback_pair_for_class(message_bytes, TrafficClass::Normal)
    }

    fn loopback_pair_for_class(
        &self,
        message_bytes: u32,
        traffic_class: &str,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        self.loopback_pair_for_class(message_bytes, traffic_class_from_label(traffic_class)?)
    }

    fn pingpong_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        self.pingpong_pair_for_class(message_bytes, TrafficClass::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SecuritySpec {
        SecuritySpec::routing_tcp()
    }

    #[test]
    fn uds_rules_are_created_per_traffic_class() {
        let rules = build_rules_for_classes(
            &spec(),
            "app",
            1000,
            &["127.0.0.1:9000".to_string()],
            &[TrafficClass::Normal, TrafficClass::Safety],
        );

        assert_eq!(rules.len(), 4);
        assert!(rules.iter().any(|r| {
            r.name == "seshat-encrypt-normal-c0"
                && r.direction == "encrypt"
                && r.listen_proto == "uds"
                && r.traffic_class == "normal"
        }));
        assert!(rules.iter().any(|r| {
            r.name == "seshat-decrypt-safety-c0"
                && r.direction == "decrypt"
                && r.listen_proto == "uds"
                && r.traffic_class == "safety"
        }));
    }

    #[test]
    fn uds_rules_are_independent_per_connection() {
        // Multi-connection fix: each connection must get its own rule pair with a
        // DISTINCT app_id and a DISTINCT upstream port, or the gateway evicts
        // siblings that share one (uid, app_id, class, direction) key and only the
        // last connection survives (the historical ≥2-connection zero-metric bug).
        let addrs = [
            "127.0.0.1:9000".to_string(),
            "127.0.0.1:9001".to_string(),
            "127.0.0.1:9002".to_string(),
        ];
        let rules = build_rules_for_classes(&spec(), "app", 1000, &addrs, &[TrafficClass::Normal]);
        assert_eq!(
            rules.len(),
            6,
            "3 connections × 1 class × (encrypt+decrypt)"
        );

        // Distinct app_ids per connection.
        let app_ids: std::collections::HashSet<_> =
            rules.iter().map(|r| r.app_id.clone()).collect();
        assert_eq!(app_ids.len(), 3, "one app_id per connection: {app_ids:?}");

        // Distinct upstream ports per connection (encrypt dials, decrypt listens).
        let ports: std::collections::HashSet<_> =
            rules.iter().map(|r| r.upstream_addr.clone()).collect();
        assert_eq!(
            ports.len(),
            3,
            "one upstream port per connection: {ports:?}"
        );

        // Rule names stay unique.
        let names: std::collections::HashSet<_> = rules.iter().map(|r| r.name.clone()).collect();
        assert_eq!(names.len(), 6, "rule names unique across connections");
    }

    #[test]
    fn class_labels_accept_legacy_safety_names() {
        assert_eq!(
            traffic_class_from_label("safety-critical").unwrap(),
            TrafficClass::Safety
        );
        assert_eq!(
            traffic_class_from_label("non-safety").unwrap(),
            TrafficClass::Normal
        );
    }

    /// Regression + feature test: in scg-scg the encrypt endpoint was provisioned
    /// on the decrypt-only process (a single shared mgmt socket) and failed gRPC
    /// `not_found`. With per-direction socket routing, both endpoints provision
    /// across the two gateways. Needs a working gateway binary; skips otherwise.
    #[test]
    fn uds_scg_to_scg_provisions_both_endpoints() {
        let _guard = gateway::gateway_test_guard();
        let work_dir =
            std::env::temp_dir().join(format!("seshat-uds-scgscg-{}", std::process::id()));
        let Some(binary) = gateway::locate_working_binary(&work_dir) else {
            eprintln!("skip: no working gateway binary");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };

        let transport = GatewayUdsTransport::start(
            "uds",
            &spec(),
            Topology::ScgToScg,
            &binary,
            &work_dir,
            &[],
            "scgscg-app",
            1,
        )
        .expect("uds scg-scg gateway pair starts");
        assert_eq!(transport.pids().len(), 2, "scg-scg spawns two gateways");

        // The call that previously failed `not_found` on the encrypt direction.
        let pair = transport.loopback_pair_for_class(256, TrafficClass::Normal);
        assert!(
            pair.is_ok(),
            "scg-scg must provision both encrypt and decrypt endpoints: {:?}",
            pair.err()
        );

        transport.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&work_dir);
    }
}
