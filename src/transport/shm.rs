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

use super::{DataSink, DataSource, DuplexEnd, RecvOutcome, Transport, RECV_POLL_TIMEOUT};
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
        match self
            .client
            .try_send(self.traffic_id, buf)
            .map_err(|e| io::Error::other(format!("SHM send: {e}")))?
        {
            true => Ok(()),
            false => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn send_batch(&mut self, msgs: &[&[u8]]) -> io::Result<usize> {
        // Push the whole batch with a single gateway wakeup (one eventfd signal
        // for up to BATCH_MAX frames) instead of signalling per message. A short
        // count means SHM backpressure; the engine yields and retries the rest.
        self.client
            .try_send_batch(self.traffic_id, msgs)
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
        // Single-copy, allocation-free: pop the payload straight into `buf`.
        match self.client.recv_into(buf, Some(self.timeout)) {
            Ok(Some((_traffic_id, len))) => Ok(RecvOutcome::Message(len)),
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
        let cap = max.min(buf.len() / stride).min(lens.len());

        // Block once for the first message; if it times out the ring is idle.
        let mut count = match self.client.recv_into(&mut buf[..stride], Some(self.timeout)) {
            Ok(Some((_tid, len))) => {
                lens[0] = len;
                1
            }
            Ok(None) => return Ok(BatchOutcome::Timeout),
            Err(e) => {
                let msg = format!("{e}");
                return if msg.contains("closed") || msg.contains("EOF") {
                    Ok(BatchOutcome::Closed)
                } else {
                    Err(io::Error::other(format!("SHM recv: {e}")))
                };
            }
        };

        // Drain whatever else is already queued without blocking, so one wake
        // services a whole burst (mirrors the datagram recvmmsg fast path).
        while count < cap {
            let base = count * stride;
            match self
                .client
                .try_recv_into(&mut buf[base..base + stride])
                .map_err(|e| io::Error::other(format!("SHM recv: {e}")))?
            {
                Some((_tid, len)) => {
                    lens[count] = len;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(BatchOutcome::Messages(count))
    }

    fn close(&mut self) {
        // ScgClient deregisters on drop.
    }
}

/// Client-side full-duplex end for the closed-loop ping-pong RTT mode.
///
/// The SCG SHM data path is one-way per endpoint, so a round trip is formed by
/// sending on the **encrypt** ring and reading the same framed message back off
/// the **decrypt** ring after it has traversed the gateway. With exactly one
/// message in flight this measures true closed-loop gateway latency, free of the
/// queueing-depth artifact that inflates the open-loop "sustained" path.
struct ShmDuplexClient {
    tx: ScgClient,
    rx: ScgClient,
    traffic_id: u32,
    timeout: Duration,
}

impl DuplexEnd for ShmDuplexClient {
    fn send_msg(&mut self, buf: &[u8]) -> io::Result<()> {
        // Block until the (typically shallow) ring accepts the single in-flight
        // message; yield rather than spin so a busy gateway can drain.
        loop {
            match self
                .tx
                .try_send(self.traffic_id, buf)
                .map_err(|e| io::Error::other(format!("SHM send: {e}")))?
            {
                true => return Ok(()),
                false => std::thread::yield_now(),
            }
        }
    }

    fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvOutcome> {
        match self.rx.recv_into(buf, Some(self.timeout)) {
            Ok(Some((_traffic_id, len))) => Ok(RecvOutcome::Message(len)),
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
        // ScgClients deregister on drop.
    }
}

/// Server-side stub for SHM ping-pong: the gateway itself relays each message
/// from the encrypt endpoint to the decrypt endpoint, so no external echo is
/// required. This end simply idles until the run completes.
struct ShmNullServer;

impl DuplexEnd for ShmNullServer {
    fn send_msg(&mut self, _buf: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn recv_msg(&mut self, _buf: &mut [u8]) -> io::Result<RecvOutcome> {
        // Idle without burning a core; the echo path lives inside the gateway.
        std::thread::sleep(Duration::from_millis(5));
        Ok(RecvOutcome::Timeout)
    }

    fn close(&mut self) {}
}
pub struct GatewayShmTransport {
    name: &'static str,
    pub(crate) mgmt_socket: PathBuf,
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
        tuning: &crate::gateway::config::ShmTuning,
    ) -> io::Result<Self> {
        use crate::gateway::config::{ApiConfig, GatewayConfig, RuleConfig};
        use crate::gateway::NamedGateway;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SHM_MGMT_ID: AtomicU64 = AtomicU64::new(0);

        std::fs::create_dir_all(work_dir)?;

        let uid = unsafe { libc::getuid() };
        let shm_ring = if ring_capacity == 0 {
            DEFAULT_RING_CAPACITY as usize
        } else {
            ring_capacity as usize
        };

        // Build SHM rules: listen_proto="shm" with app_id and allowed_uids.
        // apply_encrypt/apply_decrypt reset listen_proto, so set it after.
        let upstream_addr = format!("127.0.0.1:{}", gateway::reserve_local_port()?);
        let encrypt = spec.apply_encrypt(
            RuleConfig::new("seshat-encrypt", "encrypt", "unused", &upstream_addr)
                .app_id(app_id)
                .traffic_class("normal")
                .allowed_uid(uid),
        ).listen_proto("shm");
        let decrypt = spec.apply_decrypt(
            RuleConfig::new("seshat-decrypt", "decrypt", "unused", &upstream_addr)
                .app_id(app_id)
                .traffic_class("normal")
                .allowed_uid(uid),
        ).listen_proto("shm");

        // Build plan with API config (required for SHM endpoint provisioning).
        let id = SHM_MGMT_ID.fetch_add(1, Ordering::Relaxed);
        let runtime_dir = gateway::short_runtime_dir("ss", id)?;
        let sock = runtime_dir.join("mgmt.sock");
        let api = ApiConfig::new(
            &sock.to_string_lossy(),
            &runtime_dir.to_string_lossy(),
            shm_ring,
        )
        .shm_tuning(tuning);

        let gateways = match topology {
            Topology::SingleGateway => vec![NamedGateway {
                label: "scg".to_string(),
                config: GatewayConfig::new(vec![encrypt, decrypt])
                    .log_level("info")
                    .allow_all()
                    .api(api),
            }],
            Topology::ScgToScg => {
                let id2 = SHM_MGMT_ID.fetch_add(1, Ordering::Relaxed);
                let runtime_dir2 = gateway::short_runtime_dir("ss", id2)?;
                let sock2 = runtime_dir2.join("mgmt.sock");
                let api2 = ApiConfig::new(
                    &sock2.to_string_lossy(),
                    &runtime_dir2.to_string_lossy(),
                    shm_ring,
                )
                .shm_tuning(tuning);
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

        let mgmt_socket = running.mgmt_socket_path().ok_or_else(|| {
            io::Error::other("gateway has no management socket path for SHM provisioning")
        })?;

        Ok(GatewayShmTransport {
            name,
            mgmt_socket,
            app_id: app_id.to_string(),
            ring_capacity: shm_ring as u64,
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

        // The decrypt endpoint must be listening before encrypt performs its
        // initial TLS handshake; otherwise the retry backoff can consume an
        // entire short measurement window.
        let decrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Decrypt,
                self.ring_capacity,
            )
            .map_err(io::Error::other)?;

        let encrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Encrypt,
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

    fn pingpong_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let mgmt = MgmtClient::new(&self.mgmt_socket);

        // Same provisioning order as `loopback_pair`: the decrypt endpoint must
        // exist before encrypt performs its initial TLS handshake.
        let decrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Decrypt,
                self.ring_capacity,
            )
            .map_err(io::Error::other)?;

        let encrypt_ep = mgmt
            .create_shm(
                &self.app_id,
                TrafficClass::Normal,
                Direction::Encrypt,
                self.ring_capacity,
            )
            .map_err(io::Error::other)?;

        // The client drives the loop: send on encrypt, read the echo off
        // decrypt. The gateway relays between the two, so the server end is a
        // no-op stub.
        let client = Box::new(ShmDuplexClient {
            tx: encrypt_ep.client,
            rx: decrypt_ep.client,
            traffic_id: 1,
            timeout: RECV_POLL_TIMEOUT,
        });
        let server = Box::new(ShmNullServer);

        Ok((client, server))
    }
}
