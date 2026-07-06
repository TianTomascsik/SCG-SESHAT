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
use std::time::{Duration, Instant};

use scg_client::ScgClient;

use super::{DataSink, DataSource, DuplexEnd, RecvOutcome, Transport, RECV_POLL_TIMEOUT};
use crate::gateway::grpc_client::{Direction, MgmtClient, TrafficClass};
use crate::gateway::{self, RunningPath, SecuritySpec, Topology};

/// How long to wait for each gateway process to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Default ring capacity per direction (1 MiB).
const DEFAULT_RING_CAPACITY: u64 = 1024 * 1024;

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
            format!("unsupported SHM traffic class '{other}'"),
        )),
    }
}

/// Sender side wrapping an `ScgClient` connected to the encrypt SHM endpoint.
struct ShmSink {
    client: ScgClient,
    traffic_id: u32,
    /// Byte count from the last [`DataSink::reserve`], consumed by the next
    /// [`DataSink::commit_reserved`] (the zero-copy build-in-ring path).
    pending_len: Option<usize>,
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

    fn reserve(&mut self, len: usize) -> Option<&mut [u8]> {
        // Slot-ring only: hand the workload generator a writable view straight
        // into the shared-memory ring slot so it builds the message in place,
        // with no staging buffer and no buffer→ring copy. `None` on a full ring,
        // the byte-stream ring, or too-large a message → caller falls back to
        // `send_msg`.
        match self.client.reserve_raw() {
            Ok(Some((ptr, cap))) if len <= cap => {
                self.pending_len = Some(len);
                // SAFETY: `ptr` points at `cap` writable bytes of the reserved
                // (not-yet-published) ring slot, valid until the matching
                // `commit_raw` (single-producer discipline). We expose `len`
                // (≤ cap) of them, tied to `&mut self`, so the caller cannot hold
                // the slice across `commit_reserved`.
                Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
            }
            _ => None,
        }
    }

    fn commit_reserved(&mut self) -> io::Result<()> {
        let len = self
            .pending_len
            .take()
            .ok_or_else(|| io::Error::other("SHM commit_reserved without a reserve"))?;
        match self.client.commit_raw(self.traffic_id, len) {
            Ok(true) => Ok(()),
            // The slot was free at reserve and a single producer cannot fill it
            // in between, so this is unreachable in practice; treat defensively
            // as backpressure so the caller retries rather than losing the frame.
            Ok(false) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Err(e) => Err(io::Error::other(format!("SHM commit: {e}"))),
        }
    }

    fn supports_inplace(&self) -> bool {
        self.client.supports_inplace()
    }

    fn commit_batched(&mut self) -> io::Result<bool> {
        let len = self
            .pending_len
            .take()
            .ok_or_else(|| io::Error::other("SHM commit_batched without a reserve"))?;
        self.client
            .commit_raw_nosignal(self.traffic_id, len)
            .map_err(|e| io::Error::other(format!("SHM commit: {e}")))
    }

    fn flush_batch(&mut self) -> io::Result<()> {
        self.client
            .flush_c2g()
            .map_err(|e| io::Error::other(format!("SHM flush: {e}")))
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
        let mut count = match self
            .client
            .recv_into(&mut buf[..stride], Some(self.timeout))
        {
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

    fn supports_inplace_recv(&self) -> bool {
        self.client.supports_inplace_recv()
    }

    fn recv_inplace(
        &mut self,
        max: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> io::Result<crate::transport::BatchOutcome> {
        use crate::transport::BatchOutcome;
        // Block once for the first message; then drain whatever else is queued,
        // handing each payload to `f` straight from the ring (no copy).
        match self.client.wait_readable(Some(self.timeout)) {
            Ok(true) => {}
            Ok(false) => return Ok(BatchOutcome::Timeout),
            Err(e) => {
                let msg = format!("{e}");
                return if msg.contains("closed") || msg.contains("EOF") {
                    Ok(BatchOutcome::Closed)
                } else {
                    Err(io::Error::other(format!("SHM recv: {e}")))
                };
            }
        }
        let mut count = 0;
        while count < max {
            // The peeked payload borrows the client; confine that borrow to this
            // block so `advance_recv` can re-borrow after `f` runs.
            let got = match self.client.peek_payload() {
                Some((_tid, payload)) => {
                    f(payload);
                    true
                }
                None => false,
            };
            if !got {
                break;
            }
            self.client.advance_recv();
            count += 1;
        }
        if count == 0 {
            Ok(BatchOutcome::Timeout)
        } else {
            Ok(BatchOutcome::Messages(count))
        }
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
        // Wait for the (typically shallow) ring to accept the single in-flight
        // message, yielding rather than spinning so a busy gateway can drain.
        // Bound the wait by `timeout` (the same window `recv_msg` polls on) so a
        // gateway that has stopped draining the encrypt ring — e.g. a
        // mis-provisioned upstream whose handshake never completes, so nothing is
        // ever relayed — surfaces as `WouldBlock` instead of wedging the worker
        // forever. Mirrors `ShmSink::send_msg`; the ping-pong client loop then
        // re-observes the phase flag and exits cleanly (the run records zero
        // metrics and is discarded as a skip).
        let deadline = Instant::now() + self.timeout;
        loop {
            match self
                .tx
                .try_send(self.traffic_id, buf)
                .map_err(|e| io::Error::other(format!("SHM send: {e}")))?
            {
                true => return Ok(()),
                false => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    std::thread::yield_now();
                }
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
    /// Management socket of the encrypt gateway (also the single-gateway socket;
    /// used by the hot-reload accessor).
    pub(crate) mgmt_socket: PathBuf,
    /// Management socket of the decrypt gateway. Equals `mgmt_socket` for
    /// single-gateway; distinct in scg-scg where encrypt (scg-a) and decrypt
    /// (scg-b) are separate processes and each direction must be provisioned on
    /// its own gateway's socket.
    decrypt_mgmt_socket: PathBuf,
    app_id: String,
    ring_capacity: u64,
    running: Option<RunningPath>,
}

impl GatewayShmTransport {
    /// Start a gateway configured for SHM endpoints and provision the management
    /// API.
    #[allow(clippy::too_many_arguments)]
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
        Self::start_with_classes(
            name,
            spec,
            topology,
            binary,
            work_dir,
            gateway_cores,
            app_id,
            ring_capacity,
            tuning,
            &[TrafficClass::Normal],
        )
    }

    /// Start a gateway with SHM endpoint templates for the requested traffic
    /// classes.
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_classes(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
        ring_capacity: u64,
        tuning: &crate::gateway::config::ShmTuning,
        classes: &[TrafficClass],
    ) -> io::Result<Self> {
        use crate::gateway::config::{ApiConfig, GatewayConfig};
        use crate::gateway::NamedGateway;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SHM_MGMT_ID: AtomicU64 = AtomicU64::new(0);

        std::fs::create_dir_all(work_dir)?;

        // SAFETY: `libc::getuid()` is an always-successful POSIX syscall that takes no
        // arguments, never fails, touches no memory, and cannot trap; it simply returns
        // the caller's real user ID as a `uid_t`. There is no precondition to uphold.
        let uid = unsafe { libc::getuid() };
        let shm_ring = if ring_capacity == 0 {
            DEFAULT_RING_CAPACITY as usize
        } else {
            ring_capacity as usize
        };
        let classes = normalize_classes(classes);

        // Build SHM rules: listen_proto="shm" with app_id and allowed_uids.
        // apply_encrypt/apply_decrypt reset listen_proto, so set it after.
        let upstream_addr = format!("127.0.0.1:{}", gateway::reserve_local_port()?);
        let rules = build_rules_for_classes(spec, app_id, uid, &upstream_addr, &classes);

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

        // Encrypt endpoints are provisioned via `sock` (the encrypt gateway),
        // decrypt endpoints via `decrypt_sock`. Single-gateway keeps both rules
        // in one process so the sockets coincide; scg-scg splits encrypt onto
        // scg-a (`sock`) and decrypt onto scg-b (`sock2`), so each direction must
        // be provisioned on its own gateway's socket or it fails `not_found`.
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
                let id2 = SHM_MGMT_ID.fetch_add(1, Ordering::Relaxed);
                let runtime_dir2 = gateway::short_runtime_dir("ss", id2)?;
                let sock2 = runtime_dir2.join("mgmt.sock");
                let api2 = ApiConfig::new(
                    &sock2.to_string_lossy(),
                    &runtime_dir2.to_string_lossy(),
                    shm_ring,
                )
                .shm_tuning(tuning);
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

        Ok(GatewayShmTransport {
            name,
            mgmt_socket: sock,
            decrypt_mgmt_socket: decrypt_sock,
            app_id: app_id.to_string(),
            ring_capacity: shm_ring as u64,
            running: Some(running),
        })
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

        // The decrypt endpoint must be listening before encrypt performs its
        // initial TLS handshake; otherwise the retry backoff can consume an
        // entire short measurement window.
        let decrypt_ep = decrypt_mgmt
            .create_shm(&self.app_id, class, Direction::Decrypt, self.ring_capacity)
            .map_err(io::Error::other)?;

        let encrypt_ep = encrypt_mgmt
            .create_shm(&self.app_id, class, Direction::Encrypt, self.ring_capacity)
            .map_err(io::Error::other)?;

        let sink = Box::new(ShmSink {
            client: encrypt_ep.client,
            traffic_id: 1,
            pending_len: None,
        });
        let source = Box::new(ShmSource {
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

        // Same provisioning order as `loopback_pair`: the decrypt endpoint must
        // exist before encrypt performs its initial TLS handshake.
        let decrypt_ep = decrypt_mgmt
            .create_shm(&self.app_id, class, Direction::Decrypt, self.ring_capacity)
            .map_err(io::Error::other)?;

        let encrypt_ep = encrypt_mgmt
            .create_shm(&self.app_id, class, Direction::Encrypt, self.ring_capacity)
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

fn build_rules_for_classes(
    spec: &SecuritySpec,
    app_id: &str,
    uid: u32,
    upstream_addr: &str,
    classes: &[TrafficClass],
) -> Vec<crate::gateway::config::RuleConfig> {
    use crate::gateway::config::RuleConfig;

    let mut rules = Vec::with_capacity(classes.len() * 2);
    for class in classes {
        let label = class_label(*class);
        let encrypt = spec
            .apply_encrypt(
                RuleConfig::new(
                    &format!("seshat-encrypt-{label}"),
                    "encrypt",
                    "unused",
                    upstream_addr,
                )
                .app_id(app_id)
                .traffic_class(label)
                .allowed_uid(uid),
            )
            .traffic_class(label)
            .listen_proto("shm");
        let decrypt = spec
            .apply_decrypt(
                RuleConfig::new(
                    &format!("seshat-decrypt-{label}"),
                    "decrypt",
                    "unused",
                    upstream_addr,
                )
                .app_id(app_id)
                .traffic_class(label)
                .allowed_uid(uid),
            )
            .traffic_class(label)
            .listen_proto("shm");
        rules.push(encrypt);
        rules.push(decrypt);
    }
    rules
}

impl Transport for GatewayShmTransport {
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
    fn shm_rules_are_created_per_traffic_class() {
        let rules = build_rules_for_classes(
            &spec(),
            "app",
            1000,
            "127.0.0.1:9000",
            &[TrafficClass::Normal, TrafficClass::Safety],
        );

        assert_eq!(rules.len(), 4);
        assert!(rules.iter().any(|r| {
            r.name == "seshat-encrypt-normal"
                && r.direction == "encrypt"
                && r.listen_proto == "shm"
                && r.traffic_class == "normal"
        }));
        assert!(rules.iter().any(|r| {
            r.name == "seshat-decrypt-safety"
                && r.direction == "decrypt"
                && r.listen_proto == "shm"
                && r.traffic_class == "safety"
        }));
    }

    /// Regression + feature test: in scg-scg the encrypt endpoint was provisioned
    /// on the decrypt-only process (single shared mgmt socket) and failed gRPC
    /// `not_found`. With per-direction socket routing both endpoints provision
    /// across the two gateways. Needs a working gateway binary; skips otherwise.
    #[test]
    fn shm_scg_to_scg_provisions_both_endpoints() {
        let _guard = gateway::gateway_test_guard();
        let work_dir =
            std::env::temp_dir().join(format!("seshat-shm-scgscg-{}", std::process::id()));
        let Some(binary) = gateway::locate_working_binary(&work_dir) else {
            eprintln!("skip: no working gateway binary");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };

        let transport = GatewayShmTransport::start(
            "shm",
            &spec(),
            Topology::ScgToScg,
            &binary,
            &work_dir,
            &[],
            "scgscg-shm-app",
            0,
            &crate::gateway::config::ShmTuning::default(),
        )
        .expect("shm scg-scg gateway pair starts");
        assert_eq!(transport.pids().len(), 2, "scg-scg spawns two gateways");

        let pair = transport.loopback_pair_for_class(256, TrafficClass::Normal);
        assert!(
            pair.is_ok(),
            "scg-scg must provision both encrypt and decrypt endpoints: {:?}",
            pair.err()
        );

        transport.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&work_dir);
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
}
