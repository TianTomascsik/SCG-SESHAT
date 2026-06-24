//! Gateway-backed TCP transport (Phase 2): drives benchmark traffic through one
//! or two real `gateway` processes instead of a local loopback socket.
//!
//! Wire model (see [`crate::gateway`]): the SESHAT sender speaks **plaintext
//! TCP** to the gateway's encrypt-rule ingress; the gateway performs any
//! TLS/kTLS/DTLS internally between its encrypt and decrypt rules; the decrypt
//! rule forwards **plaintext TCP** to our backend listener, which becomes the
//! SESHAT receiver. So from the harness's point of view this is still framed
//! TCP — only the path in between is secured by the device under test.
//!
//! Lifecycle ordering matters:
//!   1. Reserve the backend port and build the gateway config pointing the
//!      decrypt rule's upstream at it.
//!   2. Bind the backend listener *before* starting the gateway, mirroring the
//!      validated echo round-trip: readiness probes that get forwarded down the
//!      path then arrive as short-lived connections that close without sending
//!      any data, which [`GatewayTcpTransport::accept_forwarded`] skips.
//!   3. Start the gateway(s) and wait until they accept connections.
//!
//! [`GatewayTcpTransport::loopback_pair`] (named for the trait, though nothing
//! is loopback here) connects one sender to the ingress and accepts the matching
//! forwarded connection as the receiver, skipping any leftover probe connection
//! that the gateway already closed. Calls are sequential in the run engine, so
//! connect-then-accept pairs the two halves deterministically.
#![allow(dead_code)] // consumed by the run command wiring (WP2.5).

use std::io;
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use super::{tcp, udp, DataSink, DataSource, DuplexEnd, Transport, RECV_POLL_TIMEOUT};
use crate::gateway::{
    add_management_uds_template, build_path, reserve_local_port, start_path, RunningPath,
    SecuritySpec, Topology,
};

/// How long to wait for each gateway process to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a single sender connect may take through the gateway.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the gateway to forward a connection to the backend.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll cadence while waiting on a non-blocking accept.
const ACCEPT_POLL: Duration = Duration::from_millis(5);
/// How long to peek a freshly accepted connection to catch a late closed
/// readiness probe. Startup drains the normal probe connections before a run,
/// so this is only a short safety net rather than a 200 ms cost per benchmark
/// connection.
const LIVENESS_PROBE: Duration = Duration::from_millis(10);
/// Maximum wait while draining the forwarded TCP connections created by the
/// gateway readiness probes. No SESHAT client can connect before `start`
/// returns, so every connection in this window is safe to discard.
const READINESS_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// A benchmark transport whose data plane traverses real gateway process(es).
pub struct GatewayTcpTransport {
    name: &'static str,
    ingress_addr: String,
    backend: TcpListener,
    running: Option<RunningPath>,
}

impl GatewayTcpTransport {
    /// Start the secured path described by `spec`/`topology` using `binary`. The
    /// backend listener is bound before the gateway starts so the path is
    /// reachable end-to-end the instant the gateway is ready. The gateway is
    /// best-effort pinned to `gateway_cores` (when non-empty).
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
    ) -> io::Result<Self> {
        Self::start_inner(name, spec, topology, binary, work_dir, gateway_cores, None)
    }

    /// Start a TCP data path with the management API and a UDS endpoint
    /// template enabled. This is used by hot-reload scenarios that must
    /// exercise a real add/remove endpoint control-plane action.
    pub fn start_with_management_endpoint(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        app_id: &str,
    ) -> io::Result<Self> {
        Self::start_inner(
            name,
            spec,
            topology,
            binary,
            work_dir,
            gateway_cores,
            Some(app_id),
        )
    }

    fn start_inner(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        management_endpoint_app_id: Option<&str>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;

        // Reserve the backend port, point the decrypt rule at it, then bind the
        // real listener before launching the gateway.
        let backend_addr = format!("127.0.0.1:{}", reserve_local_port()?);
        let mut plan = build_path(spec, topology, &backend_addr)?;
        if let Some(app_id) = management_endpoint_app_id {
            add_management_uds_template(&mut plan, app_id)?;
        }
        let ingress_addr = plan.ingress_addr.clone();

        let backend = TcpListener::bind(&backend_addr)?;
        backend.set_nonblocking(true)?;

        let running = start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;
        drain_readiness_probes(&backend)?;

        Ok(GatewayTcpTransport {
            name,
            ingress_addr,
            backend,
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

    /// Captured gateway log files, for post-run effective-protocol scanning.
    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.running
            .as_ref()
            .map(RunningPath::log_paths)
            .unwrap_or_default()
    }

    /// The address senders connect to (the encrypt-rule ingress).
    pub fn ingress_addr(&self) -> &str {
        &self.ingress_addr
    }

    /// Gracefully stop the gateway process(es).
    pub fn shutdown(mut self) -> io::Result<()> {
        if let Some(running) = self.running.take() {
            running.shutdown()?;
        }
        Ok(())
    }

    /// Accept the next *live* forwarded connection within [`ACCEPT_TIMEOUT`],
    /// skipping connections the gateway already closed (leftover readiness
    /// probes forwarded down the path).
    fn accept_forwarded(&self) -> io::Result<TcpStream> {
        let deadline = Instant::now() + ACCEPT_TIMEOUT;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "gateway did not forward a live connection to the backend in time",
                ));
            }
            match self.backend.accept() {
                Ok((stream, _peer)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(LIVENESS_PROBE))?;
                    let mut probe = [0u8; 1];
                    match stream.peek(&mut probe) {
                        // EOF: a closed readiness-probe connection — skip it.
                        Ok(0) => continue,
                        // Already carrying data, or open but idle (the real
                        // sender connection, which has not sent yet): keep it.
                        Ok(_) => return Ok(stream),
                        Err(e)
                            if e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::TimedOut =>
                        {
                            return Ok(stream)
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Discard forwarded connections created solely by `start_path` readiness
/// probing.  Previously `accept_forwarded` waited 200 ms on *every* new
/// connection to distinguish these from a real client. At 256+ connections
/// that serialized setup for tens of seconds before traffic could start.
fn drain_readiness_probes(backend: &TcpListener) -> io::Result<()> {
    let deadline = Instant::now() + READINESS_DRAIN_TIMEOUT;
    loop {
        match backend.accept() {
            Ok((stream, _peer)) => drop(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Ok(());
                }
                thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(e),
        }
    }
}

impl Transport for GatewayTcpTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let addr = self
            .ingress_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("gateway ingress address did not resolve"))?;

        // Connect the sender first; the gateway then forwards a connection to
        // our backend listener, which we accept as the matching receiver.
        let client = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        client.set_nodelay(true)?;

        let server = self.accept_forwarded()?;
        server.set_nonblocking(false)?;
        server.set_nodelay(true)?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        let sink = tcp::sink_from_stream(client);
        let source = tcp::source_from_stream(server, message_bytes);
        Ok((sink, source))
    }

    fn pingpong_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DuplexEnd>, Box<dyn DuplexEnd>)> {
        let addr = self
            .ingress_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("gateway ingress address did not resolve"))?;

        // Same connect-then-accept handshake as `loopback_pair`, but both ends
        // are kept full-duplex: the TCP connection is bidirectional and the
        // gateway relays each direction, so the client's request reaches the
        // backend and the backend's echo flows back to the client through the
        // secured path.
        let client = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        client.set_nodelay(true)?;
        client.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        let server = self.accept_forwarded()?;
        server.set_nonblocking(false)?;
        server.set_nodelay(true)?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        Ok((
            tcp::duplex_from_stream(client, message_bytes),
            tcp::duplex_from_stream(server, message_bytes),
        ))
    }
}

/// A benchmark transport whose data plane traverses real gateway process(es)
/// over **UDP datagrams** (the DTLS path, F-05 `udp`).
///
/// The SESHAT sender emits plaintext UDP datagrams to the encrypt-rule ingress;
/// the gateway runs DTLS between its encrypt and decrypt rules; the decrypt rule
/// forwards plaintext datagrams to our pre-bound backend socket, which becomes
/// the receiver. One datagram carries exactly one SESHAT message, so datagram
/// boundaries are preserved end-to-end and no re-framing is needed.
///
/// Because the decrypt rule converges every flow onto a single upstream address,
/// this transport models a **single logical flow**; multi-connection UDP through
/// one rule pair is out of scope (the run wiring restricts it to one connection).
pub struct GatewayUdpTransport {
    name: &'static str,
    ingress_addr: String,
    backend: UdpSocket,
    running: Option<RunningPath>,
}

impl GatewayUdpTransport {
    /// Start the secured UDP path described by `spec`/`topology` using `binary`.
    /// The backend datagram socket is bound before the gateway starts so the
    /// path is reachable the instant the gateway is ready. The gateway is
    /// best-effort pinned to `gateway_cores` (when non-empty).
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
    ) -> io::Result<Self> {
        std::fs::create_dir_all(work_dir)?;

        let backend_addr = format!("127.0.0.1:{}", reserve_local_port()?);
        let plan = build_path(spec, topology, &backend_addr)?;
        let ingress_addr = plan.ingress_addr.clone();

        // Bind the backend datagram socket before launching the gateway so no
        // forwarded datagram is lost for want of a bound receiver.
        let backend = UdpSocket::bind(&backend_addr)?;

        let running = start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

        Ok(GatewayUdpTransport {
            name,
            ingress_addr,
            backend,
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

    /// Captured gateway log files, for post-run effective-protocol scanning.
    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.running
            .as_ref()
            .map(RunningPath::log_paths)
            .unwrap_or_default()
    }

    /// The address senders send datagrams to (the encrypt-rule ingress).
    pub fn ingress_addr(&self) -> &str {
        &self.ingress_addr
    }

    /// Gracefully stop the gateway process(es).
    pub fn shutdown(mut self) -> io::Result<()> {
        if let Some(running) = self.running.take() {
            running.shutdown()?;
        }
        Ok(())
    }
}

impl Transport for GatewayUdpTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn loopback_pair(
        &self,
        _message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        let target = self
            .ingress_addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("gateway ingress address did not resolve"))?;

        // The sender connects an ephemeral socket to the ingress; the receiver
        // shares the pre-bound backend socket (single-flow path).
        let sink = udp::sink_connected_to(target)?;
        let src_sock = self.backend.try_clone()?;
        src_sock.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;
        let source = udp::source_from_socket(src_sock);
        Ok((sink, source))
    }
}

/// A started gateway data-plane transport: TCP (routing / TLS / mTLS /
/// integrity-only), UDP (DTLS), UDS (gRPC-provisioned), SHM
/// (gRPC-provisioned ring buffer), or TPROXY (transparent interception).
/// Wraps the concrete transports so the run wiring can sample PIDs and shut
/// down uniformly while still handing the engine a `&dyn Transport`.
pub enum GatewayDut {
    Tcp(GatewayTcpTransport),
    Udp(GatewayUdpTransport),
    Uds(super::uds::GatewayUdsTransport),
    Shm(super::shm::GatewayShmTransport),
    Tproxy(super::tproxy::TproxyTransport),
}

impl GatewayDut {
    /// Borrow the inner transport for the run engine.
    pub fn as_transport(&self) -> &dyn Transport {
        match self {
            Self::Tcp(t) => t,
            Self::Udp(t) => t,
            Self::Uds(t) => t,
            Self::Shm(t) => t,
            Self::Tproxy(t) => t,
        }
    }

    /// OS pids of the gateway process(es), for `/proc/<pid>` system metrics.
    pub fn pids(&self) -> Vec<i32> {
        match self {
            Self::Tcp(t) => t.pids(),
            Self::Udp(t) => t.pids(),
            Self::Uds(t) => t.pids(),
            Self::Shm(t) => t.pids(),
            Self::Tproxy(t) => t.pids(),
        }
    }

    /// Captured gateway log files, for post-run effective-protocol scanning.
    pub fn log_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Tcp(t) => t.log_paths(),
            Self::Udp(t) => t.log_paths(),
            Self::Uds(t) => t.log_paths(),
            Self::Shm(t) => t.log_paths(),
            Self::Tproxy(t) => t.log_paths(),
        }
    }

    /// Gracefully stop the gateway process(es).
    pub fn shutdown(self) -> io::Result<()> {
        match self {
            Self::Tcp(t) => t.shutdown(),
            Self::Udp(t) => t.shutdown(),
            Self::Uds(t) => t.shutdown(),
            Self::Shm(t) => t.shutdown(),
            Self::Tproxy(t) => t.shutdown(),
        }
    }

    /// Config paths of the gateway process(es) (for hot-reload injection).
    pub fn config_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Tcp(t) => t
                .running
                .as_ref()
                .map(|r| r.config_paths())
                .unwrap_or_default(),
            Self::Udp(t) => t
                .running
                .as_ref()
                .map(|r| r.config_paths())
                .unwrap_or_default(),
            Self::Uds(_) | Self::Shm(_) | Self::Tproxy(_) => Vec::new(),
        }
    }

    /// Borrow the first gateway process (for SIGHUP/reload).
    pub fn first_process(&self) -> Option<&crate::gateway::process::GatewayProcess> {
        match self {
            Self::Tcp(t) => t.running.as_ref().and_then(|r| r.first_process()),
            Self::Udp(t) => t.running.as_ref().and_then(|r| r.first_process()),
            Self::Uds(_) | Self::Shm(_) | Self::Tproxy(_) => None,
        }
    }

    /// Management socket path for gRPC operations (hot-reload add/remove).
    pub fn mgmt_socket_path(&self) -> Option<PathBuf> {
        match self {
            Self::Tcp(t) => t.running.as_ref().and_then(|r| r.mgmt_socket_path()),
            Self::Udp(t) => t.running.as_ref().and_then(|r| r.mgmt_socket_path()),
            Self::Uds(t) => Some(t.mgmt_socket.clone()),
            Self::Shm(t) => Some(t.mgmt_socket.clone()),
            Self::Tproxy(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Interface, Pattern, Sender};
    use crate::gateway::locate_working_binary;
    use crate::run::engine::{run_scenario, RunParams};

    fn periodic_sender() -> Sender {
        Sender {
            interface: Interface::Tcp,
            target_addr: "unused".into(),
            pattern: Pattern::Periodic,
            rate_limit_mbps: None,
            interval_us: Some(50),
            burst_count: None,
            burst_pause_us: None,
            ramp_start_mbps: None,
            ramp_step_mbps: None,
            ramp_step_interval_secs: None,
        }
    }

    fn quick_params() -> RunParams {
        RunParams {
            message_bytes: 256,
            connections: 1,
            runs: 1,
            warmup: Duration::from_millis(80),
            measure: Duration::from_millis(250),
            cooldown: Duration::from_millis(40),
            remove_outliers: true,
            sender_cores: vec![],
            receiver_cores: vec![],
            sender: periodic_sender(),
            mode: crate::run::engine::RunMode::Throughput,
        }
    }

    /// Run the real engine through a routing gateway and assert metrics flow.
    fn drive_engine(topology: Topology) {
        let _guard = crate::gateway::gateway_test_guard();
        let work_dir = std::env::temp_dir().join(format!(
            "seshat-gw-xport-{}-{topology:?}",
            std::process::id()
        ));
        let Some(binary) = locate_working_binary(&work_dir) else {
            eprintln!("skip: no gateway binary supports the routing provider");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };

        let spec = SecuritySpec::routing_tcp();
        let transport =
            GatewayTcpTransport::start("tcp", &spec, topology, &binary, &work_dir, &[]).unwrap();
        assert!(!transport.pids().is_empty(), "gateway pids should be known");

        let stats = run_scenario(&transport, &quick_params(), |_, _| {}).unwrap();

        assert_eq!(stats.runs.len(), 1);
        assert!(
            stats.runs.iter().all(|r| r.messages > 0),
            "no messages flowed through the gateway"
        );
        assert_eq!(stats.total_lost, 0, "routing TCP path must be lossless");
        assert!(stats.throughput_gbps.mean > 0.0);

        transport.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    #[test]
    fn engine_runs_through_single_gateway() {
        drive_engine(Topology::SingleGateway);
    }

    #[test]
    fn engine_runs_through_scg_to_scg() {
        drive_engine(Topology::ScgToScg);
    }

    /// Run the real engine through a DTLS gateway over UDP and assert datagrams
    /// flow. UDP may drop a few datagrams under load, so this only requires
    /// forward progress (not zero loss like the TCP path).
    fn drive_udp_engine(topology: Topology) {
        let _guard = crate::gateway::gateway_test_guard();
        let work_dir =
            std::env::temp_dir().join(format!("seshat-gw-udp-{}-{topology:?}", std::process::id()));
        let Some(binary) = locate_working_binary(&work_dir) else {
            eprintln!("skip: no gateway binary supports the routing provider");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        };
        if !crate::pki::openssl_available() {
            eprintln!("skip: openssl CLI not available for DTLS certificates");
            let _ = std::fs::remove_dir_all(&work_dir);
            return;
        }

        let id = crate::pki::generate_self_signed(&work_dir, 2).unwrap();
        let spec = SecuritySpec::dtls_server("dtls1.2", &id.cert, &id.key);
        let transport =
            GatewayUdpTransport::start("dtls", &spec, topology, &binary, &work_dir, &[]).unwrap();
        assert!(!transport.pids().is_empty(), "gateway pids should be known");

        let stats = run_scenario(&transport, &quick_params(), |_, _| {}).unwrap();

        assert_eq!(stats.runs.len(), 1);
        assert!(
            stats.runs.iter().all(|r| r.messages > 0),
            "no datagrams flowed through the DTLS gateway"
        );
        assert!(stats.throughput_gbps.mean > 0.0);

        transport.shutdown().unwrap();
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    #[test]
    fn engine_runs_through_dtls_single_gateway() {
        drive_udp_engine(Topology::SingleGateway);
    }

    #[test]
    fn engine_runs_through_dtls_scg_to_scg() {
        drive_udp_engine(Topology::ScgToScg);
    }
}
