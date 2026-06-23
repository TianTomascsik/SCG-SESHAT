//! TPROXY transparent transport (WP2.7).
//!
//! Benchmarks the gateway's transparent proxy mode (`transparent: true` in the
//! rule config), where the gateway intercepts traffic via iptables TPROXY without
//! the client knowing a proxy exists. The sender connects to the receiver's
//! address directly; iptables redirects the traffic to the gateway, which
//! forwards it to the original destination.
//!
//! **Requires `CAP_NET_ADMIN`** for iptables/ip-rule manipulation. When the
//! capability is absent, the transport probes and skips with a clear message.
#![allow(dead_code)]

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::{tcp, DataSink, DataSource, DuplexEnd, Transport, RECV_POLL_TIMEOUT};
use crate::gateway::config::{GatewayConfig, RuleConfig};
use crate::gateway::process::GatewayProcess;
use crate::gateway::reserve_local_port;

/// The fwmark used by TPROXY iptables rules.
const TPROXY_MARK: u32 = 0x1;
/// Routing table for marked packets.
const TPROXY_TABLE: u32 = 100;
/// Timeout for the gateway readiness probe.
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for a sender connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Check if we have CAP_NET_ADMIN by attempting to set IP_TRANSPARENT on a
/// dummy socket.
pub fn has_cap_net_admin() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return false;
        }
        let one: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd,
            libc::SOL_IP,
            19, // IP_TRANSPARENT
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::close(fd);
        rc == 0
    }
}

/// TPROXY iptables/routing state. Cleaned up on drop.
struct TproxyRules {
    listen_port: u16,
    gateway_port: u16,
}

impl TproxyRules {
    /// Set up iptables TPROXY + ip rule + ip route for intercepting traffic to
    /// `listen_port` and redirecting it to `gateway_port`.
    fn setup(listen_port: u16, gateway_port: u16) -> io::Result<Self> {
        // ip rule add fwmark 1 lookup 100
        run_cmd("ip", &["rule", "add", "fwmark", "1", "lookup", "100"])?;

        // ip route add local 0/0 dev lo table 100
        run_cmd(
            "ip",
            &["route", "add", "local", "0/0", "dev", "lo", "table", "100"],
        )?;

        // iptables -t mangle -A PREROUTING -p tcp --dport <listen_port>
        //   -j TPROXY --on-port <gateway_port> --tproxy-mark 0x1/0x1
        run_cmd(
            "iptables",
            &[
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                &listen_port.to_string(),
                "-j",
                "TPROXY",
                "--on-port",
                &gateway_port.to_string(),
                "--tproxy-mark",
                "0x1/0x1",
            ],
        )?;

        Ok(TproxyRules {
            listen_port,
            gateway_port,
        })
    }

    /// Remove the iptables/routing rules.
    fn teardown(&self) {
        let _ = run_cmd(
            "iptables",
            &[
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                &self.listen_port.to_string(),
                "-j",
                "TPROXY",
                "--on-port",
                &self.gateway_port.to_string(),
                "--tproxy-mark",
                "0x1/0x1",
            ],
        );
        let _ = run_cmd(
            "ip",
            &[
                "route", "del", "local", "0/0", "dev", "lo", "table", "100",
            ],
        );
        let _ = run_cmd("ip", &["rule", "del", "fwmark", "1", "lookup", "100"]);
    }
}

impl Drop for TproxyRules {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn run_cmd(program: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "{program} {}: {stderr}",
            args.join(" ")
        )));
    }
    Ok(())
}

/// A benchmark transport that exercises the gateway's TPROXY transparent mode.
///
/// The sender connects to a "virtual" target address; iptables redirects the
/// traffic to the gateway which proxies it transparently to the real backend.
pub struct TproxyTransport {
    name: &'static str,
    /// The address the sender connects to (intercepted by TPROXY).
    target_addr: SocketAddr,
    /// The backend listener (real destination).
    backend: TcpListener,
    /// The gateway process.
    gateway: Option<GatewayProcess>,
    /// TPROXY iptables rules (cleaned up on drop).
    rules: Option<TproxyRules>,
}

impl TproxyTransport {
    /// Start a TPROXY transparent gateway path.
    ///
    /// Returns `Err` with `ErrorKind::PermissionDenied` if `CAP_NET_ADMIN` is
    /// missing.
    pub fn start(
        name: &'static str,
        binary: &Path,
        work_dir: &Path,
    ) -> io::Result<Self> {
        if !has_cap_net_admin() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TPROXY requires CAP_NET_ADMIN — skipping",
            ));
        }

        std::fs::create_dir_all(work_dir)?;

        // The "target" address the sender thinks it's connecting to.
        let target_port = reserve_local_port()?;
        let target_addr: SocketAddr = format!("127.0.0.1:{target_port}").parse().unwrap();

        // The gateway's listen port (where TPROXY redirects to).
        let gw_port = reserve_local_port()?;

        // The real backend.
        let backend_port = reserve_local_port()?;
        let backend_addr = format!("127.0.0.1:{backend_port}");
        let backend = TcpListener::bind(&backend_addr)?;
        backend.set_nonblocking(true)?;

        // Build gateway config: one transparent encrypt rule.
        let rule = RuleConfig::new(
            "tproxy-encrypt",
            "encrypt",
            &format!("127.0.0.1:{gw_port}"),
            "auto", // TPROXY recovers original destination
        )
        .security("routing")
        .param("transparent", true);

        let config = GatewayConfig::new(vec![rule])
            .log_level("info")
            .allow_all();

        // Set up TPROXY iptables rules.
        let rules = TproxyRules::setup(target_port, gw_port)?;

        // Start the gateway.
        let mut gateway =
            GatewayProcess::spawn(binary, &config, work_dir, "tproxy", "info")?;
        gateway.wait_ready(READY_TIMEOUT)?;

        Ok(TproxyTransport {
            name,
            target_addr,
            backend,
            gateway: Some(gateway),
            rules: Some(rules),
        })
    }

    /// OS pid of the gateway process.
    pub fn pids(&self) -> Vec<i32> {
        self.gateway.as_ref().map(|g| vec![g.pid()]).unwrap_or_default()
    }

    /// Captured gateway log file.
    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.gateway
            .as_ref()
            .map(|g| vec![g.log_path().to_path_buf()])
            .unwrap_or_default()
    }

    /// Gracefully stop the gateway and remove iptables rules.
    pub fn shutdown(mut self) -> io::Result<()> {
        // Drop rules first (cleanup iptables).
        self.rules.take();
        if let Some(gw) = self.gateway.take() {
            gw.shutdown()?;
        }
        Ok(())
    }

    /// Accept a forwarded connection from the gateway.
    fn accept_forwarded(&self) -> io::Result<TcpStream> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TPROXY gateway did not forward connection to backend",
                ));
            }
            match self.backend.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    return Ok(stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Transport for TproxyTransport {
    fn name(&self) -> &'static str {
        self.name
    }

    fn loopback_pair(
        &self,
        message_bytes: u32,
    ) -> io::Result<(Box<dyn DataSink>, Box<dyn DataSource>)> {
        // The sender connects to the target address (intercepted by TPROXY).
        let client = TcpStream::connect_timeout(&self.target_addr, CONNECT_TIMEOUT)?;
        client.set_nodelay(true)?;

        // The gateway transparently forwards to our backend.
        let server = self.accept_forwarded()?;
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
        let client = TcpStream::connect_timeout(&self.target_addr, CONNECT_TIMEOUT)?;
        client.set_nodelay(true)?;
        client.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        let server = self.accept_forwarded()?;
        server.set_nodelay(true)?;
        server.set_read_timeout(Some(RECV_POLL_TIMEOUT))?;

        Ok((
            tcp::duplex_from_stream(client, message_bytes),
            tcp::duplex_from_stream(server, message_bytes),
        ))
    }
}
