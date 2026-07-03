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
    // SAFETY: `libc::socket` is called with valid constant domain/type/protocol
    // arguments and its return value is checked (`fd < 0` bails out before any
    // further use). `setsockopt` receives that valid `fd`, a pointer to the live
    // stack `c_int` `one` whose length is passed exactly as `size_of::<c_int>()`,
    // and its result `rc` is the value returned. `libc::close` is called once on
    // the same valid `fd` before returning, so the descriptor is not leaked.
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
    /// Set up the full TPROXY recipe — policy route, the `DIVERT` chain for
    /// established flows, and the new-connection redirect — for intercepting
    /// traffic to `listen_port` and steering it to `gateway_port`.
    fn setup(listen_port: u16, gateway_port: u16) -> io::Result<Self> {
        // Creating the DIVERT chain is best-effort: a leftover from a crashed
        // run means it already exists (the strict commands below re-flush it).
        let _ = run_cmd("iptables", &["-t", "mangle", "-N", "DIVERT"]);
        for cmd in setup_commands(listen_port, gateway_port) {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            run_cmd(args[0], &args[1..])?;
        }
        Ok(TproxyRules {
            listen_port,
            gateway_port,
        })
    }

    /// Remove the iptables/routing rules (reverse order of `setup`).
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
            "iptables",
            &[
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-p",
                "tcp",
                "-m",
                "socket",
                "-j",
                "DIVERT",
            ],
        );
        let _ = run_cmd("iptables", &["-t", "mangle", "-F", "DIVERT"]);
        let _ = run_cmd("iptables", &["-t", "mangle", "-X", "DIVERT"]);
        let _ = run_cmd(
            "ip",
            &["route", "del", "local", "0/0", "dev", "lo", "table", "100"],
        );
        let _ = run_cmd("ip", &["rule", "del", "fwmark", "1", "lookup", "100"]);
    }
}

impl Drop for TproxyRules {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// The ordered list of `(program, args…)` commands that install the TPROXY
/// recipe for `listen_port → gateway_port`. Excludes the best-effort
/// `iptables -N DIVERT` chain creation (handled separately in [`TproxyRules::setup`]).
/// Returned as data so the rule set can be asserted without `CAP_NET_ADMIN`.
fn setup_commands(listen_port: u16, gateway_port: u16) -> Vec<Vec<String>> {
    let s = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<String>>();
    let lp = listen_port.to_string();
    let gp = gateway_port.to_string();
    vec![
        // Policy route: fwmark-1 packets are delivered to the local transparent
        // sockets via a dedicated table.
        s(&["ip", "rule", "add", "fwmark", "1", "lookup", "100"]),
        s(&[
            "ip", "route", "add", "local", "0/0", "dev", "lo", "table", "100",
        ]),
        // DIVERT chain: packets that already belong to an established transparent
        // socket (`-m socket`) are marked and accepted so they reach that socket
        // directly. Without it the redirect intercepts the SYN but the data
        // packets of the established flow are not steered to the gateway socket,
        // so the connection establishes yet zero bytes ever arrive.
        s(&["iptables", "-t", "mangle", "-F", "DIVERT"]),
        s(&[
            "iptables",
            "-t",
            "mangle",
            "-A",
            "DIVERT",
            "-j",
            "MARK",
            "--set-mark",
            "0x1",
        ]),
        s(&["iptables", "-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT"]),
        s(&[
            "iptables",
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "-m",
            "socket",
            "-j",
            "DIVERT",
        ]),
        // New connections to <listen_port> are redirected to the gateway's
        // transparent listener on <gateway_port>.
        s(&[
            "iptables",
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            &lp,
            "-j",
            "TPROXY",
            "--on-port",
            &gp,
            "--tproxy-mark",
            "0x1/0x1",
        ]),
    ]
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
    pub fn start(name: &'static str, binary: &Path, work_dir: &Path) -> io::Result<Self> {
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

        // Build gateway config: one transparent encrypt rule forwarding to the
        // explicit loopback backend.
        //
        // We deliberately do NOT use the `"auto"` original-destination mode here.
        // The gateway *does* recover the TPROXY original destination correctly —
        // `SO_ORIGINAL_DST` (conntrack REDIRECT/DNAT) with a `getsockname`
        // fallback on the `IP_TRANSPARENT` socket for true TPROXY (SCG-TRA #59,
        // and the code-review M10 fix that added the fallback). The blocker is
        // *loopback*, not the gateway: with `"auto"` the gateway would forward to
        // the recovered original destination, which is the same `target_port` the
        // client dialed. On a single host that forward re-enters `PREROUTING` on
        // `lo` and hits the same `-j TPROXY` rule → an interception loop; giving
        // `target_port` a real listener to break the loop makes the `-m socket`
        // DIVERT rule steer the *client's* SYN straight to that listener,
        // bypassing the gateway. Client and gateway-forward are indistinguishable
        // packets on one host (same 5-tuple shape, same uid), so a true `"auto"`
        // path needs distinct client/backend hosts (multi-netns) — out of scope
        // for this loopback throughput transport. The M10 recovery logic itself
        // is covered by the gateway's `recover_transparent_dst` unit tests.
        //
        // Forwarding to the explicit backend still exercises the full TPROXY data
        // path — client → iptables `TPROXY` redirect → gateway `IP_TRANSPARENT`
        // listener → relay → backend — which is what the throughput benchmark
        // measures.
        let rule = RuleConfig::new(
            "tproxy-encrypt",
            "encrypt",
            &format!("127.0.0.1:{gw_port}"),
            &backend_addr,
        )
        .security("routing")
        .param("transparent", true);

        let config = GatewayConfig::new(vec![rule]).log_level("info").allow_all();

        // Set up TPROXY iptables rules.
        let rules = TproxyRules::setup(target_port, gw_port)?;

        // Start the gateway.
        let mut gateway = GatewayProcess::spawn(binary, &config, work_dir, "tproxy", "info")?;
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
        self.gateway
            .as_ref()
            .map(|g| vec![g.pid()])
            .unwrap_or_default()
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

    /// Accept the real forwarded connection from the gateway, skipping dead
    /// readiness-probe leftovers.
    ///
    /// `GatewayProcess::wait_ready` confirms the transparent listener is up by
    /// opening a throwaway TCP connection to it; the gateway forwards that probe
    /// to the backend and the probe is closed immediately, leaving an EOF
    /// connection queued ahead of the real sender's. Accepting it would make the
    /// receiver read EOF while the sender's bytes pile up on an unaccepted
    /// connection (the original "did not forward" timeout). A probe connection
    /// reads EOF straight away; the real one blocks until the sender starts — so
    /// discard any connection that is already at EOF.
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
                    // Probe leftovers are already closed (EOF); the real connection
                    // blocks waiting for the sender's first bytes. `peek` lets us
                    // tell them apart without consuming the payload.
                    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
                    let mut probe = [0u8; 1];
                    match stream.peek(&mut probe) {
                        Ok(0) => continue, // EOF: readiness-probe leftover — discard
                        _ => {
                            // Has data, or live-but-idle (timeout/would-block): the
                            // real forwarded connection.
                            stream.set_read_timeout(None)?;
                            stream.set_nonblocking(false)?;
                            return Ok(stream);
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_installs_divert_chain_and_redirect() {
        let cmds = setup_commands(18001, 18002);
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();

        // Policy route for fwmark-1 (transparent local delivery).
        assert!(
            flat.iter().any(|c| c == "ip rule add fwmark 1 lookup 100"),
            "missing fwmark policy rule: {flat:?}"
        );
        assert!(
            flat.iter()
                .any(|c| c.starts_with("ip route add local") && c.ends_with("table 100")),
            "missing local route in table 100: {flat:?}"
        );

        // DIVERT chain for established flows (`-m socket`) — the rule whose absence
        // let the SYN through but dropped the connection's data packets.
        assert!(
            flat.iter()
                .any(|c| c.contains("-A DIVERT") && c.contains("MARK --set-mark 0x1")),
            "DIVERT chain must mark established packets: {flat:?}"
        );
        assert!(
            flat.iter()
                .any(|c| c.contains("-A PREROUTING") && c.contains("-m socket -j DIVERT")),
            "missing `-m socket -j DIVERT` rule for established flows: {flat:?}"
        );

        // New-connection redirect with the correct listen/gateway ports.
        assert!(
            flat.iter().any(|c| c.contains("-j TPROXY")
                && c.contains("--dport 18001")
                && c.contains("--on-port 18002")
                && c.contains("--tproxy-mark 0x1/0x1")),
            "missing TPROXY redirect 18001->18002: {flat:?}"
        );

        // The `-m socket` divert rule must precede the new-connection TPROXY rule
        // so established packets are diverted before being re-redirected.
        let socket_idx = flat
            .iter()
            .position(|c| c.contains("-m socket -j DIVERT"))
            .unwrap();
        let tproxy_idx = flat.iter().position(|c| c.contains("-j TPROXY")).unwrap();
        assert!(
            socket_idx < tproxy_idx,
            "`-m socket` DIVERT must be installed before the TPROXY redirect"
        );
    }
}
