//! TPROXY transparent transport.
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
use crate::gateway::{
    build_path, reserve_local_port_for, start_path, NamedGateway, PathPlan, RunningPath,
    SecuritySpec, Topology,
};
use crate::net::AddressFamily;

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
    family: AddressFamily,
}

impl TproxyRules {
    /// Set up the full TPROXY recipe — policy route, the `DIVERT` chain for
    /// established flows, and the new-connection redirect — for intercepting
    /// traffic to `listen_port` and steering it to `gateway_port` on address
    /// `family` (IPv4 uses `iptables`/`ip`; IPv6 uses `ip6tables`/`ip -6`).
    fn setup(listen_port: u16, gateway_port: u16, family: AddressFamily) -> io::Result<Self> {
        // Creating the DIVERT chain is best-effort: a leftover from a crashed
        // run means it already exists (the strict commands below re-flush it).
        let _ = run_cmd(iptables_bin(family), &["-t", "mangle", "-N", "DIVERT"]);
        for cmd in setup_commands(listen_port, gateway_port, family) {
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            run_cmd(args[0], &args[1..])?;
        }
        Ok(TproxyRules {
            listen_port,
            gateway_port,
            family,
        })
    }

    /// Remove the iptables/routing rules (reverse order of `setup`).
    fn teardown(&self) {
        let ipt = iptables_bin(self.family);
        let _ = run_cmd(
            ipt,
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
            ipt,
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
        let _ = run_cmd(ipt, &["-t", "mangle", "-F", "DIVERT"]);
        let _ = run_cmd(ipt, &["-t", "mangle", "-X", "DIVERT"]);
        let mut route_del = ip_args(self.family);
        route_del.extend([
            "route",
            "del",
            "local",
            local_route_prefix(self.family),
            "dev",
            "lo",
            "table",
            "100",
        ]);
        let _ = run_cmd("ip", &route_del);
        let mut rule_del = ip_args(self.family);
        rule_del.extend(["rule", "del", "fwmark", "1", "lookup", "100"]);
        let _ = run_cmd("ip", &rule_del);
    }
}

impl Drop for TproxyRules {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// The `iptables` binary for `family`: `iptables` for IPv4, `ip6tables` for IPv6.
fn iptables_bin(family: AddressFamily) -> &'static str {
    if family.is_ipv6() {
        "ip6tables"
    } else {
        "iptables"
    }
}

/// The `local` route prefix that catches every marked packet for `family`.
fn local_route_prefix(family: AddressFamily) -> &'static str {
    if family.is_ipv6() {
        "::/0"
    } else {
        "0/0"
    }
}

/// The `ip` sub-command prefix for `family`: empty for IPv4, `-6` for IPv6.
/// Returned as owned `&'static str` args so it composes with borrowed literals.
fn ip_args(family: AddressFamily) -> Vec<&'static str> {
    if family.is_ipv6() {
        vec!["-6"]
    } else {
        Vec::new()
    }
}

/// The ordered list of `(program, args…)` commands that install the TPROXY
/// recipe for `listen_port → gateway_port`. Excludes the best-effort
/// `iptables -N DIVERT` chain creation (handled separately in [`TproxyRules::setup`]).
/// Returned as data so the rule set can be asserted without `CAP_NET_ADMIN`.
fn setup_commands(listen_port: u16, gateway_port: u16, family: AddressFamily) -> Vec<Vec<String>> {
    let s = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<String>>();
    let lp = listen_port.to_string();
    let gp = gateway_port.to_string();
    let ipt = iptables_bin(family);
    let prefix = local_route_prefix(family);
    // `ip rule`/`ip route` need a `-6` after `ip` for IPv6; splice it in.
    let mut ip_rule = vec!["ip"];
    ip_rule.extend(ip_args(family));
    ip_rule.extend(["rule", "add", "fwmark", "1", "lookup", "100"]);
    let mut ip_route = vec!["ip"];
    ip_route.extend(ip_args(family));
    ip_route.extend(["route", "add", "local", prefix, "dev", "lo", "table", "100"]);
    vec![
        // Policy route: fwmark-1 packets are delivered to the local transparent
        // sockets via a dedicated table.
        s(&ip_rule),
        s(&ip_route),
        // DIVERT chain: packets that already belong to an established transparent
        // socket (`-m socket`) are marked and accepted so they reach that socket
        // directly. Without it the redirect intercepts the SYN but the data
        // packets of the established flow are not steered to the gateway socket,
        // so the connection establishes yet zero bytes ever arrive.
        s(&[ipt, "-t", "mangle", "-F", "DIVERT"]),
        s(&[
            ipt,
            "-t",
            "mangle",
            "-A",
            "DIVERT",
            "-j",
            "MARK",
            "--set-mark",
            "0x1",
        ]),
        s(&[ipt, "-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT"]),
        s(&[
            ipt,
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
            ipt,
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

/// The original single-hop plan: one transparent `routing` rule that intercepts on
/// `gw_port` and forwards straight to the plaintext backend. Preserved verbatim for
/// `routing` single-gateway so the known-good routing_tproxy path is unchanged.
fn single_transparent_routing_plan(
    gw_port: u16,
    backend_addr: &str,
    family: AddressFamily,
) -> PathPlan {
    let gw_addr = family.loopback_socket(gw_port);
    let rule = RuleConfig::new("tproxy-encrypt", "encrypt", &gw_addr, backend_addr)
        .security("routing")
        .param("transparent", true);
    PathPlan {
        ingress_addr: gw_addr,
        backend_addr: backend_addr.to_string(),
        gateways: vec![NamedGateway {
            label: "scg".to_string(),
            config: GatewayConfig::new(vec![rule]).log_level("info").allow_all(),
        }],
    }
}

/// Build the standard encrypt/decrypt path for `spec`/`topology`, then retarget the
/// ingress encrypt rule onto the transparent TPROXY listen port `gw_port`. The
/// gateway intercepts on `gw_port`, applies the scenario's crypto, and either
/// (single-gateway) decrypts back to the plaintext backend in the same process, or
/// (scg-scg) tunnels to a second gateway that decrypts to the backend. Split out so
/// the config wiring is unit-testable without `CAP_NET_ADMIN`.
fn build_transparent_plan(
    spec: &SecuritySpec,
    topology: Topology,
    gw_port: u16,
    backend_addr: &str,
    connections: usize,
) -> io::Result<PathPlan> {
    let mut plan = build_path(spec, topology, backend_addr, connections)?;
    let gw_addr = spec.address_family.loopback_socket(gw_port);
    let mut retargeted = false;
    for gw in &mut plan.gateways {
        for rule in &mut gw.config.rules {
            if rule.direction == "encrypt" {
                rule.listen_addr = gw_addr.clone();
                rule.provider_params
                    .insert("transparent".to_string(), serde_json::Value::Bool(true));
                retargeted = true;
            }
        }
    }
    if !retargeted {
        return Err(io::Error::other(
            "TPROXY path has no encrypt rule to make transparent",
        ));
    }
    Ok(plan)
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
    /// The gateway process(es): one for single-gateway, two for scg-scg.
    running: Option<RunningPath>,
    /// TPROXY iptables rules (cleaned up on drop).
    rules: Option<TproxyRules>,
}

impl TproxyTransport {
    /// Start a TPROXY transparent gateway path carrying the scenario's security
    /// (`spec`) and topology.
    ///
    /// Returns `Err` with `ErrorKind::PermissionDenied` if `CAP_NET_ADMIN` is
    /// missing.
    ///
    /// We deliberately do NOT use the `"auto"` original-destination mode. The
    /// gateway *does* recover the TPROXY original destination correctly
    /// (`SO_ORIGINAL_DST` with a `getsockname` fallback on the `IP_TRANSPARENT`
    /// socket — the gateway hardens original-destination recovery, with its own `recover_transparent_dst`
    /// tests). The blocker is *loopback*: with `"auto"` the gateway would forward to
    /// the recovered destination (the same `target_port` the client dialed), which
    /// re-enters `PREROUTING` on `lo`, hits the same `-j TPROXY` rule, and loops.
    /// Using an explicit backend still exercises the full data path (client →
    /// iptables redirect → gateway `IP_TRANSPARENT` listener → relay → backend).
    pub fn start(
        name: &'static str,
        spec: &SecuritySpec,
        topology: Topology,
        binary: &Path,
        work_dir: &Path,
        gateway_cores: &[usize],
        connections: usize,
    ) -> io::Result<Self> {
        if !has_cap_net_admin() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TPROXY requires CAP_NET_ADMIN — skipping",
            ));
        }

        std::fs::create_dir_all(work_dir)?;

        let family = spec.address_family;

        // The "target" address the sender thinks it's connecting to.
        let target_port = reserve_local_port_for(family)?;
        let target_addr: SocketAddr = family
            .loopback_socket(target_port)
            .parse()
            .map_err(|e| io::Error::other(format!("invalid TPROXY target address: {e}")))?;
        // The gateway's transparent listen port (where TPROXY redirects to).
        let gw_port = reserve_local_port_for(family)?;
        // The real backend (plaintext egress).
        let backend_port = reserve_local_port_for(family)?;
        let backend_addr = family.loopback_socket(backend_port);
        let backend = TcpListener::bind(&backend_addr)?;
        backend.set_nonblocking(true)?;

        // Plaintext routing over a single gateway keeps the original, known-good
        // *single* transparent hop (gw_port → backend). Any crypto, or a two-gateway
        // topology, needs the standard encrypt/decrypt path with the ingress encrypt
        // rule retargeted transparent so the plaintext backend still terminates the
        // tunnel — see `build_transparent_plan`.
        let plan = if spec.provider == "routing" && matches!(topology, Topology::SingleGateway) {
            single_transparent_routing_plan(gw_port, &backend_addr, family)
        } else {
            build_transparent_plan(spec, topology, gw_port, &backend_addr, connections)?
        };

        // Set up TPROXY iptables rules (redirect <target_port> onto <gw_port>).
        let rules = TproxyRules::setup(target_port, gw_port, family)?;

        let running = start_path(&plan, binary, work_dir, READY_TIMEOUT, gateway_cores)?;

        Ok(TproxyTransport {
            name,
            target_addr,
            backend,
            running: Some(running),
            rules: Some(rules),
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

    /// Gracefully stop the gateway process(es) and remove iptables rules.
    pub fn shutdown(mut self) -> io::Result<()> {
        // Drop rules first (cleanup iptables).
        self.rules.take();
        if let Some(running) = self.running.take() {
            running.shutdown()?;
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
    use crate::gateway::SecuritySpec;
    use std::path::Path;

    #[test]
    fn routing_single_gateway_keeps_the_known_good_single_transparent_hop() {
        // Plaintext routing on one gateway must stay byte-for-byte the original
        // single transparent rule (gw_port → backend), not the 2-hop path.
        let spec = SecuritySpec::routing_tcp();
        let plan = if spec.provider == "routing"
            && matches!(Topology::SingleGateway, Topology::SingleGateway)
        {
            single_transparent_routing_plan(19001, "127.0.0.1:19002", AddressFamily::Ipv4)
        } else {
            unreachable!()
        };
        assert_eq!(plan.gateways.len(), 1);
        let rules = &plan.gateways[0].config.rules;
        assert_eq!(rules.len(), 1, "routing tproxy is a single transparent hop");
        assert_eq!(rules[0].direction, "encrypt");
        assert_eq!(rules[0].security_provider, "routing");
        assert_eq!(rules[0].listen_addr, "127.0.0.1:19001");
        assert_eq!(rules[0].upstream_addr, "127.0.0.1:19002");
        assert_eq!(
            rules[0].provider_params.get("transparent"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn crypto_retargets_ingress_encrypt_transparent_and_carries_security() {
        // A TLS scenario must reach the transparent listener as `tls` (not the old
        // hard-coded routing), with the decrypt rule terminating at the backend.
        let spec =
            SecuritySpec::tls_server("tls1.3", Path::new("/tmp/c.pem"), Path::new("/tmp/k.pem"));
        let plan =
            build_transparent_plan(&spec, Topology::SingleGateway, 19010, "127.0.0.1:19011", 1)
                .unwrap();
        let enc = plan.gateways[0]
            .config
            .rules
            .iter()
            .find(|r| r.direction == "encrypt")
            .unwrap();
        assert_eq!(enc.security_provider, "tls");
        assert_eq!(enc.listen_addr, "127.0.0.1:19010");
        assert_eq!(
            enc.provider_params.get("transparent"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn crypto_scg_to_scg_splits_transparent_encrypt_from_decrypt() {
        let spec =
            SecuritySpec::tls_server("tls1.3", Path::new("/tmp/c.pem"), Path::new("/tmp/k.pem"));
        let plan =
            build_transparent_plan(&spec, Topology::ScgToScg, 19020, "127.0.0.1:19021", 1).unwrap();
        assert_eq!(plan.gateways.len(), 2);
        assert!(plan.gateways[0]
            .config
            .rules
            .iter()
            .all(|r| r.direction == "encrypt"));
        assert!(plan.gateways[1]
            .config
            .rules
            .iter()
            .all(|r| r.direction == "decrypt"));
    }

    #[test]
    fn setup_installs_divert_chain_and_redirect() {
        let cmds = setup_commands(18001, 18002, AddressFamily::Ipv4);
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

    #[test]
    fn ipv6_uses_ip6tables_and_v6_policy_route() {
        let cmds = setup_commands(18001, 18002, AddressFamily::Ipv6);
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();

        // Policy plumbing goes through `ip -6` and a `::/0` local route.
        assert!(
            flat.iter()
                .any(|c| c == "ip -6 rule add fwmark 1 lookup 100"),
            "missing v6 fwmark policy rule: {flat:?}"
        );
        assert!(
            flat.iter()
                .any(|c| c == "ip -6 route add local ::/0 dev lo table 100"),
            "missing v6 local route in table 100: {flat:?}"
        );
        // Every packet-filter command must target ip6tables, never iptables.
        assert!(
            flat.iter().all(|c| !c.starts_with("iptables ")),
            "v6 setup must not use iptables: {flat:?}"
        );
        assert!(
            flat.iter()
                .any(|c| c.starts_with("ip6tables ") && c.contains("-j TPROXY")),
            "missing ip6tables TPROXY redirect: {flat:?}"
        );
    }

    #[test]
    fn ipv6_routing_plan_brackets_the_transparent_listener() {
        let plan = single_transparent_routing_plan(19001, "[::1]:19002", AddressFamily::Ipv6);
        let rules = &plan.gateways[0].config.rules;
        assert_eq!(rules[0].listen_addr, "[::1]:19001");
        assert_eq!(rules[0].upstream_addr, "[::1]:19002");
        assert_eq!(plan.ingress_addr, "[::1]:19001");
    }

    #[test]
    fn ipv6_crypto_plan_retargets_bracketed_transparent_listener() {
        let spec =
            SecuritySpec::tls_server("tls1.3", Path::new("/tmp/c.pem"), Path::new("/tmp/k.pem"))
                .with_address_family(AddressFamily::Ipv6);
        let plan = build_transparent_plan(&spec, Topology::SingleGateway, 19010, "[::1]:19011", 1)
            .unwrap();
        let enc = plan.gateways[0]
            .config
            .rules
            .iter()
            .find(|r| r.direction == "encrypt")
            .unwrap();
        assert_eq!(enc.security_provider, "tls");
        assert_eq!(enc.listen_addr, "[::1]:19010");
    }
}
