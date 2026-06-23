//! Topology management: virtual network namespaces, veth pairs, and helpers for
//! simulating multi-host deployments on a single machine (WP4.1).
//!
//! The `setup` and `teardown` subcommands use these primitives to create and
//! destroy network topologies before/after benchmark runs. Requires
//! `CAP_NET_ADMIN` (skips with a clear message when unavailable).
//!
//! Supported modes:
//!   - **Loopback**: No setup needed (default; all on `127.0.0.1`).
//!   - **Veth**: A veth pair connecting two endpoints (same network namespace).
//!   - **Netns**: Full network namespace isolation (gateway in ns1, SESHAT in
//!     ns2, connected by a veth pair).
#![allow(dead_code)]

pub mod impair;

use std::io;
use std::process::Command;

/// Supported topology modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyMode {
    /// Everything on loopback — no special setup.
    Loopback,
    /// A veth pair connecting two IP addresses.
    Veth,
    /// Full network namespace isolation.
    Netns,
}

/// State of a provisioned virtual topology. Cleaned up on drop.
pub struct ProvisionedTopology {
    pub mode: TopologyMode,
    /// Namespace names (if netns mode).
    pub namespaces: Vec<String>,
    /// Veth pair names.
    pub veth_pair: Option<(String, String)>,
    /// IP addresses assigned to each end.
    pub addrs: (String, String),
}

impl ProvisionedTopology {
    /// The address the sender uses (end A).
    pub fn sender_addr(&self) -> &str {
        &self.addrs.0
    }
    /// The address the receiver uses (end B).
    pub fn receiver_addr(&self) -> &str {
        &self.addrs.1
    }
}

impl Drop for ProvisionedTopology {
    fn drop(&mut self) {
        if let Err(e) = teardown_topology(self) {
            log::warn!("topology teardown failed: {e}");
        }
    }
}

/// Check if we have the capabilities needed for topology creation.
pub fn has_net_admin() -> bool {
    crate::transport::tproxy::has_cap_net_admin()
}

/// Create a veth pair topology.
///
/// Creates `veth_a`/`veth_b` with the specified IP addresses and prefix length.
pub fn setup_veth(
    ip_a: &str,
    ip_b: &str,
    prefix_len: u8,
) -> io::Result<ProvisionedTopology> {
    if !has_net_admin() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "topology setup requires CAP_NET_ADMIN — skipping",
        ));
    }

    let veth_a = "seshat-a".to_string();
    let veth_b = "seshat-b".to_string();

    // ip link add seshat-a type veth peer name seshat-b
    run_cmd("ip", &[
        "link", "add", &veth_a, "type", "veth", "peer", "name", &veth_b,
    ])?;

    // Assign IPs.
    let cidr_a = format!("{ip_a}/{prefix_len}");
    let cidr_b = format!("{ip_b}/{prefix_len}");
    run_cmd("ip", &["addr", "add", &cidr_a, "dev", &veth_a])?;
    run_cmd("ip", &["addr", "add", &cidr_b, "dev", &veth_b])?;

    // Bring up.
    run_cmd("ip", &["link", "set", &veth_a, "up"])?;
    run_cmd("ip", &["link", "set", &veth_b, "up"])?;

    Ok(ProvisionedTopology {
        mode: TopologyMode::Veth,
        namespaces: Vec::new(),
        veth_pair: Some((veth_a, veth_b)),
        addrs: (ip_a.to_string(), ip_b.to_string()),
    })
}

/// Create a full netns topology: two network namespaces connected by a veth pair.
pub fn setup_netns(
    ns_a: &str,
    ns_b: &str,
    ip_a: &str,
    ip_b: &str,
    prefix_len: u8,
) -> io::Result<ProvisionedTopology> {
    if !has_net_admin() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "topology setup requires CAP_NET_ADMIN — skipping",
        ));
    }

    let veth_a = "seshat-a".to_string();
    let veth_b = "seshat-b".to_string();

    // Create namespaces.
    run_cmd("ip", &["netns", "add", ns_a])?;
    run_cmd("ip", &["netns", "add", ns_b])?;

    // Create veth pair.
    run_cmd("ip", &[
        "link", "add", &veth_a, "type", "veth", "peer", "name", &veth_b,
    ])?;

    // Move each end into its namespace.
    run_cmd("ip", &["link", "set", &veth_a, "netns", ns_a])?;
    run_cmd("ip", &["link", "set", &veth_b, "netns", ns_b])?;

    // Configure addresses inside each namespace.
    let cidr_a = format!("{ip_a}/{prefix_len}");
    let cidr_b = format!("{ip_b}/{prefix_len}");
    run_cmd("ip", &["netns", "exec", ns_a, "ip", "addr", "add", &cidr_a, "dev", &veth_a])?;
    run_cmd("ip", &["netns", "exec", ns_b, "ip", "addr", "add", &cidr_b, "dev", &veth_b])?;

    // Bring up interfaces + loopback inside namespaces.
    run_cmd("ip", &["netns", "exec", ns_a, "ip", "link", "set", &veth_a, "up"])?;
    run_cmd("ip", &["netns", "exec", ns_a, "ip", "link", "set", "lo", "up"])?;
    run_cmd("ip", &["netns", "exec", ns_b, "ip", "link", "set", &veth_b, "up"])?;
    run_cmd("ip", &["netns", "exec", ns_b, "ip", "link", "set", "lo", "up"])?;

    Ok(ProvisionedTopology {
        mode: TopologyMode::Netns,
        namespaces: vec![ns_a.to_string(), ns_b.to_string()],
        veth_pair: Some((veth_a, veth_b)),
        addrs: (ip_a.to_string(), ip_b.to_string()),
    })
}

/// Tear down a provisioned topology. Called by `Drop` and the `teardown` command.
pub fn teardown_topology(topo: &ProvisionedTopology) -> io::Result<()> {
    match topo.mode {
        TopologyMode::Loopback => Ok(()),
        TopologyMode::Veth => {
            if let Some((ref a, _)) = topo.veth_pair {
                // Deleting one end removes both.
                let _ = run_cmd("ip", &["link", "del", a]);
            }
            Ok(())
        }
        TopologyMode::Netns => {
            // Delete namespaces (this also removes the veth interfaces).
            for ns in &topo.namespaces {
                let _ = run_cmd("ip", &["netns", "del", ns]);
            }
            Ok(())
        }
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
