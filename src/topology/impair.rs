//! Network impairment injection via `tc netem`.
//!
//! Applies latency, jitter, loss, bandwidth limitation, reorder, and duplicate
//! to a network interface. Used by the `impair` subcommand and integrated into
//! the run engine when a scenario has `network_impairment` configured.
//!
//! Requires `CAP_NET_ADMIN`. Cleaned up on drop or teardown.
#![allow(dead_code)]

use std::io;
use std::process::Command;

/// Network impairment parameters.
#[derive(Debug, Clone, Default)]
pub struct Impairment {
    /// Extra delay in milliseconds.
    pub delay_ms: Option<u32>,
    /// Delay jitter in milliseconds (± variation).
    pub jitter_ms: Option<u32>,
    /// Packet loss percentage (0.0 - 100.0).
    pub loss_pct: Option<f64>,
    /// Bandwidth limit in Mbit/s.
    pub bandwidth_mbit: Option<u32>,
    /// Packet reorder percentage.
    pub reorder_pct: Option<f64>,
    /// Packet duplicate percentage.
    pub duplicate_pct: Option<f64>,
}

/// Applied impairment state. Removes the qdisc on drop.
pub struct AppliedImpairment {
    interface: String,
}

impl Drop for AppliedImpairment {
    fn drop(&mut self) {
        let _ = remove_impairment(&self.interface);
    }
}

/// Apply a `tc netem` qdisc to the specified interface.
///
/// Example: `tc qdisc add dev veth0 root netem delay 50ms 10ms loss 1%`
pub fn apply_impairment(interface: &str, imp: &Impairment) -> io::Result<AppliedImpairment> {
    let mut args = vec!["qdisc", "add", "dev", interface, "root", "netem"];

    let delay_str;
    let jitter_str;
    let loss_str;
    let reorder_str;
    let dup_str;
    let rate_str;

    if let Some(delay) = imp.delay_ms {
        delay_str = format!("{delay}ms");
        args.push("delay");
        args.push(&delay_str);
        if let Some(jitter) = imp.jitter_ms {
            jitter_str = format!("{jitter}ms");
            args.push(&jitter_str);
        }
    }

    if let Some(loss) = imp.loss_pct {
        loss_str = format!("{loss}%");
        args.push("loss");
        args.push(&loss_str);
    }

    if let Some(reorder) = imp.reorder_pct {
        reorder_str = format!("{reorder}%");
        args.push("reorder");
        args.push(&reorder_str);
    }

    if let Some(dup) = imp.duplicate_pct {
        dup_str = format!("{dup}%");
        args.push("duplicate");
        args.push(&dup_str);
    }

    if let Some(bw) = imp.bandwidth_mbit {
        rate_str = format!("{bw}mbit");
        args.push("rate");
        args.push(&rate_str);
    }

    run_cmd("tc", &args)?;
    Ok(AppliedImpairment {
        interface: interface.to_string(),
    })
}

/// Remove the netem qdisc from an interface.
pub fn remove_impairment(interface: &str) -> io::Result<()> {
    run_cmd("tc", &["qdisc", "del", "dev", interface, "root"])
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
