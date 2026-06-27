//! Effective-protocol detection from gateway logs (Phase E).
//!
//! The gateway can be *asked* for kTLS (kernel TLS offload) yet silently fall
//! back to userspace TLS when the platform lacks support — e.g. WSL2, where the
//! `tls` upper-layer protocol is unavailable. Trusting the configured protocol
//! would then mislabel a userspace run as kernel-offloaded. This module distils
//! what the gateway logs reveal so the report can show the *effective* protocol.
//!
//! Detection is keyed to the gateway's `info`-level logging contract: a kTLS
//! fallback always emits a `WARNING: kTLS [may] not [be] active` line, whereas
//! the success path is logged only at `debug`. We therefore take the *requested*
//! state from the resolved configuration and treat the absence of a fallback
//! warning (when kTLS was requested) as confirmation that kTLS engaged.

use std::path::Path;

/// What the gateway actually negotiated, distilled from its logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effective {
    /// kTLS (kernel offload) was requested by the resolved configuration.
    pub kernel_requested: bool,
    /// kTLS is actually active on the data-plane socket.
    pub kernel_active: bool,
    /// A protocol-version downgrade note, when the logs reveal one.
    pub version_downgrade: Option<String>,
    /// Handshakes the gateway logged as resuming a cached session
    /// (`resumed=true`) — ground truth from `SSL_session_reused`.
    pub resumed_handshakes: u64,
    /// Handshakes the gateway logged as full key exchanges (`resumed=false`).
    pub full_handshakes: u64,
    /// Verbatim warning/error lines worth surfacing in the report.
    pub notes: Vec<String>,
}

impl Effective {
    /// True when the gateway did not deliver the requested protocol — kTLS ran
    /// in userspace, or a version downgrade was observed.
    pub fn is_fallback(&self) -> bool {
        (self.kernel_requested && !self.kernel_active) || self.version_downgrade.is_some()
    }

    /// Fraction of observed handshakes that resumed a session (0..=1), or `None`
    /// when the gateway logged no resumption markers (e.g. a non-TLS run, or a
    /// build without the `resumed=` log). The ground-truth counterpart to the
    /// timing-based first-vs-resumed handshake latency.
    pub fn resumed_fraction(&self) -> Option<f64> {
        let total = self.resumed_handshakes + self.full_handshakes;
        (total > 0).then(|| self.resumed_handshakes as f64 / total as f64)
    }
}

/// Markers the gateway emits when kTLS was requested but is not active.
const KTLS_INACTIVE_MARKERS: &[&str] =
    &["ktls not active", "ktls may not be active", "active=false"];

/// Scan the gateway `log_paths` for evidence of a protocol fallback.
///
/// `kernel_requested` comes from the resolved configuration (whether the rule
/// provider was `ktls`); the logs alone cannot confirm the success path because
/// the gateway logs it at `debug`, below its `info` runtime level. A fallback,
/// by contrast, is always surfaced as a `warn`.
pub fn scan_effective<P: AsRef<Path>>(log_paths: &[P], kernel_requested: bool) -> Effective {
    let mut inactive = false;
    let mut notes = Vec::new();
    let mut resumed_handshakes = 0u64;
    let mut full_handshakes = 0u64;
    for path in log_paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let low = line.to_ascii_lowercase();
            // Ground-truth resumption from the gateway's `resumed=` accept marker.
            if low.contains("resumed=true") {
                resumed_handshakes += 1;
            } else if low.contains("resumed=false") {
                full_handshakes += 1;
            }
            if KTLS_INACTIVE_MARKERS.iter().any(|m| low.contains(m)) {
                inactive = true;
                notes.push(line.trim().to_string());
            } else if low.contains("error")
                && (low.contains("dtls") || low.contains("ktls") || low.contains("handshake"))
            {
                notes.push(line.trim().to_string());
            }
        }
    }
    Effective {
        kernel_requested,
        kernel_active: kernel_requested && !inactive,
        version_downgrade: None,
        resumed_handshakes,
        full_handshakes,
        notes,
    }
}

/// Combine the *configured* protocol label with the gateway's effective state.
///
/// A kTLS request that fell back to userspace is relabelled
/// `tls/<v> (ktls->userspace)`; an observed version downgrade is annotated in
/// parentheses; otherwise the configured label is returned unchanged.
pub fn effective_protocol_label(configured: &str, eff: &Effective) -> String {
    if eff.kernel_requested && !eff.kernel_active {
        // kTLS fell back to userspace TLS at the same negotiated version.
        let base = configured.replacen("ktls", "tls", 1);
        return format!("{base} (ktls->userspace)");
    }
    if let Some(downgrade) = &eff.version_downgrade {
        return format!("{configured} ({downgrade})");
    }
    configured.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_log(tag: &str, body: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("seshat-logscan-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.log");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn ktls_requested_without_warning_is_active() {
        let (dir, log) = write_log("active", "[enc] TLS listener ready\n[enc] relay started\n");
        let eff = scan_effective(&[log], true);
        assert!(eff.kernel_requested);
        assert!(eff.kernel_active);
        assert!(!eff.is_fallback());
        assert_eq!(effective_protocol_label("ktls/1.3", &eff), "ktls/1.3");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ktls_fallback_warning_marks_userspace() {
        let (dir, log) = write_log(
            "fallback",
            "[enc] kTLS handshake OK (1.20 ms, ULP=, active=false)\n\
             [enc] WARNING: kTLS not active. run as root to enable.\n",
        );
        let eff = scan_effective(&[log], true);
        assert!(eff.kernel_requested);
        assert!(!eff.kernel_active);
        assert!(eff.is_fallback());
        assert!(!eff.notes.is_empty());
        assert_eq!(
            effective_protocol_label("ktls/1.3", &eff),
            "tls/1.3 (ktls->userspace)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn counts_resumed_and_full_handshakes() {
        let (dir, log) = write_log(
            "resume",
            "[dec] TLS accept from 127.0.0.1:5 (0.80 ms, resumed=false)\n\
             [dec] TLS accept from 127.0.0.1:6 (0.20 ms, resumed=true)\n\
             [dec] TLS accept from 127.0.0.1:7 (0.18 ms, resumed=true)\n",
        );
        let eff = scan_effective(&[log], false);
        assert_eq!(eff.full_handshakes, 1);
        assert_eq!(eff.resumed_handshakes, 2);
        // 2 of 3 handshakes resumed.
        assert!((eff.resumed_fraction().unwrap() - 2.0 / 3.0).abs() < 1e-9);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resumed_fraction_is_none_without_markers() {
        let empty: [&Path; 0] = [];
        assert_eq!(scan_effective(&empty, false).resumed_fraction(), None);
    }

    #[test]
    fn not_requested_is_passthrough() {
        let empty: [&Path; 0] = [];
        let eff = scan_effective(&empty, false);
        assert!(!eff.kernel_requested);
        assert!(!eff.kernel_active);
        assert!(!eff.is_fallback());
        assert_eq!(effective_protocol_label("tls/1.2", &eff), "tls/1.2");
    }
}
