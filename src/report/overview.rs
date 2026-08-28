//! Consolidated performance overview (`PERFORMANCE_OVERVIEW.txt`).
//!
//! Reads the top-level `summary.csv` of a result tree — which already holds one
//! row per executed scenario across every config in a `suite` run — and renders
//! themed tables (throughput, one-way latency, round-trip, saturation,
//! connection rate), a leaderboard, and summary statistics. The same text is
//! printed to the terminal and written to `PERFORMANCE_OVERVIEW.txt` so the two
//! never drift. Scenario classification follows the established name-prefix
//! convention (`lat_`, `pp_`, `conn_`).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Maximum rule width, matching the live console layout.
const WIDTH: usize = 72;

/// A subset of the columnar `summary.csv` row needed for the overview.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SummaryRow {
    pub scenario: String,
    pub transport: String,
    pub protocol: String,
    pub effective_protocol: String,
    pub message_bytes: String,
    pub connections: String,
    pub throughput_mean: f64,
    pub throughput_ci95: f64,
    pub latency_mean_us: f64,
    pub latency_p99_us: f64,
    pub loss_pct: f64,
    pub headroom: f64,
    pub harness_limited: bool,
    pub bottleneck: String,
    pub saturation_gbps: f64,
    pub max_lossfree_gbps: f64,
    pub rtt_mean_us: f64,
    pub rtt_p50_us: f64,
    pub rtt_p99_us: f64,
    pub conns_per_sec: f64,
    pub handshake_p50_us: f64,
    pub handshake_p99_us: f64,
}

impl SummaryRow {
    /// The protocol to display: the effective protocol when known (captures
    /// kTLS→userspace fallback), otherwise the configured protocol.
    fn shown_protocol(&self) -> &str {
        if self.effective_protocol.is_empty() {
            &self.protocol
        } else {
            &self.effective_protocol
        }
    }
}

/// Whether a scenario name is a latency / ping-pong / conn-rate row (excluded
/// from the throughput leaderboard, which ranks bandwidth).
fn is_special(name: &str) -> bool {
    name.starts_with("lat_") || name.starts_with("pp_") || name.starts_with("conn_")
}

/// Read the result tree's `summary.csv`, render the overview, print it, and
/// write it to `PERFORMANCE_OVERVIEW.txt`. A no-op when there is nothing to
/// summarize (missing or empty `summary.csv`).
pub fn render_and_write(root: &Path) -> io::Result<()> {
    let summary_path = root.join("summary.csv");
    let text = match fs::read_to_string(&summary_path) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let rows = parse_summary(&text);
    let report = render_overview(&rows);
    if report.is_empty() {
        return Ok(());
    }
    print!("{report}");
    fs::write(root.join("PERFORMANCE_OVERVIEW.txt"), &report)
}

/// Parse a `summary.csv` (header + CRLF rows, RFC-4180 quoting) into rows,
/// keyed by header name so column order does not matter.
pub fn parse_summary(text: &str) -> Vec<SummaryRow> {
    let mut lines = text
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty());
    let header = match lines.next() {
        Some(h) => parse_record(h),
        None => return Vec::new(),
    };
    let idx: HashMap<&str, usize> = header
        .iter()
        .enumerate()
        .map(|(i, h)| (h.as_str(), i))
        .collect();

    let mut rows = Vec::new();
    for line in lines {
        let f = parse_record(line);
        let s = |name: &str| -> String {
            idx.get(name)
                .and_then(|&i| f.get(i))
                .cloned()
                .unwrap_or_default()
        };
        let num = |name: &str| -> f64 {
            idx.get(name)
                .and_then(|&i| f.get(i))
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        let flag = |name: &str| -> bool {
            idx.get(name)
                .and_then(|&i| f.get(i))
                .map(|v| v == "true")
                .unwrap_or(false)
        };
        rows.push(SummaryRow {
            scenario: s("scenario"),
            transport: s("transport"),
            protocol: s("protocol"),
            effective_protocol: s("effective_protocol"),
            message_bytes: s("message_bytes"),
            connections: s("connections"),
            throughput_mean: num("throughput_gbps_mean"),
            throughput_ci95: num("throughput_gbps_ci95"),
            latency_mean_us: num("latency_mean_us"),
            latency_p99_us: num("latency_p99_us_mean"),
            loss_pct: num("loss_pct"),
            headroom: num("headroom"),
            harness_limited: flag("harness_limited"),
            bottleneck: s("bottleneck"),
            saturation_gbps: num("saturation_gbps"),
            max_lossfree_gbps: num("max_lossfree_gbps"),
            rtt_mean_us: num("rtt_us_mean"),
            rtt_p50_us: num("rtt_us_p50"),
            rtt_p99_us: num("rtt_us_p99"),
            conns_per_sec: num("conns_per_sec"),
            handshake_p50_us: num("conn_handshake_p50_us"),
            handshake_p99_us: num("conn_handshake_p99_us"),
        });
    }
    rows
}

/// Render the full overview report as plain text (no ANSI), suitable for both
/// the terminal and `PERFORMANCE_OVERVIEW.txt`.
pub fn render_overview(rows: &[SummaryRow]) -> String {
    let mut buf = String::new();
    if rows.is_empty() {
        return buf;
    }
    section(&mut buf, "PERFORMANCE OVERVIEW");
    buf.push('\n');

    render_throughput(&mut buf, rows);
    render_latency(&mut buf, rows);
    render_roundtrip(&mut buf, rows);
    render_saturation(&mut buf, rows);
    render_connrate(&mut buf, rows);
    render_leaderboard(&mut buf, rows);
    render_summary_stats(&mut buf, rows);
    buf
}

fn render_throughput(buf: &mut String, rows: &[SummaryRow]) {
    // Exclude latency/ping-pong/conn-rate rows: they have dedicated sections and
    // their "throughput" is not a bandwidth-capacity figure.
    let mut thr: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.throughput_mean > 0.1 && !is_special(&r.scenario))
        .collect();
    if thr.is_empty() {
        return;
    }
    thr.sort_by(|a, b| b.throughput_mean.total_cmp(&a.throughput_mean));
    section(buf, "Throughput");
    let headers = &[
        "Scenario",
        "Transport",
        "Protocol",
        "Bytes",
        "Conns",
        "Throughput Gbit/s",
        "p99 µs",
        "Loss %",
        "Headroom",
    ];
    let mut data = Vec::new();
    for r in &thr {
        let mut tput = format!("{:.3} ± {:.3}", r.throughput_mean, r.throughput_ci95);
        if r.bottleneck == "host-saturated" {
            tput.push_str(" \u{2020}");
        } else if r.harness_limited {
            tput.push_str(" *");
        }
        data.push(vec![
            r.scenario.clone(),
            r.transport.clone(),
            r.shown_protocol().to_string(),
            r.message_bytes.clone(),
            r.connections.clone(),
            tput,
            format!("{:.1}", r.latency_p99_us),
            format!("{:.3}", r.loss_pct),
            if r.headroom > 0.0 {
                format!("{:.1}×", r.headroom)
            } else {
                "-".to_string()
            },
        ]);
    }
    table(buf, headers, &data, b"lllrrrrrr");
    if thr.iter().any(|r| r.harness_limited) {
        buf.push_str(
            "  * harness-limited (<3× headroom): a lower bound, not the DUT's capacity.\n",
        );
    }
    buf.push('\n');
}

fn render_latency(buf: &mut String, rows: &[SummaryRow]) {
    let lat: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.scenario.starts_with("lat_"))
        .collect();
    if lat.is_empty() {
        return;
    }
    section(buf, "One-Way Latency");
    let headers = &[
        "Scenario",
        "Transport",
        "Protocol",
        "Mean µs",
        "p99 µs",
        "Loss %",
    ];
    let data: Vec<Vec<String>> = lat
        .iter()
        .map(|r| {
            vec![
                r.scenario.clone(),
                r.transport.clone(),
                r.shown_protocol().to_string(),
                format!("{:.1}", r.latency_mean_us),
                format!("{:.1}", r.latency_p99_us),
                format!("{:.3}", r.loss_pct),
            ]
        })
        .collect();
    table(buf, headers, &data, b"lllrrr");
    buf.push('\n');
}

fn render_roundtrip(buf: &mut String, rows: &[SummaryRow]) {
    let pp: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.scenario.starts_with("pp_"))
        .collect();
    if pp.is_empty() {
        return;
    }
    section(buf, "Round-Trip Time");
    let headers = &[
        "Scenario",
        "Transport",
        "Protocol",
        "Mean µs",
        "p50 µs",
        "p99 µs",
    ];
    let data: Vec<Vec<String>> = pp
        .iter()
        .map(|r| {
            vec![
                r.scenario.clone(),
                r.transport.clone(),
                r.shown_protocol().to_string(),
                format!("{:.1}", r.rtt_mean_us),
                format!("{:.1}", r.rtt_p50_us),
                format!("{:.1}", r.rtt_p99_us),
            ]
        })
        .collect();
    table(buf, headers, &data, b"lllrrr");
    buf.push('\n');
}

fn render_saturation(buf: &mut String, rows: &[SummaryRow]) {
    let sat: Vec<&SummaryRow> = rows.iter().filter(|r| r.saturation_gbps > 0.0).collect();
    if sat.is_empty() {
        return;
    }
    section(buf, "Saturation Sweep");
    let headers = &[
        "Scenario",
        "Transport",
        "Ceiling Gbit/s",
        "Loss-free Gbit/s",
    ];
    let data: Vec<Vec<String>> = sat
        .iter()
        .map(|r| {
            vec![
                r.scenario.clone(),
                r.transport.clone(),
                format!("{:.3}", r.saturation_gbps),
                format!("{:.3}", r.max_lossfree_gbps),
            ]
        })
        .collect();
    table(buf, headers, &data, b"llrr");
    buf.push('\n');
}

fn render_connrate(buf: &mut String, rows: &[SummaryRow]) {
    let conn: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.scenario.starts_with("conn_") || r.conns_per_sec > 0.0)
        .collect();
    if conn.is_empty() {
        return;
    }
    section(buf, "Connection Rate");
    let headers = &[
        "Scenario",
        "Transport",
        "Protocol",
        "Conn/s",
        "hs p50 µs",
        "hs p99 µs",
    ];
    let data: Vec<Vec<String>> = conn
        .iter()
        .map(|r| {
            vec![
                r.scenario.clone(),
                r.transport.clone(),
                r.shown_protocol().to_string(),
                format!("{:.0}", r.conns_per_sec),
                format!("{:.1}", r.handshake_p50_us),
                format!("{:.1}", r.handshake_p99_us),
            ]
        })
        .collect();
    table(buf, headers, &data, b"lllrrr");
    buf.push('\n');
}

fn render_leaderboard(buf: &mut String, rows: &[SummaryRow]) {
    let mut board: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.throughput_mean > 0.0 && !is_special(&r.scenario))
        .collect();
    if board.is_empty() {
        return;
    }
    board.sort_by(|a, b| b.throughput_mean.total_cmp(&a.throughput_mean));
    section(buf, "Throughput Leaderboard");
    let headers = &["Rank", "Scenario", "Protocol", "Throughput Gbit/s"];
    let data: Vec<Vec<String>> = board
        .iter()
        .enumerate()
        .map(|(i, r)| {
            vec![
                format!("{}", i + 1),
                r.scenario.clone(),
                r.shown_protocol().to_string(),
                format!("{:.3}", r.throughput_mean),
            ]
        })
        .collect();
    table(buf, headers, &data, b"rllr");
    buf.push('\n');
}

fn render_summary_stats(buf: &mut String, rows: &[SummaryRow]) {
    let thr: Vec<&SummaryRow> = rows
        .iter()
        .filter(|r| r.throughput_mean > 0.0 && !is_special(&r.scenario))
        .collect();
    if thr.is_empty() {
        return;
    }
    section(buf, "Summary Statistics");
    let best = thr
        .iter()
        .max_by(|a, b| a.throughput_mean.total_cmp(&b.throughput_mean));
    let worst = thr
        .iter()
        .min_by(|a, b| a.throughput_mean.total_cmp(&b.throughput_mean));
    let mean = thr.iter().map(|r| r.throughput_mean).sum::<f64>() / thr.len() as f64;
    if let Some(b) = best {
        kv(
            buf,
            "Best throughput",
            &format!("{} ({:.3} Gbit/s)", b.scenario, b.throughput_mean),
        );
    }
    if let Some(w) = worst {
        kv(
            buf,
            "Worst throughput",
            &format!("{} ({:.3} Gbit/s)", w.scenario, w.throughput_mean),
        );
    }
    kv(buf, "Mean throughput", &format!("{mean:.3} Gbit/s"));
    buf.push('\n');
}

// ── plain-text rendering helpers (mirror console:: layout, no ANSI) ──────────

/// Append a double-line section header.
fn section(buf: &mut String, title: &str) {
    let prefix = format!("═══ {title} ");
    let fill = WIDTH.saturating_sub(prefix.chars().count());
    buf.push_str(&prefix);
    for _ in 0..fill {
        buf.push('═');
    }
    buf.push('\n');
}

/// Append a `  label : value` line.
fn kv(buf: &mut String, label: &str, value: &str) {
    buf.push_str(&format!("  {label:<18}: {value}\n"));
}

/// Append a box-drawn table; `aligns` is per-column `b'l'`/`b'r'`.
fn table(buf: &mut String, headers: &[&str], rows: &[Vec<String>], aligns: &[u8]) {
    if headers.is_empty() {
        return;
    }
    let ncols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(ncols) {
            let w = cell.chars().count();
            if w > widths[i] {
                widths[i] = w;
            }
        }
    }
    border(buf, &widths, '┌', '┬', '┐');
    buf.push_str(" │");
    for (i, h) in headers.iter().enumerate() {
        buf.push_str(&format!(" {:<width$} │", h, width = widths[i]));
    }
    buf.push('\n');
    border(buf, &widths, '├', '┼', '┤');
    for row in rows {
        buf.push_str(" │");
        for (i, cell) in row.iter().enumerate().take(ncols) {
            let w = widths[i];
            if aligns.get(i).copied().unwrap_or(b'l') == b'r' {
                buf.push_str(&format!(" {cell:>w$} │"));
            } else {
                buf.push_str(&format!(" {cell:<w$} │"));
            }
        }
        buf.push('\n');
    }
    border(buf, &widths, '└', '┴', '┘');
}

/// Append a horizontal table border with the given corner/junction glyphs.
fn border(buf: &mut String, widths: &[usize], left: char, mid: char, right: char) {
    buf.push(' ');
    buf.push(left);
    let n = widths.len();
    for (i, w) in widths.iter().enumerate() {
        for _ in 0..(w + 2) {
            buf.push('─');
        }
        if i + 1 < n {
            buf.push(mid);
        }
    }
    buf.push(right);
    buf.push('\n');
}

/// Split one CSV record (RFC-4180 quoting; mirrors [`super::csv`]).
fn parse_record(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => out.push(std::mem::take(&mut field)),
                _ => field.push(c),
            }
        }
    }
    out.push(field);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_csv() -> String {
        // Header subset + two throughput rows and one latency row.
        let header = "scenario,transport,protocol,message_bytes,connections,\
            throughput_gbps_mean,throughput_gbps_ci95,latency_mean_us,latency_p99_us_mean,\
            loss_pct,headroom,harness_limited,saturation_gbps,max_lossfree_gbps,\
            effective_protocol,rtt_us_mean,rtt_us_p50,rtt_us_p99,conns_per_sec,\
            conn_handshake_p50_us,conn_handshake_p99_us";
        let fast = "tcp_fast,tcp,none,1024,1,9.500,0.100,12.0,18.0,0.001,5.0,false,\
            0,0,none,0,0,0,0,0,0";
        let slow = "ktls_slow,tcp,ktls/1.3,1024,1,3.200,0.050,40.0,80.0,0.010,2.0,true,\
            0,0,ktls/1.3,0,0,0,0,0,0";
        let lat = "lat_tcp,tcp,none,256,1,0,0,30.0,55.0,0.000,0,false,0,0,none,0,0,0,0,0,0";
        format!("{header}\r\n{fast}\r\n{slow}\r\n{lat}\r\n")
    }

    #[test]
    fn parses_rows_by_header_name() {
        let rows = parse_summary(&sample_csv());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].scenario, "tcp_fast");
        assert!((rows[0].throughput_mean - 9.5).abs() < 1e-9);
        assert!(rows[1].harness_limited);
        assert_eq!(rows[2].scenario, "lat_tcp");
        assert!((rows[2].latency_p99_us - 55.0).abs() < 1e-9);
    }

    #[test]
    fn parse_record_handles_quotes_and_commas() {
        let f = parse_record(r#"a,"b,c","say ""hi""",d"#);
        assert_eq!(f, vec!["a", "b,c", "say \"hi\"", "d"]);
    }

    #[test]
    fn overview_orders_leaderboard_by_throughput_desc() {
        let report = render_overview(&parse_summary(&sample_csv()));
        assert!(report.contains("PERFORMANCE OVERVIEW"));
        assert!(report.contains("Throughput Leaderboard"));
        // The faster scenario must appear before the slower one in the report.
        let fast = report.find("tcp_fast").expect("fast present");
        let slow = report.find("ktls_slow").expect("slow present");
        assert!(
            fast < slow,
            "leaderboard should rank tcp_fast above ktls_slow"
        );
        // Latency rows are excluded from the leaderboard ranking.
        assert!(report.contains("One-Way Latency"));
        // Harness-limited footnote is present because ktls_slow is flagged.
        assert!(report.contains("harness-limited"));
    }

    #[test]
    fn empty_input_yields_empty_report() {
        assert!(render_overview(&[]).is_empty());
        assert!(parse_summary("").is_empty());
    }
}
