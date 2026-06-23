//! Console UI primitives: banner, section rules, key/value rows, boxed tables,
//! and status glyphs. Output is plain ASCII/Unicode with optional ANSI colour
//! that is automatically disabled when stdout is not a TTY or `NO_COLOR` is set.
//!
//! The visual language uses:
//! - `══════` double-line rules for major section breaks
//! - `──────` single-line rules for sub-sections
//! - `┌─┬─┐ │ │ │ ├─┼─┤ └─┴─┘` box-drawing for data tables
//! - Consistent SI units: Gbit/s, µs, %, conn/s
//!
//! Some helpers are consumed by later work packages (validate/list/sysinfo);
//! `dead_code` is allowed while the harness is built out.
#![allow(dead_code)]

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum line width for formatted output (fits an 80-col terminal with margin).
pub const WIDTH: usize = 72;

/// Tagline shown under the banner.
pub const TAGLINE: &str = "SCG Evaluation, Stress & Harness Analysis Toolkit";

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);
static QUIET: AtomicBool = AtomicBool::new(false);

/// Initialise console behaviour. Call once at start-up.
///
/// * `quiet` suppresses the banner and all non-essential decorative output.
pub fn init(quiet: bool) {
    let color = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
    COLOR_ENABLED.store(color, Ordering::Relaxed);
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Whether colour output is currently enabled.
pub fn color_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

/// Whether quiet mode is active.
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

fn paint(code: &str, text: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Green text (success).
pub fn green(text: &str) -> String {
    paint("32", text)
}

/// Red text (failure).
pub fn red(text: &str) -> String {
    paint("31", text)
}

/// Yellow text (warning).
pub fn yellow(text: &str) -> String {
    paint("33", text)
}

/// Dim text (secondary information).
pub fn dim(text: &str) -> String {
    paint("2", text)
}

/// Bold text.
pub fn bold(text: &str) -> String {
    paint("1", text)
}

/// Success glyph (`✔`).
pub fn check() -> String {
    green("✔")
}

/// Failure glyph (`✖`).
pub fn cross() -> String {
    red("✖")
}

/// Warning glyph (`⚠`).
pub fn warn() -> String {
    yellow("⚠")
}

/// Print the SESHAT banner with version + tagline. No-op in quiet mode.
pub fn banner() {
    if is_quiet() {
        return;
    }
    let art = r#"
███████╗███████╗███████╗██╗  ██╗ █████╗ ████████╗
██╔════╝██╔════╝██╔════╝██║  ██║██╔══██╗╚══██╔══╝
███████╗█████╗  ███████╗███████║███████║   ██║   
╚════██║██╔══╝  ╚════██║██╔══██║██╔══██║   ██║   
███████║███████╗███████║██║  ██║██║  ██║   ██║   
╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
"#;
    println!("{}", bold(art.trim_end_matches('\n')));
    println!(
        "    v{} | {}",
        env!("CARGO_PKG_VERSION"),
        dim(TAGLINE)
    );
    println!();
}

/// Print a left-aligned section rule, e.g. ` ── Title ─────────────────────`.
pub fn rule(title: &str) {
    let prefix = format!(" ── {title} ");
    let dashes = WIDTH.saturating_sub(prefix.chars().count());
    println!("{}{}", prefix, "─".repeat(dashes));
}

/// Print a `label : value` row aligned to `label_width` columns.
pub fn kv(label: &str, value: &str, label_width: usize) {
    println!("  {label:<label_width$}: {value}");
}

/// Print a raw line of text to stdout.
pub fn line(text: &str) {
    println!("{text}");
}

/// Print a closing rule (a full-width line of `─`).
pub fn end_rule() {
    println!(" {}", "─".repeat(WIDTH - 1));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scientific section & table primitives
// ═══════════════════════════════════════════════════════════════════════════════

/// Print a major section header using double-line box-drawing:
/// `══════ TITLE ══════════════════════════════════════════════════`
pub fn section(title: &str) {
    let prefix = format!("═══ {} ", title);
    let fill = WIDTH.saturating_sub(prefix.chars().count());
    let line = format!("{}{}", prefix, "═".repeat(fill));
    println!("{}", bold(&line));
}

/// Print a boxed scenario/result card.
/// `card_title` is shown in the top border; `rows` are `(label, value)` pairs.
pub fn card(card_title: &str, rows: &[(&str, String)]) {
    let inner = WIDTH - 4; // 2 for `│ ` + 2 for ` │`
    // Top border with optional title
    if card_title.is_empty() {
        println!(" ┌{}┐", "─".repeat(inner + 2));
    } else {
        let title_str = format!("─ {} ", card_title);
        let rest = (inner + 2).saturating_sub(title_str.chars().count());
        println!(" ┌{}{}┐", title_str, "─".repeat(rest));
    }
    // Find max label width for alignment
    let max_label = rows.iter().map(|(l, _)| l.chars().count()).max().unwrap_or(0);
    for (label, value) in rows {
        let content = format!("{:<width$}  │  {}", label, value, width = max_label);
        let pad = inner.saturating_sub(content.chars().count());
        println!(" │ {}{} │", content, " ".repeat(pad));
    }
    // Bottom border
    println!(" └{}┘", "─".repeat(inner + 2));
}

/// Print a single boxed line (used for run progress inside a card context).
pub fn card_line(text: &str) {
    let inner = WIDTH - 4;
    let pad = inner.saturating_sub(text.chars().count());
    println!(" │ {}{} │", text, " ".repeat(pad));
}

/// Print a table with box-drawing borders. `headers` and `rows` are slices of
/// string slices, each slice having the same number of columns.
/// `alignments` specifies per-column alignment: 'l' = left, 'r' = right.
pub fn table(headers: &[&str], rows: &[Vec<String>], alignments: &[u8]) {
    if headers.is_empty() {
        return;
    }
    let ncols = headers.len();
    // Compute column widths: max of header width and all row cell widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(ncols) {
            let w = cell.chars().count();
            if w > widths[i] {
                widths[i] = w;
            }
        }
    }
    // Clamp total width
    let total: usize = widths.iter().sum::<usize>() + 3 * ncols + 1; // │ + spaces
    if total > WIDTH + 10 {
        // Shrink first column to fit
        let excess = total - WIDTH;
        if widths[0] > excess + 4 {
            widths[0] -= excess;
        }
    }

    // Draw top border: ┌──────┬──────┬──────┐
    print!(" ┌");
    for (i, w) in widths.iter().enumerate() {
        print!("{}", "─".repeat(w + 2));
        if i < ncols - 1 {
            print!("┬");
        }
    }
    println!("┐");

    // Draw header row
    print!(" │");
    for (i, hdr) in headers.iter().enumerate() {
        print!(" {:<width$} │", hdr, width = widths[i]);
    }
    println!();

    // Draw header separator: ├──────┼──────┼──────┤
    print!(" ├");
    for (i, w) in widths.iter().enumerate() {
        print!("{}", "─".repeat(w + 2));
        if i < ncols - 1 {
            print!("┼");
        }
    }
    println!("┤");

    // Draw data rows
    for row in rows {
        print!(" │");
        for (i, cell) in row.iter().enumerate().take(ncols) {
            let w = widths[i];
            let align = alignments.get(i).copied().unwrap_or(b'l');
            if align == b'r' {
                print!(" {:>width$} │", cell, width = w);
            } else {
                print!(" {:<width$} │", cell, width = w);
            }
        }
        println!();
    }

    // Draw bottom border: └──────┴──────┴──────┘
    print!(" └");
    for (i, w) in widths.iter().enumerate() {
        print!("{}", "─".repeat(w + 2));
        if i < ncols - 1 {
            print!("┴");
        }
    }
    println!("┘");
}
