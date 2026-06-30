//! Live benchmark progress: a ticking elapsed timer, spinner, bar, and the
//! currently-running scenario, rendered with `indicatif`.
//!
//! The default console view is compact — the detailed per-run/calibration/result
//! renderers are suppressed (see [`crate::console::is_verbose`]) in favour of
//! this bar plus one result line per finished scenario. The view adapts to the
//! environment:
//!
//! * **default + TTY** — an animated bar with a steadily-advancing elapsed
//!   timer; each finished scenario prints one compact line above the bar.
//! * **default + non-TTY** (piped/CI) — no animation; a discrete start line and
//!   a compact result line per scenario, so transcripts stay clean.
//! * **`--verbose`** — no animated bar; a discrete `[elapsed] [i/total] ▶ name`
//!   line precedes each scenario's full detail (so elapsed + current test are
//!   still always visible).
//! * **`--quiet`** — nothing here; only warnings/errors and the final report.

use std::io::IsTerminal;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};

use crate::config::Scenario;
use crate::console;

/// The currently-active *live* progress bar, if any. The logger consults this so
/// its lines print cleanly above the bar (via `suspend`) instead of colliding
/// with it on stderr. `None` whenever no animated bar is drawing
/// (quiet/non-TTY/verbose), in which case logging writes directly.
static ACTIVE_BAR: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// Run `f` while any active live progress bar is suspended, so other stderr
/// output (the logger) prints cleanly above the bar rather than smearing onto
/// it. When no live bar is active, `f` runs directly.
pub fn with_suspended_bar(f: impl FnOnce()) {
    let bar = ACTIVE_BAR.lock().ok().and_then(|slot| slot.clone());
    match bar {
        Some(b) => b.suspend(f),
        None => f(),
    }
}

/// A live progress handle for one benchmark run or suite.
pub struct Progress {
    bar: ProgressBar,
    /// Animated bar with a steady tick (default mode on a TTY).
    live: bool,
    /// Emit a discrete `[elapsed] [i/total] ▶ name` line per scenario (verbose
    /// mode, or default mode without a TTY — never in quiet mode).
    announce: bool,
    /// Print one compact result line per finished scenario (default mode; in
    /// verbose mode the detailed renderers already show the result).
    compact: bool,
    started: Instant,
}

impl Progress {
    /// Start progress tracking over `total` scenarios. The display mode is
    /// derived from the global console flags (`--quiet`/`--verbose`) and whether
    /// stderr is a terminal.
    pub fn start(total: usize) -> Self {
        let tty = std::io::stderr().is_terminal();
        let quiet = console::is_quiet();
        let verbose = console::is_verbose();
        let live = tty && !quiet && !verbose;
        let announce = !quiet && !live;
        let compact = !quiet && !verbose;

        let bar = if live {
            let pb = ProgressBar::new(total as u64);
            pb.set_style(style(console::color_enabled()));
            pb.enable_steady_tick(Duration::from_millis(120));
            pb
        } else {
            ProgressBar::hidden()
        };
        // Register the live bar so the logger can suspend it around its writes.
        if live {
            if let Ok(mut slot) = ACTIVE_BAR.lock() {
                *slot = Some(bar.clone());
            }
        }

        Progress {
            bar,
            live,
            announce,
            compact,
            started: Instant::now(),
        }
    }

    /// `MM:SS` wall time since this run started.
    fn elapsed_tag(&self) -> String {
        let s = self.started.elapsed().as_secs();
        format!("{:02}:{:02}", s / 60, s % 60)
    }

    /// Announce that scenario `idx` (0-based) of `total` is starting.
    pub fn start_scenario(&self, idx: usize, total: usize, scenario: &Scenario) {
        if self.live {
            let mut msg = format!("running {}", scenario.name);
            if console::is_describe() {
                msg.push_str(&format!(" — {}", scenario.describe()));
            }
            self.bar.set_message(msg);
        } else if self.announce {
            let mut line = format!(
                "[{}] [{}/{}] \u{25b6} {}",
                self.elapsed_tag(),
                idx + 1,
                total,
                scenario.name
            );
            if console::is_describe() {
                line.push_str(&format!(" — {}", scenario.describe()));
            }
            println!("{}", console::dim(&line));
        }
    }

    /// Mark the current scenario finished, advancing the bar and (in compact
    /// mode) printing `compact_line` above it.
    pub fn finish_scenario(&self, compact_line: &str) {
        self.bar.inc(1);
        if !self.compact {
            return;
        }
        if self.live {
            self.bar.suspend(|| println!("{compact_line}"));
        } else {
            println!("{compact_line}");
        }
    }

    /// Clear the bar so the final report renders against a clean line, and
    /// deregister it from the logger coordination slot.
    pub fn finish(&self) {
        if let Ok(mut slot) = ACTIVE_BAR.lock() {
            *slot = None;
        }
        self.bar.finish_and_clear();
    }

    /// Wall time since this run started.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Build the bar template, dropping ANSI colour when `color` is false.
fn style(color: bool) -> ProgressStyle {
    let template = if color {
        "{spinner:.green} {elapsed_precise} {bar:18.cyan/blue} {pos}/{len} \u{2502} {wide_msg}"
    } else {
        "{spinner} {elapsed_precise} {bar:18} {pos}/{len} \u{2502} {wide_msg}"
    };
    ProgressStyle::with_template(template)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("\u{2588}\u{2589}\u{258a}\u{258b}\u{258c}\u{258d}\u{258e}\u{258f} ")
}
