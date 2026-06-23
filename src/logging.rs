//! Level-based logging (F-16). A small `log::Log` implementation that writes to
//! stderr with coloured level tags, honouring the `--log-level` and `--quiet`
//! global flags. Using the `log` facade keeps call sites simple
//! (`log::info!(...)`) while giving us full control over formatting.

use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::console;

struct SeshatLogger {
    level: LevelFilter,
}

impl Log for SeshatLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let tag = match record.level() {
            Level::Error => console::red("ERROR"),
            Level::Warn => console::yellow("WARN "),
            Level::Info => console::green("INFO "),
            Level::Debug => console::dim("DEBUG"),
            Level::Trace => console::dim("TRACE"),
        };
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "[{tag}] {}", record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

/// Initialise the global logger. Call once, after [`console::init`].
///
/// In quiet mode the floor is raised to warnings so routine progress is
/// suppressed while errors/warnings still surface.
pub fn init(level: LevelFilter, quiet: bool) {
    let effective = if quiet {
        level.min(LevelFilter::Warn)
    } else {
        level
    };
    let logger = SeshatLogger { level: effective };
    // Safe to ignore the error: it only fails if a logger is already set, which
    // never happens because we initialise exactly once at start-up.
    let _ = log::set_boxed_logger(Box::new(logger));
    log::set_max_level(effective);
}
