//! SESHAT — the SCG benchmark harness.
//!
//! `main` parses the CLI, initialises the console and logger, then dispatches to
//! the selected subcommand. Command handlers live in [`commands`]; as the
//! phases land they are filled in (config/validate/list/sysinfo first).

mod cli;
mod commands;
mod config;
mod console;
mod gateway;
mod logging;
mod matrix;
mod metrics;
mod pki;
mod proto;
mod report;
mod run;
mod sysinfo;
mod time;
mod topology;
mod transport;
mod workload;

use std::process::ExitCode;

use clap::Parser;

use cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();

    console::init(cli.quiet);
    logging::init(cli.log_level.into(), cli.quiet);

    match commands::dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
