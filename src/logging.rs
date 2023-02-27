//! TODO: Just see [`setup_logging`] for now.

use color_eyre::config::HookBuilder;
use eyre::Result;
use eyre::WrapErr;
use std::env;
use std::fs;
use std::io;
use std::panic;
use tracing::error;
use tracing::trace;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::never;
use tracing_error::ErrorLayer;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::{self};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;
use tracing_subscriber::EnvFilter;

/// Sets up logging, courtesy of [`tracing`]. Will write to `radium.log` and
/// `stdout`. Note that on release mode, `stdout`, while written to, is not
/// viewable.
#[inline(always)]
pub fn setup_logging() -> Result<WorkerGuard> {
    // Backtrace should only be enabled in debug mode
    #[cfg(debug_assertions)]
    env::set_var("RUST_BACKTRACE", "full");

    // We don't care if this fails, as it means the log didn't exist already
    fs::remove_file("radium.log").ok();

    let (log_file, guard) = tracing_appender::non_blocking(never("", "radium.log"));

    __setup_tracing(log_file)?;
    
    __setup_hooks()?;

    trace!("Logging successfully setup");

    // Return guard to guarantee everything is logged before closing
    Ok(guard)
}

/// Extracted from `__setup_logging()`
#[inline(always)]
fn __setup_tracing(log_file: NonBlocking) -> Result<()> {
    // We want logs in release mode to be a little less verbose
    #[cfg(debug_assertions)]
    const ENV_FILTER: &str = "trace";
    #[cfg(not(debug_assertions))]
    const ENV_FILTER: &str = "debug";

    // FIXME: This writes to stdout even in release mode, where it isn't visible.
    // This should be fixed.
    let fmt_layer = fmt::layer()
        .with_writer(log_file.and(io::stdout))
        .with_thread_names(true);

    registry()
        .with(ErrorLayer::default())
        .with(EnvFilter::try_new(ENV_FILTER)?)
        .with(fmt_layer)
        .init();

    Ok(())
}

/// Extracted from `__setup_logging()`
#[inline(always)]
fn __setup_hooks() -> Result<()> {
    // Setup color-eyre with custom settings
    let (ph, eh) = HookBuilder::default()
        .display_env_section(false)
        .panic_section("Please report this at: https://github.com/Centri3/speng-starb/issues/new")
        .into_hooks();

    eh.install().wrap_err("Failed to install color-eyre")?;

    panic::set_hook(Box::new(move |pi| {
        error!(
            "Panicked, handing off to color-eyre:\n\n{}",
            ph.panic_report(pi),
        );
    }));

    Ok(())
}
