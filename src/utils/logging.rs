use color_eyre::config::HookBuilder;
use eyre::Result;
use eyre::WrapErr;
use std::env;
use std::fs;
use std::io::stdout;
use std::panic;
use tracing::error;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::never;
use tracing_error::ErrorLayer;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Default, Eq, PartialEq)]
pub enum SetupFile {
    #[default]
    Retain,
    Overwrite,
}

#[inline]
pub fn setup(setup_file: &SetupFile) -> WorkerGuard {
    try_setup(setup_file).expect("Failed to setup logging")
}

#[inline]
pub fn try_setup(setup_file: &SetupFile) -> Result<WorkerGuard> {
    #[cfg(debug_assertions)]
    env::set_var("RUST_BACKTRACE", "full");

    if *setup_file == SetupFile::Overwrite {
        // We don't care if this fails, as it means the log didn't exist already
        _ = fs::remove_file("radium.log");
    }

    let (log_file, guard) = tracing_appender::non_blocking(never("", "radium.log"));

    __setup_tracing(log_file)?;

    __setup_hooks()?;

    // Return guard to guarantee everything is logged before closing
    Ok(guard)
}

#[inline(always)]
fn __setup_tracing(log_file: NonBlocking) -> Result<()> {
    let fmt_layer = fmt::layer()
        .with_writer(log_file.and(stdout))
        .with_thread_names(true);

    registry()
        .with(ErrorLayer::default())
        .with(EnvFilter::try_new("[loader],[libradium]")?)
        .with(fmt_layer)
        .init();

    Ok(())
}

#[inline(always)]
fn __setup_hooks() -> Result<()> {
    // Setup color-eyre with custom settings
    let (ph, eh) = HookBuilder::default()
        .display_env_section(false)
        .panic_section("Please report this at: https://github.com/Centri3/speng-radium/issues/new")
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
