#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_use]
extern crate eyre;

#[macro_use]
extern crate tracing;

mod exe;
mod logging;
mod serde;
mod utils;
use logging::setup_logging;

check_target!();

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");
}
