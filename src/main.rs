#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod logging;

use logging::setup_logging;

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");
}
