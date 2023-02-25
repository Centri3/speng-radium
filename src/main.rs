#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod exe;
mod logging;
mod serde;
mod utils;
use logging::setup_logging;

use exe::exe;
use exe::handlers::file::FileHandler;
use exe::ExeHandler;

check_target!();

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    let exe = exe(FileHandler::new("SpaceEngine.exe").unwrap());

    tracing::info!("{:x?}", exe.0.read().read_to::<u32>(0x2780009000).unwrap());
}
