#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod exe;
mod logging;
mod serde;
mod utils;

use exe::exe;
use exe::handlers::file::FileHandler;
use exe::ExeHandler;
use logging::setup_logging;

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    let exe = exe(FileHandler::new("SpaceEngine.exe").unwrap());
}

mod tests {
    use crate::logging::setup_logging;

    #[test]
    fn a() {
        setup_logging().unwrap();
    }
}
