#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod exe;
mod logging;

use exe::exe;
use exe::handlers::file::FileHandler;
use exe::headers::NtImage;
use logging::setup_logging;

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    let exe = exe(FileHandler::new("SpaceEngine.exe").unwrap());
    NtImage::from_exe(exe).unwrap();
}
