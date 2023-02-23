#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use exe::HandlerA;
use exe::HandlerB;
use exe::EXE;
use logging::setup_logging;

#[macro_use]
extern crate eyre;

#[macro_use]
extern crate tracing;

mod exe;
mod logging;
mod serde;

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    EXE.init(HandlerB).unwrap();
    EXE.say_hi();
}

