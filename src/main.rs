use exe::{EXE, HandlerA, HandlerB};

#[macro_use]
extern crate eyre;

#[macro_use]
extern crate tracing;

mod exe;
mod serde;

fn main() {
    EXE.init(HandlerB).unwrap();

    EXE.say_hi();
}
