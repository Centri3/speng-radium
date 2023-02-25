//! TODO: Just see [`exe`] and [`Exe`] for now.

use crate::utils::short_type_name;
use bytemuck::Pod;
use eyre::Result;
use parking_lot::RwLock;
use std::slice::SliceIndex;

/// TODO: TBD
pub fn exe<H: ExeHandler>(handler: H) -> Exe<H> {
    Exe::new(handler)
}

/// Abstraction over handling reading/writing to a file or running program.
/// Allows any type implementing [`ExeHandler`]. Should only be initialized
/// once. Also see [`EXE`].
pub struct Exe<H: ExeHandler>(RwLock<H>);

impl<H: ExeHandler> Exe<H> {
    /// Construct [`Exe`]. Also see [`exe`].
    #[inline]
    #[instrument(skip(handler), fields(H = short_type_name::<H>()))]
    pub fn new(handler: H) -> Self {
        info!("Creating an `Exe`");

        Self(RwLock::new(handler))
    }
}

pub trait ExeHandler {
    fn read(&self, index: usize) -> Result<u8>;

    fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: SliceIndex<[u8], Output = [u8]>;

    fn read_to<P: Pod>(&self, index: usize) -> Result<P>;

    unsafe fn write(&self, index: usize, value: u8) -> Result<u8>;

    unsafe fn write_many<R>(&self, range: R, value: &[u8]) -> Result<Vec<u8>>
    where
        R: SliceIndex<[u8], Output = [u8]>;

    unsafe fn write_to<P: Pod>(&self, index: usize, value: P) -> Result<P>;
}
