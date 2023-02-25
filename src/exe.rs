//! TODO: Just see [`exe`] and [`Exe`] for now.

pub mod handlers;

use crate::utils::short_type_name;
use bytemuck::bytes_of;
use bytemuck::from_bytes;
use bytemuck::Pod;
use eyre::eyre;
use eyre::Result;
use parking_lot::RwLock;
use std::fmt::Debug;
use std::mem::size_of;
use std::slice::SliceIndex;
use tracing::instrument;
use tracing::trace;

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
        // TODO: Log stuff here
        Self(RwLock::new(handler))
    }
}

pub trait ExeHandler {
    fn read(&self, index: usize) -> Result<u8>;

    fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>;

    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.read_many(index..index + size_of::<P>())
            .map(|b| *from_bytes(&b))
    }

    #[inline]
    #[instrument(skip(self))]
    fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        // TODO: We want this to be automatically implemented
        todo!();
    }

    unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8>;

    unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>>;

    #[inline]
    #[instrument(skip(self))]
    unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.write_many(index, bytes_of(&value))
            .map(|b| *from_bytes(&b))
    }
}
