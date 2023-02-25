//! TODO: Just see [`exe`] and [`Exe`] for now.

pub mod handlers;

use crate::utils::short_type_name;
use bytemuck::bytes_of;
use bytemuck::from_bytes;
use bytemuck::Pod;
use eyre::eyre;
use eyre::Result;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use parking_lot::RwLockWriteGuard;
use std::fmt::Debug;
use std::mem::size_of;
use std::slice::SliceIndex;
use tracing::instrument;

pub fn exe<H: ExeHandler>(handler: H) -> Exe<H> {
    Exe::new(handler)
}

/// Abstraction over handling reading/writing to a file or running program.
/// Allows any type implementing [`ExeHandler`]. Should only be initialized
/// once. Also see [`EXE`].
#[derive(Debug)]
pub struct Exe<H: ExeHandler>(RwLock<H>);

impl<H: ExeHandler> Exe<H> {
    /// Construct [`Exe`]. Also see [`exe`].
    #[inline]
    #[instrument(skip(handler), fields(H = short_type_name::<H>()))]
    pub fn new(handler: H) -> Self {
        // TODO: Log stuff here
        Self(RwLock::new(handler))
    }

    /// Get read access. Does not fail, though can dead-lock.
    #[inline]
    #[instrument(skip(self))]
    pub fn reader(&self) -> RwLockReadGuard<H> {
        self.0.read()
    }

    /// Get write access. Does not fail, though can dead-lock.
    #[inline]
    #[instrument(skip(self))]
    pub fn writer(&self) -> RwLockWriteGuard<H> {
        self.0.write()
    }

    /// Try to get exclusive read access. Does not block.
    #[inline]
    #[instrument(skip(self))]
    pub fn try_reader(&self) -> Result<RwLockReadGuard<H>> {
        self.0
            .try_read()
            .ok_or_else(|| eyre!("Could not get exclusive read access"))
    }

    /// Try to get exclusive write access. Does not block.
    #[inline]
    #[instrument(skip(self))]
    pub fn try_writer(&self) -> Result<RwLockWriteGuard<H>> {
        self.0
            .try_write()
            .ok_or_else(|| eyre!("Could not get exclusive write access"))
    }

    /// Convenience function to call `read` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub fn read(&self, index: usize) -> Result<u8> {
        self.reader().read(index)
    }

    /// Convenience function to call `read_many` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>,
    {
        self.reader().read_many(range)
    }

    /// Convenience function to call `read_to` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.reader().read_to(index)
    }

    /// Convenience function to call `read_to_string` on the provided
    /// [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        self.reader().read_to_string(index, size)
    }

    /// Convenience function to call `write` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub unsafe fn write(&self, index: usize, value: u8) -> Result<u8> {
        self.writer().write(index, value)
    }

    /// Convenience function to call `write_many` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub unsafe fn write_many(&self, index: usize, value: &[u8]) -> Result<Vec<u8>> {
        self.writer().write_many(index, value)
    }

    /// Convenience function to call `write_to` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    pub unsafe fn write_to<P: Debug + Pod>(&self, index: usize, value: P) -> Result<P> {
        self.writer().write_to(index, value)
    }
}

/// The backbone of a handler. Your handler for [`Exe`] must implement this.
///
/// This only contains read/write functions; if you need more specialized
/// functions (like saving to a file), then you can implement them for your
/// handler directly.
pub trait ExeHandler {
    fn read(&self, index: usize) -> Result<u8> {
        Ok(self.read_many(index..=index)?[0usize])
    }

    fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>;

    /// Convenience function to call `read_many` with the bytes of `P`. `P` must
    /// implement [`Pod`]!. This function is implemented automatically.
    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.read_many(index..index + size_of::<P>())
            .map(|b| *from_bytes(&b))
    }

    /// Read bytes at `index` and cast to a [`String`]. Will read until `NULL`
    /// is found or it's read `size` number of bytes. Will return [`Err`] if
    /// it's out of bounds or invalid UTF-8! Will also return [`Err`] if it
    /// has `NULL` outside of trailing `NULL` bytes. Don't read UTF-16.
    ///
    /// You should only specify a size ([`Some`]) if its size is known,
    /// otherwise you should use [`None`].
    #[inline]
    #[instrument(skip(self))]
    fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        // TODO: We want this to be automatically implemented
        todo!();
    }

    unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        Ok(self.write_many(index, &[value])?[0usize])
    }

    unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>>;

    /// Convenience function to call `write_many` with the bytes of `P`. `P`
    /// must implement [`Pod`]!. This function is implemented automatically.
    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.write_many(index, bytes_of(&value))
            .map(|b| *from_bytes(&b))
    }
}
