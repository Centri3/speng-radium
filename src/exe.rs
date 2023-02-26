//! TODO: Just see [`exe`] and [`Exe`] for now.

pub mod handlers;
pub mod headers;

use self::headers::NtDirectory;
use self::headers::NtDirectoryEntry;
use self::headers::NtImage;
use self::headers::NtImageSections;
use self::headers::NtOptional;
use crate::utils::short_type_name;
use bytemuck::bytes_of;
use bytemuck::from_bytes;
use bytemuck::Pod;
use eyre::eyre;
use eyre::Result;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use parking_lot::RwLockWriteGuard;
use std::ffi::CString;
use std::fmt::Debug;
use std::mem::size_of;
use std::slice::SliceIndex;
use tracing::info;
use tracing::instrument;

// TODO: Docs.
#[inline(always)]
pub fn exe<H: ExeHandler>(handler: H) -> Exe<H> {
    Exe::new(handler)
}

/// Abstraction over handling reading/writing to a file or running program.
#[derive(Debug)]
pub struct Exe<H: ExeHandler>(RwLock<H>);

impl<H: ExeHandler> Exe<H> {
    /// Create an [`Exe`]. Also see [`exe`].
    #[inline]
    #[instrument(skip(handler), fields(H = short_type_name::<H>()))]
    pub fn new(handler: H) -> Self {
        info!("Creating `Exe`");

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
    #[inline]
    #[instrument(skip(self))]
    pub fn read(&self, index: usize) -> Result<u8> {
        self.reader().read(index)
    }

    /// Convenience function to call `read_many` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    #[inline]
    #[instrument(skip(self))]
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
    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    pub fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.reader().read_to(index)
    }

    /// Convenience function to call `read_to_string` on the provided
    /// [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    #[inline]
    #[instrument(skip(self))]
    pub fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        self.reader().read_to_string(index, size)
    }

    /// Convenience function to call `write` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler,
    /// then call `reader` or `writer` to get read/write access to your
    /// handler. You can then call said function.
    #[inline]
    #[instrument(skip(self))]
    pub unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        self.writer().write(index, value)
    }

    /// Convenience function to call `write_many` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    #[inline]
    #[instrument(skip(self))]
    pub unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>> {
        self.writer().write_many(index, value)
    }

    /// Convenience function to call `write_to` on the provided [`ExeHandler`]
    ///
    /// If you need a more specialized function provided by a handler, then call
    /// `reader` or `writer` to get read/write access to your handler. You can
    /// then call said function.
    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    pub unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.writer().write_to(index, value)
    }

    pub fn headers(&self) -> Result<NtImage> {
        static HEADERS: OnceCell<NtImage> = OnceCell::new();

        info!("Getting `Exe`'s headers");

        todo!();
    }

    pub fn __get_optional(&self) -> Result<NtOptional> {
        todo!();
    }

    pub fn __get_directory(&self) -> Result<NtDirectory> {
        todo!();
    }

    pub fn __get_directory_entry(&self) -> Result<NtDirectoryEntry> {
        todo!();
    }

    pub fn __get_sections(&self) -> Result<NtImageSections> {
        todo!();
    }
}

/// The backbone of a handler. Your handler for [`Exe`] must implement this.
///
/// This only contains read/write functions; if you need more specialized
/// functions (like saving to a file), then you can implement them for your
/// handler directly.
pub trait ExeHandler {
    /// Get the byte at `index`. This function is implemented automatically
    /// using `read_many`.
    fn read(&self, index: usize) -> Result<u8> {
        Ok(self.read_many(index..=index)?[0usize])
    }

    /// Get the bytes in `range`.
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

    /// Read bytes at `index` and cast to a [`String`]. The string has to be
    /// `NULL` terminated and UTF-8! Will panic if it contains a `NULL` byte
    /// (outside of trailing `NULL` bytes). This function is implemented
    /// automatically.
    ///
    /// You should only specify a size ([`Some`]) if its size is known,
    /// otherwise you should use [`None`].
    #[inline]
    #[instrument(skip(self))]
    fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        let bytes = match size {
            Some(size) => self.__read_to_string_some(index, size),
            None => self.__read_to_string_none(index),
        }?;

        // We use [`CString`] here to return [`Err`] if it has `NULL`.
        Ok(CString::new(bytes.as_slice())?.to_str()?.to_string())
    }

    /// Extracted from `read_to_string`
    #[inline(always)]
    fn __read_to_string_some(&self, index: usize, size: usize) -> Result<Vec<u8>> {
        let bytes = self.read_many(index..index + size)?;

        // Number of `NULL` bytes at the end of `bytes`
        let num_of_nulls = bytes
            .rsplit(|&b| b != 0u8)
            .next()
            .expect("This is unreachable.")
            .len();

        Ok(bytes[..bytes.len() - num_of_nulls].to_vec())
    }

    /// Extracted from `read_to_string`
    #[inline(always)]
    fn __read_to_string_none(&self, index: usize) -> Result<Vec<u8>> {
        // This is quite slow, as every call to `read_many` has to create a
        // [`Vec<u8>`]. It's not a big loss, though, only ~3ms here
        // TODO: This is a stupid way of doing this
        Ok(self
            .read_many(index..)?
            .split(|&b| b == 0u8)
            .next()
            .expect("Same here.")
            .to_vec())
    }

    /// Write the byte in `value` to `index`. Returns the previous byte, which
    /// can be ignored. This function is implemented automatically using
    /// `write_many`.
    unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        Ok(self.write_many(index, &[value])?[0usize])
    }

    /// Write the bytes in `value` to `index`. Returns the previous bytes, which
    /// can be ignored.
    unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>>;

    /// Convenience function to call `write_many` with the bytes of `P`. `P`
    /// must implement [`Pod`]!. This function is implemented automatically.
    /// Returns the previous bytes, casted to `P`, which can be ignored.
    #[inline]
    #[instrument(skip(self), fields(P = short_type_name::<P>()))]
    unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.write_many(index, bytes_of(&value))
            .map(|b| *from_bytes(&b))
    }
}
