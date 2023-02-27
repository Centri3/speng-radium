pub mod handlers;
pub mod headers;

use bytemuck::bytes_of;
use bytemuck::from_bytes;
use bytemuck::Pod;
use eyre::eyre;
use eyre::Result;
use parking_lot::RwLock;
use parking_lot::RwLockReadGuard;
use parking_lot::RwLockWriteGuard;
use std::any::type_name;
use std::ffi::CString;
use std::fmt::Debug;
use std::mem::size_of;
use std::slice::SliceIndex;
use tracing::info;
use tracing::instrument;

#[inline(always)]
pub fn exe<H: ExeHandler>(handler: H) -> Exe<H> {
    Exe::new(handler)
}

#[derive(Debug)]
pub struct Exe<H: ExeHandler>(RwLock<H>);

impl<H: ExeHandler> Exe<H> {
    #[inline]
    #[instrument(skip(handler), fields(H = type_name::<H>()))]
    pub fn new(handler: H) -> Self {
        info!("Creating `Exe`");

        Self(RwLock::new(handler))
    }

    #[inline]
    pub fn reader(&self) -> RwLockReadGuard<H> {
        self.0.read()
    }

    #[inline]
    pub fn writer(&self) -> RwLockWriteGuard<H> {
        self.0.write()
    }

    #[inline]
    #[instrument(skip(self))]
    pub fn try_reader(&self) -> Result<RwLockReadGuard<H>> {
        self.0
            .try_read()
            .ok_or_else(|| eyre!("Could not get exclusive read access"))
    }

    #[inline]
    #[instrument(skip(self))]
    pub fn try_writer(&self) -> Result<RwLockWriteGuard<H>> {
        self.0
            .try_write()
            .ok_or_else(|| eyre!("Could not get exclusive write access"))
    }

    #[inline]
    pub fn handler_type(&self) -> ExeHandlerType {
        self.reader().handler_type()
    }

    #[inline]
    #[instrument(skip(self))]
    pub fn read(&self, index: usize) -> Result<u8> {
        self.reader().read(index)
    }

    #[inline]
    #[instrument(skip(self))]
    pub fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>,
    {
        self.reader().read_many(range)
    }

    #[inline]
    #[instrument(skip(self), fields(P = type_name::<P>()))]
    pub fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.reader().read_to(index)
    }

    #[inline]
    #[instrument(skip(self))]
    pub unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        self.writer().write(index, value)
    }

    #[inline]
    #[instrument(skip(self))]
    pub unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>> {
        self.writer().write_many(index, value)
    }

    #[inline]
    #[instrument(skip(self), fields(P = type_name::<P>()))]
    pub unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.writer().write_to(index, value)
    }

    #[inline]
    #[instrument(skip(self))]
    pub fn read_to_string(&self, index: usize, size: Option<usize>) -> Result<String> {
        let bytes = match size {
            Some(size) => self.read_to_string_some(index, size),
            None => self.read_to_string_none(index),
        }?;

        // We use CString here to return Err if it has NULL.
        Ok(CString::new(bytes.as_slice())?.to_str()?.to_string())
    }

    #[inline(always)]
    fn read_to_string_some(&self, index: usize, size: usize) -> Result<Vec<u8>> {
        let bytes = self.read_many(index..index + size)?;

        // Number of `NULL` bytes at the end of `bytes`
        let num_of_nulls = bytes
            .rsplit(|&b| b != 0u8)
            .next()
            .expect("This is unreachable.")
            .len();

        Ok(bytes[..bytes.len() - num_of_nulls].to_vec())
    }

    #[inline(always)]
    fn read_to_string_none(&self, index: usize) -> Result<Vec<u8>> {
        // TODO: This is a stupid way of doing this
        Ok(self
            .read_many(index..)?
            .split(|&b| b == 0u8)
            .next()
            .expect("Same here.")
            .to_vec())
    }
}

pub trait ExeHandler {
    fn handler_type(&self) -> ExeHandlerType;

    fn read(&self, index: usize) -> Result<u8> {
        Ok(self.read_many(index..=index)?[0usize])
    }

    fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>;

    #[inline]
    #[instrument(skip(self), fields(P = type_name::<P>()))]
    fn read_to<P: Pod>(&self, index: usize) -> Result<P> {
        self.read_many(index..index + size_of::<P>())
            .map(|b| *from_bytes(&b))
    }

    unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        Ok(self.write_many(index, &[value])?[0usize])
    }

    unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>>;

    #[inline]
    #[instrument(skip(self), fields(P = type_name::<P>()))]
    unsafe fn write_to<P: Debug + Pod>(&mut self, index: usize, value: P) -> Result<P> {
        self.write_many(index, bytes_of(&value))
            .map(|b| *from_bytes(&b))
    }
}

#[derive(Debug)]
pub enum ExeHandlerType {
    RawData,
    Virtual,
}
