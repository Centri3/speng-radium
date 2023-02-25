//! TODO:

use crate::exe::ExeHandler;
use eyre::eyre;
use eyre::Result;
use std::fmt::Debug;
use std::fs;
use std::mem::replace;
use std::slice::SliceIndex;
use tracing::instrument;

#[derive(Debug)]
pub struct FileHandler(Vec<u8>);

impl FileHandler {
    #[inline]
    #[instrument]
    pub fn new(path: impl AsRef<str> + Debug) -> Result<Self> {
        Ok(Self(fs::read(path.as_ref())?))
    }
}

impl ExeHandler for FileHandler {
    #[inline]
    #[instrument(skip(self), fields(len = self.0.len()))]
    fn read(&self, index: usize) -> Result<u8> {
        // This is a faster implementation of this
        self.0
            .get(index)
            .copied()
            .ok_or_else(|| eyre!("Index out of bounds"))
    }

    #[inline]
    #[instrument(skip(self), fields(len = self.0.len()))]
    fn read_many<R>(&self, range: R) -> Result<Vec<u8>>
    where
        R: Debug + SliceIndex<[u8], Output = [u8]>,
    {
        self.0
            .get(range)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| eyre!("Index out of bounds"))
    }

    #[inline]
    #[instrument(skip(self), fields(len = self.0.len()))]
    unsafe fn write(&mut self, index: usize, value: u8) -> Result<u8> {
        // This is a faster implementation of this
        Ok(replace(
            self.0
                .get_mut(index)
                .ok_or_else(|| eyre!("Index out of bounds"))?,
            value,
        ))
    }

    #[inline]
    #[instrument(skip(self), fields(len = self.0.len()))]
    unsafe fn write_many(&mut self, index: usize, value: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .0
            .splice(index..index + value.len(), value.to_vec())
            .collect())
    }
}
