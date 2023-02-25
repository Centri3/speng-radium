use crate::exe::ExeHandler;
use eyre::eyre;
use eyre::Result;
use std::fmt::Debug;
use std::slice::SliceIndex;
use tracing::instrument;
use tracing::trace;

#[derive(Debug)]
pub struct FileHandler(Vec<u8>);

impl FileHandler {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl ExeHandler for FileHandler {
    #[inline]
    #[instrument(skip(self), fields(len = self.len()))]
    fn read(&self, index: usize) -> Result<u8> {
        self.0
            .get(index)
            .copied()
            .ok_or_else(|| eyre!("Index out of bounds"))
    }

    #[inline]
    #[instrument(skip(self), fields(len = self.len()))]
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
    #[instrument(skip(self), fields(len = self.len()))]
    unsafe fn write(&self, index: usize, value: u8) -> Result<u8> {
        todo!()
    }

    #[inline]
    #[instrument(skip(self), fields(len = self.len()))]
    unsafe fn write_many(&self, index: usize, value: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
