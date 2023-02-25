//! TODO: Just see [`EXE`] and [`Exe`] for now.

use std::fmt;
use std::ops::Range;
use std::ops::RangeBounds;
use std::slice::SliceIndex;

use crate::utils::short_type_name;
use eyre::Result;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;

/// Global variable for [`Exe`]. Can be initialized by calling `EXE.init()`
pub static EXE: Exe<HandlerA> = Exe::__define();

/// Abstraction over handling reading/writing to a file or running program.
/// Allows any type implementing [`ExeHandler`]. Should only be initialized
/// once. Also see [`EXE`].
pub struct Exe<E: ExeHandler>(OnceCell<RwLock<E>>);

impl<E: ExeHandler> Exe<E> {
    /// Internal function to define [`EXE`].
    #[inline]
    const fn __define() -> Self {
        Self(OnceCell::new())
    }

    /// Internal function to reduce code repetition. Gets `EXE.handler`, and
    /// panics if it's uninitialized.
    #[inline]
    fn __inner(&self) -> &RwLock<E> {
        self.0.get().expect("`EXE` was uninitialized!")
    }

    /// Initialize [`EXE`] with `handler`. `handler` must be an [`ExeHandler`].
    /// Don't call this twice (at least successfully).
    #[inline]
    #[instrument(skip(self, handler), fields(H = short_type_name::<H>()))]
    pub fn init<H: ExeHandler + Send + Sync + 'static>(&self, handler: H) -> Result<()> {
        info!("Initializing `EXE`");

        // self.0
        //     .set(Box::new(RwLock::new(handler)))
        //     .map_err(|_| eyre!("`EXE` was already initialized!"))?;

        Ok(())
    }
}

pub struct HandlerA;

impl ExeHandler for HandlerA {}

pub trait ExeHandler {
    // fn read(&self, index: usize) -> Result<u8>;

    // fn read_many(&self, range: Range<usize>) -> Result<Vec<u8>>;
}
