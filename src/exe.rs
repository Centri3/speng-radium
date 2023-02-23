//! TODO: Just see [`EXE`] and [`Exe`] for now.

use eyre::Result;
use once_cell::sync::OnceCell;

/// Type of `EXE.inner`. Typing [`Box<dyn ExeHandler + Send + Sync>`] over and
/// over again is time consuming, and really ugly.
type Inner = Box<dyn ExeHandler + Send + Sync>;

/// Global variable for [`Exe`]. Can be initialized by calling `EXE.init()`
pub static EXE: Exe = Exe::__define();

/// Abstraction over handling reading/writing to a file or running program.
/// Allows any type implementing [`ExeHandler`]. Should only be initialized
/// once. Also see [`EXE`].
#[repr(transparent)]
pub struct Exe {
    inner: OnceCell<Inner>,
}

impl Exe {
    /// Internal function to define [`EXE`].
    #[inline(always)]
    const fn __define() -> Self {
        Self {
            inner: OnceCell::new(),
        }
    }

    /// Internal function to reduce code repetition. Gets `EXE.inner`.
    #[inline(always)]
    fn __inner(&self) -> Result<&Inner> {
        self.inner.get().ok_or_else(|| eyre!("a"))
    }

    /// Initialize [`EXE`] with `handler`. `handler` must be an [`ExeHandler`].
    /// Don't call this twice (at least successfully).
    #[inline]
    pub fn init<H: ExeHandler + Send + Sync + 'static>(&self, handler: H) -> Result<()> {
        self.inner
            .set(Box::new(handler))
            .map_err(|_| eyre!("lol"))?;

        Ok(())
    }

    pub fn say_hi(&self) {
        self.__inner().unwrap().say_hi();
    }
}

pub struct HandlerA;

impl ExeHandler for HandlerA {
    fn say_hi(&self) {
        println!("hi from HandlerA");
    }
}

pub struct HandlerB;

impl ExeHandler for HandlerB {
    fn say_hi(&self) {
        println!("hi from HandlerB");
    }
}

pub trait ExeHandler {
    fn say_hi(&self);
}
