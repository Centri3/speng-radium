use eyre::Result;
use once_cell::sync::OnceCell;

pub static EXE: Exe = Exe::__define();

#[repr(transparent)]
pub struct Exe {
    inner: OnceCell<Box<dyn ExeHandler + Send + Sync>>,
}

impl Exe {
    const fn __define() -> Self {
        Self {
            inner: OnceCell::new(),
        }
    }

    pub fn init(&self, handler: impl ExeHandler + Send + Sync + 'static) -> Result<()> {
        self.inner
            .set(Box::new(handler))
            .map_err(|_| eyre!("lol"))?;

        Ok(())
    }

    pub fn say_hi(&self) {
        self.inner.get().unwrap().say_hi();
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
