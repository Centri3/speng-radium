use crate::utils::__query_range_checked;
use crate::utils::__round_to_page_boundaries;
use hashbrown::HashSet;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use region::page;
use region::Protection;
use region::Region;
use std::slice;
use thiserror::Error;
use tracing::info;
use tracing::instrument;
use tracing::trace;

#[derive(Debug, Error)]
pub enum RawHookError {
    #[error("Encountered `region::Error`: {0}")]
    RegionError(region::Error),
    #[error("`RawHook` at `{0:x?}` was already present")]
    AlreadyPresent(*const ()),
}

impl From<region::Error> for RawHookError {
    fn from(value: region::Error) -> Self {
        RawHookError::RegionError(value)
    }
}

#[inline]
#[must_use = "You should check whether a hook is already present"]
pub(crate) fn raw_hooks() -> &'static Mutex<HashSet<usize>> {
    static RAW_HOOKS: OnceCell<Mutex<HashSet<usize>>> = OnceCell::new();

    RAW_HOOKS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Debug)]
pub struct RawHook<T> {
    target: *const T,
    detour: *const T,
    trampoline: *const T,
    prev_bytes: Vec<u8>,
}

impl<T> RawHook<T> {
    /// The bitness of our instructions. For SE, this is always 64.
    const INSTRUCTION_BITNESS: u32 = 64u32;
    /// We only need to replace at most 16-bytes, as that's the largest
    /// instruction possible in the `x86_64` architecture.
    const INSTRUCTION_MAX_SIZE: usize = 0x10usize;

    pub fn new(target: *const T, detour: *const T) -> Result<Self, RawHookError> {
        // Verify all pages are mapped, this is what makes new safe.
        __query_range_checked(target, Self::INSTRUCTION_MAX_SIZE)?;

        // SAFETY: Because we guaranteed no pages are unmapped above, this is safe. At
        // least, for constructing a RawHook... Enabling one is a whole other story.
        unsafe { Self::new_unchecked(target.cast(), detour.cast()) }
    }

    #[instrument]
    pub unsafe fn new_unchecked(target: *const T, detour: *const T) -> Result<Self, RawHookError> {
        trace!("Constructing new `RawHook`");

        let _guard = unsafe {
            region::protect_with_handle(
                target,
                Self::INSTRUCTION_MAX_SIZE,
                Protection::READ_WRITE_EXECUTE,
            )?
        };

        // Create an x86_64 decoder. This will allow us to add a jmp or call easily
        let decoder = unsafe {
            Decoder::with_ip(
                Self::INSTRUCTION_BITNESS,
                slice::from_raw_parts(target.cast(), Self::INSTRUCTION_MAX_SIZE),
                target as u64,
                DecoderOptions::NO_INVALID_CHECK,
            )
        };

        let instrs = decoder.into_iter().collect::<Vec<Instruction>>();
        let num = instrs
            .iter()
            .filter_map(|i| {
                if i.ip() >= target as u64 + 0x5u64 {
                    None
                } else {
                    Some(i.len())
                }
            })
            .sum::<usize>();

        for i in instrs {
            println!("IP: {:X} INSTRUCTION: {i}, LEN: {}", i.ip(), i.len());
        }

        println!("{num}");

        todo!();
    }
}

static BYTES: &[u8] = &[
    0x48, 0x83, 0xEC, 0x28, 0xE8, 0xDB, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn a() {
        unsafe {
            panic!("{}", RawHook::new(BYTES.as_ptr().cast::<()>(), ptr::null()).unwrap_err());
        }
    }
}
