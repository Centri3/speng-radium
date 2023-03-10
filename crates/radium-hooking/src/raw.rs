use crate::utils::__query_range_checked;
use crate::utils::__round_to_page_boundaries;
use hashbrown::HashSet;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use region::alloc;
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
        // least, for constructing a RawHook... enabling one is a whole other story.
        unsafe { Self::new_unchecked(target.cast(), detour.cast()) }
    }

    #[instrument]
    pub unsafe fn new_unchecked(target: *const T, detour: *const T) -> Result<Self, RawHookError> {
        trace!("Constructing new `RawHook`");

        // SAFETY: This will be set back to its original protection when dropped, and
        // since we assume all threads are suspended when hooking, this is fine.
        let _guard = unsafe {
            region::protect_with_handle(
                target,
                Self::INSTRUCTION_MAX_SIZE,
                Protection::READ_WRITE_EXECUTE,
            )?
        };

        // SAFETY: THIS IS NOT SAFE. The caller must uphold that this is mapped. See
        // new, which does this for you.
        let bytes = unsafe { slice::from_raw_parts(target.cast(), Self::INSTRUCTION_MAX_SIZE) };

        // Create an x86_64 decoder. This will allow us to initialize our hook
        let decoder = Decoder::with_ip(
            Self::INSTRUCTION_BITNESS,
            bytes,
            target as u64,
            DecoderOptions::NO_INVALID_CHECK,
        );

        // This will get number of bytes we should replace
        let num = decoder
            .into_iter()
            .collect::<Vec<Instruction>>()
            .iter()
            .filter_map(|i| {
                trace!(ip = i.ip(), len = i.len(), %i, "Found instruction");

                match i.ip() <= target as u64 + 0x5u64 {
                    true => Some(i.len()),
                    false => None,
                }
            })
            .sum::<usize>();

        trace!(num, nops = num - 5usize, "Got number of bytes to replace");

        // Construct a trampoline function with enough room for the original bytes and a
        // jmp instruction.
        let trampoline =
            alloc(bytes[..num].len() + 5usize, Protection::READ_WRITE_EXECUTE)?.as_ptr::<T>();

        Ok(Self {
            target,
            detour,
            trampoline,
            prev_bytes: bytes[..num].to_vec(),
        })
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
