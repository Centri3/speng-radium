use hashbrown::HashSet;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use region::page;
use region::protect_with_handle;
use region::query;
use region::Protection;
use std::slice;
use thiserror::Error;

use crate::utils::__round_to_page_boundaries;

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
pub struct RawHook<T = ()> {
    new: *const T,
    trampoline: *const T,
}

impl<T> RawHook<T> {
    pub unsafe fn new(target: *const T, detour: *const T) -> Result<Self, RawHookError> {
        // The bitness of our instructions. For SE, this is always 64.
        const INSTRUCTION_BITNESS: u32 = 64u32;
        // We only need to replace at most 16-bytes, as that's the largest instruction
        // possible in the x86_64 architecture.
        const INSTRUCTION_MAX_SIZE: usize = 0x10usize;

        // This will return Err if any pages are unmapped
        // TODO(Centri3): Test this
        {
            let (address, size) = __round_to_page_boundaries(target, INSTRUCTION_MAX_SIZE)?;

            for i in 0usize..size / page::size() {
                query((address as usize + i * page::size()) as *const T)?;
            }
        }

        // SAFETY: We guarantee every page accessed is mapped, so this is ok. Also,
        // since we assume that all threads are suspended, this is fine, as we
        // will restore the original protection before they're resumed.
        #[rustfmt::skip]
        let _handle = unsafe {
            protect_with_handle(
                target,
                INSTRUCTION_MAX_SIZE,
                Protection::READ_WRITE_EXECUTE
            )?
        };

        // SAFETY: Since target is mapped memory (guaranteed above), this is ok.
        let mut decoder = unsafe {
            Decoder::with_ip(
                INSTRUCTION_BITNESS,
                slice::from_raw_parts(target.cast(), INSTRUCTION_MAX_SIZE),
                target as u64,
                DecoderOptions::NO_INVALID_CHECK,
            )
        };

        let instrs = decoder.iter().collect::<Vec<Instruction>>();
        let mut num_to_replace = 0usize;

        for instr in instrs.iter() {
            num_to_replace += instr.len();

            if num_to_replace >= 5usize {
                break;
            }
        }

        for instr in instrs.iter() {
            println!("INSTRUCTION: {instr}, SIZE: {}", instr.len());
        }

        println!("{}", num_to_replace);

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
