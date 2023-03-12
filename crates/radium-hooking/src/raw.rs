use crate::utils::__alloc_at_2gb;
use crate::utils::__query_range_checked;
use hashbrown::HashSet;
use iced_x86::code_asm::rsp;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::code_asm::*;
use iced_x86::BlockEncoder;
use iced_x86::BlockEncoderOptions;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::IcedError;
use iced_x86::Instruction;
use iced_x86::InstructionBlock;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use region::Allocation;
use region::Protection;
use std::fmt::Debug;
use std::slice;
use thiserror::Error;
use tracing::instrument;
use tracing::trace;

#[derive(Debug, Error)]
pub enum RawHookError {
    #[error("Encountered `region::Error`: {0}")]
    RegionError(#[from] region::Error),
    #[error("Encountered `IcedError`: {0}")]
    IcedError(#[from] IcedError),
}

#[inline]
#[must_use = "You should check whether a hook is already present"]
pub(crate) fn raw_hooks() -> &'static Mutex<HashSet<usize>> {
    static RAW_HOOKS: OnceCell<Mutex<HashSet<usize>>> = OnceCell::new();

    RAW_HOOKS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub struct RawHook<T> {
    target: *const T,
    detour: *const T,
    trampoline: Allocation,
    prev_instr: Vec<Instruction>,
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

        // TODO: Check here that both target and detour are executable

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
        let dec = unsafe {
            Decoder::with_ip(
                Self::INSTRUCTION_BITNESS,
                slice::from_raw_parts(target.cast(), Self::INSTRUCTION_MAX_SIZE),
                target as u64,
                DecoderOptions::NONE,
            )
        };

        let instrs = dec.into_iter().collect::<Vec<Instruction>>();

        // This will get number of bytes we should replace
        let num = instrs
            .iter()
            .filter_map(|i| {
                trace!(ip = i.ip(), len = i.len(), %i, "Found instruction");

                match i.ip() <= target as u64 + 0x5u64 {
                    true => Some(1usize),
                    false => None,
                }
            })
            .sum::<usize>();

        trace!(num, nops = num - 5usize, "Got number of bytes to replace");

        // Allocate a trampoline function with enough room for the original bytes and a
        // jmp instruction. This will be constructed later, when enabled.
        let trampoline = __alloc_at_2gb(target, num + 1000, Protection::READ_WRITE_EXECUTE)?;

        Ok(Self {
            target,
            detour,
            trampoline,
            prev_instr: instrs[..num].to_vec(),
        })
    }

    #[instrument(skip(self), fields(target = ?self.target, detour = ?self.detour))]
    pub unsafe fn enable(&mut self) -> Result<(), RawHookError> {
        let mut asm = CodeAssembler::new(Self::INSTRUCTION_BITNESS)?;

        asm.push(rax)?;
        asm.mov(rax, self.detour as u64)?;
        asm.mov(byte_ptr(rsp) - 8u64, rax)?;
        asm.pop(rax)?;
        asm.ret()?;

        let trampoline = asm.assemble(self.trampoline.as_ptr::<()>() as u64)?;

        // Relocate to our trampoline function
        let original = BlockEncoder::encode(
            Self::INSTRUCTION_BITNESS,
            InstructionBlock::new(
                &self.prev_instr,
                self.trampoline.as_ptr::<()>() as u64 + trampoline.len() as u64,
            ),
            BlockEncoderOptions::NONE,
        )?
        .code_buffer;

        let bytes = [trampoline, original].concat();

        // TODO: safety docs
        unsafe { self.trampoline.as_mut_ptr::<Vec<u8>>().write(bytes.clone()) };

        for instr in Decoder::with_ip(
            Self::INSTRUCTION_BITNESS,
            &bytes,
            self.trampoline.as_ptr::<()>() as u64,
            DecoderOptions::NONE,
        ) {
            println!("{}", instr);
        }

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
            panic!(
                "{}",
                RawHook::new(BYTES.as_ptr().cast::<()>(), ptr::null())
                    .unwrap()
                    .enable()
                    .unwrap_err()
            );
        }
    }
}
