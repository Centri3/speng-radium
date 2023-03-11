use crate::utils::__query_range_checked;
use crate::utils::__round_to_page_boundaries;
use hashbrown::HashSet;
use iced_x86::code_asm::rsp;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::code_asm::*;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::IcedError;
use iced_x86::Instruction;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use region::alloc;
use region::page;
use region::Allocation;
use region::Protection;
use region::Region;
use std::fmt::Debug;
use std::mem::forget;
use std::slice;
use thiserror::Error;
use tracing::info;
use tracing::instrument;
use tracing::trace;

#[derive(Debug, Error)]
pub enum RawHookError {
    #[error("Encountered `region::Error`: {0}")]
    RegionError(#[from] region::Error),
    #[error("Encountered `IcedError`: {0}")]
    IcedError(#[from] IcedError),
    #[error("`RawHook` at `{0:x?}` was already present")]
    AlreadyPresent(*const ()),
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
        let trampoline = alloc(
            instrs[..num].iter().map(|i| i.len()).sum::<usize>() + 5usize,
            Protection::READ_WRITE_EXECUTE,
        )?;

        Ok(Self {
            target,
            detour,
            trampoline,
            prev_instr: instrs[..num].to_vec(),
        })
    }

    #[instrument(skip(self), fields(target = ?self.target, detour = ?self.detour))]
    pub unsafe fn enable(&mut self) -> Result<(), RawHookError> {
        let mut ca = CodeAssembler::new(Self::INSTRUCTION_BITNESS)?;

        ca.add(rsp, 0x08)?;
        // FIXME: This may get truncated!!! Also ensure adding 8 then subtracting 8 is
        // the right way of doing this (I don't think it is lol!)
        ca.mov(byte_ptr(rsp) - 0x08usize, self.detour as i32)?;
        ca.ret()?;

        // Add our trampoline function
        // FIXME: The bytes written here (at least for any referencing memory) are
        // always wrong
        for instr in &mut self.prev_instr.clone() {
            if !instr.is_invalid() {
                ca.add_instruction(*instr)?;
            }
        }

        ca.push(rax)?;
        // FIXME: This may get truncated!!! Also ensure pushing then subtracting 8 is
        // the right way of doing this (I don't think it is lol!)
        ca.mov(rax, i64::MAX)?;
        ca.mov(qword_ptr(rsp) - 0x08usize, rax)?;
        ca.pop(rax)?;
        ca.ret()?;

        let bytes = ca.assemble(self.trampoline.as_ptr::<()>() as u64)?;
        unsafe { self.trampoline.as_mut_ptr::<Vec<u8>>().write(bytes) };

        unsafe {
            let bytes = &self.trampoline.as_ptr::<Vec<u8>>().read();

            let dec = Decoder::with_ip(
                64,
                bytes,
                self.trampoline.as_ptr::<()>() as u64,
                DecoderOptions::NONE,
            );

            for i in dec {
                println!("{:x} LEN: {:x} INSTRUCTION: {i}", i.ip(), i.len());
            }
        };

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
            println!("{:?}", BYTES as *const _);

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
