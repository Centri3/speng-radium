pub mod logging;

use eyre::Result;
use std::arch::global_asm;
use std::ffi::c_void;
use tracing::info;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
use windows::Win32::System::Diagnostics::Debug::SetThreadContext;
use windows::Win32::System::Diagnostics::Debug::CONTEXT as UNALIGNED_CONTEXT;

extern "C" {
    pub fn store_registers();

    pub fn restore_registers();
}

global_asm!(
    "
    .global store_registers
    store_registers:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push rsp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    .global restore_registers
    restore_registers:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsp
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    "
);

const CONTEXT_AMD64: u32 = 0x00100000;
// const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x00000001;
// const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x00000002;
// const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x00000004;
// const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x00000008;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;
// const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER |
// CONTEXT_FLOATING_POINT;

#[allow(clippy::upper_case_acronyms)]
#[repr(align(16))]
#[derive(Default)]
struct CONTEXT(UNALIGNED_CONTEXT);

#[inline]
pub unsafe fn __set_execute_breakpoint(hthread: HANDLE, address: u64) -> Result<()> {
    info!(address = ?address as *const c_void, "Setting execute breakpoint");

    __update_context(hthread, |context| {
        // Set debug register 0
        context.Dr0 = address;
        context.Dr7 |= 1u64;

        Ok(())
    })
}

#[inline]
pub unsafe fn __unset_execute_breakpoint(hthread: HANDLE) -> Result<()> {
    info!("Unsetting execute breakpoint");

    __update_context(hthread, |context| {
        // Reset debug register 0
        context.Dr0 = 0u64;
        context.Dr7 |= 0u64;

        Ok(())
    })
}

#[inline]
pub unsafe fn __update_context<F>(hthread: HANDLE, update: F) -> Result<()>
where
    F: Fn(&mut UNALIGNED_CONTEXT) -> Result<()>,
{
    let mut context = CONTEXT(UNALIGNED_CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    });

    unsafe { GetThreadContext(hthread, &mut context.0) };

    update(&mut context.0)?;

    unsafe { SetThreadContext(hthread, &context.0) };

    Ok(())
}
