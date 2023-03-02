#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod logging;

use crate::logging::SetupFile;
use eyre::eyre;
use eyre::Context;
use eyre::Result;
use path_clean::PathClean;
use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::mem::transmute;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use tracing::debug;
use tracing::info;
use windows::s;
use windows::w;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::DBG_CONTINUE;
use windows::Win32::Foundation::DBG_EXCEPTION_NOT_HANDLED;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent;
use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
use windows::Win32::System::Diagnostics::Debug::DebugSetProcessKillOnExit;
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::Debug::SetThreadContext;
use windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::Debug::CONTEXT as UNALIGNED_CONTEXT;
use windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_DEBUG_EVENT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::SuspendThread;
use windows::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS;
use windows::Win32::System::Threading::DEBUG_PROCESS;
use windows::Win32::System::Threading::DETACHED_PROCESS;

const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x00000001;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x00000002;
const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x00000004;
const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x00000008;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;
const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

#[allow(clippy::upper_case_acronyms)]
#[repr(align(16))]
#[derive(Default)]
struct CONTEXT(UNALIGNED_CONTEXT);

fn main() {
    let _guard = logging::setup(SetupFile::Overwrite).expect("Failed to setup logging");

    // We must do this to use Result everywhere
    __start_modded_se().expect("Failed to start modded SE");
}

#[inline(always)]
fn __start_modded_se() -> Result<()> {
    let cwd = env::current_dir()?;

    // Log cwd because it's helpful
    info!(?cwd);

    Command::new(cwd.join("SpaceEngine.exe"))
        .creation_flags(DEBUG_ONLY_THIS_PROCESS.0 | DEBUG_PROCESS.0 | DETACHED_PROCESS.0)
        .env("_NO_DEBUG_HEAP", "1")
        .spawn()
        .wrap_err("Starting `SpaceEngine.exe` failed")?;

    if !cwd.join("libradium.dll").try_exists()? {
        return Err(eyre!("`libradium.dll` does not exist"));
    }

    // Generate steam_appid.txt
    write!(File::create("steam_appid.txt")?, "314650")?;

    // We want to reuse CREATE_PROCESS_DEBUG_EVENT later, so we put this here
    // instead. Probably unsafe, or just stupid.
    let mut dbg_event = DEBUG_EVENT::default();

    // Debugger loop
    loop {
        // SAFETY: This uses a mutable reference, so it's safe
        unsafe { WaitForDebugEvent(&mut dbg_event, u32::MAX) };

        // CREATE_PROCESS_DEBUG_EVENT happens first, then EXCEPTION_DEBUG_EVENT is
        // expected later (as we force an exception!)
        match dbg_event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => __handle_exception(dbg_event)?,
            CREATE_PROCESS_DEBUG_EVENT => __handle_p_creation(dbg_event)?,
            // Unknown or unused exception, skip it
            _ => {}
        };
    }

    Ok(())
}

#[allow(clippy::fn_to_numeric_cast)]
#[inline(always)]
fn __handle_p_creation(dbg_event: DEBUG_EVENT) -> Result<()> {
    info!("Got `CREATE_PROCESS_DEBUG_INFO`, SE has been started");

    // SAFETY: This is only called when CREATE_PROCESS_DEBUG_EVENT is encountered,
    // so this will always be initialized
    let info = unsafe { dbg_event.u.CreateProcessInfo };

    let mut context = CONTEXT(UNALIGNED_CONTEXT {
        ContextFlags: CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    });

    unsafe { GetThreadContext(info.hThread, &mut context.0).unwrap() };

    // Set Dr0 to the entry point of SE
    context.0.Dr0 = info.lpStartAddress.unwrap() as u64;

    // Enable Dr0 breakpoint. We don't need to modify the type or size here, as this
    // is an exception breakpoint by default
    context.0.Dr7 = 1u64;

    unsafe { SetThreadContext(info.hThread, &context.0).unwrap() };

    // Continue debugger
    unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE) };

    Ok(())
}

#[allow(clippy::fn_to_numeric_cast)]
#[inline(always)]
fn __handle_exception(dbg_event: DEBUG_EVENT) -> Result<()> {
    // SAFETY: This is only called when EXCEPTION_DEBUG_EVENT is encountered,
    // so this will always be initialized
    let info = unsafe { dbg_event.u.Exception };
    // SAFETY: This is guaranteed to be initialized, as CREATE_PROCESS_DEBUG_EVENT
    // is always encountered. BUT, if it's encountered twice, then this may be an
    // issue.
    let (hprocess, hthread, entry_point) = unsafe {
        (
            dbg_event.u.CreateProcessInfo.hProcess,
            dbg_event.u.CreateProcessInfo.hThread,
            dbg_event.u.CreateProcessInfo.lpStartAddress.unwrap(),
        )
    };

    let mut context = CONTEXT(UNALIGNED_CONTEXT {
        ContextFlags: CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    });

    unsafe { GetThreadContext(hthread, &mut context.0).unwrap() };

    if context.0.Dr0 == entry_point as u64 {
        unsafe {
            // This is fine since this will be resumed by the dll later
            SuspendThread(hthread);

            // ☹️
            let absolute_path = Path::new("libradium.dll").canonicalize()?;

            let dll_path = absolute_path
                .to_str()
                .expect("Failed to convert path to `libradium.dll` to a string")
                .as_bytes();

            // SAFETY: Checking if this is NULL guarantees this is safe, as the memory will
            // always be allocated
            let alloc = VirtualAllocEx(
                hprocess,
                None,
                dll_path.len(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            );

            if alloc.is_null() {
                return Err(eyre!("Failed to allocate memory for `libradium.dll`"));
            }

            // SAFETY: We just allocated this memory, so this is fine
            WriteProcessMemory(
                hprocess,
                alloc,
                dll_path.as_ptr().cast(),
                dll_path.len(),
                None,
            );

            // SAFETY: VERY UNSAFE BECAUSE OF TRANSMUTE. This will call LoadLibraryW.
            CreateRemoteThread(
                hprocess,
                None,
                0usize,
                Some(transmute(
                    GetProcAddress(GetModuleHandleW(w!("kernel32.dll"))?, s!("LoadLibraryW"))
                        .ok_or_else(|| eyre!("Failed to get address of `LoadLibraryW`"))?,
                )),
                Some(alloc),
                0u32,
                None,
            )?;

            // TODO: Should this restore Dr0 of the main thread here? Doesn't really make a
            // difference, but it can...

            // SAFETY: This will only continue on our exception, so this is safe
            ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);

            // Exit debugger
            DebugSetProcessKillOnExit(false);
            DebugActiveProcessStop(dbg_event.dwProcessId);
        }
    }

    // SAFETY: If this isn't our exception, we mark it as unhandled
    unsafe {
        ContinueDebugEvent(
            dbg_event.dwProcessId,
            dbg_event.dwThreadId,
            DBG_EXCEPTION_NOT_HANDLED,
        )
    };

    Ok(())
}
