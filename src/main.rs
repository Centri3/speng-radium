#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use eyre::eyre;
use eyre::Context;
use eyre::Result;
use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::mem::transmute;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::ptr::null_mut;
use tracing::debug;
use tracing::info;
use tracing::warn;
use windows::s;
use windows::w;
use windows::Win32::Foundation::DBG_CONTINUE;
use windows::Win32::Foundation::DBG_EXCEPTION_NOT_HANDLED;
use windows::Win32::Foundation::EXCEPTION_SINGLE_STEP;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent;
use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
use windows::Win32::System::Diagnostics::Debug::DebugSetProcessKillOnExit;
use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
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
    // Setup logging and overwrite the log file, panicking if it fails
    let _guard = logging::setup(SetupFile::Overwrite);

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

    let mut hprocess = HANDLE::default();
    let mut hthread = HANDLE::default();
    let mut base = null_mut::<c_void>();
    let mut entry = null_mut::<c_void>();

    // Debugger loop
    loop {
        let mut dbg_event = DEBUG_EVENT::default();

        // SAFETY: This uses a mutable reference, so it's safe
        unsafe { WaitForDebugEvent(&mut dbg_event, u32::MAX) };

        // CREATE_PROCESS_DEBUG_EVENT happens first, then EXCEPTION_DEBUG_EVENT is
        // expected later (as we force an exception!)
        // FIXME: Close handles here
        match dbg_event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => __handle_process_creation(
                dbg_event,
                &mut hprocess,
                &mut hthread,
                &mut base,
                &mut entry,
            )?,
            EXCEPTION_DEBUG_EVENT => {
                let exit = __handle_exception(dbg_event, hprocess, hthread, base, entry)?;

                // Exit debugger loop
                if exit {
                    break;
                }
            }
            // Unknown or unused event, skip it
            _ => unsafe {
                ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);
            },
        };
    }

    info!("Debugger loop has been escaped, loader's job is done here");

    Ok(())
}

#[inline(always)]
fn __handle_process_creation(
    dbg_event: DEBUG_EVENT, hprocess: &mut HANDLE, hthread: &mut HANDLE, base: &mut *mut c_void,
    entry: &mut *mut c_void,
) -> Result<()> {
    info!("Got `CREATE_PROCESS_DEBUG_INFO`, SE has been started");

    // SAFETY: This is only called when CREATE_PROCESS_DEBUG_EVENT is encountered,
    // so this will always be initialized
    let info = unsafe { dbg_event.u.CreateProcessInfo };

    (*hprocess, *hthread, *base, *entry) = (
        info.hProcess,
        info.hThread,
        info.lpBaseOfImage,
        info.lpStartAddress.unwrap() as *mut c_void,
    );

    // Print debug info
    info!(?base, ?entry, "Basic info of SE");

    let mut context = CONTEXT(UNALIGNED_CONTEXT {
        ContextFlags: CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    });

    unsafe { GetThreadContext(info.hThread, &mut context.0) };

    // Set Dr0 to the entry point of SE
    context.0.Dr0 = info.lpStartAddress.unwrap() as usize as u64;

    // Enable Dr0 breakpoint. We don't need to modify the type or size here, as this
    // is an exception breakpoint by default
    context.0.Dr7 = 1u64;

    unsafe { SetThreadContext(info.hThread, &context.0) };

    debug!("Breakpoint at entry has been set");

    // Continue debugger
    unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE) };

    Ok(())
}

#[inline(always)]
fn __handle_exception(
    dbg_event: DEBUG_EVENT, hprocess: HANDLE, hthread: HANDLE, base: *const c_void,
    entry: *const c_void,
) -> Result<bool> {
    // SAFETY: This is only called when EXCEPTION_DEBUG_EVENT is encountered,
    // so this will always be initialized
    let info = unsafe { dbg_event.u.Exception.ExceptionRecord };

    if info.ExceptionAddress == entry as *mut c_void && info.ExceptionCode == EXCEPTION_SINGLE_STEP
    {
        unsafe {
            debug!("Breakpoint at entry has been hit");

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

            // SAFETY: VERY UNSAFE BECAUSE OF TRANSMUTE. This will call LoadLibraryA.
            CreateRemoteThread(
                hprocess,
                None,
                0usize,
                Some(transmute(
                    GetProcAddress(GetModuleHandleW(w!("kernel32.dll"))?, s!("LoadLibraryA"))
                        .ok_or_else(|| eyre!("Failed to get address of `LoadLibraryA`"))?,
                )),
                Some(alloc),
                0u32,
                None,
            )?;

            let mut context = CONTEXT(UNALIGNED_CONTEXT {
                ContextFlags: CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS,
                ..Default::default()
            });

            GetThreadContext(hthread, &mut context.0);

            // Set Dr0 to 0
            context.0.Dr0 = 0u64;

            // Disable Dr0 breakpoint
            context.0.Dr7 = 0u64;

            // FIXME: This doesn't restore debug registers, just sets them to 0. But it
            // makes literally zero difference.
            SetThreadContext(hthread, &context.0);

            // SAFETY: This will only continue on our exception, so this is safe
            ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);

            // Exit debugger
            DebugSetProcessKillOnExit(false);
            DebugActiveProcessStop(dbg_event.dwProcessId);

            return Ok(true);
        }
    }

    warn!(address = ?info.ExceptionAddress, "Unexpected exception!");

    // SAFETY: If this isn't our exception, we mark it as unhandled
    unsafe {
        ContinueDebugEvent(
            dbg_event.dwProcessId,
            dbg_event.dwThreadId,
            DBG_EXCEPTION_NOT_HANDLED,
        )
    };

    Ok(false)
}
