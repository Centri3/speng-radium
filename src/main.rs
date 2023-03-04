#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use eyre::eyre;
use eyre::Context;
use eyre::Result;
use if_chain::if_chain;
use lnk::ShellLink;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::mem::transmute;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;
use tracing::trace;
use tracing::trace_span;
use tracing::warn;
use windows::s;
use windows::w;
use windows::Win32::Foundation::CloseHandle;
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
use windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_INFO;
use windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT_CODE;
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::LOAD_DLL_DEBUG_EVENT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::GetExitCodeProcess;
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::System::Threading::GetThreadId;
use windows::Win32::System::Threading::SuspendThread;
use windows::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS;
use windows::Win32::System::Threading::DEBUG_PROCESS;
use windows::Win32::System::Threading::DETACHED_PROCESS;

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

fn main() {
    // We must do this to use Result everywhere. If main returns Result, color-eyre
    // won't catch it
    __start_modded_se().expect("Failed to start modded SE");
}

#[inline(always)]
fn __start_modded_se() -> Result<()> {
    // We do this before setting up the log so we don't use the wrong cwd
    let path = __get_exe_path()?;

    // Setup logging and overwrite the log file, panicking if it fails
    let _guard = logging::setup(&SetupFile::Overwrite);
    // Create a span so we know what's from the loader
    let _span = trace_span!("loader").entered();

    info!("Starting loader, this should not take long");

    Command::new(&path)
        .creation_flags(DEBUG_ONLY_THIS_PROCESS.0 | DEBUG_PROCESS.0 | DETACHED_PROCESS.0)
        .env("_NO_DEBUG_HEAP", "1")
        .spawn()
        .wrap_err("Starting `SpaceEngine.exe` failed")?;

    // Generate steam_appid.txt
    write!(File::create("steam_appid.txt")?, "314650")?;

    let mut cproc_event = DEBUG_EVENT::default();

    // Wait for CREATE_PROCESS_DEBUG_EVENT, this is guaranteed to be the first event
    // so we don't enter loop yet
    unsafe { WaitForDebugEvent(&mut cproc_event, u32::MAX) };

    if cproc_event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
        return Err(eyre!("First event was not `CREATE_PROCESS_DEBUG_EVENT`"));
    }

    // SAFETY: The if statement above guarantees this is initialized
    let cproc_info = unsafe { cproc_event.u.CreateProcessInfo };

    cproc_info
        .lpStartAddress
        .ok_or_else(|| eyre!("SE does not have start address"))?;

    // SAFETY: `GetProcessId` and `GetThreadId` should be safe. They don't take any
    // raw pointers, and just return a u32.
    unsafe {
        info!(
            pid = ?GetProcessId(cproc_info.hProcess) as *const c_void,
            tid = ?GetThreadId(cproc_info.hThread) as *const c_void,
            base = ?cproc_info.lpBaseOfImage,
            entry = ?cproc_info.lpStartAddress.unwrap() as usize as *const c_void,
            "Got `CREATE_PROCESS_DEBUG_EVENT`, SE has been started",
        );
    }

    // SAFETY: Safe if SE's being debugged, which it is.
    unsafe {
        __set_execute_breakpoint(
            cproc_info.hThread,
            cproc_info.lpStartAddress.unwrap() as usize as u64,
        )?;
    }

    // SAFETY: This isn't an EXCEPTION_DEBUG_EVENT, so this is safe.
    unsafe {
        ContinueDebugEvent(
            cproc_event.dwProcessId,
            cproc_event.dwThreadId,
            DBG_CONTINUE,
        );
    }

    info!("Starting debugger loop");

    // Now we enter debugger loop
    loop {
        unsafe {
            let mut exit_code = 0u32;

            // Ensure SE's still open
            GetExitCodeProcess(cproc_info.hProcess, &mut exit_code);

            if exit_code != 259u32 {
                return Err(eyre!("SE has been closed"));
            }
        }

        let mut dbg_event = DEBUG_EVENT::default();

        // Close loader if it takes over a second to get an event
        unsafe { WaitForDebugEvent(&mut dbg_event, 1000u32).expect("Timeout exceeded") };

        // Print info of this event
        __print_dbg_event(dbg_event)?;

        unsafe {
            match dbg_event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    if __handle_exception(dbg_event, cproc_info)? {
                        break;
                    }
                }
                CREATE_PROCESS_DEBUG_EVENT => _ = CloseHandle(dbg_event.u.CreateProcessInfo.hFile),
                LOAD_DLL_DEBUG_EVENT => _ = CloseHandle(dbg_event.u.LoadDll.hFile),
                _ => {}
            }

            // FIXME: This will incorrectly be called on an unhandled exception, though it
            // doesn't cause any issues, as far as I know.
            ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);
        }
    }

    info!("Debugger loop has been exited, loader's job is done");

    Ok(())
}

#[inline(always)]
fn __get_exe_path() -> Result<PathBuf> {
    // God, I fucking love this crate. I need to use it more
    if_chain! {
        if cfg!(debug_assertions);
        if let Ok(lnk) = ShellLink::open("SpaceEngine.lnk");

        // Get path from shortcut if we're in debug mode and it exists
        then { __get_from_shortcut(&lnk) }
        // Otherwise, get from current working directory
        else { __get_from_cwd() }
    }
}

#[inline(always)]
fn __get_from_shortcut(lnk: &ShellLink) -> Result<PathBuf> {
    // Get the path pointed to by SpaceEngine.lnk
    let path = lnk
        .link_info()
        .as_ref()
        .ok_or_else(|| eyre!("`SpaceEngine.lnk` does not have `LinkInfo` structure"))?
        .local_base_path()
        .as_ref()
        .ok_or_else(|| eyre!("Can't find absolute path of `SpaceEngine.lnk`"))
        .map(|s| PathBuf::from(s.to_owned()).join("system\\SpaceEngine.exe"))?;

    // FIXME: This isn't bad per se, but our libradium.dll can be modified by
    // the time we then execute it. This isn't a big deal in an app like this,
    // especially since this is only available in debug mode, but if possible,
    // this should be fixed.
    fs::copy(
        env::current_exe()?.with_file_name("libradium.dll"),
        path.with_file_name("libradium.dll"),
    )?;

    // Set cwd to the folder containing SpaceEngine.exe
    env::set_current_dir(path.parent().unwrap())?;

    Ok(path)
}

#[inline(always)]
fn __get_from_cwd() -> Result<PathBuf> {
    Ok(env::current_dir()?.join("SpaceEngine.exe"))
}

#[inline(always)]
unsafe fn __set_execute_breakpoint(hthread: HANDLE, address: u64) -> Result<()> {
    info!(address = ?address as *const c_void, "Setting execute breakpoint");

    __update_context(hthread, |context| {
        // Set debug register 0
        context.Dr0 = address;
        context.Dr7 |= 1u64;

        Ok(())
    })
}

#[inline(always)]
unsafe fn __unset_execute_breakpoint(hthread: HANDLE) -> Result<()> {
    info!("Unsetting execute breakpoint");

    __update_context(hthread, |context| {
        // Reset debug register 0
        context.Dr0 = 0u64;
        context.Dr7 |= 0u64;

        Ok(())
    })
}

#[inline(always)]
unsafe fn __update_context<F>(hthread: HANDLE, update: F) -> Result<()>
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

#[inline(always)]
fn __print_dbg_event(dbg_event: DEBUG_EVENT) -> Result<()> {
    let u = dbg_event.u;

    unsafe {
        match dbg_event.dwDebugEventCode {
            DEBUG_EVENT_CODE(1u32) => trace!(info = ?u.Exception, "Got `EXCEPTION_DEBUG_EVENT`"),
            DEBUG_EVENT_CODE(2u32) => {
                trace!(info = ?u.CreateThread, "Got `CREATE_THREAD_DEBUG_EVENT`");
            }
            DEBUG_EVENT_CODE(3u32) => {
                trace!(info = ?u.CreateProcessInfo, "Got `CREATE_PROCESS_DEBUG_EVENT`");
            }
            DEBUG_EVENT_CODE(4u32) => trace!(info = ?u.ExitThread, "Got `EXIT_THREAD_DEBUG_EVENT`"),
            DEBUG_EVENT_CODE(5u32) => {
                trace!(info = ?u.ExitProcess, "Got `EXIT_PROCESS_DEBUG_EVENT`");
            }
            DEBUG_EVENT_CODE(6u32) => trace!(info = ?u.LoadDll, "Got `LOAD_DLL_DEBUG_EVENT`"),
            DEBUG_EVENT_CODE(7u32) => trace!(info = ?u.UnloadDll, "Got `UNLOAD_DLL_DEBUG_EVENT`"),
            DEBUG_EVENT_CODE(8u32) => {
                trace!(info = ?u.DebugString, "Got `OUTPUT_DEBUG_STRING_EVENT`");
            }
            DEBUG_EVENT_CODE(9u32) => trace!(info = ?u.RipInfo, "Got `RIP_EVENT`"),
            _ => return Err(eyre!("Invalid event code")),
        };
    }

    Ok(())
}

fn __handle_exception(
    dbg_event: DEBUG_EVENT, cproc_info: CREATE_PROCESS_DEBUG_INFO,
) -> Result<bool> {
    // SAFETY: This is guaranteed to be initialized, since this is only called when
    // an EXCEPTION_DEBUG_EVENT is encountered
    let info = unsafe { dbg_event.u.Exception.ExceptionRecord };

    if info.ExceptionAddress != cproc_info.lpStartAddress.unwrap() as *mut c_void
        || info.ExceptionCode != EXCEPTION_SINGLE_STEP
    {
        warn!("Unexpected exception! Marking as unhandled");

        // If this isn't our breakpoint, don't handle exception
        unsafe {
            ContinueDebugEvent(
                dbg_event.dwProcessId,
                dbg_event.dwThreadId,
                DBG_EXCEPTION_NOT_HANDLED,
            );
        }

        // Early return so we don't improperly mark an unhandled exception as handled
        return Ok(false);
    }

    trace!("Our breakpoint has been hit");

    unsafe {
        // Suspend main thread. This will be resumed by the dll later
        SuspendThread(cproc_info.hThread);

        let dll = r"libradium.dll".as_bytes();

        // SAFETY: Checking if this is NULL guarantees this is safe, as the memory will
        // always be allocated
        let alloc = VirtualAllocEx(
            cproc_info.hProcess,
            None,
            dll.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        if alloc.is_null() {
            return Err(eyre!("Failed to allocate memory for `libradium.dll`"));
        }

        // SAFETY: We just allocated this memory, so this is fine
        WriteProcessMemory(
            cproc_info.hProcess,
            alloc,
            dll.as_ptr().cast(),
            dll.len(),
            None,
        );

        // SAFETY: VERY UNSAFE BECAUSE OF TRANSMUTE. This will call LoadLibraryA.
        CreateRemoteThread(
            cproc_info.hProcess,
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

        __unset_execute_breakpoint(cproc_info.hThread)?;
    }

    // SAFETY: Since this is our breakpoint, this is safe
    unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE) };

    unsafe {
        // Exit debugger
        DebugSetProcessKillOnExit(false);
        DebugActiveProcessStop(dbg_event.dwProcessId);
    };

    Ok(true)
}
