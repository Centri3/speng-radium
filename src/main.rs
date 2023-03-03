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
use parking_lot::lock_api::GetThreadId;
use path_clean::PathClean;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::mem::transmute;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::null_mut;
use tracing::debug;
use tracing::event;
use tracing::info;
use tracing::span;
use tracing::trace;
use tracing::trace_span;
use tracing::warn;
use tracing::Level;
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
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::System::Threading::GetThreadId;
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
    // We must do this to use Result everywhere
    __start_modded_se().expect("Failed to start modded SE");
}

#[inline(always)]
fn __start_modded_se() -> Result<()> {
    // We do this before setting up the log so we don't use the wrong cwd
    let path = __get_exe_path()?;

    // Setup logging and overwrite the log file, panicking if it fails
    let _guard = logging::setup(SetupFile::Overwrite);
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

    // Catch if first event was somehow not CREATE_PROCESS_DEBUG_EVENT
    if cproc_event.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT {
        return Err(eyre!("First event was not `CREATE_PROCESS_DEBUG_EVENT`"));
    }

    // SAFETY: The if statement above guarantees this is initialized
    let cproc_info = unsafe { cproc_event.u.CreateProcessInfo };

    // Ensure SE gave us its start address
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

    Ok(())
}

#[inline(always)]
fn __get_exe_path() -> Result<PathBuf> {
    // God, I fucking love this crate. I need to use it more
    if_chain! {
        if cfg!(debug_assertions);
        if let Ok(lnk) = ShellLink::open("SpaceEngine.lnk");

        // Get path from shortcut if we're in debug mode and it exists
        then { __get_from_shortcut(lnk) }
        // Otherwise, get from current working directory
        else { __get_from_cwd() }
    }
}

#[inline(always)]
fn __get_from_shortcut(lnk: ShellLink) -> Result<PathBuf> {
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
