#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod logging;

use eyre::eyre;
use eyre::Context;
use eyre::Result;
use lnk::ShellLink;
use logging::setup_logging;
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
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
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

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    __start_modded_se().unwrap();
}

/// Extracted from [`main`]. Starts modded SE.
#[inline(always)]
fn __start_modded_se() -> Result<()> {
    let path = __get_exe_path().expect("Failed to get path to SpaceEngine.exe");

    // TODO: Check if speng_radium.dll exists
    // TODO: Check if steam_appid.txt exists

    // FIXME: Temporary solution
    let path = if path.join("../../").clean().ends_with("system") {
        "SpaceEngine.exe".into()
    } else {
        path
    };

    Command::new(&path)
        // SpaceEngine/system/SpaceEngine.exe -> SpaceEngine/system
        .current_dir(&path.join("../").clean())
        // Debug SE and don't inherit console
        .creation_flags(DEBUG_ONLY_THIS_PROCESS.0 | DEBUG_PROCESS.0 | DETACHED_PROCESS.0)
        // Don't use debug heap. Speeds up modded SE a LOT.
        .env("_NO_DEBUG_HEAP", "1")
        .spawn()?;

    // TODO: Unwrapping these is very annoying

    // Handles to SE
    let mut hprocess = None;
    let mut hthread = None;
    // Basic data of SE
    let mut pid = None;
    let mut tid = None;
    let mut base = None;
    let mut entry = None;
    // First byte at SE's entry point
    let mut original_byte = None;

    loop {
        let mut dbg_event = DEBUG_EVENT::default();

        // SAFETY: Safe, as we use a mutable reference here instead of a raw pointer
        unsafe { WaitForDebugEvent(&mut dbg_event, u32::MAX) };

        // We want to raise an exception once SE's main thread reaches SE's entry point,
        // so we can suspend it. We do this when SE's created.
        if dbg_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            // SAFETY: The if statement above guarantees this field is initialized
            let info = unsafe { dbg_event.u.CreateProcessInfo };

            // Save handles to SE
            (hprocess, hthread) = (Some(info.hProcess), Some(info.hThread));

            // Get some basic data of SE from `info`
            (pid, tid, base, entry) = unsafe {
                (
                    Some(GetProcessId(info.hProcess)),
                    Some(GetThreadId(info.hThread)),
                    Some(info.lpBaseOfImage),
                    Some(info.lpStartAddress.unwrap() as *mut c_void),
                )
            };

            info!(
                pid = pid.unwrap(),
                tid = tid.unwrap(),
                base = ?base.unwrap(),
                base = ?entry.unwrap(),
                "Got `CREATE_PROCESS_DEBUG_EVENT`, SE has been started"
            );

            // Save the first byte at SE's entry point
            original_byte = Some(
                *__read_memory(info.hProcess, entry.unwrap(), 1usize)?
                    .first()
                    .unwrap(),
            );

            // SAFETY: This will cause SE to raise an exception, so if it's not handled this
            // is not safe. It WILL be handled, however.
            unsafe { __write_memory(info.hProcess, entry.unwrap(), [0xccu8])? };
        }

        // TODO: More logging here
        if dbg_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            // SAFETY: The if statement above guarantees this field is initializede
            let info = unsafe { dbg_event.u.Exception.ExceptionRecord };

            // Ignore this event if it's not the one we forced, and mark it as unhandled
            if info.ExceptionAddress != entry.unwrap() {
                unsafe {
                    ContinueDebugEvent(
                        dbg_event.dwProcessId,
                        dbg_event.dwThreadId,
                        DBG_EXCEPTION_NOT_HANDLED,
                    );
                }

                continue;
            }

            let alloc = unsafe {
                // Write our dll's name to SE's memory
                VirtualAllocEx(
                    hprocess,
                    None,
                    "speng_radium.dll".as_bytes().len(),
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };

            // SAFETY: We're writing to the memory we just allocated, so this won't fail
            unsafe { __write_memory(hprocess.unwrap(), alloc, "speng_radium.dll".as_bytes())? };

            // SAFETY: This will call LoadLibraryA. TODO: VERY UNSAFE BECAUSE OF TRANSMUTE.
            unsafe {
                CreateRemoteThread(
                    hprocess,
                    None,
                    0usize,
                    Some(transmute(
                        GetProcAddress(GetModuleHandleW(w!("kernel32.dll"))?, s!("LoadLibraryA"))
                            .ok_or_else(|| eyre!("Failed to get address to LoadLibraryA"))?,
                    )),
                    Some(alloc),
                    0u32,
                    None,
                )?;
            }

            // SAFETY: We're restoring the byte that was here before, so this is fine
            unsafe {
                __write_memory(hprocess.unwrap(), entry.unwrap(), [original_byte.unwrap()])?;

                // Suspend main thread. This will be resumed by the dll later
                SuspendThread(hthread);

                // TODO: This is a stupid way of doing this
                writeln!(
                    File::create(path.join("../threadid").clean())?,
                    "{}",
                    GetThreadId(hthread.unwrap())
                )?;

                ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);

                // Exit debugger, our job is done!
                DebugSetProcessKillOnExit(false);
                DebugActiveProcessStop(dbg_event.dwProcessId);

                break;
            }
        }

        unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE) };
    }

    Ok(())
}

/// Extracted from [`__start_modded_se`]. Gets `SpaceEngine.exe`, either from
/// `SpaceEngine.lnk` if it exists, or the current working directory.
#[inline(always)]
fn __get_exe_path() -> Result<PathBuf> {
    let path = match Path::new("SpaceEngine.lnk").try_exists()? {
        // Get absolute path to `SpaceEngine.exe` from shortcut, if it exists
        true => __exe_from_shortcut(),
        // Otherwise, get from the current working directory
        false => __exe_from_path(),
    }?
    .join("system\\SpaceEngine.exe");

    // Print the path we just obtained
    info!(?path, "Successfully got absolute path to `SpaceEngine.exe`");

    Ok(path)
}

/// Extracted from [`__get_exe_path`]. Gets `SpaceEngine.exe` from
/// `SpaceEngine.lnk`.
#[inline(always)]
fn __exe_from_shortcut() -> Result<PathBuf> {
    info!("Getting absolute path to `SpaceEngine.exe` from `SpaceEngine.lnk`");

    let link = ShellLink::open("SpaceEngine.lnk")
        // Normally, I'd just put e here, but this makes it aligned with the others. It's pretty!
        .map_err(|err| eyre!("`SpaceEngine.lnk` exists, but failed to open it: {err:?}"))?;

    link.link_info()
        .as_ref()
        .ok_or_else(|| eyre!("`SpaceEngine.lnk` does not have `LinkInfo` structure"))?
        .local_base_path()
        .as_ref()
        .ok_or_else(|| eyre!("Can't find absolute path of `SpaceEngine.lnk`"))
        .map(|s| PathBuf::from(s.clone()))
}

/// Extracted from [`__get_exe_path`]. Gets `SpaceEngine.exe` from the current
/// working directory.
#[inline(always)]
fn __exe_from_path() -> Result<PathBuf> {
    info!("Getting absolute path to `SpaceEngine.exe` from cwd");

    // I don't think this will ever fail.
    env::current_dir().wrap_err(eyre!("Failed to get cwd"))
}

/// Internal function to reduce code repetition. This is easier to use than
/// calling [`ReadProcessMemory`] over and over again.
#[inline(always)]
fn __read_memory(handle: HANDLE, address: *const c_void, size: usize) -> Result<Vec<u8>> {
    // This will be filled later
    let mut buffer = vec![0u8; size];

    // SAFETY: Reading with `ReadProcessMemory` is safe, as it'll return `Err` if
    // any error occurs, rather than crashing.
    unsafe {
        if !ReadProcessMemory(
            handle,
            address,
            buffer.as_mut_ptr().cast::<c_void>(),
            size,
            None,
        )
        .as_bool()
        {
            return Err(eyre!(
                "Failed to read memory at `{address:?}`, `{size:?}`: {}",
                GetLastError().0
            ));
        }
    }

    Ok(buffer)
}

/// Internal function to reduce code repetition. This is easier to use than
/// calling [`WriteProcessMemory`] over and over again.
#[inline(always)]
unsafe fn __write_memory(
    handle: HANDLE, address: *const c_void, value: impl AsRef<[u8]>,
) -> Result<()> {
    let value = value.as_ref();

    // SAFETY: This is safe as long as you don't overwrite executing code.
    unsafe {
        WriteProcessMemory(
            handle,
            address,
            value.as_ptr().cast::<c_void>(),
            value.len(),
            None,
        );

        FlushInstructionCache(handle, Some(address), value.len());
    }

    Ok(())
}
