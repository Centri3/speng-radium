#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use eyre::eyre;
use eyre::Result;
use eyre::WrapErr;
use if_chain::if_chain;
use lnk::ShellLink;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::mem::transmute;
use std::os::windows::prelude::AsRawHandle;
use std::os::windows::prelude::OwnedHandle;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;
use tracing::trace_span;
use tracing_appender::non_blocking::WorkerGuard;
use windows::s;
use windows::w;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::CREATE_SUSPENDED;
use windows::Win32::System::Threading::DETACHED_PROCESS;
use windows::Win32::System::Threading::THREAD_CREATE_RUN_IMMEDIATELY;

// Name of our DLL we inject into SE
const DLL_NAME: &[u8] = b"libradium.dll";

fn main() {
    // We must do this to use Result everywhere. If main returns Result,
    // color-eyre won't catch it
    let _guard = __start_modded_se().expect("Failed to start modded SE");
}

#[inline(always)]
fn __start_modded_se() -> Result<WorkerGuard> {
    // We do this before setting up the log so we don't use the wrong cwd
    let path = __get_exe_path()?;

    // Setup logging and overwrite the log file, panicking if it fails
    let guard = logging::setup(&SetupFile::Overwrite);
    // Create a span so we know what's from the loader
    let _span = trace_span!("loader").entered();

    info!("Starting modded SE");

    // Start SE in a suspended state, and get an OwnedHandle to it
    let hprocess: OwnedHandle = Command::new(path)
        .creation_flags(DETACHED_PROCESS.0 | CREATE_SUSPENDED.0)
        .spawn()
        .wrap_err("Starting `SpaceEngine.exe` failed")?
        .into();

    // Use shadowing to cleanly convert our OwnedHandle to HANDLE
    let hprocess = HANDLE(hprocess.as_raw_handle() as isize);

    unsafe {
        let alloc = VirtualAllocEx(
            hprocess,
            None,
            DLL_NAME.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        // SAFETY: This is safe, as if VirtualAllocEx fails, it'll return NULL, which
        // will cause this to fail, but safely.
        WriteProcessMemory(
            hprocess,
            alloc,
            DLL_NAME.as_ptr().cast(),
            DLL_NAME.len(),
            None,
        )
        .unwrap();

        CreateRemoteThread(
            hprocess,
            None,
            0usize,
            Some(
                // SAFETY: LPTHREAD_START_ROUTINE and LoadLibraryA have similar signatures, so this
                // is ok.
                transmute(
                    GetProcAddress(
                        GetModuleHandleW(w!("kernel32.dll"))
                            .wrap_err("Failed to get handle to `kernel32.dll`")?,
                        s!("LoadLibraryA"),
                    )
                    .ok_or_else(|| eyre!("Failed to get address of `LoadLibraryA`"))?,
                ),
            ),
            // Provide the name of our dll to LoadLibraryA
            Some(alloc),
            THREAD_CREATE_RUN_IMMEDIATELY.0,
            None,
        )
        .expect("TODO:");
    }

    Ok(guard)
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
