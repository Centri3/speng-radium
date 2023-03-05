mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use detour::static_detour;
use eyre::eyre;
use eyre::Result;
use gag::Redirect;
use path_clean::PathClean;
use std::arch::asm;
use std::arch::global_asm;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::fs::DirEntry;
use std::fs::File;
use std::mem::size_of;
use std::mem::transmute;
use std::path::PathBuf;
use std::thread::Builder;
use steamworks::sys::SteamAPI_ISteamApps_GetCurrentBetaName;
use steamworks::sys::SteamAPI_Init;
use steamworks::sys::SteamAPI_RestartAppIfNecessary;
use steamworks::sys::SteamAPI_Shutdown;
use steamworks::sys::SteamAPI_SteamApps_v008;
use steamworks::sys::SteamAPI_SteamUGC_v016;
use tracing::info;
use tracing::trace_span;
use tracing::warn;
use windows::core::InParam;
use windows::core::PCWSTR;
use windows::s;
use windows::w;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Thread32Next;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::VirtualFree;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::THREAD_ALL_ACCESS;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;
use windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::HMENU;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONWARNING;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;
use windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE;
use windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE;
use windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW;

static_detour! {
    static CreateWindowExWHook: unsafe extern "system" fn(WINDOW_EX_STYLE, PCWSTR, PCWSTR, WINDOW_STYLE, i32, i32, i32, i32, HWND, HMENU, HINSTANCE, *const c_void) -> HWND;
}

#[rustfmt::skip]
type FnCreateWindowExW = unsafe extern "system" fn(WINDOW_EX_STYLE, PCWSTR, PCWSTR, WINDOW_STYLE, i32, i32, i32, i32, HWND, HMENU, HINSTANCE, *const c_void) -> HWND;

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, reason: u32, _: usize) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        Builder::new()
            .name("dll-main".to_owned())
            .spawn(attach)
            .unwrap();
    }

    true
}

// TODO: If this panics or otherwise crashes, it sometimes won't finish logging.
// This makes debugging a pain...
fn attach() {
    // Setup logging and retain the log file, panicking if it fails
    let _guard = logging::setup(&SetupFile::Retain);

    // We must do this to use Result everywhere. If main returns Result, color-eyre
    // won't catch it
    __attach().unwrap();
}

fn __attach() -> Result<()> {
    // Create a span so we know what's from here
    let _span = trace_span!("libradium").entered();

    info!("I have been loaded by SE");

    // Resume the main thread of SE
    unsafe {
        assert_ne!(
            ResumeThread(OpenThread(
                THREAD_SUSPEND_RESUME,
                false,
                fs::read_to_string("mainthread")?.parse::<u32>()?,
            )?),
            u32::MAX
        );
    }

    // Clean up
    fs::remove_file("mainthread")?;

    Ok(())
}
