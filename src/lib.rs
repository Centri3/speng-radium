mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use ctor::ctor;
use eyre::Result;
use if_chain::if_chain;
use std::ffi::c_void;
use std::mem::size_of;
use steamworks::sys::SteamAPI_ISteamApps_GetCurrentBetaName;
use steamworks::sys::SteamAPI_Init;
use steamworks::sys::SteamAPI_Shutdown;
use steamworks::sys::SteamAPI_SteamApps_v008;
use steamworks::Client;
use tracing::info;
use tracing::trace;
use tracing::trace_span;
use tracing::warn;
use windows::w;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Thread32Next;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONWARNING;
use windows::Win32::UI::WindowsAndMessaging::MB_OK;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

#[ctor]
fn ctor() {
    // We must do this to use Result everywhere. If main returns Result, color-eyre
    // won't catch it
    __ctor().unwrap();
}

fn __ctor() -> Result<()> {
    // Setup logging and retain the log file, panicking if it fails
    let _guard = logging::setup(&SetupFile::Retain);
    // Create a span so we know what's from here
    let _span = trace_span!("libradium").entered();

    info!("I have been loaded by SE");

    // Setup steam API
    let apps = unsafe {
        SteamAPI_Init();

        SteamAPI_SteamApps_v008()
    };

    let mut beta_name = ['\0'; 64usize];

    let is_beta = unsafe {
        SteamAPI_ISteamApps_GetCurrentBetaName(
            apps,
            beta_name.as_mut_ptr().cast(),
            beta_name.len() as i32,
        )
    };

    // Convert beta_name to string
    let beta_name = beta_name.iter().collect::<String>().replace('\0', "");

    info!(%beta_name, is_beta);

    // TODO: This should be properly tested.
    if !beta_name.is_empty() && beta_name != "beta" {
        warn!("User is using a branch other than public or beta! This is unsupported.");

        unsafe {
            MessageBoxW(
                None,
                w!(
                    "Please use either public or beta branch. Other branches are unsupported! \
                     There may be bugs, or there may be not."
                ),
                w!("Bad branch!"),
                MB_OKCANCEL | MB_ICONWARNING,
            )
        };
    }

    // Shutdown steam API
    unsafe { SteamAPI_Shutdown() };

    __resume_thread();

    Ok(())
}

#[inline(always)]
fn __resume_thread() {
    unsafe {
        info!("Resuming main thread of SE");

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0u32).unwrap();
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        info!("Snapped threads, iterating...");

        while Thread32Next(snapshot, &mut entry).as_bool() {
            // TODO: I don't think this is necessary
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            // There's only our thread and the main thread when this is ran, so we just
            // resume the first one where this isn't true
            if entry.th32OwnerProcessID != GetCurrentProcessId()
                || entry.th32ThreadID == GetCurrentThreadId()
            {
                continue;
            }

            // This is cast to c_void so it prints as hex in the log. Probably unnecessary
            info!(tid = ?entry.th32ThreadID as *const c_void, "Found main thread of SE");

            let hthread = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID).unwrap();

            ResumeThread(hthread);

            CloseHandle(hthread);

            break;
        }
    }
}
