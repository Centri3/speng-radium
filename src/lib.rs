mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use eyre::Result;
use path_clean::PathClean;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::fs::DirEntry;
use std::mem::size_of;
use std::path::PathBuf;
use std::thread::Builder;
use steamworks::sys::SteamAPI_ISteamApps_GetCurrentBetaName;
use steamworks::sys::SteamAPI_Init;
use steamworks::sys::SteamAPI_Shutdown;
use steamworks::sys::SteamAPI_SteamApps_v008;
use tracing::info;
use tracing::trace_span;
use tracing::warn;
use windows::w;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Thread32Next;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONWARNING;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;

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

fn attach() {
    // Setup logging and retain the log file, panicking if it fails
    let _guard = logging::setup(&SetupFile::Retain);

    // We must do this to use Result everywhere. If main returns Result, color-eyre
    // won't catch it
    let result = __attach();
    // TODO: This should close SE if it unwraps.
    result.unwrap();
}

fn __attach() -> Result<()> {
    // Create a span so we know what's from here
    let _span = trace_span!("libradium").entered();

    info!("I have been loaded by SE");

    let cwd = env::current_dir()?;
    let exe = env::current_exe()?;

    info!(?cwd);
    info!(?exe);

    // Setup steam API
    let apps = unsafe {
        SteamAPI_Init();

        SteamAPI_SteamApps_v008()
    };

    let mut beta_name = [0u8; 64usize];

    let is_beta = unsafe {
        SteamAPI_ISteamApps_GetCurrentBetaName(
            apps,
            beta_name.as_mut_ptr().cast(),
            beta_name.len() as i32,
        )
    };

    // Convert beta_name to string
    let beta_name = String::from_utf8(beta_name.to_vec())?.replace('\0', "");

    info!(%beta_name, is_beta);

    // TODO: This should be properly tested.
    if !beta_name.is_empty() && beta_name != "beta" {
        warn!("User is using a branch other than public or beta! This is unsupported.");

        unsafe {
            MessageBoxW(
                None,
                w!(
                    "Please use either public or beta branch. Other branches are unsupported! \
                     There may be bugs, or there may not be."
                ),
                w!("Bad branch!"),
                MB_OKCANCEL | MB_ICONWARNING,
            )
        };
    }

    info!("Looking for addons folder");

    if cwd.join("../addons").clean().try_exists()? {
        fn walk_dir(entry: &DirEntry, directories: &mut Vec<PathBuf>) -> Result<()> {
            if entry.path().is_dir() {
                directories.push(entry.path());

                for entry in fs::read_dir(entry.path())? {
                    let entry = entry?;

                    walk_dir(&entry, directories)?;
                }
            }

            Ok(())
        }

        // TODO: This should also read pak files, too. And the workshop...

        let mut directories = vec![];

        directories.push(cwd.join("../addons").clean());

        info!("Found addons folder, iterating...");

        for entry in fs::read_dir(cwd.join("../addons").clean())? {
            let entry = entry?;

            if entry.path().is_dir() {
                walk_dir(&entry, &mut directories)?;
            }
        }

        info!(?directories);
    } else {
        warn!("Could not find addons folder!")
    }

    // Shutdown steam API
    unsafe { SteamAPI_Shutdown() };

    __resume_thread()?;

    Ok(())
}

#[inline(always)]
fn __resume_thread() -> Result<()> {
    unsafe {
        info!("Resuming main thread of SE");

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0u32)?;
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

            let hthread = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)?;

            ResumeThread(hthread);

            CloseHandle(hthread);

            break;
        }
    }

    Ok(())
}
