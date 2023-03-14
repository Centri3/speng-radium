mod build;
mod patch;
mod utils;
mod workshop;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use dll_syringe::process::OwnedProcess;
use eyre::Result;
use if_chain::if_chain;
use path_clean::PathClean;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::s;
use windows::w;
use std::fs;
use std::path::Path;
use std::thread::Builder;
use tracing::info;
use tracing::trace_span;
use tracing_appender::non_blocking::WorkerGuard;
use walkdir::WalkDir;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;
use retour::static_detour;



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

// FIXME: If this segfaults, it won't finish printing to log. This makes
// debugging a pain... Sadly, I don't think this can be fixed.
fn attach() {
    // We must do this to use Result everywhere. If main returns Result, color-eyre
    // won't catch it
    let _guard = __attach().unwrap();
}

fn __attach() -> Result<WorkerGuard> {
    // Setup logging and retain the log file, panicking if it fails
    let guard = logging::setup(&SetupFile::Retain);
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

    info!("Finding mod dlls");

    let mut dlls = vec![];

    for entry in WalkDir::new(Path::new("../mods").clean()) {
        let entry = entry.unwrap();
        let path = entry.path();

        if_chain! {
            if path.is_file();
            if let Some(extension) = path.extension();
            if extension == "dll";

            then { dlls.push(path.to_owned()); }
        }
    }

    let x = unsafe { GetProcAddress(GetModuleHandleW(w!("OPENGL32.dll"))?, s!("wglSwapBuffers")).unwrap() };

    info!("{:?}", x as *const ());

    // let target = OwnedProcess::from_pid(unsafe { GetCurrentProcessId() })?;

    

    Ok(guard)
}
