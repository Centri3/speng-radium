mod build;
mod utils;

use crate::utils::logging;
use crate::utils::logging::SetupFile;
use std::mem::size_of;
use std::thread::Builder;
use tracing::trace;
use windows::w;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Thread32Next;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

fn main() {
    // Setup logging and retain the log file, panicking if it fails
    let _guard = logging::setup(SetupFile::Retain);

    trace!("`libradium.dll` has been loaded by SE");

    unsafe {
        if MessageBoxW(
            None,
            w!("Hello from Radium! Successfully injected libradium.dll into SE."),
            w!("Hello, world!"),
            MB_OKCANCEL | MB_ICONINFORMATION,
        ) == MESSAGEBOX_RESULT(2i32)
        {
            TerminateProcess(GetCurrentProcess(), 0u32);
        }

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0u32).unwrap();
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        // TODO: Should this unwrap here?
        while Thread32Next(snapshot, &mut entry).as_bool() {
            entry.dwSize = size_of::<THREADENTRY32>() as u32;

            // There's only our thread and the main thread when this is ran, so we just
            // resume the first one where this isn't true
            if entry.th32OwnerProcessID == GetCurrentProcessId()
                && entry.th32ThreadID != GetCurrentThreadId()
            {
                let hthread = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID).unwrap();

                ResumeThread(hthread);

                CloseHandle(hthread);

                break;
            }
        }
    }

    panic!();
}

#[no_mangle]
extern "system" fn DllMain(_: HINSTANCE, reason: u32, _: usize) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        Builder::new()
            .name("dll-main".to_owned())
            .spawn(main)
            .unwrap();
    }

    true
}
