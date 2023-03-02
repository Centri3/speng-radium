mod build;
mod logging;

use logging::SetupFile;
use std::fs;
use std::thread::Builder;
use windows::w;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::System::Threading::THREAD_ALL_ACCESS;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

fn main() {
    let _guard = logging::setup(SetupFile::Retain).expect("Failed to setup logging");

    unsafe {
        if MessageBoxW(
            None,
            w!("Hello from Radium! Successfully injected speng_radium.dll into SE."),
            w!("Hello, world!"),
            MB_OKCANCEL | MB_ICONINFORMATION,
        ) == MESSAGEBOX_RESULT(2i32)
        {
            TerminateProcess(GetCurrentProcess(), 0u32);
        }

        // FIXME: THIS SHOULD NOT PANIC.
        let handle = OpenThread(
            THREAD_ALL_ACCESS,
            false,
            fs::read_to_string("threadid")
                .unwrap()
                .trim()
                .parse::<isize>()
                .unwrap() as u32,
        );

        ResumeThread(handle.unwrap());
    }
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
