mod build;

use std::thread;
use windows::w;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows::Win32::UI::WindowsAndMessaging::MB_OKCANCEL;
use windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT;

fn main() {
    unsafe {
        if MessageBoxW(
            None,
            w!("Hello from Radium! Successfully injected radium_dll.dll into SE."),
            w!("Hello, world!"),
            MB_OKCANCEL | MB_ICONINFORMATION,
        ) == MESSAGEBOX_RESULT(2i32)
        {
            TerminateProcess(GetCurrentProcess(), 0u32);
        }
    }
}

#[no_mangle]
extern "system" fn DllMain(_: HINSTANCE, reason: u32, _: usize) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        thread::spawn(main);
    }

    true
}
