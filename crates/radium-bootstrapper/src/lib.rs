mod utils;

use std::ffi::c_void;
use std::iter::once;
use std::thread;
use windows::s;
use windows::w;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
use windows::Win32::UI::WindowsAndMessaging::MB_OK;
use windows_sys::core::PCSTR;
use windows_sys::core::PCWSTR;
use windows_sys::core::PSTR;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::Storage::FileSystem::GET_FILE_VERSION_INFO_FLAGS;
use windows_sys::Win32::Storage::FileSystem::VER_FIND_FILE_FLAGS;
use windows_sys::Win32::Storage::FileSystem::VER_FIND_FILE_STATUS;

lazy_export! {
    fn GetFileVersionInfoA(a: PCSTR, b: u32, c: u32, d: *mut c_void) -> i32;
    fn GetFileVersionInfoExA(a: GET_FILE_VERSION_INFO_FLAGS, b: PCSTR, c: u32, d: u32, e: *mut c_void) -> i32;
    fn GetFileVersionInfoExW(a: GET_FILE_VERSION_INFO_FLAGS, b: PCWSTR, c: u32, d: u32, e: *mut c_void) -> i32;
    fn GetFileVersionInfoSizeA(a: PCSTR, b: *mut u32) -> u32;
    fn GetFileVersionInfoSizeExA(a: GET_FILE_VERSION_INFO_FLAGS, b: PCSTR, c: *mut u32) -> u32;
    fn GetFileVersionInfoSizeExW(a: GET_FILE_VERSION_INFO_FLAGS, b: PCWSTR, c: *mut u32) -> u32;
    fn GetFileVersionInfoSizeW(a: PCWSTR, b: *mut u32) -> u32;
    fn GetFileVersionInfoW(a: PCWSTR, b: u32, c: u32, d: *mut c_void) -> i32;
    fn VerFindFileA(a: VER_FIND_FILE_FLAGS, b: PCSTR, c: PCSTR, d: PCSTR, e: PSTR, f: *mut u32, g: PSTR, h: *mut u32) -> VER_FIND_FILE_STATUS;
    fn VerFindFileW(a: VER_FIND_FILE_FLAGS, b: PCWSTR, c: PCWSTR, d: PCWSTR, e: PWSTR, f: *mut u32, g: PWSTR, h: *mut u32) -> VER_FIND_FILE_STATUS;
    fn VerInstallFileA(a: VER_FIND_FILE_FLAGS, b: PCSTR, c: PCSTR, d: PCSTR, e: PSTR, f: PSTR, g: PSTR, h: *mut u32) -> VER_FIND_FILE_STATUS;
    fn VerInstallFileW(a: VER_FIND_FILE_FLAGS, b: PCWSTR, c: PCWSTR, d: PCWSTR, e: PWSTR, f: PWSTR, g: PWSTR, h: *mut u32) -> VER_FIND_FILE_STATUS;
    fn VerLanguageNameA(a: u32, b: PSTR, c: u32) -> u32;
    fn VerLanguageNameW(a: u32, b: PWSTR, c: u32) -> u32;
    fn VerQueryValueA(a: *const c_void, b: PCSTR, c: *mut *mut c_void, d: *mut u32) -> i32;
    fn VerQueryValueW(a: *const c_void, b: PCWSTR, c: *mut *mut c_void, d: *mut u32) -> i32;
}

fn main() {
    unsafe {
        MessageBoxW(
            HWND(0isize),
            w!("yeaaaaaaaaaaaaaaaaaah"),
            w!("trans rights!"),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

#[no_mangle]
pub extern "system" fn DllMain(_: HINSTANCE, reason: u32, _: usize) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        thread::spawn(main);
    }

    true
}
