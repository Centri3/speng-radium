mod utils;

use std::ffi::c_void;
use windows::s;
use windows_sys::core::PCSTR;
use windows_sys::core::PCWSTR;
use windows_sys::core::PSTR;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoA;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoExA;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoExW;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoSizeA;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoSizeExA;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoSizeExW;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoSizeW;
use windows_sys::Win32::Storage::FileSystem::GetFileVersionInfoW;
use windows_sys::Win32::Storage::FileSystem::VerFindFileA;
use windows_sys::Win32::Storage::FileSystem::VerFindFileW;
use windows_sys::Win32::Storage::FileSystem::VerInstallFileA;
use windows_sys::Win32::Storage::FileSystem::VerInstallFileW;
use windows_sys::Win32::Storage::FileSystem::VerLanguageNameA;
use windows_sys::Win32::Storage::FileSystem::VerLanguageNameW;
use windows_sys::Win32::Storage::FileSystem::VerQueryValueA;
use windows_sys::Win32::Storage::FileSystem::VerQueryValueW;
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

pub extern "system" fn DllMain(_: *mut u8, call_reason: i32, _: *mut u8) -> bool {
    if call_reason == 1 {}

    true
}
