#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod logging;

use logging::setup_logging;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use tracing::error;
use tracing::info;
use windows::s;
use windows::w;
use windows::Win32::Foundation::DBG_CONTINUE;
use windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows::Win32::Storage::FileSystem::FILE_NAME;
use windows::Win32::System::Diagnostics::Debug::ContinueDebugEvent;
use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
use windows::Win32::System::Diagnostics::Debug::DebugSetProcessKillOnExit;
use windows::Win32::System::Diagnostics::Debug::WaitForDebugEvent;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT;
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_DEBUG_EVENT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::GetProcessId;
use windows::Win32::System::Threading::GetThreadId;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;

fn main() {
    /*
    std::env::set_current_dir("C:/Program Files (x86)/Steam/steamapps/common/SpaceEngine/system")
        .unwrap();
    */

    let _guard = setup_logging().expect("Failed to setup logging");
    let mut entry = 0usize;

    Command::new(Path::new("SpaceEngine.exe").canonicalize().unwrap())
        .creation_flags(0x1)
        .env("_NO_DEBUG_HEAP", "1")
        .spawn()
        .unwrap();

    loop {
        unsafe {
            let mut event = DEBUG_EVENT::default();

            DebugSetProcessKillOnExit(false);
            WaitForDebugEvent(&mut event, u32::MAX);

            match event.dwDebugEventCode.0 {
                0u32 => break,
                1u32 => info!("DEBUG_EVENT(1): {:?}", event.u.Exception),
                2u32 => info!("DEBUG_EVENT(2): {:?}", event.u.CreateThread),
                3u32 => info!("DEBUG_EVENT(3): {:?}", event.u.CreateProcessInfo),
                4u32 => info!("DEBUG_EVENT(4): {:?}", event.u.ExitThread),
                5u32 => info!("DEBUG_EVENT(5): {:?}", event.u.ExitProcess),
                6u32 => info!("DEBUG_EVENT(6): {:?}", event.u.LoadDll),
                7u32 => info!("DEBUG_EVENT(7): {:?}", event.u.UnloadDll),
                8u32 => info!("DEBUG_EVENT(8): {:?}", event.u.DebugString),
                9u32 => info!("DEBUG_EVENT(9): {:?}", event.u.RipInfo),
                _ => error!(
                    "DEBUG_EVENT({}): Unknown event code!",
                    event.dwDebugEventCode.0
                ),
            }

            if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                let mut name = [0u16; 2048];
                GetFinalPathNameByHandleW(
                    event.u.CreateProcessInfo.hFile,
                    &mut name,
                    FILE_NAME(0x8),
                );

                let pid = GetProcessId(event.u.CreateProcessInfo.hProcess);
                let tid = GetThreadId(event.u.CreateProcessInfo.hThread);

                info!(
                    "File name: {}",
                    String::from_utf16_lossy(&name).replace('\0', "")
                );

                info!("PID: {pid:X}");
                info!("TID: {tid:X}");

                entry = event.u.CreateProcessInfo.lpStartAddress.unwrap() as _;

                info!("ENTRY: {:X}", entry);

                WriteProcessMemory(
                    event.u.CreateProcessInfo.hProcess,
                    entry as _,
                    [0xCC].as_ptr() as _,
                    1usize,
                    None,
                );
            }

            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
                && event.u.Exception.ExceptionRecord.ExceptionAddress == entry as _
            {
                let load_library_a = GetProcAddress(
                    GetModuleHandleW(w!("kernel32.dll")).unwrap(),
                    s!("LoadLibraryA"),
                )
                .unwrap();

                info!("LoadLibraryA: {:X?}", load_library_a as usize);

                let hprocess = OpenProcess(PROCESS_ALL_ACCESS, false, event.dwProcessId).unwrap();

                let memory = VirtualAllocEx(
                    hprocess,
                    None,
                    10000,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                );

                info!("ADDRESS: {memory:X?}");

                let string = "radium_dll.dll";

                WriteProcessMemory(
                    hprocess,
                    memory,
                    string.as_ptr() as _,
                    string.as_bytes().len(),
                    None,
                );

                CreateRemoteThread(
                    hprocess,
                    None,
                    0usize,
                    Some(std::mem::transmute(load_library_a)),
                    Some(memory),
                    0u32,
                    None,
                )
                .unwrap();

                WriteProcessMemory(
                    event.u.CreateProcessInfo.hProcess,
                    entry as _,
                    [0x48].as_ptr() as _,
                    1usize,
                    None,
                );

                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);

                DebugActiveProcessStop(event.dwProcessId);

                break;
            }

            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
        }
    }
}
