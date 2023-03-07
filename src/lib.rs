mod build;
mod patch;
mod utils;
mod workshop;

use crate::patch::run_patches;
use crate::patch::FnReplace;
use crate::patch::Patches;
use crate::utils::logging;
use crate::utils::logging::SetupFile;
use crate::workshop::WorkshopItem;
use detour::RawDetour;
use eyre::eyre;
use eyre::Result;
use path_clean::PathClean;
use std::arch::asm;
use std::arch::global_asm;
use std::collections::HashMap;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::mem::size_of;
use std::mem::transmute;
use std::mem::ManuallyDrop;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::thread::Builder;
use steamworks_sys::ISteamUGC;
use steamworks_sys::SteamAPI_ISteamUGC_GetItemInstallInfo;
use steamworks_sys::SteamAPI_ISteamUGC_GetNumSubscribedItems;
use steamworks_sys::SteamAPI_ISteamUGC_GetSubscribedItems;
use steamworks_sys::SteamAPI_Init;
use steamworks_sys::SteamAPI_RestartAppIfNecessary;
use steamworks_sys::SteamAPI_Shutdown;
use steamworks_sys::SteamAPI_SteamUGC_v016;
use tracing::debug;
use tracing::info;
use tracing::trace_span;
use tracing_appender::non_blocking::WorkerGuard;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::ProcessStatus::K32EnumProcessModules;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::OpenThread;
use windows::Win32::System::Threading::ResumeThread;
use windows::Win32::System::Threading::THREAD_SUSPEND_RESUME;

static mut BASE_ADDRESS: usize = 0usize;
static mut TEST: usize = 0usize;

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

    unsafe {
        SteamAPI_RestartAppIfNecessary(314650u32);
        SteamAPI_Init();
    }

    info!("Initialized Steam API");

    let ugc = unsafe { SteamAPI_SteamUGC_v016() };
    let mut items = __get_workshop_items(ugc)?;
    let addons = __get_workshop_items_addons()?;

    info!("Found subscribed workshop items");

    for (_, item) in items.iter() {
        debug!(item.id, ?item.path)
    }

    // Remove disabled addons
    for addon in addons.iter() {
        if !addon.enabled.unwrap() && items.get(&addon.id).is_some() {
            items.remove(&addon.id).unwrap();
        }
    }

    info!("Disabled items based on `addons.cfg`");

    for (_, item) in items.iter() {
        debug!(item.id, ?item.path)
    }

    let mut modules = [HINSTANCE(0isize); 1024usize];
    unsafe {
        K32EnumProcessModules(
            GetCurrentProcess(),
            modules.as_mut_ptr().cast(),
            size_of::<[HINSTANCE; 1024usize]>() as u32,
            &mut 0u32,
        )
    };

    unsafe { BASE_ADDRESS = modules[0usize].0 as usize };

    fn __run_patches() {
        let patches: Patches = unsafe {
            (
                vec![],
                None,
                vec![],
                Some(Box::new(transmute::<_, fn()>(TEST))),
                None,
                vec![],
                None,
            )
        };

        run_patches(patches);
    }

    let hook = unsafe {
        let hook = ManuallyDrop::new(RawDetour::new(
            (BASE_ADDRESS + 0x3eaf10) as *const (),
            __run_patches as *const (),
        )?);

        TEST = hook.trampoline() as *const _ as usize;

        hook
    };

    unsafe { hook.enable()? };

    unsafe { SteamAPI_Shutdown() };

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

    std::thread::sleep(std::time::Duration::from_secs(10000));

    Ok(guard)
}

#[inline(always)]
fn __get_workshop_items(ugc: *mut ISteamUGC) -> Result<HashMap<u64, WorkshopItem>> {
    let num_of_items = unsafe { SteamAPI_ISteamUGC_GetNumSubscribedItems(ugc) };
    let mut item_ids = vec![0u64; num_of_items as usize];

    // This will get the id of every item the user's subscribed to
    unsafe { SteamAPI_ISteamUGC_GetSubscribedItems(ugc, item_ids.as_mut_ptr(), num_of_items) };

    let mut items = HashMap::with_capacity(num_of_items as usize);

    for item_id in item_ids {
        let mut path = [0u8; 1024usize];

        unsafe {
            SteamAPI_ISteamUGC_GetItemInstallInfo(
                ugc,
                item_id,
                &mut 0u64,
                path.as_mut_ptr().cast(),
                path.len() as u32,
                &mut 0u32,
            );
        }

        assert!(items
            .insert(
                item_id,
                WorkshopItem {
                    path: PathBuf::from(String::from_utf8(path.to_vec())?.replace('\0', "")),
                    id: item_id,
                    enabled: None,
                },
            )
            .is_none());
    }

    Ok(items)
}

// TODO: This is both disgusting and will fail if either Id or Enabled are
// within Path. FIX LATER.
#[inline(always)]
fn __get_workshop_items_addons() -> Result<Vec<WorkshopItem>> {
    let addons = fs::read_to_string(env::current_dir()?.join("../config/addons.cfg").clean())?;
    let mut items = vec![];

    for (path_indice, _) in addons.match_indices("Path") {
        let id_indice = path_indice
            + addons[path_indice..]
                .find("Id")
                .ok_or_else(|| eyre!("Missing `Id` field on addon"))?;

        let enabled_indice = id_indice
            + addons[id_indice..]
                .find("Enabled")
                .ok_or_else(|| eyre!("Missing `Enabled` field on addon"))?;

        let path_start = path_indice
            + addons[path_indice..]
                .find('"')
                .ok_or_else(|| eyre!("Unexpectedly got `None`"))?;

        let path = addons[path_start..]
            .split_once('\n')
            .ok_or_else(|| eyre!("Unexpectedly got `None`"))?
            .0
            .replace('"', "");

        let id = addons[id_indice..]
            .split_whitespace()
            .nth(1usize)
            .ok_or_else(|| eyre!("Unexpectedly got `None`"))?
            .parse::<u64>()?;

        let enabled = match addons[enabled_indice..]
            .split_whitespace()
            .nth(1usize)
            .ok_or_else(|| eyre!("Unexpectedly got `None`"))?
        {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(eyre!("Field `Enabled` was not bool")),
        }?;

        items.push(WorkshopItem {
            path: PathBuf::from(path),
            id,
            enabled: Some(enabled),
        })
    }

    Ok(items)
}
