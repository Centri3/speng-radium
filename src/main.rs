#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod build;
mod logging;

use eyre::eyre;
use eyre::Context;
use eyre::Result;
use lnk::ShellLink;
use logging::setup_logging;
use path_clean::PathClean;
use std::env;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;
use windows::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS;
use windows::Win32::System::Threading::DEBUG_PROCESS;
use windows::Win32::System::Threading::DETACHED_PROCESS;

fn main() {
    let _guard = setup_logging().expect("Failed to setup logging");

    __start_modded_se().unwrap();
}

#[inline(always)]
fn __get_exe_path() -> Result<PathBuf> {
    let path = match Path::new("SpaceEngine.lnk").try_exists()? {
        // Get absolute path to `SpaceEngine.exe` from shortcut, if it exists
        true => __exe_from_shortcut(),
        // Otherwise, get from the current working directory
        false => __exe_from_path(),
    }?
    .join("system\\SpaceEngine.exe");

    // Print the path we just obtained
    info!(?path, "Successfully got absolute path to `SpaceEngine.exe`");

    Ok(path)
}

#[inline(always)]
fn __exe_from_shortcut() -> Result<PathBuf> {
    info!("Getting absolute path to `SpaceEngine.exe` from `SpaceEngine.lnk`");

    let link = ShellLink::open("SpaceEngine.lnk")
        // Normally, I'd just put e here, but this makes it aligned with the others. It's pretty!
        .map_err(|err| eyre!("`SpaceEngine.lnk` exists, but failed to open it: {err:?}"))?;

    link.link_info()
        .as_ref()
        .ok_or_else(|| eyre!("`SpaceEngine.lnk` does not have `LinkInfo` structure"))?
        .local_base_path()
        .as_ref()
        .ok_or_else(|| eyre!("Can't find absolute path of `SpaceEngine.lnk`"))
        .map(|s| PathBuf::from(s.to_owned()))
}

#[inline(always)]
fn __exe_from_path() -> Result<PathBuf> {
    info!("Getting absolute path to `SpaceEngine.exe` from cwd");

    // I don't think this will ever fail.
    env::current_dir().wrap_err(eyre!("Failed to get cwd"))
}

fn __start_modded_se() -> Result<()> {
    let path = __get_exe_path().expect("Failed to get path to SpaceEngine.exe");

    Command::new(&path)
        // SpaceEngine/system/SpaceEngine.exe -> SpaceEngine/system
        .current_dir(&path.join("../").clean())
        // Debug SE and don't inherit console
        .creation_flags(DEBUG_ONLY_THIS_PROCESS.0 | DEBUG_PROCESS.0 | DETACHED_PROCESS.0)
        // Don't use debug heap. Speeds up modded SE a LOT.
        .env("_NO_DEBUG_HEAP", "1")
        .spawn()?;

    Ok(())
}
