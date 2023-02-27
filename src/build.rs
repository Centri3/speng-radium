// Linux users can (probably!) run Radium through Proton: <https://gist.github.com/michaelbutler/f364276f4030c5f449252f2c4d960bd2>.
#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
compile_error!("Radium can only be compiled on Windows");
