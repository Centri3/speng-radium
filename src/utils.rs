//! TODO: This just contains random stuff that might be useful.

pub mod short_names;

use std::any;

/// Calls [`shorten_type_name`] with the return value of [`any::type_name`].
#[inline]
pub fn short_type_name<T>() -> String
where
    T: ?Sized,
{
    short_names::get_short_name(any::type_name::<T>())
}

/// Prevent compiling if `target_arch` != `x86_64` && `target_os` != `windows`.
/// Linux users can (probably!) [run Radium through Proton](https://gist.github.com/michaelbutler/f364276f4030c5f449252f2c4d960bd2).
#[macro_export]
macro_rules! check_target {
    () => {
        #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
        compile_error!("Radium can only be compiled on Windows");
    };
}
