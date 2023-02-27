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
