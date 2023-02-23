#![allow(clippy::trait_duplication_in_bounds)]

//! # Overview
//!
//! Contains serde definitions for remote types, allowing implementations of
//! [`Serialize`]/[`Deserialize`] where they otherwise aren't implemented.
//!
//! # Current Implementations
//!
//! ## [`once_cell`]
//! - `sync::OnceCell`

use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde::Serialize;

/// Contains definitions for [`once_cell`]
pub mod __once_cell {
    /// Contains definitions for [`once_cell::sync`]
    pub mod __sync {
        use super::super::*;

        /// Definition for [`once_cell::sync::OnceCell`]. `T` must implement
        /// `Serialize`. Will dead-lock if serialized while uninitialized!
        #[derive(Deserialize, Serialize)]
        #[serde(remote = "OnceCell")]
        pub struct __OnceCell<T: Serialize + 'static>(#[serde(getter = "OnceCell::wait")] T);

        impl<T> From<__OnceCell<T>> for OnceCell<T>
        where
            T: Serialize + 'static,
        {
            fn from(value: __OnceCell<T>) -> Self {
                Self::with_value(value.0)
            }
        }
    }
}
