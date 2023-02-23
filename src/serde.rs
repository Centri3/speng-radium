//! # Overview
//!
//! Contains [`serde`] definitions for remote types, allowing implementations of
//! [`Serialize`]/[`Deserialize`] where they otherwise aren't implemented.
//!
//! # Structure
//!
//! The structure of modules here is the same as the crates it provides
//! definitions for; in other words, [`once_cell::sync::OnceCell`] becomes
//! [`__once_cell::__sync::__OnceCell`]. This is to keep this module orderly,
//! rather than putting every definition at the root like a free for all (if
//! this was done, items like [`unsync::OnceCell`] and
//! [`sync::OnceCell`] would clash).
//!
//! # Current Definitions
//!
//! ## [`once_cell`]
//! - [`sync::OnceCell`]

// False positives. Seemingly can't disable this for individual types, sadly.
#![allow(clippy::trait_duplication_in_bounds)]

// These are for docs, they are not to be used.
#[allow(unused_imports)]
use once_cell::sync;
#[allow(unused_imports)]
use once_cell::unsync;

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
