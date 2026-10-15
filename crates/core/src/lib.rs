//! `quorum-core`: the trusted core of the quorum HSM.
//!
//! This crate is the code that runs *inside* the HSM. It is `no_std`, does no
//! heap allocation and contains no `unsafe`, so the same code can run in the
//! host emulator today and on a microcontroller later.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod hsm;
pub mod keystore;
pub mod wire;

pub use hsm::{Hsm, Session, Storage, StorageError};

#[cfg(test)]
mod tests;
