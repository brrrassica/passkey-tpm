//! User verification providers for passkey-tpm.
//!
//! [`fprintd`] talks to the fprintd daemon (`net.reactivated.Fprint`) over D-Bus to verify a
//! fingerprint for a given user. The broker turns a [`fprintd::UvResult::Match`] into UV
//! evidence; every other outcome must be treated as "no user verification".
//!
//! With the `mock` feature, `mock` provides an in-process fake fprintd service so the broker
//! and this crate can be tested on a private bus without hardware.
#![forbid(unsafe_code)]

pub mod fprintd;
pub mod polkit;
pub mod seat;

#[cfg(feature = "mock")]
pub mod mock;
