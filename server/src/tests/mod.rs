//! Hermetic tests: no network beyond loopback, no Docker, no directory.
//!
//! Unit tests live next to this file as `unit_<module>.rs`, included by their module (`#[path]`) so they can
//! see its private items. Shared fakes (directory, LDAP byte streams, a test PKI, a TLS client) are in
//! `support`; the end-to-end tests (TLS listener with a fake directory, LDAPS directory against a fake 389 DS)
//! and the tests of `main.rs`'s helpers are here.

mod e2e_directory;
mod e2e_serve;
mod main_fns;
pub mod support;
