//! LocalSend CLI Library (`lsend`)
//!
//! Provides the command-line utility, TLS certificate fingerprint pinning verifier,
//! and UDS IPC client connecting to `localsendd`.

pub mod args;
pub mod commands;
pub mod ipc_client;
pub mod tls_client;

pub use args::{Cli, Commands, TrustAction};
