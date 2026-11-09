//! findarat: Linux-first local network discovery and device intelligence.

pub mod app;
pub mod cli;
pub mod config;
pub mod discovery;
pub mod error;
pub mod fingerprint;
pub mod inventory;
pub mod io;
pub mod models;
pub mod network;
pub mod scanner;
pub mod tui;

/// Tool version reported in exports and the TUI header.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Export/import schema version. Bump only for incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;
