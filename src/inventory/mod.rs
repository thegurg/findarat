//! Persistent inventory: SQLite storage, identity matching, and history diffs.

pub mod database;
pub mod history;
pub mod identity;

pub use database::{Database, UpsertOptions, UpsertOutcome};
