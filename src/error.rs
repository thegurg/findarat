//! Error types used at the application boundary.
//!
//! Most fallible functions return `anyhow::Result` for contextual error chains.
//! A small number of errors carry a stable process exit code so scripts can
//! distinguish "not found" from "invalid input".

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum FindaratError {
    #[error("device not found: {0}")]
    DeviceNotFound(String),
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("permission required: {0}")]
    PermissionRequired(String),
    #[error("database error: {0}")]
    Database(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl FindaratError {
    /// Stable exit codes documented in the README.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::DeviceNotFound(_) => 3,
            Self::Validation(_) | Self::Config(_) => 4,
            Self::PermissionRequired(_) => 5,
            Self::Database(_) => 6,
            Self::Io(_) => 1,
        }
    }
}

/// Exit codes for the CLI. `2` is reserved for clap usage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Failure = 1,
    Usage = 2,
    NotFound = 3,
    Validation = 4,
    Permission = 5,
    Database = 6,
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

/// Convert an error chain into a process exit code by looking for a
/// [`FindaratError`] anywhere in the chain.
pub fn exit_code_for(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(findarat) = cause.downcast_ref::<FindaratError>() {
            return findarat.exit_code();
        }
    }
    1
}
