//! Configuration types and defaults.
//!
//! The on-disk format is TOML. Unknown keys are ignored so a newer config can
//! be read by an older binary, but invalid values are rejected with an
//! actionable error.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "table" | "text" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            other => Err(format!("invalid output format: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub discovery: DiscoveryConfig,
    pub scanner: ScannerConfig,
    pub storage: StorageConfig,
    pub tui: TuiConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Preferred interface. `None` means auto-detect the default route.
    pub interface: Option<String>,
    pub default_output: OutputFormat,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            interface: None,
            default_output: OutputFormat::Table,
            log_level: "warn".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub arp: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub netbios: bool,
    /// Per-provider timeout. Providers that exceed it are reported as failed
    /// while other providers continue.
    pub timeout_ms: u64,
    /// Attempt reverse DNS for hosts that have no hostname from discovery.
    pub resolve_hostnames: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            arp: true,
            mdns: true,
            ssdp: true,
            netbios: true,
            timeout_ms: 2500,
            resolve_hostnames: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub default_ports: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
    /// Maximum connection attempts started per second. Zero means no explicit
    /// rate limit (concurrency still applies).
    pub rate_limit_per_sec: u32,
    pub banner_grab: bool,
    /// Safety cap on the number of hosts a single TCP scan may target.
    pub max_hosts: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            default_ports: "common".to_string(),
            timeout_ms: 1000,
            concurrency: 100,
            rate_limit_per_sec: 0,
            banner_grab: true,
            max_hosts: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// SQLite database path. `~` is expanded; relative paths are resolved
    /// against the configuration file's directory.
    pub database: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database: "~/.local/share/findarat/findarat.db".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TuiConfig {
    pub show_colors: bool,
    pub refresh_interval_ms: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            show_colors: true,
            refresh_interval_ms: 1000,
        }
    }
}

impl Config {
    /// Validate semantic constraints. Called after deserialization and before
    /// the configuration is used.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(interface) = &self.general.interface {
            if interface.trim().is_empty() {
                return Err("general.interface must not be empty (omit it to auto-detect)".into());
            }
        }
        match self.general.log_level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            other => {
                return Err(format!(
                "general.log_level must be one of error, warn, info, debug, trace (got {other:?})"
            ))
            }
        }

        if !(200..=30_000).contains(&self.discovery.timeout_ms) {
            return Err(format!(
                "discovery.timeout_ms must be between 200 and 30000 (got {})",
                self.discovery.timeout_ms
            ));
        }

        if !(50..=60_000).contains(&self.scanner.timeout_ms) {
            return Err(format!(
                "scanner.timeout_ms must be between 50 and 60000 (got {})",
                self.scanner.timeout_ms
            ));
        }
        if !(1..=1024).contains(&self.scanner.concurrency) {
            return Err(format!(
                "scanner.concurrency must be between 1 and 1024 (got {})",
                self.scanner.concurrency
            ));
        }
        if self.scanner.rate_limit_per_sec > 100_000 {
            return Err(format!(
                "scanner.rate_limit_per_sec must be at most 100000 (got {})",
                self.scanner.rate_limit_per_sec
            ));
        }
        if !(1..=65534).contains(&self.scanner.max_hosts) {
            return Err(format!(
                "scanner.max_hosts must be between 1 and 65534 (got {})",
                self.scanner.max_hosts
            ));
        }
        crate::scanner::parse_ports(&self.scanner.default_ports).map_err(|err| {
            format!(
                "scanner.default_ports is invalid ({:?}): {err}",
                self.scanner.default_ports
            )
        })?;

        if self.storage.database.trim().is_empty() {
            return Err("storage.database must not be empty".into());
        }

        if !(100..=60_000).contains(&self.tui.refresh_interval_ms) {
            return Err(format!(
                "tui.refresh_interval_ms must be between 100 and 60000 (got {})",
                self.tui.refresh_interval_ms
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn rejects_bad_concurrency() {
        let mut config = Config::default();
        config.scanner.concurrency = 0;
        assert!(config.validate().unwrap_err().contains("concurrency"));
    }

    #[test]
    fn rejects_bad_port_spec() {
        let mut config = Config::default();
        config.scanner.default_ports = "not-ports".into();
        assert!(config.validate().unwrap_err().contains("default_ports"));
    }

    #[test]
    fn parses_partial_toml_with_defaults() {
        let config: Config = toml::from_str(
            r#"
            [scanner]
            timeout_ms = 500
            "#,
        )
        .unwrap();
        assert_eq!(config.scanner.timeout_ms, 500);
        assert_eq!(config.scanner.concurrency, 100);
        assert!(config.discovery.arp);
    }

    #[test]
    fn output_format_round_trip() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::Table.as_str(), "table");
    }
}
