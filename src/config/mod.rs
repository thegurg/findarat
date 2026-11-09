//! Configuration loading and XDG path resolution.

pub mod settings;

use anyhow::Context;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::FindaratError;
pub use settings::{
    Config, DiscoveryConfig, GeneralConfig, OutputFormat, ScannerConfig, StorageConfig, TuiConfig,
};

pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# findarat configuration
# Location: $XDG_CONFIG_HOME/findarat/config.toml (usually ~/.config/findarat/config.toml)

[general]
# Leave unset to auto-detect the interface carrying the default route.
# interface = "wlan0"
default_output = "table"       # table | json
log_level = "warn"             # error | warn | info | debug | trace

[discovery]
arp = true
mdns = true
ssdp = true
netbios = true
timeout_ms = 2500              # per-provider timeout
resolve_hostnames = true       # reverse DNS for hosts without an advertised name

[scanner]
default_ports = "common"       # common | all | 1-1024 | 22,80,443
timeout_ms = 1000              # TCP connect timeout
concurrency = 100              # simultaneous connection attempts
rate_limit_per_sec = 0         # 0 = no explicit rate limit
banner_grab = true
max_hosts = 4096               # safety cap for one TCP scan

[storage]
database = "~/.local/share/findarat/findarat.db"

[tui]
show_colors = true
refresh_interval_ms = 1000
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPaths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub database: PathBuf,
}

impl ConfigPaths {
    /// Resolve paths from XDG environment variables, with explicit overrides
    /// taking precedence.
    pub fn resolve(config_override: Option<&Path>, database_override: Option<&Path>) -> Self {
        let config_file = config_override
            .map(absolute_path)
            .unwrap_or_else(|| config_home().join("findarat").join("config.toml"));
        let data_dir = data_home().join("findarat");
        let database = database_override
            .map(absolute_path)
            .unwrap_or_else(|| data_dir.join("findarat.db"));
        Self {
            config_file,
            data_dir,
            database,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub paths: ConfigPaths,
    /// `None` when no configuration file existed and defaults were used.
    pub source: Option<PathBuf>,
    pub warnings: Vec<String>,
}

impl LoadedConfig {
    pub fn load(
        config_override: Option<&Path>,
        database_override: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let mut paths = ConfigPaths::resolve(config_override, database_override);
        let mut warnings = Vec::new();

        let (mut config, source) = if paths.config_file.exists() {
            let content = fs::read_to_string(&paths.config_file).with_context(|| {
                format!("failed to read config file {}", paths.config_file.display())
            })?;
            let config: Config = toml::from_str(&content).map_err(|err| {
                FindaratError::Config(format!(
                    "failed to parse config file {}: {err}",
                    paths.config_file.display()
                ))
            })?;
            (config, Some(paths.config_file.clone()))
        } else {
            (Config::default(), None)
        };

        if let Some(database) = database_override {
            paths.database = absolute_path(database);
            config.storage.database = paths.database.display().to_string();
        } else if source.is_none() {
            // Keep the default database in the XDG data directory rather than
            // a literal home path, so XDG_DATA_HOME is respected.
            config.storage.database = paths.database.display().to_string();
        } else {
            let base = paths.config_file.parent();
            let resolved = expand_path(&config.storage.database, base)?;
            if resolved != paths.database {
                paths.database = resolved;
            }
        }

        if let Some(interface) = &config.general.interface {
            if interface.trim() != interface || interface.contains(char::is_whitespace) {
                warnings.push(format!(
                    "general.interface contains whitespace: {interface:?}"
                ));
            }
        }

        config.validate().map_err(FindaratError::Config)?;

        Ok(Self {
            config,
            paths,
            source,
            warnings,
        })
    }

    /// Effective database path (after config, XDG, and CLI resolution).
    pub fn database_path(&self) -> &Path {
        &self.paths.database
    }

    pub fn config_path(&self) -> &Path {
        &self.paths.config_file
    }

    /// Write the documented default template, creating parent directories.
    /// Existing files are only replaced when `force` is true.
    pub fn write_default_template(path: &Path, force: bool) -> anyhow::Result<()> {
        if path.exists() && !force {
            return Err(FindaratError::Validation(format!(
                "{} already exists; use --force to overwrite",
                path.display()
            ))
            .into());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, DEFAULT_CONFIG_TEMPLATE)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn xdg_dir(variable: &str, fallback: PathBuf) -> PathBuf {
    match env::var_os(variable) {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                home_dir().join(path)
            }
        }
        _ => fallback,
    }
}

pub fn config_home() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", home_dir().join(".config"))
}

pub fn data_home() -> PathBuf {
    xdg_dir("XDG_DATA_HOME", home_dir().join(".local").join("share"))
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Expand `~`, `~/...`, and relative paths. Relative paths are resolved
/// against `base` (normally the config file's directory).
pub fn expand_path(value: &str, base: Option<&Path>) -> anyhow::Result<PathBuf> {
    let value = value.trim();
    if value.is_empty() {
        return Err(FindaratError::Config("path must not be empty".into()).into());
    }
    let path = if value == "~" {
        home_dir()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        PathBuf::from(value)
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        let base = match base {
            Some(base) => base.to_path_buf(),
            None => env::current_dir().context("cannot resolve relative path")?,
        };
        Ok(base.join(path))
    }
}

/// Render the effective configuration as TOML for `findarat config`.
pub fn render_effective(config: &Config) -> anyhow::Result<String> {
    toml::to_string_pretty(config).context("failed to serialize effective configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid_toml_and_valid_config() {
        let config: Config = toml::from_str(DEFAULT_CONFIG_TEMPLATE).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn expands_tilde_paths() {
        let home = home_dir();
        assert_eq!(expand_path("~/x", None).unwrap(), home.join("x"));
        assert_eq!(expand_path("~", None).unwrap(), home);
    }

    #[test]
    fn resolves_relative_paths_against_base() {
        let base = Path::new("/etc/findarat");
        assert_eq!(
            expand_path("data.db", Some(base)).unwrap(),
            PathBuf::from("/etc/findarat/data.db")
        );
        assert_eq!(
            expand_path("/var/lib/findarat.db", Some(base)).unwrap(),
            PathBuf::from("/var/lib/findarat.db")
        );
    }

    #[test]
    fn explicit_overrides_are_absolute() {
        let paths =
            ConfigPaths::resolve(Some(Path::new("conf.toml")), Some(Path::new("db.sqlite")));
        assert!(paths.config_file.is_absolute());
        assert!(paths.database.is_absolute());
    }

    #[test]
    fn invalid_config_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[scanner]\nconcurrency = 0\n").unwrap();
        let error = LoadedConfig::load(Some(&path), None).unwrap_err();
        assert!(error.to_string().contains("concurrency"));
    }
}
