//! Export inventory to JSON, CSV, or a SQLite snapshot.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::FindaratError;
use crate::inventory::Database;
use crate::models::{Change, Device, ScanSession};

/// Versioned JSON document used by `findarat export --format json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub schema_version: u32,
    pub tool: String,
    pub tool_version: String,
    pub exported_at: DateTime<Utc>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub scan_sessions: Vec<ScanSession>,
    #[serde(default)]
    pub changes: Vec<Change>,
}

impl ExportEnvelope {
    pub fn new(
        devices: Vec<Device>,
        scan_sessions: Vec<ScanSession>,
        changes: Vec<Change>,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            tool: "findarat".to_string(),
            tool_version: crate::VERSION.to_string(),
            exported_at: Utc::now(),
            devices,
            scan_sessions,
            changes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Sqlite,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Sqlite => "sqlite",
        }
    }

    /// Infer a format from the file extension, defaulting to JSON.
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref()
        {
            Some("csv") => Self::Csv,
            Some("db") | Some("sqlite") | Some("sqlite3") => Self::Sqlite,
            _ => Self::Json,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "sqlite" | "db" => Ok(Self::Sqlite),
            other => Err(FindaratError::Validation(format!(
                "invalid export format {other:?}; expected json, csv, or sqlite"
            ))
            .into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExportReport {
    pub path: PathBuf,
    pub format: ExportFormat,
    pub devices: usize,
    pub sessions: usize,
    pub changes: usize,
    pub bytes: u64,
}

/// Write the inventory to `path`. Existing files are only replaced when
/// `force` is true.
pub fn export(
    format: ExportFormat,
    path: &Path,
    database: &Database,
    force: bool,
) -> Result<ExportReport> {
    if path.exists() && !force {
        return Err(FindaratError::Validation(format!(
            "{} already exists; use --force to overwrite",
            path.display()
        ))
        .into());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    let devices = database.list_devices_full()?;
    let sessions = database.list_scan_sessions(None)?;
    let changes = database.list_changes(None)?;
    let device_count = devices.len();
    let session_count = sessions.len();
    let change_count = changes.len();

    match format {
        ExportFormat::Json => {
            let envelope = ExportEnvelope::new(devices, sessions, changes);
            let json = serde_json::to_string_pretty(&envelope)
                .context("failed to serialize export JSON")?;
            fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
        }
        ExportFormat::Csv => export_csv(path, &devices)?,
        ExportFormat::Sqlite => {
            database
                .connection()
                .backup(
                    rusqlite::MAIN_DB,
                    path,
                    None::<fn(rusqlite::backup::Progress)>,
                )
                .with_context(|| format!("failed to write SQLite snapshot {}", path.display()))?;
        }
    }

    let bytes = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    Ok(ExportReport {
        path: path.to_path_buf(),
        format,
        devices: device_count,
        sessions: session_count,
        changes: change_count,
        bytes,
    })
}

#[derive(Debug, Serialize)]
struct CsvDeviceRow {
    id: Option<i64>,
    last_ip: String,
    mac: String,
    hostname: String,
    vendor: String,
    device_type: String,
    os: String,
    interface: String,
    first_seen: String,
    last_seen: String,
    active: bool,
    open_ports: String,
    services: String,
    identifiers: String,
    evidence_count: usize,
    observation_count: usize,
}

fn export_csv(path: &Path, devices: &[Device]) -> Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_path(path)
        .with_context(|| format!("failed to create CSV {}", path.display()))?;

    for device in devices {
        let ports = crate::app::port_list(&device.ports);
        let services = device.service_summary();
        let identifiers = device
            .identifiers
            .iter()
            .map(|identifier| format!("{}={}", identifier.kind, identifier.value))
            .collect::<Vec<_>>()
            .join("; ");
        writer
            .serialize(CsvDeviceRow {
                id: device.id,
                last_ip: device.last_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                mac: device.mac.clone().unwrap_or_default(),
                hostname: device.hostname.clone().unwrap_or_default(),
                vendor: device.vendor.clone().unwrap_or_default(),
                device_type: device.device_type.as_str().to_string(),
                os: device.os.clone().unwrap_or_default(),
                interface: device.interface.clone().unwrap_or_default(),
                first_seen: device.first_seen.to_rfc3339(),
                last_seen: device.last_seen.to_rfc3339(),
                active: device.active,
                open_ports: ports,
                services,
                identifiers,
                evidence_count: device.evidence.len(),
                observation_count: device.observations.len(),
            })
            .context("failed to serialize CSV row")?;
    }
    writer.flush().context("failed to flush CSV export")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Evidence, Observation};
    use tempfile::tempdir;

    fn sample_device() -> Device {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.id = Some(1);
        device.last_ip = Some("192.168.1.10".parse().unwrap());
        device.mac = Some("AA:BB:CC:DD:EE:01".to_string());
        device.hostname = Some("alpha".to_string());
        device.add_evidence(Evidence::direct("mac", "AA:BB:CC:DD:EE:01", "arp", now));
        device.observations.push(Observation::new(now, "arp"));
        device
    }

    #[test]
    fn json_round_trips_through_envelope() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        let mut database = Database::open_in_memory().unwrap();
        database
            .upsert_device(&sample_device(), None, false)
            .unwrap();
        let report = export(ExportFormat::Json, &path, &database, false).unwrap();
        assert_eq!(report.devices, 1);
        let text = fs::read_to_string(&path).unwrap();
        let envelope: ExportEnvelope = serde_json::from_str(&text).unwrap();
        assert_eq!(envelope.schema_version, crate::SCHEMA_VERSION);
        assert_eq!(envelope.devices.len(), 1);
        assert_eq!(envelope.devices[0].hostname.as_deref(), Some("alpha"));
    }

    #[test]
    fn csv_contains_a_header_and_one_row() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.csv");
        let mut database = Database::open_in_memory().unwrap();
        database
            .upsert_device(&sample_device(), None, false)
            .unwrap();
        export(ExportFormat::Csv, &path, &database, false).unwrap();
        let mut reader = csv::Reader::from_path(&path).unwrap();
        assert_eq!(reader.headers().unwrap().len(), 16);
        assert_eq!(reader.records().count(), 1);
    }

    #[test]
    fn sqlite_snapshot_can_be_opened() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("snapshot.db");
        let mut database = Database::open_in_memory().unwrap();
        database
            .upsert_device(&sample_device(), None, false)
            .unwrap();
        export(ExportFormat::Sqlite, &path, &database, false).unwrap();
        let snapshot = Database::open_read_only(&path).unwrap();
        assert_eq!(snapshot.count_devices().unwrap(), 1);
    }

    #[test]
    fn existing_file_requires_force() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        fs::write(&path, "existing").unwrap();
        let database = Database::open_in_memory().unwrap();
        assert!(export(ExportFormat::Json, &path, &database, false).is_err());
        assert!(export(ExportFormat::Json, &path, &database, true).is_ok());
    }

    #[test]
    fn format_inference_and_parsing() {
        assert_eq!(
            ExportFormat::from_path(Path::new("x.csv")),
            ExportFormat::Csv
        );
        assert_eq!(
            ExportFormat::from_path(Path::new("x.sqlite3")),
            ExportFormat::Sqlite
        );
        assert_eq!(
            ExportFormat::from_path(Path::new("x.json")),
            ExportFormat::Json
        );
        assert_eq!(ExportFormat::parse("CSV").unwrap(), ExportFormat::Csv);
        assert!(ExportFormat::parse("yaml").is_err());
    }
}
