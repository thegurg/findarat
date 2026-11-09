//! Import inventory from JSON or another findarat SQLite database.
//!
//! Imports are validated before anything is written. `dry_run` reports what
//! would happen without changing the destination, and `merge` controls whether
//! devices matching an existing identity are updated or skipped.

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::FindaratError;
use crate::inventory::{Database, UpsertOptions};
use crate::models::ScanSession;

use super::export::ExportEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Json,
    Sqlite,
}

impl ImportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sqlite => "sqlite",
        }
    }

    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref()
        {
            Some("db") | Some("sqlite") | Some("sqlite3") => Self::Sqlite,
            _ => Self::Json,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Err(FindaratError::Validation(
                "auto is resolved from the file extension before parsing".into(),
            )
            .into()),
            "json" => Ok(Self::Json),
            "sqlite" | "db" => Ok(Self::Sqlite),
            other => Err(FindaratError::Validation(format!(
                "invalid import format {other:?}; expected auto, json, or sqlite"
            ))
            .into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportOptions {
    pub dry_run: bool,
    pub merge: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            merge: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportAction {
    Create,
    Merge,
    Skip,
}

impl ImportAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Merge => "merge",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDeviceOutcome {
    pub label: String,
    pub action: ImportAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub dry_run: bool,
    pub merge: bool,
    pub source: PathBuf,
    pub format: String,
    pub devices_created: usize,
    pub devices_merged: usize,
    pub devices_skipped: usize,
    pub sessions_imported: usize,
    pub changes_imported: usize,
    pub outcomes: Vec<ImportDeviceOutcome>,
    pub warnings: Vec<String>,
}

impl ImportReport {
    fn new(source: &Path, format: ImportFormat, options: ImportOptions) -> Self {
        Self {
            dry_run: options.dry_run,
            merge: options.merge,
            source: source.to_path_buf(),
            format: format.as_str().to_string(),
            devices_created: 0,
            devices_merged: 0,
            devices_skipped: 0,
            sessions_imported: 0,
            changes_imported: 0,
            outcomes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn summary(&self) -> String {
        let prefix = if self.dry_run {
            "would import"
        } else {
            "imported"
        };
        format!(
            "{prefix} {} created, {} merged, {} skipped, {} session(s), {} change(s)",
            self.devices_created,
            self.devices_merged,
            self.devices_skipped,
            self.sessions_imported,
            self.changes_imported
        )
    }
}

pub fn import(
    format: ImportFormat,
    path: &Path,
    database: &mut Database,
    options: ImportOptions,
) -> Result<ImportReport> {
    let envelope = match format {
        ImportFormat::Json => read_json(path)?,
        ImportFormat::Sqlite => read_sqlite(path, database)?,
    };
    apply_envelope(database, envelope, path, format, options)
}

fn read_json(path: &Path) -> Result<ExportEnvelope> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read import file {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    if value.is_array() {
        let devices = serde_json::from_value(value).with_context(|| {
            format!(
                "invalid device array in {}; expected findarat devices",
                path.display()
            )
        })?;
        Ok(ExportEnvelope::new(devices, Vec::new(), Vec::new()))
    } else {
        serde_json::from_value(value).with_context(|| {
            format!(
                "invalid findarat export in {}; expected a versioned export object",
                path.display()
            )
        })
    }
}

fn read_sqlite(path: &Path, destination: &Database) -> Result<ExportEnvelope> {
    if same_file(path, destination.path()) {
        return Err(
            FindaratError::Validation("cannot import a database into itself".into()).into(),
        );
    }
    let source = Database::open_read_only(path)?;
    let version = source
        .schema_version()
        .with_context(|| format!("{} is not a findarat database", path.display()))?;
    if version > crate::SCHEMA_VERSION {
        return Err(FindaratError::Database(format!(
            "source database schema version {version} is newer than this build supports ({})",
            crate::SCHEMA_VERSION
        ))
        .into());
    }
    let devices = source.list_devices_full()?;
    let scan_sessions = source.list_scan_sessions(None)?;
    let changes = source.list_changes(None)?;
    Ok(ExportEnvelope {
        schema_version: version,
        tool: "findarat".to_string(),
        tool_version: crate::VERSION.to_string(),
        exported_at: Utc::now(),
        devices,
        scan_sessions,
        changes,
    })
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn apply_envelope(
    database: &mut Database,
    envelope: ExportEnvelope,
    path: &Path,
    format: ImportFormat,
    options: ImportOptions,
) -> Result<ImportReport> {
    if envelope.schema_version == 0 || envelope.schema_version > crate::SCHEMA_VERSION {
        return Err(FindaratError::Validation(format!(
            "unsupported import schema version {}; this build supports 1..={}",
            envelope.schema_version,
            crate::SCHEMA_VERSION
        ))
        .into());
    }

    let mut report = ImportReport::new(path, format, options);
    let mut device_map: HashMap<i64, i64> = HashMap::new();
    let mut session_map: HashMap<i64, i64> = HashMap::new();

    for session in &envelope.scan_sessions {
        import_session(database, session, &mut session_map, &mut report)?;
    }

    let mut missing_change_devices: HashSet<i64> = HashSet::new();
    for device in &envelope.devices {
        if !has_identity(device) {
            report.warnings.push(format!(
                "skipped device {:?}: no IP, MAC, hostname, or identifier",
                device.display_name()
            ));
            report.devices_skipped += 1;
            report.outcomes.push(ImportDeviceOutcome {
                label: device.display_name(),
                action: ImportAction::Skip,
                device_id: device.id,
                matched_by: None,
            });
            continue;
        }

        let matched = database.find_match(device)?;
        let old_id = device.id;
        let label = device.display_name();

        if let Some(found) = &matched {
            if !options.merge {
                report.devices_skipped += 1;
                report.outcomes.push(ImportDeviceOutcome {
                    label,
                    action: ImportAction::Skip,
                    device_id: Some(found.device_id),
                    matched_by: Some(found.reason.clone()),
                });
                continue;
            }
            if options.dry_run {
                report.devices_merged += 1;
                report.outcomes.push(ImportDeviceOutcome {
                    label,
                    action: ImportAction::Merge,
                    device_id: Some(found.device_id),
                    matched_by: Some(found.reason.clone()),
                });
                if let Some(old_id) = old_id {
                    device_map.insert(old_id, found.device_id);
                }
                continue;
            }
            let outcome = database.upsert_device_with_options(
                device,
                &UpsertOptions {
                    scan_id: None,
                    ports_scanned: false,
                    record_changes: false,
                    preserve_active: true,
                    synthesize_observations: false,
                },
            )?;
            if let Some(old_id) = old_id {
                device_map.insert(old_id, outcome.device_id);
            }
            report.devices_merged += 1;
            report.outcomes.push(ImportDeviceOutcome {
                label,
                action: ImportAction::Merge,
                device_id: Some(outcome.device_id),
                matched_by: Some(found.reason.clone()),
            });
        } else if options.dry_run {
            report.devices_created += 1;
            report.outcomes.push(ImportDeviceOutcome {
                label,
                action: ImportAction::Create,
                device_id: None,
                matched_by: None,
            });
        } else {
            let outcome = database.upsert_device_with_options(
                device,
                &UpsertOptions {
                    scan_id: None,
                    ports_scanned: false,
                    record_changes: false,
                    preserve_active: true,
                    synthesize_observations: false,
                },
            )?;
            if let Some(old_id) = old_id {
                device_map.insert(old_id, outcome.device_id);
            }
            report.devices_created += 1;
            report.outcomes.push(ImportDeviceOutcome {
                label,
                action: ImportAction::Create,
                device_id: Some(outcome.device_id),
                matched_by: None,
            });
        }
    }

    for change in &envelope.changes {
        if options.dry_run {
            report.changes_imported += 1;
            continue;
        }
        let Some(device_id) = device_map.get(&change.device_id).copied() else {
            if missing_change_devices.insert(change.device_id) {
                report.warnings.push(format!(
                    "skipped change history for device {}: the device was not imported",
                    change.device_id
                ));
            }
            continue;
        };
        let mut change = change.clone();
        change.id = None;
        change.device_id = device_id;
        change.scan_id = change
            .scan_id
            .and_then(|scan_id| session_map.get(&scan_id).copied());
        if database.insert_imported_change(&change)? {
            report.changes_imported += 1;
        }
    }

    if report.dry_run {
        report.sessions_imported = envelope
            .scan_sessions
            .iter()
            .filter(|session| {
                session
                    .id
                    .map(|id| !session_map.contains_key(&id))
                    .unwrap_or(true)
            })
            .count();
    }

    Ok(report)
}

fn import_session(
    database: &mut Database,
    session: &ScanSession,
    session_map: &mut HashMap<i64, i64>,
    report: &mut ImportReport,
) -> Result<()> {
    let existing = existing_session(database, session)?;
    if let Some(existing) = existing {
        if let Some(old_id) = session.id {
            session_map.insert(old_id, existing);
        }
        return Ok(());
    }
    if report.dry_run {
        if let Some(old_id) = session.id {
            // No local id exists yet; changes referencing it are counted but
            // not linked in a dry run.
            session_map.insert(old_id, old_id);
        }
        report.sessions_imported += 1;
        return Ok(());
    }
    let mut imported = session.clone();
    imported.id = None;
    let new_id = database.create_scan_session(&imported)?;
    if let Some(old_id) = session.id {
        session_map.insert(old_id, new_id);
    }
    report.sessions_imported += 1;
    Ok(())
}

fn existing_session(database: &Database, session: &ScanSession) -> Result<Option<i64>> {
    let started_at = session
        .started_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    Ok(database
        .connection()
        .query_row(
            "SELECT id FROM scan_sessions WHERE started_at = ?1 ORDER BY id LIMIT 1",
            params![started_at],
            |row| row.get(0),
        )
        .optional()?)
}

fn has_identity(device: &crate::models::Device) -> bool {
    device.last_ip.is_some()
        || device.mac.is_some()
        || device.hostname.is_some()
        || !device.identifiers.is_empty()
}

/// Build a report for an empty import, used by the TUI while a path is typed.
pub fn empty_report(path: &Path, format: ImportFormat) -> ImportReport {
    ImportReport::new(path, format, ImportOptions::default())
}

/// Exposed for tests that need a deterministic timestamp.
pub fn export_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::export::{self, ExportFormat};
    use crate::models::{ChangeKind, Device, Evidence};
    use tempfile::tempdir;

    fn sample_device(ip: &str, mac: &str, hostname: &str) -> Device {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.last_ip = Some(ip.parse().unwrap());
        device.mac = Some(mac.to_string());
        device.hostname = Some(hostname.to_string());
        device.add_evidence(Evidence::direct("mac", mac, "arp", now));
        device
    }

    fn export_json(database: &Database, path: &Path) {
        export::export(ExportFormat::Json, path, database, true).unwrap();
    }

    #[test]
    fn dry_run_does_not_write() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        let mut source = Database::open_in_memory().unwrap();
        source
            .upsert_device(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        export_json(&source, &path);

        let mut destination = Database::open_in_memory().unwrap();
        let report = import(
            ImportFormat::Json,
            &path,
            &mut destination,
            ImportOptions {
                dry_run: true,
                merge: true,
            },
        )
        .unwrap();
        assert_eq!(report.devices_created, 1);
        assert_eq!(destination.count_devices().unwrap(), 0);
    }

    #[test]
    fn merge_updates_matching_device_instead_of_duplicating() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        let mut source = Database::open_in_memory().unwrap();
        source
            .upsert_device(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        export_json(&source, &path);

        let mut destination = Database::open_in_memory().unwrap();
        destination
            .upsert_device(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        let report = import(
            ImportFormat::Json,
            &path,
            &mut destination,
            ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(report.devices_merged, 1);
        assert_eq!(destination.count_devices().unwrap(), 1);
    }

    #[test]
    fn no_merge_skips_matching_device() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        let mut source = Database::open_in_memory().unwrap();
        source
            .upsert_device(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        export_json(&source, &path);

        let mut destination = Database::open_in_memory().unwrap();
        destination
            .upsert_device(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        let report = import(
            ImportFormat::Json,
            &path,
            &mut destination,
            ImportOptions {
                dry_run: false,
                merge: false,
            },
        )
        .unwrap();
        assert_eq!(report.devices_skipped, 1);
        assert_eq!(destination.count_devices().unwrap(), 1);
    }

    #[test]
    fn imports_sqlite_and_maps_changes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("snapshot.db");
        let mut source = Database::open_in_memory().unwrap();
        let outcome = source
            .upsert_device_with_options(
                &sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                &UpsertOptions {
                    record_changes: false,
                    ..UpsertOptions::default()
                },
            )
            .unwrap();
        let mut change = crate::models::Change::new(
            outcome.device_id,
            ChangeKind::DeviceAdded,
            None,
            Some("alpha".to_string()),
            Utc::now(),
        );
        change.device_label = Some("alpha".to_string());
        source.insert_imported_change(&change).unwrap();
        export::export(ExportFormat::Sqlite, &path, &source, true).unwrap();

        let mut destination = Database::open_in_memory().unwrap();
        let report = import(
            ImportFormat::Sqlite,
            &path,
            &mut destination,
            ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(report.devices_created, 1);
        assert_eq!(report.changes_imported, 1);
        assert_eq!(destination.count_devices().unwrap(), 1);
        assert_eq!(destination.list_changes(None).unwrap().len(), 1);
    }

    #[test]
    fn rejects_newer_schema_versions() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("export.json");
        fs::write(
            &path,
            r#"{"schema_version": 999, "tool": "findarat", "tool_version": "x", "exported_at": "2026-01-01T00:00:00Z", "devices": []}"#,
        )
        .unwrap();
        let mut database = Database::open_in_memory().unwrap();
        let error = import(
            ImportFormat::Json,
            &path,
            &mut database,
            ImportOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("schema version"));
    }

    #[test]
    fn accepts_bare_device_array() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("devices.json");
        let device = sample_device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha");
        fs::write(&path, serde_json::to_string(&vec![device]).unwrap()).unwrap();
        let mut database = Database::open_in_memory().unwrap();
        let report = import(
            ImportFormat::Json,
            &path,
            &mut database,
            ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(report.devices_created, 1);
    }

    #[test]
    fn report_summary_mentions_dry_run() {
        let report = ImportReport {
            dry_run: true,
            merge: true,
            source: PathBuf::from("x.json"),
            format: "json".to_string(),
            devices_created: 1,
            devices_merged: 0,
            devices_skipped: 0,
            sessions_imported: 0,
            changes_imported: 0,
            outcomes: Vec::new(),
            warnings: Vec::new(),
        };
        assert!(report.summary().starts_with("would import"));
    }
}
