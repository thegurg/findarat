//! SQLite inventory storage.
//!
//! The schema keeps identities, observations, evidence, ports, services, scan
//! sessions, and detected changes. Device rows hold a convenient last-known
//! snapshot, but the observation history is authoritative.

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::FindaratError;
use crate::models::{
    Change, ChangeKind, Confidence, Device, DeviceType, Evidence, EvidenceKind, Identifier,
    IdentifierKind, Observation, PortObservation, PortState, Protocol, ProviderReport, ScanSession,
    ScanStatus, ServiceObservation,
};
use crate::network::interface::normalise_mac;

use super::history::{self, ChangeRecord};
use super::identity::{self, IdentityMatch, MatchBasis};

const SCHEMA_VERSION: u32 = 1;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    interface TEXT,
    subnet TEXT,
    status TEXT NOT NULL,
    device_count INTEGER NOT NULL DEFAULT 0,
    providers_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_ip TEXT,
    last_mac TEXT,
    last_hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    os TEXT,
    interface TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_interface ON devices(interface);

CREATE TABLE IF NOT EXISTS identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_identifiers_lookup ON identifiers(kind, value);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    interface TEXT,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    details TEXT,
    observation_key TEXT NOT NULL,
    UNIQUE(device_id, observation_key)
);
CREATE INDEX IF NOT EXISTS idx_observations_device ON observations(device_id, observed_at);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    property TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    note TEXT,
    UNIQUE(device_id, property, value, source)
);
CREATE INDEX IF NOT EXISTS idx_evidence_device ON evidence(device_id);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    port INTEGER,
    protocol TEXT NOT NULL,
    version TEXT,
    source TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    service_key TEXT NOT NULL,
    UNIQUE(device_id, service_key)
);
CREATE INDEX IF NOT EXISTS idx_services_device ON services(device_id);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    detected_at TEXT NOT NULL,
    device_label TEXT,
    change_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at);
CREATE INDEX IF NOT EXISTS idx_changes_device ON changes(device_id, detected_at);
"#;

#[derive(Debug, Clone)]
pub struct UpsertOptions {
    pub scan_id: Option<i64>,
    pub ports_scanned: bool,
    pub record_changes: bool,
    pub preserve_active: bool,
    pub synthesize_observations: bool,
}

impl Default for UpsertOptions {
    fn default() -> Self {
        Self {
            scan_id: None,
            ports_scanned: false,
            record_changes: false,
            preserve_active: true,
            synthesize_observations: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpsertOutcome {
    pub device_id: i64,
    pub created: bool,
    pub matched_by: Option<String>,
    pub changes: Vec<Change>,
}

pub struct Database {
    conn: Connection,
    path: PathBuf,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory {}", parent.display())
            })?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        let mut database = Self {
            conn,
            path: path.to_path_buf(),
        };
        database.configure()?;
        database.migrate()?;
        Ok(database)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
        let mut database = Self {
            conn,
            path: PathBuf::from(":memory:"),
        };
        database.configure()?;
        database.migrate()?;
        Ok(database)
    }

    /// Open an existing database without migrating or changing journal mode.
    /// Used by import previews and SQLite exports.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| format!("failed to open database {} read-only", path.display()))?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn configure(&mut self) -> Result<()> {
        self.conn
            .pragma_update(None, "foreign_keys", "ON")
            .context("failed to enable SQLite foreign keys")?;
        self.conn
            .busy_timeout(Duration::from_secs(5))
            .context("failed to set SQLite busy timeout")?;
        if self.path != Path::new(":memory:") {
            self.conn
                .pragma_update(None, "journal_mode", "WAL")
                .context("failed to enable SQLite WAL mode")?;
            self.conn
                .pragma_update(None, "synchronous", "NORMAL")
                .context("failed to configure SQLite synchronous mode")?;
        }
        Ok(())
    }

    fn migrate(&mut self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .context("failed to create schema metadata table")?;
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to read database schema version")?;
        let existing = existing
            .map(|value| {
                value.parse::<u32>().map_err(|error| {
                    FindaratError::Database(format!(
                        "invalid database schema version {value:?}: {error}"
                    ))
                })
            })
            .transpose()?;
        if let Some(version) = existing {
            if version > SCHEMA_VERSION {
                return Err(FindaratError::Database(format!(
                    "database schema version {version} is newer than this build supports ({SCHEMA_VERSION}); upgrade findarat"
                ))
                .into());
            }
        }
        self.conn
            .execute_batch(SCHEMA_SQL)
            .context("failed to apply database schema")?;
        if existing.is_none() {
            self.conn
                .execute(
                    "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )
                .context("failed to record database schema version")?;
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<u32> {
        let value: String = self.conn.query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )?;
        value.parse().map_err(|error| {
            FindaratError::Database(format!("invalid schema version: {error}")).into()
        })
    }

    // ------------------------------------------------------------------
    // Scan sessions
    // ------------------------------------------------------------------

    pub fn create_scan_session(&mut self, session: &ScanSession) -> Result<i64> {
        let providers = serde_json::to_string(&session.providers)
            .context("failed to serialize provider reports")?;
        self.conn.execute(
            "INSERT INTO scan_sessions(started_at, finished_at, interface, subnet, status, device_count, providers_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                to_ts(session.started_at),
                session.finished_at.map(to_ts),
                session.interface,
                session.subnet,
                session.status.as_str(),
                session.device_count as i64,
                providers,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_scan_session(
        &mut self,
        id: i64,
        status: ScanStatus,
        providers: &[ProviderReport],
        device_count: usize,
        finished_at: DateTime<Utc>,
    ) -> Result<()> {
        let providers =
            serde_json::to_string(providers).context("failed to serialize provider reports")?;
        self.conn.execute(
            "UPDATE scan_sessions SET finished_at = ?1, status = ?2, providers_json = ?3, device_count = ?4 WHERE id = ?5",
            params![to_ts(finished_at), status.as_str(), providers, device_count as i64, id],
        )?;
        Ok(())
    }

    pub fn get_scan_session(&self, id: i64) -> Result<Option<ScanSession>> {
        let session = self
            .conn
            .query_row(
                "SELECT id, started_at, finished_at, interface, subnet, status, device_count, providers_json
                 FROM scan_sessions WHERE id = ?1",
                params![id],
                row_to_scan_session,
            )
            .optional()?;
        session.transpose()
    }

    pub fn list_scan_sessions(&self, limit: Option<usize>) -> Result<Vec<ScanSession>> {
        let mut statement = self.conn.prepare(
            "SELECT id, started_at, finished_at, interface, subnet, status, device_count, providers_json
             FROM scan_sessions ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit_to_i64(limit)], row_to_scan_session)?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row??);
        }
        Ok(sessions)
    }

    // ------------------------------------------------------------------
    // Devices
    // ------------------------------------------------------------------

    pub fn upsert_device(
        &mut self,
        device: &Device,
        scan_id: Option<i64>,
        ports_scanned: bool,
    ) -> Result<UpsertOutcome> {
        self.upsert_device_with_options(
            device,
            &UpsertOptions {
                scan_id,
                ports_scanned,
                record_changes: true,
                preserve_active: false,
                synthesize_observations: true,
            },
        )
    }

    pub fn upsert_device_with_options(
        &mut self,
        device: &Device,
        options: &UpsertOptions,
    ) -> Result<UpsertOutcome> {
        let mac = device.mac.as_deref().and_then(normalise_mac);
        let hostname_key = device.hostname.as_deref().and_then(identity::hostname_key);
        let matched = self.find_match_internal(
            mac.as_deref(),
            hostname_key.as_deref(),
            device.last_ip,
            device.last_seen,
        )?;

        let transaction = self.conn.transaction()?;
        let mut outcome = UpsertOutcome::default();

        if let Some(found) = matched {
            let existing = load_device_with_conn(&transaction, found.device_id, false)?
                .ok_or_else(|| {
                    FindaratError::Database(format!(
                        "identity match referenced missing device {}",
                        found.device_id
                    ))
                })?;
            outcome.device_id = found.device_id;
            outcome.matched_by = Some(found.reason);
            let changes =
                update_existing_device(&transaction, &existing, device, mac.as_deref(), options)?;
            outcome.changes = changes;
            write_children(&transaction, found.device_id, device, options)?;
        } else {
            let active = if options.preserve_active {
                device.active
            } else {
                true
            };
            transaction.execute(
                "INSERT INTO devices(last_ip, last_mac, last_hostname, vendor, device_type, os, interface, active, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    device.last_ip.map(|ip| ip.to_string()),
                    mac,
                    device.hostname,
                    device.vendor,
                    device.device_type.as_str(),
                    device.os,
                    device.interface,
                    i64::from(active),
                    to_ts(device.first_seen),
                    to_ts(device.last_seen),
                ],
            )?;
            let id = transaction.last_insert_rowid();
            outcome.device_id = id;
            outcome.created = true;
            outcome.matched_by = Some("new device".to_string());
            if options.record_changes {
                let change = insert_change(
                    &transaction,
                    options.scan_id,
                    id,
                    ChangeRecord {
                        kind: ChangeKind::DeviceAdded,
                        old_value: None,
                        new_value: Some(device_label(device)),
                    },
                    device.last_seen,
                    Some(device_label(device)),
                )?;
                outcome.changes.push(change);
            }
            write_children(&transaction, id, device, options)?;
        }

        transaction.commit()?;
        Ok(outcome)
    }

    pub fn find_match(&self, device: &Device) -> Result<Option<IdentityMatch>> {
        let mac = device.mac.as_deref().and_then(normalise_mac);
        let hostname = device.hostname.as_deref().and_then(identity::hostname_key);
        self.find_match_internal(
            mac.as_deref(),
            hostname.as_deref(),
            device.last_ip,
            device.last_seen,
        )
    }

    fn find_match_internal(
        &self,
        mac: Option<&str>,
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        observed_at: DateTime<Utc>,
    ) -> Result<Option<IdentityMatch>> {
        let mut candidates = Vec::new();

        if let Some(mac) = mac {
            let found = self
                .conn
                .query_row(
                    "SELECT i.device_id FROM identifiers i JOIN devices d ON d.id = i.device_id
                     WHERE i.kind = 'mac' AND i.value = ?1 ORDER BY d.last_seen DESC LIMIT 1",
                    params![mac],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            if let Some(device_id) = found {
                let confidence = identity::mac_confidence(mac);
                candidates.push(IdentityMatch {
                    device_id,
                    basis: MatchBasis::Mac,
                    confidence,
                    reason: if confidence == Confidence::High {
                        "exact MAC match".to_string()
                    } else {
                        "exact locally administered MAC match".to_string()
                    },
                });
            }
        }

        if let Some(hostname) = hostname {
            let mut statement = self.conn.prepare(
                "SELECT DISTINCT i.device_id FROM identifiers i
                 WHERE i.kind = 'hostname' AND i.value = ?1 LIMIT 2",
            )?;
            let ids: Vec<i64> = statement
                .query_map(params![hostname], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if ids.len() == 1 {
                candidates.push(IdentityMatch {
                    device_id: ids[0],
                    basis: MatchBasis::Hostname,
                    confidence: Confidence::Medium,
                    reason: format!("exact hostname match ({hostname})"),
                });
            }
        }

        if let Some(ip) = ip {
            let found = self
                .conn
                .query_row(
                    "SELECT i.device_id, d.last_mac, d.last_seen FROM identifiers i
                     JOIN devices d ON d.id = i.device_id
                     WHERE i.kind = 'ip' AND i.value = ?1 LIMIT 1",
                    params![ip.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((device_id, existing_mac, last_seen)) = found {
                let last_seen = parse_ts(&last_seen)?;
                let age = observed_at
                    .signed_duration_since(last_seen)
                    .to_std()
                    .unwrap_or_default();
                if identity::ip_match_allowed(existing_mac.is_some(), mac.is_some(), age) {
                    candidates.push(IdentityMatch {
                        device_id,
                        basis: MatchBasis::Ip,
                        confidence: Confidence::Low,
                        reason: format!("IP-only match ({ip}); identity uncertain"),
                    });
                }
            }
        }

        Ok(identity::choose(candidates))
    }

    pub fn list_devices(&self) -> Result<Vec<Device>> {
        self.list_devices_internal(false)
    }

    pub fn list_devices_full(&self) -> Result<Vec<Device>> {
        self.list_devices_internal(true)
    }

    fn list_devices_internal(&self, include_observations: bool) -> Result<Vec<Device>> {
        let mut statement = self
            .conn
            .prepare("SELECT id FROM devices ORDER BY last_seen DESC, id DESC")?;
        let ids: Vec<i64> = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut devices = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(device) = load_device_with_conn(&self.conn, id, include_observations)? {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    pub fn get_device(&self, id: i64) -> Result<Option<Device>> {
        load_device_with_conn(&self.conn, id, true)
    }

    pub fn find_device(&self, target: &str) -> Result<Option<Device>> {
        let target = target.trim();
        if target.is_empty() {
            return Ok(None);
        }
        if let Ok(id) = target.parse::<i64>() {
            if let Some(device) = self.get_device(id)? {
                return Ok(Some(device));
            }
        }
        if let Ok(ip) = target.parse::<IpAddr>() {
            if let Some(id) = self.device_id_for("ip", &ip.to_string())? {
                return self.get_device(id);
            }
        }
        if let Some(mac) = normalise_mac(target) {
            if let Some(id) = self.device_id_for("mac", &mac)? {
                return self.get_device(id);
            }
        }
        if let Some(hostname) = identity::hostname_key(target) {
            if let Some(id) = self.device_id_for("hostname", &hostname)? {
                return self.get_device(id);
            }
        }
        Ok(None)
    }

    fn device_id_for(&self, kind: &str, value: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT i.device_id FROM identifiers i JOIN devices d ON d.id = i.device_id
                 WHERE i.kind = ?1 AND i.value = ?2 ORDER BY d.last_seen DESC LIMIT 1",
                params![kind, value],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn count_devices(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;
        Ok(count.max(0) as usize)
    }

    pub fn count_active_devices(&self) -> Result<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM devices WHERE active = 1", [], |row| {
                    row.get(0)
                })?;
        Ok(count.max(0) as usize)
    }

    // ------------------------------------------------------------------
    // History
    // ------------------------------------------------------------------

    pub fn list_changes(&self, limit: Option<usize>) -> Result<Vec<Change>> {
        let mut statement = self.conn.prepare(
            "SELECT id, scan_id, device_id, kind, old_value, new_value, detected_at, device_label
             FROM changes ORDER BY detected_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit_to_i64(limit)], row_to_change)?;
        let mut changes = Vec::new();
        for row in rows {
            changes.push(row?);
        }
        Ok(changes)
    }

    pub fn device_changes(&self, device_id: i64, limit: Option<usize>) -> Result<Vec<Change>> {
        let mut statement = self.conn.prepare(
            "SELECT id, scan_id, device_id, kind, old_value, new_value, detected_at, device_label
             FROM changes WHERE device_id = ?1 ORDER BY detected_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![device_id, limit_to_i64(limit)], row_to_change)?;
        let mut changes = Vec::new();
        for row in rows {
            changes.push(row?);
        }
        Ok(changes)
    }

    pub fn device_observations(
        &self,
        device_id: i64,
        limit: Option<usize>,
    ) -> Result<Vec<Observation>> {
        load_observations(&self.conn, device_id, limit)
    }

    /// Mark active devices that were not seen in a scan as disappeared.
    pub fn mark_disappeared(
        &mut self,
        scan_id: Option<i64>,
        seen: &HashSet<i64>,
        interface: Option<&str>,
        before: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Vec<Change>> {
        let mut statement = self.conn.prepare(
            "SELECT id, last_ip, last_mac, last_hostname, interface FROM devices
             WHERE active = 1 AND last_seen < ?1",
        )?;
        let rows = statement.query_map(params![to_ts(before)], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut candidates = Vec::new();
        for row in rows {
            candidates.push(row?);
        }
        drop(statement);

        let transaction = self.conn.transaction()?;
        let mut changes = Vec::new();
        for (id, ip, mac, hostname, device_interface) in candidates {
            if seen.contains(&id) {
                continue;
            }
            if let Some(interface) = interface {
                if device_interface.as_deref() != Some(interface) {
                    continue;
                }
            }
            transaction.execute("UPDATE devices SET active = 0 WHERE id = ?1", params![id])?;
            let label = hostname
                .clone()
                .or(mac.clone())
                .or(ip.clone())
                .unwrap_or_else(|| format!("device {id}"));
            let change = insert_change(
                &transaction,
                scan_id,
                id,
                ChangeRecord {
                    kind: ChangeKind::DeviceDisappeared,
                    old_value: Some(label.clone()),
                    new_value: None,
                },
                now,
                Some(label),
            )?;
            changes.push(change);
        }
        transaction.commit()?;
        Ok(changes)
    }

    pub fn insert_imported_change(&mut self, change: &Change) -> Result<bool> {
        let label = change.device_label.clone();
        let key = change_key(
            change.device_id,
            change.kind,
            change.old_value.as_deref(),
            change.new_value.as_deref(),
            change.detected_at,
        );
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO changes(scan_id, device_id, kind, old_value, new_value, detected_at, device_label, change_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                change.scan_id,
                change.device_id,
                change.kind.as_str(),
                change.old_value,
                change.new_value,
                to_ts(change.detected_at),
                label,
                key,
            ],
        )?;
        Ok(inserted > 0)
    }
}

fn write_children(
    transaction: &Transaction<'_>,
    device_id: i64,
    device: &Device,
    options: &UpsertOptions,
) -> Result<()> {
    let mac = device.mac.as_deref().and_then(normalise_mac);
    let mut identifiers: Vec<Identifier> = Vec::new();
    if let Some(mac) = &mac {
        identifiers.push(Identifier::new(
            IdentifierKind::Mac,
            mac.clone(),
            identity::mac_confidence(mac),
            device.first_seen,
            device.last_seen,
        ));
    }
    if let Some(ip) = device.last_ip {
        identifiers.push(Identifier::new(
            IdentifierKind::Ip,
            ip.to_string(),
            Confidence::High,
            device.first_seen,
            device.last_seen,
        ));
    }
    if let Some(hostname) = device.hostname.as_deref().and_then(identity::hostname_key) {
        identifiers.push(Identifier::new(
            IdentifierKind::Hostname,
            hostname,
            Confidence::Medium,
            device.first_seen,
            device.last_seen,
        ));
    }
    identifiers.extend(device.identifiers.iter().cloned());
    let mut seen_identifiers = HashSet::new();
    for identifier in identifiers {
        if !seen_identifiers.insert((identifier.kind.as_str(), identifier.value.clone())) {
            continue;
        }
        transaction.execute(
            "INSERT INTO identifiers(device_id, kind, value, confidence, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(device_id, kind, value) DO UPDATE SET
                 first_seen = MIN(identifiers.first_seen, excluded.first_seen),
                 last_seen = MAX(identifiers.last_seen, excluded.last_seen),
                 confidence = CASE
                     WHEN CASE excluded.confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END
                       >= CASE identifiers.confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END
                     THEN excluded.confidence ELSE identifiers.confidence END",
            params![
                device_id,
                identifier.kind.as_str(),
                identifier.value,
                identifier.confidence.as_str(),
                to_ts(identifier.first_seen),
                to_ts(identifier.last_seen),
            ],
        )?;
    }

    for evidence in &device.evidence {
        transaction.execute(
            "INSERT INTO evidence(device_id, property, value, source, confidence, kind, observed_at, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(device_id, property, value, source) DO UPDATE SET
                 observed_at = CASE WHEN excluded.observed_at > evidence.observed_at THEN excluded.observed_at ELSE evidence.observed_at END,
                 note = COALESCE(excluded.note, evidence.note)",
            params![
                device_id,
                evidence.property,
                evidence.value,
                evidence.source,
                evidence.confidence.as_str(),
                evidence.kind.as_str(),
                to_ts(evidence.observed_at),
                evidence.note,
            ],
        )?;
    }

    if options.synthesize_observations {
        let mut sources: Vec<String> = device
            .evidence
            .iter()
            .map(|evidence| evidence.source.clone())
            .collect();
        if sources.is_empty() {
            sources.push("scan".to_string());
        }
        sources.sort();
        sources.dedup();
        for source in sources {
            let observation = Observation {
                id: None,
                device_id: Some(device_id),
                scan_id: options.scan_id,
                observed_at: device.last_seen,
                source,
                interface: device.interface.clone(),
                ip: device.last_ip,
                mac: mac.clone(),
                hostname: device.hostname.clone(),
                details: None,
            };
            insert_observation(transaction, device_id, &observation)?;
        }
    }

    for observation in &device.observations {
        let mut observation = observation.clone();
        observation.device_id = Some(device_id);
        // Live scans pass their session id; imports pass `None` because the
        // foreign scan session may not exist locally.
        observation.scan_id = options.scan_id;
        insert_observation(transaction, device_id, &observation)?;
    }

    for port in &device.ports {
        transaction.execute(
            "INSERT INTO ports(device_id, ip, port, protocol, state, service, version, banner, confidence, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(device_id, ip, port, protocol) DO UPDATE SET
                 state = excluded.state,
                 service = COALESCE(excluded.service, ports.service),
                 version = COALESCE(excluded.version, ports.version),
                 banner = COALESCE(excluded.banner, ports.banner),
                 first_seen = MIN(ports.first_seen, excluded.first_seen),
                 last_seen = MAX(ports.last_seen, excluded.last_seen),
                 confidence = CASE
                     WHEN CASE excluded.confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END
                       >= CASE ports.confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END
                     THEN excluded.confidence ELSE ports.confidence END",
            params![
                device_id,
                port.ip.to_string(),
                i64::from(port.port),
                port.protocol.as_str(),
                port.state.as_str(),
                port.service,
                port.version,
                port.banner,
                port.confidence.as_str(),
                to_ts(port.first_seen),
                to_ts(port.last_seen),
            ],
        )?;
    }

    if options.ports_scanned {
        let new_keys: HashSet<(String, u16, String)> = device
            .ports
            .iter()
            .filter(|port| port.state == PortState::Open)
            .map(|port| {
                (
                    port.ip.to_string(),
                    port.port,
                    port.protocol.as_str().to_string(),
                )
            })
            .collect();
        let existing_ports = load_open_ports(transaction, device_id)?;
        for port in existing_ports {
            let key = (
                port.ip.to_string(),
                port.port,
                port.protocol.as_str().to_string(),
            );
            if !new_keys.contains(&key) {
                transaction.execute(
                    "UPDATE ports SET state = 'closed' WHERE device_id = ?1 AND ip = ?2 AND port = ?3 AND protocol = ?4",
                    params![device_id, key.0, i64::from(key.1), key.2],
                )?;
            }
        }
        let existing_services = load_active_services(transaction, device_id)?;
        let new_services: HashSet<String> = device.services.iter().map(service_key).collect();
        for service in existing_services {
            if service.source == "tcp_scan" && !new_services.contains(&service_key(&service)) {
                transaction.execute(
                    "UPDATE services SET active = 0 WHERE device_id = ?1 AND service_key = ?2",
                    params![device_id, service_key(&service)],
                )?;
            }
        }
    }

    for service in &device.services {
        transaction.execute(
            "INSERT INTO services(device_id, name, port, protocol, version, source, active, first_seen, last_seen, service_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9)
             ON CONFLICT(device_id, service_key) DO UPDATE SET
                 active = 1,
                 version = COALESCE(excluded.version, services.version),
                 first_seen = MIN(services.first_seen, excluded.first_seen),
                 last_seen = MAX(services.last_seen, excluded.last_seen)",
            params![
                device_id,
                service.name,
                service.port.map(i64::from),
                service.protocol.as_str(),
                service.version,
                service.source,
                to_ts(service.first_seen),
                to_ts(service.last_seen),
                service_key(service),
            ],
        )?;
    }

    Ok(())
}

fn update_existing_device(
    transaction: &Transaction<'_>,
    existing: &Device,
    observed: &Device,
    mac: Option<&str>,
    options: &UpsertOptions,
) -> Result<Vec<Change>> {
    let first_seen = existing.first_seen.min(observed.first_seen);
    let last_seen = existing.last_seen.max(observed.last_seen);
    let active = if options.preserve_active {
        existing.active
    } else {
        true
    };
    let device_type = if existing.device_type == DeviceType::Unknown {
        observed.device_type
    } else {
        existing.device_type
    };
    let vendor = existing.vendor.clone().or_else(|| observed.vendor.clone());
    let os = existing.os.clone().or_else(|| observed.os.clone());
    let interface = observed
        .interface
        .clone()
        .or_else(|| existing.interface.clone());
    let last_ip = observed.last_ip.or(existing.last_ip);
    let last_mac = mac.map(str::to_string).or_else(|| existing.mac.clone());
    let last_hostname = observed
        .hostname
        .clone()
        .or_else(|| existing.hostname.clone());

    transaction.execute(
        "UPDATE devices SET last_ip = ?1, last_mac = ?2, last_hostname = ?3, vendor = ?4,
             device_type = ?5, os = ?6, interface = ?7, active = ?8, first_seen = ?9, last_seen = ?10
         WHERE id = ?11",
        params![
            last_ip.map(|ip| ip.to_string()),
            last_mac,
            last_hostname,
            vendor,
            device_type.as_str(),
            os,
            interface,
            i64::from(active),
            to_ts(first_seen),
            to_ts(last_seen),
            existing.id,
        ],
    )?;

    if !options.record_changes {
        return Ok(Vec::new());
    }

    let device_id = existing.id.unwrap_or_default();
    let label = last_hostname
        .clone()
        .or(last_mac.clone())
        .or_else(|| last_ip.map(|ip| ip.to_string()))
        .unwrap_or_else(|| format!("device {device_id}"));

    let mut records = Vec::new();
    if let Some(record) = history::ip_change(
        existing.last_ip.map(|ip| ip.to_string()).as_deref(),
        observed.last_ip.map(|ip| ip.to_string()).as_deref(),
    ) {
        records.push(record);
    }
    if let Some(record) =
        history::hostname_change(existing.hostname.as_deref(), observed.hostname.as_deref())
    {
        records.push(record);
    }
    if options.ports_scanned {
        records.extend(history::port_changes(&existing.ports, &observed.ports));
        records.extend(history::service_changes(
            &existing.services,
            &observed.services,
        ));
    }

    let mut persisted = Vec::with_capacity(records.len());
    for record in records {
        persisted.push(insert_change(
            transaction,
            options.scan_id,
            device_id,
            record,
            observed.last_seen,
            Some(label.clone()),
        )?);
    }
    Ok(persisted)
}

fn insert_change(
    transaction: &Transaction<'_>,
    scan_id: Option<i64>,
    device_id: i64,
    record: ChangeRecord,
    detected_at: DateTime<Utc>,
    device_label: Option<String>,
) -> Result<Change> {
    let ChangeRecord {
        kind,
        old_value,
        new_value,
    } = record;
    let key = change_key(
        device_id,
        kind,
        old_value.as_deref(),
        new_value.as_deref(),
        detected_at,
    );
    transaction.execute(
        "INSERT OR IGNORE INTO changes(scan_id, device_id, kind, old_value, new_value, detected_at, device_label, change_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            scan_id,
            device_id,
            kind.as_str(),
            old_value.as_deref(),
            new_value.as_deref(),
            to_ts(detected_at),
            device_label.as_deref(),
            key,
        ],
    )?;
    Ok(Change {
        id: None,
        scan_id,
        device_id,
        kind,
        old_value,
        new_value,
        detected_at,
        device_label,
    })
}

fn load_device_with_conn(
    conn: &Connection,
    id: i64,
    include_observations: bool,
) -> Result<Option<Device>> {
    let row = conn
        .query_row(
            "SELECT id, last_ip, last_mac, last_hostname, vendor, device_type, os, interface, first_seen, last_seen, active
             FROM devices WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?;
    let Some((
        id,
        last_ip,
        mac,
        hostname,
        vendor,
        device_type,
        os,
        interface,
        first_seen,
        last_seen,
        active,
    )) = row
    else {
        return Ok(None);
    };

    let mut device = Device::new(parse_ts(&first_seen)?, parse_ts(&last_seen)?);
    device.id = Some(id);
    device.last_ip = parse_optional_ip(last_ip)?;
    device.mac = mac;
    device.hostname = hostname;
    device.vendor = vendor;
    device.device_type = device_type
        .parse::<DeviceType>()
        .map_err(FindaratError::Database)?;
    device.os = os;
    device.interface = interface;
    device.active = active != 0;
    device.identifiers = load_identifiers(conn, id)?;
    device.evidence = load_evidence(conn, id)?;
    device.ports = load_open_ports(conn, id)?;
    device.services = load_active_services(conn, id)?;
    if include_observations {
        device.observations = load_observations(conn, id, None)?;
    }
    Ok(Some(device))
}

fn load_identifiers(conn: &Connection, device_id: i64) -> Result<Vec<Identifier>> {
    let mut statement = conn.prepare(
        "SELECT id, kind, value, confidence, first_seen, last_seen FROM identifiers
         WHERE device_id = ?1 ORDER BY kind, last_seen DESC",
    )?;
    let rows = statement.query_map(params![device_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut identifiers = Vec::new();
    for row in rows {
        let (id, kind, value, confidence, first_seen, last_seen) = row?;
        identifiers.push(Identifier {
            id: Some(id),
            kind: kind
                .parse::<IdentifierKind>()
                .map_err(FindaratError::Database)?,
            value,
            confidence: confidence
                .parse::<Confidence>()
                .map_err(FindaratError::Database)?,
            first_seen: parse_ts(&first_seen)?,
            last_seen: parse_ts(&last_seen)?,
        });
    }
    Ok(identifiers)
}

fn load_evidence(conn: &Connection, device_id: i64) -> Result<Vec<Evidence>> {
    let mut statement = conn.prepare(
        "SELECT id, property, value, source, confidence, kind, observed_at, note FROM evidence
         WHERE device_id = ?1 ORDER BY observed_at DESC, id DESC",
    )?;
    let rows = statement.query_map(params![device_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut evidence = Vec::new();
    for row in rows {
        let (id, property, value, source, confidence, kind, observed_at, note) = row?;
        evidence.push(Evidence {
            id: Some(id),
            property,
            value,
            source,
            confidence: confidence
                .parse::<Confidence>()
                .map_err(FindaratError::Database)?,
            kind: kind
                .parse::<EvidenceKind>()
                .map_err(FindaratError::Database)?,
            observed_at: parse_ts(&observed_at)?,
            note,
        });
    }
    Ok(evidence)
}

fn load_open_ports(conn: &Connection, device_id: i64) -> Result<Vec<PortObservation>> {
    let mut statement = conn.prepare(
        "SELECT id, ip, port, protocol, state, service, version, banner, confidence, first_seen, last_seen
         FROM ports WHERE device_id = ?1 AND state = 'open' ORDER BY port",
    )?;
    let rows = statement.query_map(params![device_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;
    let mut ports = Vec::new();
    for row in rows {
        let (
            id,
            ip,
            port,
            protocol,
            state,
            service,
            version,
            banner,
            confidence,
            first_seen,
            last_seen,
        ) = row?;
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|error| FindaratError::Database(format!("invalid IP in ports: {error}")))?;
        let port = u16::try_from(port)
            .map_err(|_| FindaratError::Database(format!("invalid port number {port}")))?;
        ports.push(PortObservation {
            id: Some(id),
            ip,
            port,
            protocol: protocol
                .parse::<Protocol>()
                .map_err(FindaratError::Database)?,
            state: state
                .parse::<PortState>()
                .map_err(FindaratError::Database)?,
            service,
            version,
            banner,
            confidence: confidence
                .parse::<Confidence>()
                .map_err(FindaratError::Database)?,
            first_seen: parse_ts(&first_seen)?,
            last_seen: parse_ts(&last_seen)?,
        });
    }
    Ok(ports)
}

fn load_active_services(conn: &Connection, device_id: i64) -> Result<Vec<ServiceObservation>> {
    let mut statement = conn.prepare(
        "SELECT id, name, port, protocol, version, source, first_seen, last_seen
         FROM services WHERE device_id = ?1 AND active = 1 ORDER BY name, port",
    )?;
    let rows = statement.query_map(params![device_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;
    let mut services = Vec::new();
    for row in rows {
        let (id, name, port, protocol, version, source, first_seen, last_seen) = row?;
        let port = port
            .map(|port| {
                u16::try_from(port)
                    .map_err(|_| FindaratError::Database(format!("invalid service port {port}")))
            })
            .transpose()?;
        services.push(ServiceObservation {
            id: Some(id),
            name,
            port,
            protocol: protocol
                .parse::<Protocol>()
                .map_err(FindaratError::Database)?,
            version,
            source,
            first_seen: parse_ts(&first_seen)?,
            last_seen: parse_ts(&last_seen)?,
        });
    }
    Ok(services)
}

fn load_observations(
    conn: &Connection,
    device_id: i64,
    limit: Option<usize>,
) -> Result<Vec<Observation>> {
    let mut statement = conn.prepare(
        "SELECT id, scan_id, observed_at, source, interface, ip, mac, hostname, details
         FROM observations WHERE device_id = ?1 ORDER BY observed_at DESC, id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![device_id, limit_to_i64(limit)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<String>>(8)?,
        ))
    })?;
    let mut observations = Vec::new();
    for row in rows {
        let (id, scan_id, observed_at, source, interface, ip, mac, hostname, details) = row?;
        observations.push(Observation {
            id: Some(id),
            device_id: Some(device_id),
            scan_id,
            observed_at: parse_ts(&observed_at)?,
            source,
            interface,
            ip: parse_optional_ip(ip)?,
            mac,
            hostname,
            details: details
                .map(|value| {
                    serde_json::from_str(&value).map_err(|error| {
                        FindaratError::Database(format!("invalid observation JSON: {error}"))
                    })
                })
                .transpose()?,
        });
    }
    Ok(observations)
}

fn insert_observation(
    transaction: &Transaction<'_>,
    device_id: i64,
    observation: &Observation,
) -> Result<()> {
    let details = observation.details.as_ref().map(|value| value.to_string());
    let key = observation_key(observation, details.as_deref());
    transaction.execute(
        "INSERT OR IGNORE INTO observations(device_id, scan_id, observed_at, source, interface, ip, mac, hostname, details, observation_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            device_id,
            observation.scan_id,
            to_ts(observation.observed_at),
            observation.source,
            observation.interface,
            observation.ip.map(|ip| ip.to_string()),
            observation.mac,
            observation.hostname,
            details,
            key,
        ],
    )?;
    Ok(())
}

fn row_to_scan_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ScanSession>> {
    let id: i64 = row.get(0)?;
    let started_at: String = row.get(1)?;
    let finished_at: Option<String> = row.get(2)?;
    let interface: Option<String> = row.get(3)?;
    let subnet: Option<String> = row.get(4)?;
    let status: String = row.get(5)?;
    let device_count: i64 = row.get(6)?;
    let providers_json: String = row.get(7)?;
    Ok((|| {
        Ok(ScanSession {
            id: Some(id),
            started_at: parse_ts(&started_at)?,
            finished_at: finished_at.map(|value| parse_ts(&value)).transpose()?,
            interface,
            subnet,
            status: status
                .parse::<ScanStatus>()
                .map_err(FindaratError::Database)?,
            device_count: device_count.max(0) as usize,
            providers: serde_json::from_str(&providers_json)
                .context("invalid provider report JSON in database")?,
        })
    })())
}

fn row_to_change(row: &rusqlite::Row<'_>) -> rusqlite::Result<Change> {
    let id: i64 = row.get(0)?;
    let scan_id: Option<i64> = row.get(1)?;
    let device_id: i64 = row.get(2)?;
    let kind: String = row.get(3)?;
    let old_value: Option<String> = row.get(4)?;
    let new_value: Option<String> = row.get(5)?;
    let detected_at: String = row.get(6)?;
    let device_label: Option<String> = row.get(7)?;
    let kind = kind.parse::<ChangeKind>().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })?;
    let detected_at = parse_ts(&detected_at).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })?;
    Ok(Change {
        id: Some(id),
        scan_id,
        device_id,
        kind,
        old_value,
        new_value,
        detected_at,
        device_label,
    })
}

fn to_ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_ts(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid timestamp in database: {value:?}"))?
        .with_timezone(&Utc))
}

fn parse_optional_ip(value: Option<String>) -> Result<Option<IpAddr>> {
    value
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|error| {
                    FindaratError::Database(format!("invalid IP address {value:?}: {error}"))
                })
                .map_err(anyhow::Error::from)
        })
        .transpose()
}

fn limit_to_i64(limit: Option<usize>) -> i64 {
    limit
        .and_then(|limit| i64::try_from(limit).ok())
        .unwrap_or(-1)
}

fn device_label(device: &Device) -> String {
    device
        .hostname
        .clone()
        .or_else(|| device.mac.clone())
        .or_else(|| device.last_ip.map(|ip| ip.to_string()))
        .unwrap_or_else(|| "unknown device".to_string())
}

fn service_key(service: &ServiceObservation) -> String {
    format!(
        "{}|{}|{}|{}",
        service.name,
        service
            .port
            .map(|port| port.to_string())
            .unwrap_or_else(|| "-".to_string()),
        service.protocol.as_str(),
        service.source
    )
}

fn observation_key(observation: &Observation, details: Option<&str>) -> String {
    hash_parts(&[
        &to_ts(observation.observed_at),
        &observation.source,
        observation.interface.as_deref().unwrap_or(""),
        &observation.ip.map(|ip| ip.to_string()).unwrap_or_default(),
        observation.mac.as_deref().unwrap_or(""),
        observation.hostname.as_deref().unwrap_or(""),
        details.unwrap_or(""),
    ])
}

fn change_key(
    device_id: i64,
    kind: ChangeKind,
    old_value: Option<&str>,
    new_value: Option<&str>,
    detected_at: DateTime<Utc>,
) -> String {
    hash_parts(&[
        &device_id.to_string(),
        kind.as_str(),
        old_value.unwrap_or(""),
        new_value.unwrap_or(""),
        &to_ts(detected_at),
    ])
}

fn hash_parts(parts: &[&str]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
        "\u{1f}".hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// Helper used by import previews to describe a would-be match.
pub fn describe_match(found: &IdentityMatch) -> String {
    format!(
        "{} ({} confidence, {})",
        found.reason,
        found.confidence.as_str(),
        found.basis.as_str()
    )
}

/// A small lookup used by tests and the import report.
pub fn match_summary(found: &HashMap<i64, IdentityMatch>) -> String {
    let mut entries: Vec<String> = found
        .values()
        .map(|matched| format!("{}:{}", matched.device_id, matched.basis.as_str()))
        .collect();
    entries.sort();
    entries.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EvidenceKind;

    fn device(ip: &str, mac: &str, hostname: &str) -> Device {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.last_ip = Some(ip.parse().unwrap());
        device.mac = Some(mac.to_string());
        device.hostname = Some(hostname.to_string());
        device.interface = Some("wlan0".to_string());
        device.add_evidence(Evidence::direct("mac", mac, "arp", now));
        device
    }

    #[test]
    fn migrates_and_records_schema_version() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
        // Opening the same schema twice is idempotent.
        drop(db);
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn inserts_and_finds_devices_by_mac_ip_and_hostname() {
        let mut db = Database::open_in_memory().unwrap();
        let outcome = db
            .upsert_device(
                &device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        assert!(outcome.created);
        assert_eq!(db.count_devices().unwrap(), 1);

        assert!(db.find_device("192.168.1.10").unwrap().is_some());
        assert!(db.find_device("aa:bb:cc:dd:ee:01").unwrap().is_some());
        assert!(db.find_device("alpha").unwrap().is_some());
        assert!(db
            .find_device(&outcome.device_id.to_string())
            .unwrap()
            .is_some());
        assert!(db.find_device("missing").unwrap().is_none());
    }

    #[test]
    fn same_mac_updates_instead_of_duplicating() {
        let mut db = Database::open_in_memory().unwrap();
        let first = db
            .upsert_device(
                &device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        let mut second = device("192.168.1.11", "AA:BB:CC:DD:EE:01", "alpha");
        second.last_seen += chrono::Duration::seconds(10);
        let outcome = db.upsert_device(&second, None, false).unwrap();
        assert!(!outcome.created);
        assert_eq!(outcome.device_id, first.device_id);
        assert_eq!(db.count_devices().unwrap(), 1);
        let loaded = db.get_device(first.device_id).unwrap().unwrap();
        assert_eq!(loaded.last_ip, Some("192.168.1.11".parse().unwrap()));
        assert!(loaded
            .observations
            .iter()
            .any(|observation| observation.ip == Some("192.168.1.11".parse().unwrap())));
    }

    #[test]
    fn records_ip_and_hostname_changes() {
        let mut db = Database::open_in_memory().unwrap();
        let first = db
            .upsert_device(
                &device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        let mut second = device("192.168.1.11", "AA:BB:CC:DD:EE:01", "beta");
        second.last_seen += chrono::Duration::seconds(10);
        let outcome = db.upsert_device(&second, None, false).unwrap();
        assert!(outcome
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::IpChanged));
        assert!(outcome
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::HostnameChanged));
        let changes = db.device_changes(first.device_id, None).unwrap();
        assert!(changes
            .iter()
            .any(|change| change.kind == ChangeKind::IpChanged));
        assert!(changes
            .iter()
            .any(|change| change.kind == ChangeKind::HostnameChanged));
    }

    #[test]
    fn preserves_conflicting_evidence() {
        let mut db = Database::open_in_memory().unwrap();
        let now = Utc::now();
        let mut first = device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha");
        first.add_evidence(Evidence::inferred(
            "operating_system",
            "Linux",
            "ssh_banner",
            Confidence::Medium,
            EvidenceKind::ProbabilisticInference,
            now,
        ));
        let outcome = db.upsert_device(&first, None, false).unwrap();
        let mut second = device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha");
        second.add_evidence(Evidence::inferred(
            "operating_system",
            "Android",
            "mdns",
            Confidence::Low,
            EvidenceKind::ProbabilisticInference,
            now,
        ));
        db.upsert_device(&second, None, false).unwrap();
        let loaded = db.get_device(outcome.device_id).unwrap().unwrap();
        let values: Vec<&str> = loaded
            .evidence
            .iter()
            .filter(|evidence| evidence.property == "operating_system")
            .map(|evidence| evidence.value.as_str())
            .collect();
        assert!(values.contains(&"Linux"));
        assert!(values.contains(&"Android"));
    }

    #[test]
    fn detects_disappeared_devices_once() {
        let mut db = Database::open_in_memory().unwrap();
        let outcome = db
            .upsert_device(
                &device("192.168.1.10", "AA:BB:CC:DD:EE:01", "alpha"),
                None,
                false,
            )
            .unwrap();
        let now = Utc::now() + chrono::Duration::seconds(5);
        let changes = db
            .mark_disappeared(None, &HashSet::new(), Some("wlan0"), now, now)
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::DeviceDisappeared);
        assert_eq!(db.count_active_devices().unwrap(), 0);
        let again = db
            .mark_disappeared(None, &HashSet::new(), Some("wlan0"), now, now)
            .unwrap();
        assert!(again.is_empty());
        let loaded = db.get_device(outcome.device_id).unwrap().unwrap();
        assert!(!loaded.active);
    }

    #[test]
    fn scan_sessions_round_trip() {
        let mut db = Database::open_in_memory().unwrap();
        let mut session = ScanSession::started(
            Utc::now(),
            Some("wlan0".to_string()),
            Some("192.168.1.0/24".to_string()),
        );
        session.providers.push(ProviderReport {
            name: "arp".to_string(),
            status: crate::models::ProviderStatus::Ok,
            hosts_found: 3,
            error: None,
            duration_ms: 42,
        });
        let id = db.create_scan_session(&session).unwrap();
        db.finish_scan_session(id, ScanStatus::Completed, &session.providers, 3, Utc::now())
            .unwrap();
        let loaded = db.get_scan_session(id).unwrap().unwrap();
        assert_eq!(loaded.device_count, 3);
        assert_eq!(loaded.providers.len(), 1);
        assert_eq!(db.list_scan_sessions(None).unwrap().len(), 1);
    }
}
