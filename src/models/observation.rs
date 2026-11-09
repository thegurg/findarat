//! Historical observations, scan sessions, and detected changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// One point-in-time observation of a device by one discovery source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<i64>,
    pub observed_at: DateTime<Utc>,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Observation {
    pub fn new(observed_at: DateTime<Utc>, source: impl Into<String>) -> Self {
        Self {
            id: None,
            device_id: None,
            scan_id: None,
            observed_at,
            source: source.into(),
            interface: None,
            ip: None,
            mac: None,
            hostname: None,
            details: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    #[default]
    Running,
    Completed,
    Failed,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => Err(format!("invalid scan status: {other}")),
        }
    }
}

/// Per-provider outcome for a scan. A provider failure is recorded, never
/// allowed to abort the whole scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReport {
    pub name: String,
    pub status: ProviderStatus,
    pub hosts_found: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    #[default]
    Ok,
    Failed,
    Skipped,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

impl fmt::Display for ProviderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ok" => Ok(Self::Ok),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            other => Err(format!("invalid provider status: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    pub status: ScanStatus,
    #[serde(default)]
    pub device_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ProviderReport>,
}

impl ScanSession {
    pub fn started(
        started_at: DateTime<Utc>,
        interface: Option<String>,
        subnet: Option<String>,
    ) -> Self {
        Self {
            id: None,
            started_at,
            finished_at: None,
            interface,
            subnet,
            status: ScanStatus::Running,
            device_count: 0,
            providers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    DeviceAdded,
    DeviceDisappeared,
    IpChanged,
    HostnameChanged,
    ServiceAdded,
    ServiceRemoved,
    PortOpened,
    PortClosed,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceAdded => "device_added",
            Self::DeviceDisappeared => "device_disappeared",
            Self::IpChanged => "ip_changed",
            Self::HostnameChanged => "hostname_changed",
            Self::ServiceAdded => "service_added",
            Self::ServiceRemoved => "service_removed",
            Self::PortOpened => "port_opened",
            Self::PortClosed => "port_closed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DeviceAdded => "New device",
            Self::DeviceDisappeared => "Disappeared",
            Self::IpChanged => "IP changed",
            Self::HostnameChanged => "Hostname changed",
            Self::ServiceAdded => "Service added",
            Self::ServiceRemoved => "Service removed",
            Self::PortOpened => "Port opened",
            Self::PortClosed => "Port closed",
        }
    }
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ChangeKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "device_added" => Ok(Self::DeviceAdded),
            "device_disappeared" => Ok(Self::DeviceDisappeared),
            "ip_changed" => Ok(Self::IpChanged),
            "hostname_changed" => Ok(Self::HostnameChanged),
            "service_added" => Ok(Self::ServiceAdded),
            "service_removed" => Ok(Self::ServiceRemoved),
            "port_opened" => Ok(Self::PortOpened),
            "port_closed" => Ok(Self::PortClosed),
            other => Err(format!("invalid change kind: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<i64>,
    pub device_id: i64,
    pub kind: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    pub detected_at: DateTime<Utc>,
    /// Denormalised display name captured when the change was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

impl Change {
    pub fn new(
        device_id: i64,
        kind: ChangeKind,
        old_value: Option<String>,
        new_value: Option<String>,
        detected_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: None,
            scan_id: None,
            device_id,
            kind,
            old_value,
            new_value,
            detected_at,
            device_label: None,
        }
    }
}
