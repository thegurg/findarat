//! Domain model for devices, identifiers, ports, and services.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::evidence::{Confidence, Evidence};
use super::observation::Observation;

/// Probable device category. `Unknown` is a real answer, not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Router,
    AccessPoint,
    Smartphone,
    Laptop,
    Desktop,
    Server,
    Printer,
    SmartTv,
    Iot,
    #[default]
    Unknown,
}

impl DeviceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::AccessPoint => "access_point",
            Self::Smartphone => "smartphone",
            Self::Laptop => "laptop",
            Self::Desktop => "desktop",
            Self::Server => "server",
            Self::Printer => "printer",
            Self::SmartTv => "smart_tv",
            Self::Iot => "iot",
            Self::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Router => "Router",
            Self::AccessPoint => "Access Point",
            Self::Smartphone => "Smartphone",
            Self::Laptop => "Laptop",
            Self::Desktop => "Desktop",
            Self::Server => "Server",
            Self::Printer => "Printer",
            Self::SmartTv => "Smart TV",
            Self::Iot => "IoT Device",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeviceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace([' ', '-'], "_")
            .as_str()
        {
            "router" => Ok(Self::Router),
            "access_point" | "ap" => Ok(Self::AccessPoint),
            "smartphone" | "phone" => Ok(Self::Smartphone),
            "laptop" => Ok(Self::Laptop),
            "desktop" => Ok(Self::Desktop),
            "server" => Ok(Self::Server),
            "printer" => Ok(Self::Printer),
            "smart_tv" | "smarttv" | "tv" => Ok(Self::SmartTv),
            "iot" | "iot_device" => Ok(Self::Iot),
            "unknown" | "" => Ok(Self::Unknown),
            other => Err(format!("invalid device type: {other}")),
        }
    }
}

/// Kind of identity value attached to a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Mac,
    Ip,
    Hostname,
    NetbiosName,
}

impl IdentifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Ip => "ip",
            Self::Hostname => "hostname",
            Self::NetbiosName => "netbios_name",
        }
    }
}

impl fmt::Display for IdentifierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IdentifierKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mac" => Ok(Self::Mac),
            "ip" => Ok(Self::Ip),
            "hostname" => Ok(Self::Hostname),
            "netbios_name" | "netbios" => Ok(Self::NetbiosName),
            other => Err(format!("invalid identifier kind: {other}")),
        }
    }
}

/// An identifier observed for a device. Identifiers are historical: an old IP
/// stays attached to the device even after DHCP assigns a new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub kind: IdentifierKind,
    pub value: String,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Identifier {
    pub fn new(
        kind: IdentifierKind,
        value: impl Into<String>,
        confidence: Confidence,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> Self {
        Self {
            id: None,
            kind,
            value: value.into(),
            confidence,
            first_seen,
            last_seen,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(format!("invalid protocol: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    #[default]
    Open,
    Closed,
    Filtered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
        }
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PortState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            "filtered" => Ok(Self::Filtered),
            other => Err(format!("invalid port state: {other}")),
        }
    }
}

/// A TCP (or UDP) port observation. An open port is a fact; the service name is
/// a separate, less certain claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl PortObservation {
    pub fn open(ip: IpAddr, port: u16, observed_at: DateTime<Utc>) -> Self {
        Self {
            id: None,
            ip,
            port,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: None,
            version: None,
            banner: None,
            confidence: Confidence::Unknown,
            first_seen: observed_at,
            last_seen: observed_at,
        }
    }
}

/// A service advertised or identified on a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where the service claim came from (`mdns`, `ssdp`, `tcp`, ...).
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl ServiceObservation {
    pub fn new(
        name: impl Into<String>,
        port: Option<u16>,
        protocol: Protocol,
        source: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: None,
            name: name.into(),
            port,
            protocol,
            version: None,
            source: source.into(),
            first_seen: observed_at,
            last_seen: observed_at,
        }
    }
}

/// Aggregated, persisted view of a device.
///
/// A device is an identity, not an IP address. `last_ip`, `mac`, and `hostname`
/// are conveniences for display; the [`Identifier`] list and the observation
/// history are authoritative.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default)]
    pub device_type: DeviceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identifiers: Vec<Identifier>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceObservation>,
    /// Historical observations. Populated for detail/export views, not for
    /// the compact device list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<Observation>,
}

fn default_true() -> bool {
    true
}

impl Device {
    pub fn new(first_seen: DateTime<Utc>, last_seen: DateTime<Utc>) -> Self {
        Self {
            id: None,
            last_ip: None,
            mac: None,
            vendor: None,
            hostname: None,
            device_type: DeviceType::Unknown,
            os: None,
            interface: None,
            first_seen,
            last_seen,
            active: true,
            identifiers: Vec::new(),
            evidence: Vec::new(),
            ports: Vec::new(),
            services: Vec::new(),
            observations: Vec::new(),
        }
    }

    pub fn display_name(&self) -> String {
        self.hostname
            .clone()
            .or_else(|| self.mac.clone())
            .or_else(|| self.last_ip.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "unknown device".to_string())
    }

    pub fn open_port_summary(&self) -> String {
        let mut ports: Vec<u16> = self.ports.iter().map(|p| p.port).collect();
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            "—".to_string()
        } else {
            ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    pub fn service_summary(&self) -> String {
        let mut names: Vec<&str> = self
            .services
            .iter()
            .map(|s| s.name.as_str())
            .chain(self.ports.iter().filter_map(|p| p.service.as_deref()))
            .collect();
        names.sort_unstable();
        names.dedup();
        if names.is_empty() {
            "—".to_string()
        } else {
            names.join(", ")
        }
    }

    /// Highest confidence attached to a property, if any evidence exists.
    pub fn property_confidence(&self, property: &str) -> Option<Confidence> {
        self.evidence
            .iter()
            .filter(|e| e.property == property)
            .map(|e| e.confidence)
            .max_by_key(|c| c.rank())
    }

    /// Add evidence without duplicating an identical record. Conflicting values
    /// for the same property are intentionally preserved.
    pub fn add_evidence(&mut self, evidence: Evidence) {
        let duplicate = self.evidence.iter().any(|existing| {
            existing.property == evidence.property
                && existing.value == evidence.value
                && existing.source == evidence.source
        });
        if !duplicate {
            self.evidence.push(evidence);
        }
    }

    pub fn add_identifier(&mut self, identifier: Identifier) {
        if let Some(existing) = self
            .identifiers
            .iter_mut()
            .find(|i| i.kind == identifier.kind && i.value == identifier.value)
        {
            existing.last_seen = existing.last_seen.max(identifier.last_seen);
            existing.first_seen = existing.first_seen.min(identifier.first_seen);
            if identifier.confidence.rank() > existing.confidence.rank() {
                existing.confidence = identifier.confidence;
            }
        } else {
            self.identifiers.push(identifier);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_type_aliases_parse() {
        assert_eq!(
            "smart tv".parse::<DeviceType>().unwrap(),
            DeviceType::SmartTv
        );
        assert_eq!("AP".parse::<DeviceType>().unwrap(), DeviceType::AccessPoint);
        assert_eq!(
            "unknown".parse::<DeviceType>().unwrap(),
            DeviceType::Unknown
        );
        assert!("toaster".parse::<DeviceType>().is_err());
    }

    #[test]
    fn conflicting_evidence_is_preserved() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.add_evidence(Evidence::inferred(
            "operating_system",
            "Android",
            "service",
            Confidence::Medium,
            super::super::evidence::EvidenceKind::ProbabilisticInference,
            now,
        ));
        device.add_evidence(Evidence::inferred(
            "operating_system",
            "Linux",
            "banner",
            Confidence::Low,
            super::super::evidence::EvidenceKind::ProbabilisticInference,
            now,
        ));
        assert_eq!(device.evidence.len(), 2);
        assert_eq!(
            device.property_confidence("operating_system"),
            Some(Confidence::Medium)
        );
    }

    #[test]
    fn duplicate_evidence_is_not_added_twice() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        let evidence = Evidence::direct("mac", "AA:BB:CC:DD:EE:FF", "arp", now);
        device.add_evidence(evidence.clone());
        device.add_evidence(evidence);
        assert_eq!(device.evidence.len(), 1);
    }
}
