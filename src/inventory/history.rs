//! Change detection helpers.
//!
//! These functions are pure so the diff rules can be tested without a database.

use std::collections::BTreeSet;

use crate::models::{ChangeKind, PortObservation, ServiceObservation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    pub kind: ChangeKind,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

pub fn ip_change(old: Option<&str>, new: Option<&str>) -> Option<ChangeRecord> {
    match (old, new) {
        (Some(old), Some(new)) if old != new => Some(ChangeRecord {
            kind: ChangeKind::IpChanged,
            old_value: Some(old.to_string()),
            new_value: Some(new.to_string()),
        }),
        _ => None,
    }
}

pub fn hostname_change(old: Option<&str>, new: Option<&str>) -> Option<ChangeRecord> {
    let old_key = old.map(|value| value.trim_end_matches('.').to_ascii_lowercase());
    let new_key = new.map(|value| value.trim_end_matches('.').to_ascii_lowercase());
    match (old_key, new_key) {
        (Some(old), Some(new)) if old != new => Some(ChangeRecord {
            kind: ChangeKind::HostnameChanged,
            old_value: Some(old),
            new_value: Some(new),
        }),
        _ => None,
    }
}

pub fn port_changes(old: &[PortObservation], new: &[PortObservation]) -> Vec<ChangeRecord> {
    let old_ports: BTreeSet<String> = old
        .iter()
        .filter(|port| port.state == crate::models::PortState::Open)
        .map(port_key)
        .collect();
    let new_ports: BTreeSet<String> = new
        .iter()
        .filter(|port| port.state == crate::models::PortState::Open)
        .map(port_key)
        .collect();

    let mut changes = Vec::new();
    for port in new_ports.difference(&old_ports) {
        changes.push(ChangeRecord {
            kind: ChangeKind::PortOpened,
            old_value: None,
            new_value: Some(port.clone()),
        });
    }
    for port in old_ports.difference(&new_ports) {
        changes.push(ChangeRecord {
            kind: ChangeKind::PortClosed,
            old_value: Some(port.clone()),
            new_value: None,
        });
    }
    changes
}

pub fn service_changes(
    old: &[ServiceObservation],
    new: &[ServiceObservation],
) -> Vec<ChangeRecord> {
    let old_services: BTreeSet<String> = old.iter().map(service_key).collect();
    let new_services: BTreeSet<String> = new.iter().map(service_key).collect();

    let mut changes = Vec::new();
    for service in new_services.difference(&old_services) {
        changes.push(ChangeRecord {
            kind: ChangeKind::ServiceAdded,
            old_value: None,
            new_value: Some(service.clone()),
        });
    }
    for service in old_services.difference(&new_services) {
        changes.push(ChangeRecord {
            kind: ChangeKind::ServiceRemoved,
            old_value: Some(service.clone()),
            new_value: None,
        });
    }
    changes
}

fn port_key(port: &PortObservation) -> String {
    format!("{}/{}", port.protocol, port.port)
}

fn service_key(service: &ServiceObservation) -> String {
    match service.port {
        Some(port) => format!("{} ({}/{})", service.name, service.protocol, port),
        None => format!("{} ({})", service.name, service.protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Confidence, PortObservation, Protocol, ServiceObservation};
    use chrono::Utc;

    fn port(number: u16) -> PortObservation {
        let now = Utc::now();
        let mut port = PortObservation::open("192.168.1.10".parse().unwrap(), number, now);
        port.confidence = Confidence::High;
        port
    }

    #[test]
    fn detects_opened_and_closed_ports() {
        let old = vec![port(22), port(80)];
        let new = vec![port(22), port(443)];
        let changes = port_changes(&old, &new);
        assert!(changes.iter().any(|change| {
            change.kind == ChangeKind::PortOpened && change.new_value.as_deref() == Some("tcp/443")
        }));
        assert!(changes.iter().any(|change| {
            change.kind == ChangeKind::PortClosed && change.old_value.as_deref() == Some("tcp/80")
        }));
    }

    #[test]
    fn detects_ip_and_hostname_changes() {
        assert_eq!(
            ip_change(Some("192.168.1.10"), Some("192.168.1.11"))
                .unwrap()
                .kind,
            ChangeKind::IpChanged
        );
        assert!(ip_change(Some("192.168.1.10"), Some("192.168.1.10")).is_none());
        assert_eq!(
            hostname_change(Some("Alpha.local"), Some("beta"))
                .unwrap()
                .kind,
            ChangeKind::HostnameChanged
        );
        assert!(hostname_change(Some("alpha"), Some("ALPHA.")).is_none());
    }

    #[test]
    fn detects_service_changes() {
        let now = Utc::now();
        let old = vec![ServiceObservation::new(
            "ssh",
            Some(22),
            Protocol::Tcp,
            "tcp_scan",
            now,
        )];
        let new = vec![ServiceObservation::new(
            "http",
            Some(80),
            Protocol::Tcp,
            "tcp_scan",
            now,
        )];
        let changes = service_changes(&old, &new);
        assert!(changes
            .iter()
            .any(|change| change.kind == ChangeKind::ServiceAdded));
        assert!(changes
            .iter()
            .any(|change| change.kind == ChangeKind::ServiceRemoved));
    }
}
