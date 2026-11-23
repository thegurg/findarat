//! Human-readable explanations of a device's evidence.
//!
//! The database preserves every claim, including conflicting ones. This module
//! turns that raw record into a small report that answers "what is believed,
//! why, and what disagrees?" without hiding contradictions.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::models::{Confidence, Device, Evidence};

/// Properties where more than one value is a genuine contradiction rather than
/// a normal collection (for example many open ports or services).
const CONFLICT_PROPERTIES: &[&str] = &[
    "device_type",
    "operating_system",
    "vendor",
    "hostname",
    "model",
];

#[derive(Debug, Clone, Serialize)]
pub struct DeviceExplanation {
    pub device_id: Option<i64>,
    pub name: String,
    pub label: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub active: bool,
    pub ignored: bool,
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub identity: Vec<IdentityExplanation>,
    pub properties: Vec<PropertyExplanation>,
    pub conflicts: Vec<ConflictExplanation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityExplanation {
    pub kind: String,
    pub value: String,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropertyExplanation {
    pub property: String,
    pub selected_value: Option<String>,
    pub selected_confidence: Option<Confidence>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictExplanation {
    pub property: String,
    pub values: Vec<String>,
}

pub fn explain(device: &Device) -> DeviceExplanation {
    let identity = device
        .identifiers
        .iter()
        .map(|identifier| IdentityExplanation {
            kind: identifier.kind.to_string(),
            value: identifier.value.clone(),
            confidence: identifier.confidence,
            first_seen: identifier.first_seen,
            last_seen: identifier.last_seen,
        })
        .collect();

    let mut grouped: BTreeMap<String, Vec<Evidence>> = BTreeMap::new();
    for evidence in &device.evidence {
        grouped
            .entry(evidence.property.clone())
            .or_default()
            .push(evidence.clone());
    }

    let mut properties = Vec::with_capacity(grouped.len());
    for (property, mut evidence) in grouped {
        evidence.sort_by(|left, right| {
            right
                .confidence
                .rank()
                .cmp(&left.confidence.rank())
                .then_with(|| right.observed_at.cmp(&left.observed_at))
        });
        let selected_value = selected_value(device, &property).or_else(|| {
            evidence
                .iter()
                .max_by_key(|item| (item.confidence.rank(), item.observed_at))
                .map(|item| item.value.clone())
        });
        let selected_confidence = device.property_confidence(&property);
        properties.push(PropertyExplanation {
            property,
            selected_value,
            selected_confidence,
            evidence,
        });
    }

    let mut conflicts = Vec::new();
    for property in CONFLICT_PROPERTIES {
        let Some(evidence) = grouped_values(device, property) else {
            continue;
        };
        let mut values = evidence;
        values.sort();
        values.dedup();
        if values.len() > 1 {
            conflicts.push(ConflictExplanation {
                property: (*property).to_string(),
                values,
            });
        }
    }

    let mut warnings = Vec::new();
    if device.ignored {
        warnings.push("device is marked ignored".to_string());
    }
    if device.label.is_some() {
        warnings.push("display name is user-provided".to_string());
    }
    if let Some(mac) = &device.mac {
        if crate::network::interface::is_locally_administered(mac) {
            warnings.push(
                "MAC address is locally administered (possibly randomised); vendor lookup is unreliable"
                    .to_string(),
            );
        }
    }
    if device.device_type == crate::models::DeviceType::Unknown {
        warnings.push(
            "device type is unknown; no rule produced a confident classification".to_string(),
        );
    }
    if device.evidence.is_empty() {
        warnings.push("no evidence has been recorded for this device".to_string());
    }
    if !conflicts.is_empty() {
        warnings
            .push("conflicting claims are preserved; no value was silently discarded".to_string());
    }

    DeviceExplanation {
        device_id: device.id,
        name: device.display_name(),
        label: device.label.clone(),
        hostname: device.hostname.clone(),
        ip: device.last_ip.map(|ip| ip.to_string()),
        mac: device.mac.clone(),
        active: device.active,
        ignored: device.ignored,
        tags: device.tags.clone(),
        first_seen: device.first_seen,
        last_seen: device.last_seen,
        identity,
        properties,
        conflicts,
        warnings,
    }
}

fn selected_value(device: &Device, property: &str) -> Option<String> {
    match property {
        "device_type" => Some(device.device_type.as_str().to_string()),
        "operating_system" => device.os.clone(),
        "vendor" => device.vendor.clone(),
        "hostname" => device.hostname.clone(),
        "mac" => device.mac.clone(),
        "ip" => device.last_ip.map(|ip| ip.to_string()),
        _ => None,
    }
}

fn grouped_values(device: &Device, property: &str) -> Option<Vec<String>> {
    let values: Vec<String> = device
        .evidence
        .iter()
        .filter(|evidence| evidence.property == property)
        .map(|evidence| evidence.value.clone())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DeviceType, EvidenceKind};

    fn device_with_evidence() -> Device {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.id = Some(7);
        device.last_ip = Some("192.168.1.20".parse().unwrap());
        device.mac = Some("AA:BB:CC:DD:EE:01".to_string());
        device.hostname = Some("printer".to_string());
        device.device_type = DeviceType::Printer;
        device.add_evidence(Evidence::direct("mac", "AA:BB:CC:DD:EE:01", "arp", now));
        device.add_evidence(Evidence::inferred(
            "device_type",
            "printer",
            "port:9100",
            Confidence::Medium,
            EvidenceKind::ProbabilisticInference,
            now,
        ));
        device.add_evidence(Evidence::inferred(
            "device_type",
            "iot",
            "hostname",
            Confidence::Low,
            EvidenceKind::ProbabilisticInference,
            now,
        ));
        device
    }

    #[test]
    fn groups_evidence_and_reports_conflicts() {
        let explanation = explain(&device_with_evidence());
        assert_eq!(explanation.device_id, Some(7));
        assert!(explanation
            .properties
            .iter()
            .any(|property| property.property == "device_type" && property.evidence.len() == 2));
        assert_eq!(explanation.conflicts.len(), 1);
        assert_eq!(explanation.conflicts[0].property, "device_type");
        assert!(explanation
            .warnings
            .iter()
            .any(|warning| warning.contains("conflicting")));
    }

    #[test]
    fn user_label_wins_for_display_name() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.hostname = Some("printer".to_string());
        device.label = Some("Office printer".to_string());
        let explanation = explain(&device);
        assert_eq!(explanation.name, "Office printer");
        assert!(explanation
            .warnings
            .iter()
            .any(|warning| warning.contains("user-provided")));
    }
}
