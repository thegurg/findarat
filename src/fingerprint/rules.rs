//! User-extensible fingerprint rules.
//!
//! Rules are ordinary TOML and live in the configuration directory by default.
//! They add evidence and can fill inferred properties, but they never delete
//! evidence produced by discovery or the built-in heuristics.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::error::FindaratError;
use crate::models::{Confidence, Device, DeviceType, Evidence, EvidenceKind, PortState};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub any_ports: Vec<u16>,
    #[serde(default)]
    pub all_ports: Vec<u16>,
    #[serde(default)]
    pub hostname_contains: Vec<String>,
    #[serde(default)]
    pub vendor_contains: Vec<String>,
    #[serde(default)]
    pub banner_contains: Vec<String>,
    #[serde(default)]
    pub service_contains: Vec<String>,
    #[serde(default)]
    pub mdns_service_contains: Vec<String>,
    #[serde(default)]
    pub ssdp_type_contains: Vec<String>,
}

fn default_confidence() -> Confidence {
    Confidence::Medium
}

impl RuleSet {
    /// Load a rule file. A missing file is an empty rule set.
    pub fn load_optional(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() || !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read fingerprint rules {}", path.display()))?;
        let rules: Self = toml::from_str(&content).with_context(|| {
            format!(
                "failed to parse fingerprint rules {}; see the rule format in the README",
                path.display()
            )
        })?;
        rules
            .validate()
            .map_err(|error| FindaratError::Config(format!("{}: {error}", path.display())))?;
        Ok(rules)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        for (index, rule) in self.rules.iter().enumerate() {
            let label = if rule.name.trim().is_empty() {
                format!("rule #{}", index + 1)
            } else {
                format!("rule {:?}", rule.name)
            };
            if rule.name.trim().is_empty() {
                return Err(format!("{label}: name must not be empty"));
            }
            if !names.insert(rule.name.trim().to_string()) {
                return Err(format!("{label}: duplicate rule name"));
            }
            if !rule.has_conditions() {
                return Err(format!(
                    "{label}: at least one condition is required (ports, hostname, vendor, banner, service, mDNS, or SSDP)"
                ));
            }
            if !rule.has_outcomes() {
                return Err(format!(
                    "{label}: at least one outcome is required (device_type, os, vendor, or model)"
                ));
            }
            if let Some(device_type) = &rule.device_type {
                device_type
                    .parse::<DeviceType>()
                    .map_err(|error| format!("{label}: {error}"))?;
            }
            for (field, values) in [
                ("hostname_contains", &rule.hostname_contains),
                ("vendor_contains", &rule.vendor_contains),
                ("banner_contains", &rule.banner_contains),
                ("service_contains", &rule.service_contains),
                ("mdns_service_contains", &rule.mdns_service_contains),
                ("ssdp_type_contains", &rule.ssdp_type_contains),
            ] {
                if values.iter().any(|value| value.trim().is_empty()) {
                    return Err(format!("{label}: {field} must not contain empty strings"));
                }
            }
        }
        Ok(())
    }
}

impl Rule {
    fn has_conditions(&self) -> bool {
        !self.any_ports.is_empty()
            || !self.all_ports.is_empty()
            || !self.hostname_contains.is_empty()
            || !self.vendor_contains.is_empty()
            || !self.banner_contains.is_empty()
            || !self.service_contains.is_empty()
            || !self.mdns_service_contains.is_empty()
            || !self.ssdp_type_contains.is_empty()
    }

    fn has_outcomes(&self) -> bool {
        self.device_type.is_some()
            || self.os.is_some()
            || self.vendor.is_some()
            || self.model.is_some()
    }

    fn matches(&self, input: &RuleInput<'_>) -> bool {
        (self.any_ports.is_empty() || self.any_ports.iter().any(|port| input.ports.contains(port)))
            && (self.all_ports.is_empty()
                || self.all_ports.iter().all(|port| input.ports.contains(port)))
            && option_contains(&input.hostnames, &self.hostname_contains)
            && option_contains(&input.vendors, &self.vendor_contains)
            && list_contains(&input.banners, &self.banner_contains)
            && list_contains(&input.services, &self.service_contains)
            && list_contains(&input.mdns_service_types, &self.mdns_service_contains)
            && list_contains(&input.ssdp_device_types, &self.ssdp_type_contains)
    }
}

struct RuleInput<'a> {
    hostnames: Vec<&'a str>,
    vendors: Vec<&'a str>,
    ports: BTreeSet<u16>,
    banners: Vec<&'a str>,
    services: Vec<&'a str>,
    mdns_service_types: Vec<&'a str>,
    ssdp_device_types: Vec<&'a str>,
}

fn option_contains(values: &[&str], needles: &[String]) -> bool {
    needles.is_empty()
        || needles.iter().any(|needle| {
            values.iter().any(|value| {
                value
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
        })
}

fn list_contains(values: &[&str], needles: &[String]) -> bool {
    needles.is_empty()
        || needles.iter().any(|needle| {
            values.iter().any(|value| {
                value
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
        })
}

/// Apply every matching rule to `device`, adding evidence and filling
/// properties that are absent or weaker than the rule's confidence.
pub fn apply(
    device: &mut Device,
    rules: &[Rule],
    observed_at: DateTime<Utc>,
    mdns_service_types: &[String],
    ssdp_device_types: &[String],
) {
    if rules.is_empty() {
        return;
    }
    let matched: Vec<usize> = {
        let hostnames: Vec<&str> = device
            .label
            .as_deref()
            .into_iter()
            .chain(device.hostname.as_deref())
            .collect();
        let vendors: Vec<&str> = device.vendor.as_deref().into_iter().collect();
        let ports: BTreeSet<u16> = device
            .ports
            .iter()
            .filter(|port| port.state == PortState::Open)
            .map(|port| port.port)
            .collect();
        let banners: Vec<&str> = device
            .ports
            .iter()
            .flat_map(|port| [port.version.as_deref(), port.banner.as_deref()])
            .flatten()
            .collect();
        let services: Vec<&str> = device
            .services
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        let mdns_service_types: Vec<&str> = mdns_service_types.iter().map(String::as_str).collect();
        let ssdp_device_types: Vec<&str> = ssdp_device_types.iter().map(String::as_str).collect();
        let input = RuleInput {
            hostnames,
            vendors,
            ports,
            banners,
            services,
            mdns_service_types,
            ssdp_device_types,
        };
        rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.matches(&input))
            .map(|(index, _)| index)
            .collect()
    };

    for index in matched {
        apply_rule(device, &rules[index], observed_at);
    }
}

fn apply_rule(device: &mut Device, rule: &Rule, observed_at: DateTime<Utc>) {
    let source = format!("rule:{}", rule.name);
    let note = rule
        .note
        .clone()
        .unwrap_or_else(|| format!("matched local fingerprint rule {:?}", rule.name));

    if let Some(device_type) = &rule.device_type {
        if let Ok(device_type) = device_type.parse::<DeviceType>() {
            device.add_evidence(
                Evidence::inferred(
                    "device_type",
                    device_type.as_str(),
                    source.clone(),
                    rule.confidence,
                    EvidenceKind::ProbabilisticInference,
                    observed_at,
                )
                .with_note(note.clone()),
            );
            let existing = device.property_confidence("device_type");
            if device.device_type == DeviceType::Unknown
                || existing
                    .map(|confidence| rule.confidence.rank() >= confidence.rank())
                    .unwrap_or(true)
            {
                device.device_type = device_type;
            }
        }
    }

    if let Some(os) = &rule.os {
        device.add_evidence(
            Evidence::inferred(
                "operating_system",
                os.clone(),
                source.clone(),
                rule.confidence,
                EvidenceKind::ProbabilisticInference,
                observed_at,
            )
            .with_note(note.clone()),
        );
        let existing = device.property_confidence("operating_system");
        if device.os.is_none()
            || existing
                .map(|confidence| rule.confidence.rank() >= confidence.rank())
                .unwrap_or(true)
        {
            device.os = Some(os.clone());
        }
    }

    if let Some(vendor) = &rule.vendor {
        device.add_evidence(
            Evidence::inferred(
                "vendor",
                vendor.clone(),
                source.clone(),
                rule.confidence,
                EvidenceKind::ProbabilisticInference,
                observed_at,
            )
            .with_note(note.clone()),
        );
        let existing = device.property_confidence("vendor");
        if device.vendor.is_none()
            || existing
                .map(|confidence| rule.confidence.rank() >= confidence.rank())
                .unwrap_or(true)
        {
            device.vendor = Some(vendor.clone());
        }
    }

    if let Some(model) = &rule.model {
        device.add_evidence(
            Evidence::inferred(
                "model",
                model.clone(),
                source,
                rule.confidence,
                EvidenceKind::ProbabilisticInference,
                observed_at,
            )
            .with_note(note),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PortObservation;

    fn rule(toml: &str) -> RuleSet {
        let rules: RuleSet = toml::from_str(toml).unwrap();
        rules.validate().unwrap();
        rules
    }

    fn device_with_ports(ports: &[u16]) -> Device {
        let now = Utc::now();
        let ip = "192.168.1.20".parse().unwrap();
        let mut device = Device::new(now, now);
        device.last_ip = Some(ip);
        for port in ports {
            device.ports.push(PortObservation::open(ip, *port, now));
        }
        device
    }

    #[test]
    fn rejects_unknown_fields_and_empty_rules() {
        let unknown: Result<RuleSet, _> = toml::from_str(
            r#"
[[rule]]
name = "x"
any_ports = [80]
bogus = true
"#,
        );
        assert!(unknown.is_err());

        let empty: RuleSet = toml::from_str(
            r#"
[[rule]]
name = "x"
"#,
        )
        .unwrap();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn rejects_invalid_device_type_and_missing_outcome() {
        let invalid: RuleSet = toml::from_str(
            r#"
[[rule]]
name = "x"
any_ports = [80]
device_type = "toaster"
"#,
        )
        .unwrap();
        assert!(invalid.validate().is_err());

        let no_outcome: RuleSet = toml::from_str(
            r#"
[[rule]]
name = "x"
any_ports = [80]
"#,
        )
        .unwrap();
        assert!(no_outcome.validate().is_err());
    }

    #[test]
    fn matches_port_and_text_conditions() {
        let rules = rule(
            r#"
[[rule]]
name = "printer"
device_type = "printer"
any_ports = [631, 9100]
hostname_contains = ["printer", "hp-"]
"#,
        );
        let mut device = device_with_ports(&[9100]);
        device.hostname = Some("Office-Printer".to_string());
        apply(&mut device, &rules.rules, Utc::now(), &[], &[]);
        assert_eq!(device.device_type, DeviceType::Printer);
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.source == "rule:printer"));
    }

    #[test]
    fn all_ports_and_any_ports_are_distinct() {
        let rules = rule(
            r#"
[[rule]]
name = "server"
device_type = "server"
all_ports = [22, 443]
"#,
        );
        let mut missing = device_with_ports(&[22]);
        apply(&mut missing, &rules.rules, Utc::now(), &[], &[]);
        assert_eq!(missing.device_type, DeviceType::Unknown);

        let mut complete = device_with_ports(&[22, 443]);
        apply(&mut complete, &rules.rules, Utc::now(), &[], &[]);
        assert_eq!(complete.device_type, DeviceType::Server);
    }

    #[test]
    fn rules_do_not_override_stronger_builtin_evidence() {
        let rules = rule(
            r#"
[[rule]]
name = "weak iot"
device_type = "iot"
confidence = "low"
any_ports = [80]
"#,
        );
        let mut device = device_with_ports(&[80]);
        device.device_type = DeviceType::Router;
        let now = Utc::now();
        device.add_evidence(Evidence::inferred(
            "device_type",
            "router",
            "gateway",
            Confidence::High,
            EvidenceKind::DirectObservation,
            now,
        ));
        apply(&mut device, &rules.rules, now, &[], &[]);
        assert_eq!(device.device_type, DeviceType::Router);
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.value == "iot"));
    }

    #[test]
    fn matches_mdns_and_ssdp_conditions() {
        let rules = rule(
            r#"
[[rule]]
name = "apple tv"
device_type = "smart_tv"
mdns_service_contains = ["_airplay"]
ssdp_type_contains = ["MediaRenderer"]
"#,
        );
        let mut device = device_with_ports(&[]);
        apply(
            &mut device,
            &rules.rules,
            Utc::now(),
            &["_airplay._tcp.local".to_string()],
            &["urn:schemas-upnp-org:device:MediaRenderer:1".to_string()],
        );
        assert_eq!(device.device_type, DeviceType::SmartTv);
    }

    #[test]
    fn missing_rule_file_is_empty() {
        let rules = RuleSet::load_optional(Path::new("/nonexistent/findarat-rules.toml")).unwrap();
        assert!(rules.rules.is_empty());
    }
}
