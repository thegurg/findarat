//! Fingerprinting orchestration.
//!
//! Discovery supplies observations; this module turns them into inferred
//! properties. Every inference is recorded as evidence with its source and
//! confidence. Direct observations are never overwritten by guesses.

pub mod device_type;
pub mod hostname;
pub mod os;
pub mod oui;
pub mod services;

use chrono::{DateTime, Utc};

use crate::models::{Confidence, Device, Evidence, EvidenceKind, ServiceObservation};

#[derive(Debug, Clone)]
pub struct FingerprintInput<'a> {
    pub observed_at: DateTime<Utc>,
    pub is_gateway: bool,
    pub services: &'a [ServiceObservation],
    pub ssdp_device_types: &'a [String],
    pub ssdp_manufacturer: Option<&'a str>,
    pub ssdp_model: Option<&'a str>,
    pub netbios_present: bool,
}

/// Apply all available fingerprinting rules to a device.
pub fn apply(device: &mut Device, input: &FingerprintInput<'_>) {
    apply_vendor(device, input.observed_at);
    apply_hostname(device, input.observed_at);

    for service in input.services {
        add_service(device, service.clone());
        device.add_evidence(Evidence::inferred(
            "service",
            service.name.clone(),
            service.source.clone(),
            Confidence::High,
            EvidenceKind::DirectObservation,
            input.observed_at,
        ));
    }

    for port in device.ports.clone() {
        device.add_evidence(Evidence::inferred(
            "open_port",
            format!("tcp/{}", port.port),
            "tcp_scan",
            Confidence::High,
            EvidenceKind::DirectObservation,
            input.observed_at,
        ));
        if let Some(service) = &port.service {
            device.add_evidence(Evidence::inferred(
                "service",
                service.clone(),
                "tcp_scan",
                port.confidence,
                EvidenceKind::ProbabilisticInference,
                input.observed_at,
            ));
            let mut claim = ServiceObservation::new(
                service.clone(),
                Some(port.port),
                port.protocol,
                "tcp_scan",
                input.observed_at,
            );
            claim.version = port.version.clone();
            add_service(device, claim);
        }
    }

    let service_names: Vec<String> = device
        .services
        .iter()
        .map(|service| service.name.clone())
        .chain(input.ssdp_device_types.iter().cloned())
        .collect();
    let ports: Vec<u16> = device.ports.iter().map(|port| port.port).collect();

    let type_input = device_type::TypeInput {
        hostname: device.hostname.as_deref(),
        vendor: device.vendor.as_deref(),
        ports: &ports,
        mdns_services: &service_names,
        ssdp_device_types: input.ssdp_device_types,
        ssdp_manufacturer: input.ssdp_manufacturer,
        ssdp_model: input.ssdp_model,
        is_gateway: input.is_gateway,
        netbios_present: input.netbios_present,
    };
    let type_findings = device_type::infer_types(&type_input);
    for finding in &type_findings {
        let kind = if finding.source == "oui" {
            EvidenceKind::DatabaseInference
        } else {
            EvidenceKind::ProbabilisticInference
        };
        device.add_evidence(Evidence::inferred(
            "device_type",
            finding.device_type.as_str(),
            finding.source,
            finding.confidence,
            kind,
            input.observed_at,
        ));
    }
    if let Some(best) = device_type::best(&type_findings) {
        device.device_type = best.device_type;
    }

    let ssh_banners: Vec<String> = device
        .ports
        .iter()
        .filter(|port| port.service.as_deref() == Some("ssh"))
        .filter_map(|port| port.version.clone())
        .collect();
    let http_servers: Vec<String> = device
        .ports
        .iter()
        .filter(|port| {
            matches!(
                port.service.as_deref(),
                Some("http") | Some("http-alt") | Some("https") | Some("https-alt")
            )
        })
        .filter_map(|port| port.version.clone())
        .collect();
    let os_input = os::OsInput {
        hostname: device.hostname.as_deref(),
        ssh_banners: &ssh_banners,
        http_servers: &http_servers,
        ssdp_manufacturer: input.ssdp_manufacturer,
        ssdp_model: input.ssdp_model,
        netbios_present: input.netbios_present,
    };
    let os_findings = os::infer_os(&os_input);
    for finding in &os_findings {
        device.add_evidence(Evidence::inferred(
            "operating_system",
            finding.os,
            finding.source,
            finding.confidence,
            EvidenceKind::ProbabilisticInference,
            input.observed_at,
        ));
    }
    if let Some(best) = os::best(&os_findings) {
        let existing = device.property_confidence("operating_system");
        if device.os.is_none()
            || existing
                .map(|confidence| best.confidence.rank() >= confidence.rank())
                .unwrap_or(true)
        {
            device.os = Some(best.os.to_string());
        }
    }
}

fn apply_vendor(device: &mut Device, observed_at: DateTime<Utc>) {
    let Some(mac) = device.mac.as_deref() else {
        return;
    };
    if crate::network::interface::is_locally_administered(mac) {
        device.add_evidence(
            Evidence::inferred(
                "vendor",
                "unknown",
                "oui",
                Confidence::Unknown,
                EvidenceKind::DatabaseInference,
                observed_at,
            )
            .with_note(
                "MAC address is locally administered (possibly randomised); OUI lookup is not reliable",
            ),
        );
        return;
    }
    let Some(found) = oui::lookup(mac) else {
        return;
    };
    device.add_evidence(
        Evidence::inferred(
            "vendor",
            found.vendor,
            "oui",
            Confidence::Medium,
            EvidenceKind::DatabaseInference,
            observed_at,
        )
        .with_note(
            "OUI identifies the organisation that registered the network-interface prefix, not the device model or owner",
        ),
    );
    if device.vendor.is_none() {
        device.vendor = Some(found.vendor.to_string());
    }
}

fn apply_hostname(device: &mut Device, observed_at: DateTime<Utc>) {
    if let Some(hostname) = &device.hostname {
        device.add_evidence(
            Evidence::inferred(
                "hostname",
                hostname.clone(),
                "discovery",
                Confidence::Medium,
                EvidenceKind::DirectObservation,
                observed_at,
            )
            .with_note("advertised or resolved name; not a verified device identity"),
        );
    }
}

fn add_service(device: &mut Device, service: ServiceObservation) {
    let exists = device.services.iter().any(|existing| {
        existing.name == service.name
            && existing.port == service.port
            && existing.source == service.source
    });
    if exists {
        if let Some(existing) = device.services.iter_mut().find(|existing| {
            existing.name == service.name
                && existing.port == service.port
                && existing.source == service.source
        }) {
            existing.last_seen = existing.last_seen.max(service.last_seen);
            existing.first_seen = existing.first_seen.min(service.first_seen);
            if existing.version.is_none() {
                existing.version = service.version;
            }
        }
    } else {
        device.services.push(service);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DeviceType, PortObservation, Protocol};

    #[test]
    fn vendor_lookup_records_interface_vendor_not_device_identity() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.mac = Some("B8:27:EB:12:34:56".to_string());
        let input = FingerprintInput {
            observed_at: now,
            is_gateway: false,
            services: &[],
            ssdp_device_types: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        apply(&mut device, &input);
        assert!(device.vendor.as_deref().unwrap().contains("Raspberry Pi"));
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.property == "vendor" && evidence.note.is_some()));
    }

    #[test]
    fn randomised_mac_does_not_claim_a_vendor() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        device.mac = Some("02:11:22:33:44:55".to_string());
        let input = FingerprintInput {
            observed_at: now,
            is_gateway: false,
            services: &[],
            ssdp_device_types: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        apply(&mut device, &input);
        assert!(device.vendor.is_none());
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.property == "vendor"
                && evidence.confidence == Confidence::Unknown));
    }

    #[test]
    fn printer_port_sets_device_type_with_evidence() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        let mut port = PortObservation::open("192.168.1.20".parse().unwrap(), 631, now);
        port.service = Some("ipp".to_string());
        port.confidence = Confidence::Medium;
        device.ports.push(port);
        let input = FingerprintInput {
            observed_at: now,
            is_gateway: false,
            services: &[],
            ssdp_device_types: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        apply(&mut device, &input);
        assert_eq!(device.device_type, DeviceType::Printer);
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.property == "device_type" && evidence.value == "printer"));
    }

    #[test]
    fn services_are_deduplicated() {
        let now = Utc::now();
        let mut device = Device::new(now, now);
        let service = ServiceObservation::new("ssh", Some(22), Protocol::Tcp, "mdns", now);
        let services = vec![service.clone(), service];
        let input = FingerprintInput {
            observed_at: now,
            is_gateway: false,
            services: &services,
            ssdp_device_types: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        apply(&mut device, &input);
        assert_eq!(device.services.len(), 1);
    }
}
