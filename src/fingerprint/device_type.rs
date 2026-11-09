//! Evidence-based device-type inference.

use crate::models::{Confidence, DeviceType};

use super::hostname::hostname_hints;

#[derive(Debug, Clone)]
pub struct TypeInput<'a> {
    pub hostname: Option<&'a str>,
    pub vendor: Option<&'a str>,
    pub ports: &'a [u16],
    pub mdns_services: &'a [String],
    pub ssdp_device_types: &'a [String],
    pub ssdp_manufacturer: Option<&'a str>,
    pub ssdp_model: Option<&'a str>,
    pub is_gateway: bool,
    pub netbios_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFinding {
    pub device_type: DeviceType,
    pub confidence: Confidence,
    pub source: &'static str,
    pub reason: String,
}

fn has_port(ports: &[u16], port: u16) -> bool {
    ports.contains(&port)
}

fn has_service(services: &[String], needle: &str) -> bool {
    services
        .iter()
        .any(|service| service.to_ascii_lowercase().contains(needle))
}

fn vendor_matches(vendor: &str, needles: &[&str]) -> bool {
    let lower = vendor.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

/// Produce every plausible device-type finding, strongest first.
pub fn infer_types(input: &TypeInput<'_>) -> Vec<TypeFinding> {
    let mut findings = Vec::new();
    let mut push = |device_type, confidence, source, reason: &str| {
        findings.push(TypeFinding {
            device_type,
            confidence,
            source,
            reason: reason.to_string(),
        });
    };

    if input.is_gateway {
        push(
            DeviceType::Router,
            Confidence::High,
            "network",
            "address is the IPv4 default gateway",
        );
    }

    if input
        .ssdp_device_types
        .iter()
        .any(|kind| kind.to_ascii_lowercase().contains("internetgatewaydevice"))
    {
        push(
            DeviceType::Router,
            Confidence::High,
            "ssdp",
            "UPnP advertises InternetGatewayDevice",
        );
    }
    if input
        .ssdp_device_types
        .iter()
        .any(|kind| kind.to_ascii_lowercase().contains("mediarenderer"))
        || has_service(input.mdns_services, "_airplay._tcp")
        || has_service(input.mdns_services, "_raop._tcp")
        || has_service(input.mdns_services, "_googlecast._tcp")
    {
        push(
            DeviceType::SmartTv,
            Confidence::Medium,
            "mdns/ssdp",
            "media-rendering or casting service advertised",
        );
    }

    if has_service(input.mdns_services, "_ipp._tcp")
        || has_service(input.mdns_services, "_printer._tcp")
        || has_service(input.mdns_services, "_pdl-datastream._tcp")
        || has_port(input.ports, 631)
        || has_port(input.ports, 9100)
        || has_port(input.ports, 515)
    {
        push(
            DeviceType::Printer,
            Confidence::High,
            "ports/mdns",
            "printer service or printing port observed",
        );
    }

    if let Some(hostname) = input.hostname {
        for hint in hostname_hints(hostname) {
            push(hint.device_type, hint.confidence, "hostname", &hint.reason);
        }
    }

    if let Some(vendor) = input.vendor {
        if vendor_matches(vendor, &["espressif"]) {
            push(
                DeviceType::Iot,
                Confidence::Medium,
                "oui",
                "OUI is registered to Espressif, a common IoT radio vendor",
            );
        } else if vendor_matches(vendor, &["raspberry pi"]) {
            push(
                DeviceType::Iot,
                Confidence::Low,
                "oui",
                "OUI is registered to Raspberry Pi Foundation",
            );
        } else if vendor_matches(
            vendor,
            &[
                "mikrotik", "ubiquiti", "tp-link", "netgear", "d-link", "cisco", "aruba",
                "juniper", "zyxel", "avm gmbh",
            ],
        ) {
            push(
                DeviceType::Router,
                Confidence::Low,
                "oui",
                "OUI is registered to a networking equipment vendor",
            );
        } else if vendor_matches(vendor, &["roku", "sonos"]) {
            push(
                DeviceType::SmartTv,
                Confidence::Medium,
                "oui",
                "OUI is registered to a media-device vendor",
            );
        } else if vendor_matches(vendor, &["synology", "qnap"]) {
            push(
                DeviceType::Server,
                Confidence::Medium,
                "oui",
                "OUI is registered to a NAS vendor",
            );
        } else if vendor_matches(
            vendor,
            &["hewlett packard", "brother", "canon", "epson", "xerox"],
        ) {
            push(
                DeviceType::Printer,
                Confidence::Low,
                "oui",
                "OUI is registered to a printer vendor",
            );
        }
    }

    if let Some(model) = input.ssdp_model {
        let lower = model.to_ascii_lowercase();
        if lower.contains("printer") {
            push(
                DeviceType::Printer,
                Confidence::Medium,
                "ssdp",
                "UPnP model name mentions a printer",
            );
        } else if lower.contains("tv") || lower.contains("roku") {
            push(
                DeviceType::SmartTv,
                Confidence::Medium,
                "ssdp",
                "UPnP model name mentions a television",
            );
        }
    }
    if let Some(manufacturer) = input.ssdp_manufacturer {
        if vendor_matches(manufacturer, &["roku", "sonos"]) {
            push(
                DeviceType::SmartTv,
                Confidence::Medium,
                "ssdp",
                "UPnP manufacturer is a media-device vendor",
            );
        }
    }

    let server_ports = [3306u16, 5432, 6379, 2049]
        .iter()
        .filter(|port| has_port(input.ports, **port))
        .count();
    if server_ports >= 1 || (has_port(input.ports, 22) && has_port(input.ports, 80)) {
        push(
            DeviceType::Server,
            Confidence::Low,
            "ports",
            "service ports commonly exposed by servers were observed",
        );
    }

    if input.netbios_present && (has_port(input.ports, 445) || has_port(input.ports, 139)) {
        push(
            DeviceType::Desktop,
            Confidence::Low,
            "netbios/ports",
            "NetBIOS name and SMB ports observed; could be a Windows or Samba host",
        );
    }

    findings.sort_by(|a, b| {
        b.confidence
            .rank()
            .cmp(&a.confidence.rank())
            .then_with(|| priority(b.device_type).cmp(&priority(a.device_type)))
    });
    findings
}

pub fn best(finding: &[TypeFinding]) -> Option<&TypeFinding> {
    finding.first()
}

fn priority(device_type: DeviceType) -> u8 {
    match device_type {
        DeviceType::Router => 9,
        DeviceType::AccessPoint => 8,
        DeviceType::Printer => 7,
        DeviceType::SmartTv => 6,
        DeviceType::Server => 5,
        DeviceType::Smartphone => 4,
        DeviceType::Laptop => 3,
        DeviceType::Desktop => 2,
        DeviceType::Iot => 1,
        DeviceType::Unknown => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input<'a>() -> TypeInput<'a> {
        TypeInput {
            hostname: None,
            vendor: None,
            ports: &[],
            mdns_services: &[],
            ssdp_device_types: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            is_gateway: false,
            netbios_present: false,
        }
    }

    #[test]
    fn gateway_is_router_with_high_confidence() {
        let mut input = base_input();
        input.is_gateway = true;
        let findings = infer_types(&input);
        let best = best(&findings).unwrap();
        assert_eq!(best.device_type, DeviceType::Router);
        assert_eq!(best.confidence, Confidence::High);
    }

    #[test]
    fn printer_port_is_strong_evidence() {
        let ports = [631u16];
        let mut input = base_input();
        input.ports = &ports;
        let findings = infer_types(&input);
        let best = best(&findings).unwrap();
        assert_eq!(best.device_type, DeviceType::Printer);
        assert_eq!(best.confidence, Confidence::High);
    }

    #[test]
    fn hostname_hint_is_recorded() {
        let mut input = base_input();
        input.hostname = Some("fritzbox-7530");
        let findings = infer_types(&input);
        assert!(findings
            .iter()
            .any(|finding| finding.device_type == DeviceType::Router));
    }

    #[test]
    fn unknown_device_produces_no_finding() {
        let input = base_input();
        assert!(infer_types(&input).is_empty());
    }
}
