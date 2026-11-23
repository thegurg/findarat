//! Import hosts from Nmap XML output.
//!
//! Only ordinary scan results are read: addresses, hostnames, open ports,
//! service guesses, and OS matches. No scripts are executed and no network
//! traffic is generated.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use crate::models::{
    Confidence, Device, DeviceType, Evidence, EvidenceKind, Identifier, IdentifierKind,
    Observation, PortObservation, PortState, Protocol, ServiceObservation,
};
use crate::network::interface::normalise_mac;

use super::export::ExportEnvelope;

#[derive(Debug, Default)]
struct HostBuilder {
    ip: Option<IpAddr>,
    extra_ips: Vec<IpAddr>,
    mac: Option<String>,
    mac_vendor: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    os_vendor: Option<String>,
    device_type: Option<DeviceType>,
    ports: Vec<PendingPort>,
    up: bool,
}

#[derive(Debug)]
struct PendingPort {
    port: u16,
    protocol: Protocol,
    state: PortState,
    service: Option<String>,
    version: Option<String>,
}

pub fn read_nmap(path: &Path) -> Result<ExportEnvelope> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read Nmap XML {}", path.display()))?;
    let fallback_time = file_time(path);
    let mut reader = Reader::from_str(&content);
    reader.config_mut().trim_text(true);

    let mut observed_at = fallback_time;
    let mut builder = HostBuilder::default();
    let mut current_port: Option<PendingPort> = None;
    let mut devices = Vec::new();

    loop {
        let event = reader
            .read_event()
            .with_context(|| format!("invalid XML in {}", path.display()))?;
        match event {
            Event::Start(event) | Event::Empty(event) => match event.name().as_ref() {
                "nmaprun" => {
                    if let Some(start) = attribute(&event, "start")
                        .and_then(|value| value.parse::<i64>().ok())
                        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
                    {
                        observed_at = start;
                    }
                }
                "host" => {
                    builder = HostBuilder::default();
                    current_port = None;
                }
                "status" => {
                    if attribute(&event, "state").as_deref() == Some("up") {
                        builder.up = true;
                    }
                }
                "address" => {
                    let addr = attribute(&event, "addr");
                    match attribute(&event, "addrtype").as_deref() {
                        Some("ipv4") | Some("ipv6") => {
                            if let Some(ip) = addr.and_then(|value| value.parse::<IpAddr>().ok()) {
                                match builder.ip {
                                    None => builder.ip = Some(ip),
                                    Some(existing) if existing == ip => {}
                                    Some(existing) if ip.is_ipv4() && existing.is_ipv6() => {
                                        builder.extra_ips.push(existing);
                                        builder.ip = Some(ip);
                                    }
                                    Some(_) => builder.extra_ips.push(ip),
                                }
                            }
                        }
                        Some("mac") => {
                            builder.mac = addr.as_deref().and_then(normalise_mac);
                            builder.mac_vendor = attribute(&event, "vendor");
                        }
                        _ => {}
                    }
                }
                "hostname" => {
                    if builder.hostname.is_none() {
                        builder.hostname = attribute(&event, "name");
                    }
                }
                "port" => {
                    let port =
                        attribute(&event, "portid").and_then(|value| value.parse::<u16>().ok());
                    let protocol = attribute(&event, "protocol")
                        .and_then(|value| value.parse::<Protocol>().ok())
                        .unwrap_or(Protocol::Tcp);
                    if let Some(port) = port {
                        current_port = Some(PendingPort {
                            port,
                            protocol,
                            state: PortState::Open,
                            service: None,
                            version: None,
                        });
                    }
                }
                "state" if current_port.is_some() => {
                    if let Some(port) = current_port.as_mut() {
                        port.state = attribute(&event, "state")
                            .and_then(|value| value.parse::<PortState>().ok())
                            .unwrap_or(PortState::Open);
                    }
                }
                "service" if current_port.is_some() => {
                    if let Some(port) = current_port.as_mut() {
                        port.service = attribute(&event, "name");
                        let product = attribute(&event, "product");
                        let version = attribute(&event, "version");
                        port.version = match (product, version) {
                            (Some(product), Some(version)) => Some(format!("{product} {version}")),
                            (Some(product), None) => Some(product),
                            (None, Some(version)) => Some(version),
                            (None, None) => None,
                        };
                        if builder.device_type.is_none() {
                            builder.device_type = attribute(&event, "devicetype")
                                .as_deref()
                                .and_then(map_device_type);
                        }
                    }
                }
                "osmatch" => {
                    if builder.os.is_none() {
                        builder.os = attribute(&event, "name");
                    }
                }
                "osclass" => {
                    if builder.os.is_none() {
                        builder.os =
                            match (attribute(&event, "osfamily"), attribute(&event, "osgen")) {
                                (Some(family), Some(generation)) => {
                                    Some(format!("{family} {generation}"))
                                }
                                (Some(family), None) => Some(family),
                                _ => None,
                            };
                    }
                    if builder.os_vendor.is_none() {
                        builder.os_vendor = attribute(&event, "vendor");
                    }
                    if builder.device_type.is_none() {
                        builder.device_type = attribute(&event, "type")
                            .as_deref()
                            .and_then(map_device_type);
                    }
                }
                _ => {}
            },
            Event::End(event) => match event.name().as_ref() {
                "port" => {
                    if let Some(port) = current_port.take() {
                        builder.ports.push(port);
                    }
                }
                "host" => {
                    if builder.up {
                        if let Some(device) = finalize(std::mem::take(&mut builder), observed_at) {
                            devices.push(device);
                        }
                    }
                    builder = HostBuilder::default();
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(ExportEnvelope::new(devices, Vec::new(), Vec::new()))
}

fn finalize(builder: HostBuilder, observed_at: DateTime<Utc>) -> Option<Device> {
    let ip = builder.ip?;
    let mut device = Device::new(observed_at, observed_at);
    device.last_ip = Some(ip);
    device.mac = builder.mac.clone();
    device.hostname = builder.hostname.clone();
    device.vendor = builder.mac_vendor.clone().or(builder.os_vendor.clone());
    device.os = builder.os.clone();
    if let Some(device_type) = builder.device_type {
        device.device_type = device_type;
    }

    device.add_evidence(Evidence::direct("ip", ip.to_string(), "nmap", observed_at));
    if let Some(mac) = &builder.mac {
        device.add_evidence(Evidence::direct("mac", mac.clone(), "nmap", observed_at));
    }
    if let Some(hostname) = &builder.hostname {
        device.add_evidence(Evidence::direct(
            "hostname",
            hostname.clone(),
            "nmap",
            observed_at,
        ));
    }
    if let Some(vendor) = &builder.mac_vendor {
        device.add_evidence(Evidence::inferred(
            "vendor",
            vendor.clone(),
            "nmap",
            Confidence::Medium,
            EvidenceKind::DatabaseInference,
            observed_at,
        ));
    }
    if let Some(os) = &builder.os {
        device.add_evidence(Evidence::inferred(
            "operating_system",
            os.clone(),
            "nmap",
            Confidence::Medium,
            EvidenceKind::ProbabilisticInference,
            observed_at,
        ));
    }
    if let Some(device_type) = builder.device_type {
        device.add_evidence(Evidence::inferred(
            "device_type",
            device_type.as_str(),
            "nmap",
            Confidence::Low,
            EvidenceKind::ProbabilisticInference,
            observed_at,
        ));
    }

    let mut seen_ports = HashSet::new();
    for pending in builder.ports {
        if pending.state != PortState::Open || !seen_ports.insert((pending.port, pending.protocol))
        {
            continue;
        }
        let mut port = PortObservation::open(ip, pending.port, observed_at);
        port.protocol = pending.protocol;
        port.service = pending.service.clone();
        port.version = pending.version.clone();
        device.ports.push(port);
        device.add_evidence(Evidence::direct(
            "open_port",
            format!("{}/{}", pending.protocol, pending.port),
            "nmap",
            observed_at,
        ));
        if let Some(service) = &pending.service {
            device.add_evidence(Evidence::inferred(
                "service",
                service.clone(),
                "nmap",
                Confidence::Medium,
                EvidenceKind::ProbabilisticInference,
                observed_at,
            ));
            let mut observation = ServiceObservation::new(
                service.clone(),
                Some(pending.port),
                pending.protocol,
                "nmap",
                observed_at,
            );
            observation.version = pending.version;
            device.services.push(observation);
        }
    }

    for extra in builder.extra_ips {
        device.identifiers.push(Identifier::new(
            IdentifierKind::Ip,
            extra.to_string(),
            Confidence::High,
            observed_at,
            observed_at,
        ));
    }

    let mut observation = Observation::new(observed_at, "nmap");
    observation.ip = Some(ip);
    observation.mac = device.mac.clone();
    observation.hostname = device.hostname.clone();
    observation.details = Some(serde_json::json!({
        "open_ports": device.ports.iter().map(|port| format!("{}/{}", port.protocol, port.port)).collect::<Vec<_>>(),
        "os": device.os.clone(),
    }));
    device.observations.push(observation);

    Some(device)
}

fn map_device_type(value: &str) -> Option<DeviceType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "router" => Some(DeviceType::Router),
        "wap" | "access point" | "wireless access point" => Some(DeviceType::AccessPoint),
        "printer" => Some(DeviceType::Printer),
        "phone" | "smartphone" => Some(DeviceType::Smartphone),
        "media device" | "smart tv" | "tv" => Some(DeviceType::SmartTv),
        "webcam" | "camera" => Some(DeviceType::Iot),
        _ => None,
    }
}

fn attribute(event: &BytesStart<'_>, key: &str) -> Option<String> {
    event
        .attributes()
        .flatten()
        .find(|attribute| attribute.key.as_ref() == key)
        .and_then(|attribute| {
            attribute
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()
        })
        .map(|value| value.into_owned())
}

fn file_time(path: &Path) -> DateTime<Utc> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun start="1700000000">
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Example Vendor"/>
    <hostname name="printer.local" type="PTR"/>
    <ports>
      <port protocol="tcp" portid="631">
        <state state="open"/>
        <service name="ipp" product="CUPS" version="2.4" devicetype="printer"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.0"/>
      <osclass type="printer" osfamily="Linux" vendor="Linux"/>
    </os>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.21" addrtype="ipv4"/>
  </host>
</nmaprun>
"#;

    #[test]
    fn parses_open_hosts_ports_and_services() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("scan.xml");
        fs::write(&path, SAMPLE).unwrap();
        let envelope = read_nmap(&path).unwrap();
        assert_eq!(envelope.devices.len(), 1);
        let device = &envelope.devices[0];
        assert_eq!(device.last_ip.unwrap().to_string(), "192.168.1.20");
        assert_eq!(device.mac.as_deref(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(device.hostname.as_deref(), Some("printer.local"));
        assert_eq!(device.vendor.as_deref(), Some("Example Vendor"));
        assert_eq!(device.device_type, DeviceType::Printer);
        assert_eq!(device.ports.len(), 1);
        assert_eq!(device.ports[0].port, 631);
        assert_eq!(device.ports[0].service.as_deref(), Some("ipp"));
        assert_eq!(device.services.len(), 1);
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.property == "operating_system"));
        assert_eq!(device.last_seen.timestamp(), 1_700_000_000);
    }
}
