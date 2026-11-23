//! Import hosts from `arp-scan` plain-text output.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use crate::models::{Confidence, Device, Evidence, Observation};
use crate::network::interface::normalise_mac;

use super::export::ExportEnvelope;

pub fn read_arpscan(path: &Path) -> Result<ExportEnvelope> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read arp-scan output {}", path.display()))?;
    let observed_at = file_time(path);
    let mut devices = Vec::new();
    let mut seen = HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("Interface:")
            || line.starts_with("Starting")
            || line.starts_with("Ending")
        {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(mac) = normalise_mac(fields[1]) else {
            continue;
        };
        if !seen.insert((ip, mac.clone())) {
            continue;
        }
        let vendor = fields[2..].join(" ");
        let vendor = if vendor.is_empty()
            || vendor.starts_with("(Unknown)")
            || vendor.starts_with("(DUP:")
        {
            None
        } else {
            Some(vendor)
        };

        let mut device = Device::new(observed_at, observed_at);
        device.last_ip = Some(ip);
        device.mac = Some(mac.clone());
        device.vendor = vendor.clone();
        device.add_evidence(Evidence::direct(
            "ip",
            ip.to_string(),
            "arp-scan",
            observed_at,
        ));
        device.add_evidence(Evidence::direct(
            "mac",
            mac.clone(),
            "arp-scan",
            observed_at,
        ));
        if let Some(vendor) = &vendor {
            device.add_evidence(Evidence::inferred(
                "vendor",
                vendor.clone(),
                "arp-scan",
                Confidence::Medium,
                crate::models::EvidenceKind::DatabaseInference,
                observed_at,
            ));
        }
        let mut observation = Observation::new(observed_at, "arp-scan");
        observation.ip = Some(ip);
        observation.mac = Some(mac);
        device.observations.push(observation);
        devices.push(device);
    }

    Ok(ExportEnvelope::new(devices, Vec::new(), Vec::new()))
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

    const SAMPLE: &str = "\
Interface: wlan0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.1.10
Starting arp-scan 1.10.0 with 254 hosts
192.168.1.1\taa:bb:cc:11:22:33\tExample Router
192.168.1.20\tAA:BB:CC:DD:EE:01\tExample Vendor, Inc.
192.168.1.21\tAA:BB:CC:DD:EE:02\t(Unknown)
192.168.1.20\tAA:BB:CC:DD:EE:01\tExample Vendor, Inc.
Ending arp-scan 1.10.0: 254 hosts scanned in 2.3 seconds
";

    #[test]
    fn parses_hosts_and_skips_headers_duplicates_and_unknown_vendors() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("scan.txt");
        fs::write(&path, SAMPLE).unwrap();
        let envelope = read_arpscan(&path).unwrap();
        assert_eq!(envelope.devices.len(), 3);
        assert_eq!(
            envelope.devices[0].last_ip.unwrap().to_string(),
            "192.168.1.1"
        );
        assert_eq!(
            envelope.devices[0].vendor.as_deref(),
            Some("Example Router")
        );
        assert_eq!(
            envelope.devices[1].vendor.as_deref(),
            Some("Example Vendor, Inc.")
        );
        assert!(envelope.devices[2].vendor.is_none());
    }
}
