//! NetBIOS name-service (NBNS) discovery.
//!
//! A node-status query is broadcast to UDP port 137. Responders reveal their
//! NetBIOS names, workgroup, and sometimes their adapter MAC address. NetBIOS
//! is often disabled on modern networks, so absence of responses is normal.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::models::{Confidence, Evidence, EvidenceKind};
use crate::network::interface::normalise_mac;

use super::dns::read_name;
use super::{DiscoveredHost, DiscoveryContext, DiscoveryProvider, ProviderOutput};

const NBNS_PORT: u16 = 137;
const NBSTAT_TYPE: u16 = 0x0021;
const CLASS_IN: u16 = 0x0001;

pub struct NetbiosDiscovery;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbnsName {
    pub name: String,
    pub suffix: u8,
    pub group: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbnsResponse {
    pub names: Vec<NbnsName>,
    pub mac: Option<String>,
}

/// Build an NBNS node-status query for the wildcard name `*`.
pub fn build_node_status_query(id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // flags: query
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    packet.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                                   // NetBIOS name "*" padded to 16 bytes, first-level encoded.
    packet.push(0x20);
    packet.extend_from_slice(b"CK");
    packet.extend_from_slice(&[b'A'; 30]);
    packet.push(0);
    packet.extend_from_slice(&NBSTAT_TYPE.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    packet
}

/// Parse an NBNS node-status response.
pub fn parse_node_status_response(data: &[u8]) -> Result<NbnsResponse, String> {
    if data.len() < 12 {
        return Err("NBNS response is truncated".into());
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return Err("not an NBNS response".into());
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut position = 12usize;

    for _ in 0..qdcount {
        let (_, next) = read_name(data, position).map_err(|error| error.to_string())?;
        position = next + 4;
        if position > data.len() {
            return Err("NBNS question is truncated".into());
        }
    }

    let mut names = Vec::new();
    let mut mac = None;
    for _ in 0..ancount {
        let (_, next) = read_name(data, position).map_err(|error| error.to_string())?;
        position = next;
        if position + 10 > data.len() {
            return Err("NBNS answer is truncated".into());
        }
        let record_type = u16::from_be_bytes([data[position], data[position + 1]]);
        let rdlength = u16::from_be_bytes([data[position + 8], data[position + 9]]) as usize;
        position += 10;
        if position + rdlength > data.len() {
            return Err("NBNS rdata is truncated".into());
        }
        let rdata = &data[position..position + rdlength];
        if record_type == NBSTAT_TYPE && !rdata.is_empty() {
            let count = rdata[0] as usize;
            let names_end = 1 + count.saturating_mul(18);
            if names_end > rdata.len() {
                return Err("NBNS name table is truncated".into());
            }
            for index in 0..count {
                let start = 1 + index * 18;
                let raw_name = &rdata[start..start + 15];
                let suffix = rdata[start + 15];
                let group = rdata[start + 16] & 0x80 != 0;
                let name = String::from_utf8_lossy(raw_name)
                    .trim_matches(|c: char| c == '\0' || c == ' ')
                    .to_string();
                if !name.is_empty() {
                    names.push(NbnsName {
                        name,
                        suffix,
                        group,
                    });
                }
            }
            if rdata.len() >= names_end + 6 {
                mac = normalise_mac(&format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    rdata[names_end],
                    rdata[names_end + 1],
                    rdata[names_end + 2],
                    rdata[names_end + 3],
                    rdata[names_end + 4],
                    rdata[names_end + 5]
                ));
            }
        }
        position += rdlength;
    }

    if names.is_empty() {
        return Err("NBNS response contains no names".into());
    }
    Ok(NbnsResponse { names, mac })
}

fn workgroup(names: &[NbnsName]) -> Option<&str> {
    names
        .iter()
        .find(|name| name.suffix == 0x1C)
        .map(|name| name.name.as_str())
}

fn hostname(names: &[NbnsName]) -> Option<&str> {
    let workgroup = workgroup(names);
    names
        .iter()
        .find(|name| name.suffix == 0x00 && Some(name.name.as_str()) != workgroup && !name.group)
        .or_else(|| names.iter().find(|name| name.suffix == 0x20))
        .map(|name| name.name.as_str())
}

#[async_trait]
impl DiscoveryProvider for NetbiosDiscovery {
    fn name(&self) -> &'static str {
        "netbios"
    }

    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput> {
        let subnet = context
            .subnet
            .ok_or_else(|| anyhow::anyhow!("NetBIOS discovery requires an IPv4 subnet"))?;
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| anyhow::anyhow!("failed to open NetBIOS socket: {error}"))?;
        socket
            .set_broadcast(true)
            .map_err(|error| anyhow::anyhow!("failed to enable broadcast: {error}"))?;

        let id = (std::process::id() & 0xFFFF) as u16;
        let query = build_node_status_query(id);
        let destination = SocketAddr::from((subnet.broadcast(), NBNS_PORT));
        socket
            .send_to(&query, destination)
            .await
            .map_err(|error| anyhow::anyhow!("failed to send NetBIOS query: {error}"))?;

        let deadline = Instant::now() + Duration::from_millis(1200);
        let mut buffer = [0u8; 2048];
        let mut hosts: Vec<DiscoveredHost> = Vec::new();
        let mut seen: BTreeSet<(Ipv4Addr, String)> = BTreeSet::new();

        while Instant::now() < deadline {
            let wait = deadline.saturating_duration_since(Instant::now());
            match timeout(wait, socket.recv_from(&mut buffer)).await {
                Ok(Ok((length, source))) => {
                    let IpAddr::V4(source_ip) = source.ip() else {
                        continue;
                    };
                    if !subnet.contains(source_ip) {
                        continue;
                    }
                    let Ok(response) = parse_node_status_response(&buffer[..length]) else {
                        continue;
                    };
                    let Some(hostname) = hostname(&response.names).map(str::to_string) else {
                        continue;
                    };
                    if !seen.insert((source_ip, hostname.clone())) {
                        continue;
                    }
                    let mut host = DiscoveredHost::new(
                        Some(IpAddr::V4(source_ip)),
                        context.interface.name.clone(),
                        "netbios",
                    );
                    host.mac = response.mac.clone();
                    host.hostname = Some(hostname.clone());
                    host.netbios_names = response
                        .names
                        .iter()
                        .map(|name| name.name.clone())
                        .collect();
                    host.netbios_workgroup = workgroup(&response.names).map(str::to_string);
                    host.add_evidence(Evidence::direct(
                        "ip",
                        source_ip.to_string(),
                        "netbios",
                        Utc::now(),
                    ));
                    host.add_evidence(
                        Evidence::inferred(
                            "hostname",
                            hostname,
                            "netbios",
                            Confidence::Medium,
                            EvidenceKind::DirectObservation,
                            Utc::now(),
                        )
                        .with_note("NetBIOS name; self-reported by the device"),
                    );
                    if let Some(mac) = &response.mac {
                        host.add_evidence(Evidence::direct(
                            "mac",
                            mac.clone(),
                            "netbios",
                            Utc::now(),
                        ));
                    }
                    if let Some(workgroup) = &host.netbios_workgroup {
                        host.add_evidence(Evidence::inferred(
                            "netbios_workgroup",
                            workgroup.clone(),
                            "netbios",
                            Confidence::High,
                            EvidenceKind::DirectObservation,
                            Utc::now(),
                        ));
                    }
                    host.details = serde_json::json!({
                        "netbios_names": response.names.iter().map(|name| {
                            serde_json::json!({
                                "name": name.name,
                                "suffix": name.suffix,
                                "group": name.group,
                            })
                        }).collect::<Vec<_>>(),
                    });
                    hosts.push(host);
                }
                Ok(Err(error)) => {
                    tracing::debug!(%error, "NetBIOS receive failed");
                    break;
                }
                Err(_) => {}
            }
        }

        let note = if hosts.is_empty() {
            Some("no NetBIOS responses; NetBIOS over TCP/IP may be disabled or blocked".to_string())
        } else {
            None
        };
        Ok(ProviderOutput { hosts, note })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_packet() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x8400u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Answer name (encoded "*" padded name), ignored by the parser.
        packet.push(0x20);
        packet.extend_from_slice(b"CK");
        packet.extend_from_slice(&[b'A'; 30]);
        packet.push(0);
        packet.extend_from_slice(&NBSTAT_TYPE.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());

        let mut rdata = Vec::new();
        rdata.push(2);
        for (name, suffix, group) in [("WORKSTATION", 0x00u8, false), ("WORKGROUP", 0x1Cu8, true)] {
            let mut raw = [b' '; 15];
            let bytes = name.as_bytes();
            raw[..bytes.len()].copy_from_slice(bytes);
            rdata.extend_from_slice(&raw);
            rdata.push(suffix);
            rdata.extend_from_slice(&(if group { 0x8000u16 } else { 0u16 }).to_be_bytes());
        }
        rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);

        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        packet
    }

    #[test]
    fn builds_wildcard_node_status_query() {
        let query = build_node_status_query(0x1234);
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(query[12], 0x20);
        assert_eq!(&query[13..15], b"CK");
        assert_eq!(&query[query.len() - 4..], &[0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn parses_names_workgroup_and_mac() {
        let response = parse_node_status_response(&response_packet()).unwrap();
        assert_eq!(response.names.len(), 2);
        assert_eq!(response.names[0].name, "WORKSTATION");
        assert_eq!(response.names[0].suffix, 0x00);
        assert_eq!(response.names[1].suffix, 0x1C);
        assert_eq!(response.mac.as_deref(), Some("AA:BB:CC:11:22:33"));
        assert_eq!(hostname(&response.names), Some("WORKSTATION"));
        assert_eq!(workgroup(&response.names), Some("WORKGROUP"));
    }

    #[test]
    fn rejects_truncated_response() {
        assert!(parse_node_status_response(&[0u8; 8]).is_err());
    }
}
