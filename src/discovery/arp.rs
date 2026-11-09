//! Unprivileged IPv4 neighbour (ARP) discovery.
//!
//! Linux exposes the neighbour table through `/proc/net/arp`. To populate it
//! without raw sockets, findarat sends a one-byte UDP datagram to the discard
//! port (9) on each subnet address. This triggers normal kernel ARP resolution
//! and requires no elevated privileges. Hosts that are offline, isolated, or
//! behind a firewall simply do not appear.

use async_trait::async_trait;
use chrono::Utc;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::models::{Confidence, Evidence, EvidenceKind};
use crate::network::interface::normalise_mac;

use super::{DiscoveredHost, DiscoveryContext, DiscoveryProvider, ProviderOutput};

pub struct ArpDiscovery;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub interface: String,
    pub flags: u32,
}

impl ArpEntry {
    pub fn is_complete(&self) -> bool {
        self.flags & 0x2 != 0 && self.mac.is_some()
    }
}

/// Parse `/proc/net/arp`.
pub fn parse_arp_table(content: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let Ok(ip) = fields[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let mac = normalise_mac(fields[3]);
        let Ok(flags) = u32::from_str_radix(fields[2].trim_start_matches("0x"), 16) else {
            continue;
        };
        entries.push(ArpEntry {
            ip,
            mac,
            interface: fields[5].to_string(),
            flags,
        });
    }
    entries
}

fn read_arp_table() -> Vec<ArpEntry> {
    fs::read_to_string("/proc/net/arp")
        .map(|content| parse_arp_table(&content))
        .unwrap_or_default()
}

#[async_trait]
impl DiscoveryProvider for ArpDiscovery {
    fn name(&self) -> &'static str {
        "arp"
    }

    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput> {
        let subnet = context
            .subnet
            .ok_or_else(|| anyhow::anyhow!("ARP discovery requires an IPv4 subnet"))?;
        let local_ip = context
            .interface
            .primary_ipv4()
            .ok_or_else(|| anyhow::anyhow!("interface has no IPv4 address"))?;

        // Capture entries that are already cached before priming.
        let before = read_arp_table();

        let hosts: Vec<Ipv4Addr> = subnet
            .hosts_excluding(&[local_ip])
            .take(context.max_hosts)
            .collect();
        let truncated = subnet.host_count() > hosts.len() as u64;

        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
                .await
                .map_err(|error| anyhow::anyhow!("failed to open ARP priming socket: {error}"))?,
        );
        let mut tasks = JoinSet::new();
        for ip in &hosts {
            let socket = Arc::clone(&socket);
            let ip = *ip;
            tasks.spawn(async move {
                let _ = socket.send_to(&[0u8], SocketAddr::from((ip, 9))).await;
            });
            if tasks.len() >= 256 {
                let _ = tasks.join_next().await;
            }
        }
        while tasks.join_next().await.is_some() {}

        // Give the kernel time to complete ARP exchanges. This is intentionally
        // short; discovery should not stall the whole scan.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = read_arp_table();

        let mut seen = std::collections::BTreeSet::new();
        let mut discovered = Vec::new();
        for entry in before.into_iter().chain(after) {
            if !entry.is_complete()
                || entry.interface != context.interface.name
                || !subnet.contains(entry.ip)
                || entry.ip == local_ip
                || !seen.insert((entry.ip, entry.mac.clone()))
            {
                continue;
            }
            let Some(mac) = entry.mac.clone() else {
                continue;
            };
            let mut host = DiscoveredHost::new(
                Some(IpAddr::V4(entry.ip)),
                context.interface.name.clone(),
                "arp",
            );
            host.mac = Some(mac.clone());
            host.add_evidence(Evidence::direct(
                "ip",
                entry.ip.to_string(),
                "arp",
                Utc::now(),
            ));
            host.add_evidence(Evidence::direct("mac", mac.clone(), "arp", Utc::now()));
            if crate::network::interface::is_locally_administered(&mac) {
                host.add_evidence(
                    Evidence::inferred(
                        "mac_randomisation",
                        "locally administered",
                        "arp",
                        Confidence::Medium,
                        EvidenceKind::DirectObservation,
                        Utc::now(),
                    )
                    .with_note("locally administered MAC; vendor lookup is unreliable"),
                );
            }
            host.details = serde_json::json!({
                "arp_flags": entry.flags,
                "arp_interface": entry.interface,
            });
            discovered.push(host);
        }

        let note = if discovered.is_empty() {
            Some(
                "no complete ARP entries appeared; hosts may be offline, client-isolated, or firewalled"
                    .to_string(),
            )
        } else if truncated {
            Some(format!(
                "subnet has {} hosts; ARP priming limited to {}",
                subnet.host_count(),
                hosts.len()
            ))
        } else {
            None
        };

        Ok(ProviderOutput {
            hosts: discovered,
            note,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:11:22:33     *        wlan0
192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.3      0x1         0x2         02:11:22:33:44:55     *        eth0
";

    #[test]
    fn parses_complete_and_incomplete_entries() {
        let entries = parse_arp_table(TABLE);
        assert_eq!(entries.len(), 3);
        assert!(entries[0].is_complete());
        assert_eq!(entries[0].mac.as_deref(), Some("AA:BB:CC:11:22:33"));
        assert!(!entries[1].is_complete());
        assert_eq!(entries[2].interface, "eth0");
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let content = "header\nbad\n";
        assert!(parse_arp_table(content).is_empty());
    }
}
