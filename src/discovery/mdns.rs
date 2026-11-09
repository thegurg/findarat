//! mDNS / DNS-SD discovery.
//!
//! findarat sends PTR queries for the DNS-SD service-type enumeration name and
//! a set of common service types, then decodes the A/AAAA, PTR, SRV, and TXT
//! records in the responses. It does not depend on Avahi being installed.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::models::{Confidence, Evidence, EvidenceKind, Protocol};

use super::dns::{build_query, parse_message, DnsRecord, RData, TYPE_PTR};
use super::{
    DiscoveredHost, DiscoveredService, DiscoveryContext, DiscoveryProvider, ProviderOutput,
};

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

const QUERY_TYPES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_smb._tcp.local",
    "_workstation._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_hap._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_device-info._tcp.local",
];

pub struct MdnsDiscovery;

fn dns_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn display_hostname(name: &str) -> Option<String> {
    crate::fingerprint::hostname::normalise_hostname(name)
        .or_else(|| crate::fingerprint::hostname::clean_display_name(name.split('.').next()?))
}

#[derive(Default)]
struct Collected {
    /// instance name -> service type
    instance_types: HashMap<String, String>,
    /// instance name -> (port, target)
    srv: HashMap<String, (u16, String)>,
    /// instance name -> TXT key/values
    txt: HashMap<String, BTreeMap<String, String>>,
    /// host name -> addresses
    addresses: HashMap<String, Vec<IpAddr>>,
}

impl Collected {
    fn absorb(&mut self, record: &DnsRecord) {
        match &record.data {
            RData::Ptr(target) => {
                let key = dns_key(&record.name);
                if key != "_services._dns-sd._udp.local" {
                    self.instance_types.insert(dns_key(target), key);
                }
            }
            RData::Srv { port, target, .. } => {
                self.srv
                    .insert(dns_key(&record.name), (*port, target.clone()));
            }
            RData::Txt(values) => {
                let mut map = BTreeMap::new();
                for value in values {
                    if let Some((key, value)) = value.split_once('=') {
                        map.insert(key.to_string(), value.to_string());
                    } else if !value.is_empty() {
                        map.insert(value.clone(), String::new());
                    }
                }
                self.txt.insert(dns_key(&record.name), map);
            }
            RData::A(ip) => {
                self.addresses
                    .entry(dns_key(&record.name))
                    .or_default()
                    .push(IpAddr::V4(*ip));
            }
            RData::Aaaa(ip) => {
                self.addresses
                    .entry(dns_key(&record.name))
                    .or_default()
                    .push(IpAddr::V6(*ip));
            }
            RData::Other(_) => {}
        }
    }
}

#[async_trait]
impl DiscoveryProvider for MdnsDiscovery {
    fn name(&self) -> &'static str {
        "mdns"
    }

    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput> {
        let interface_ip = context
            .interface
            .primary_ipv4()
            .ok_or_else(|| anyhow::anyhow!("mDNS discovery requires an IPv4 address"))?;
        let (socket, bound_5353) = bind_socket(interface_ip)?;
        let socket = std::sync::Arc::new(socket);

        let queries: Vec<Vec<u8>> = QUERY_TYPES
            .iter()
            .filter_map(|name| build_query(name, TYPE_PTR, true).ok())
            .collect();

        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut next_send = Instant::now();
        let mut buffer = [0u8; 9000];
        let mut collected = Collected::default();
        let mut packets = 0usize;

        while Instant::now() < deadline {
            let now = Instant::now();
            if now >= next_send {
                for query in &queries {
                    let _ = socket
                        .send_to(
                            query,
                            SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT)),
                        )
                        .await;
                }
                next_send = now + Duration::from_millis(500);
            }

            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(next_send.saturating_duration_since(Instant::now()));
            if wait.is_zero() {
                continue;
            }
            match timeout(wait, socket.recv_from(&mut buffer)).await {
                Ok(Ok((length, _source))) => {
                    if let Ok(message) = parse_message(&buffer[..length]) {
                        if !message.is_response() {
                            continue;
                        }
                        packets += 1;
                        for record in &message.records {
                            collected.absorb(record);
                        }
                    }
                }
                Ok(Err(error)) => {
                    tracing::debug!(%error, "mDNS receive failed");
                    break;
                }
                Err(_) => {}
            }
        }

        let hosts = build_hosts(context, &collected);
        let note = if hosts.is_empty() {
            Some("no mDNS responses; mDNS may be disabled or blocked on this network".to_string())
        } else if !bound_5353 {
            Some(format!(
                "bound to an ephemeral port because 5353 was unavailable; collected {packets} mDNS packets"
            ))
        } else {
            None
        };

        Ok(ProviderOutput { hosts, note })
    }
}

fn bind_socket(interface_ip: Ipv4Addr) -> anyhow::Result<(UdpSocket, bool)> {
    use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SocketProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_multicast_ttl_v4(255)?;
    let _ = socket.set_multicast_if_v4(&interface_ip);
    let _ = socket.join_multicast_v4(&MDNS_GROUP, &interface_ip);

    let mut bound_5353 = true;
    if socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
        .is_err()
    {
        bound_5353 = false;
        socket.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into())?;
    }
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    Ok((socket, bound_5353))
}

fn build_hosts(context: &DiscoveryContext, collected: &Collected) -> Vec<DiscoveredHost> {
    let local_ip = context.interface.primary_ipv4().map(IpAddr::V4);
    let mut by_target: HashMap<String, DiscoveredHost> = HashMap::new();

    for (instance_key, (port, target)) in &collected.srv {
        let target_key = dns_key(target);
        let addresses = collected
            .addresses
            .get(&target_key)
            .cloned()
            .unwrap_or_default();
        let ip = choose_address(&addresses, local_ip);
        let hostname = display_hostname(target)
            .or_else(|| instance_key.split('.').next().and_then(display_hostname));
        let service_type = collected.instance_types.get(instance_key).cloned();
        let service_name = service_type
            .as_deref()
            .map(|value| value.trim_end_matches(".local").to_string())
            .unwrap_or_else(|| instance_key.clone());

        let key = if target_key.is_empty() {
            instance_key.clone()
        } else {
            target_key
        };
        let host = by_target.entry(key).or_insert_with(|| {
            let mut host = DiscoveredHost::new(ip, context.interface.name.clone(), "mdns");
            host.hostname = hostname.clone();
            if let Some(ip) = ip {
                host.add_evidence(Evidence::direct("ip", ip.to_string(), "mdns", Utc::now()));
            }
            if let Some(hostname) = &hostname {
                host.add_evidence(
                    Evidence::inferred(
                        "hostname",
                        hostname.clone(),
                        "mdns",
                        Confidence::Medium,
                        EvidenceKind::DirectObservation,
                        Utc::now(),
                    )
                    .with_note("hostname advertised over mDNS; not a verified identity"),
                );
            }
            host
        });
        if host.ip.is_none() {
            host.ip = ip;
        }
        if host.hostname.is_none() {
            host.hostname = hostname;
        }

        let mut service = DiscoveredService::new(service_name, "mdns");
        service.service_type = service_type;
        service.port = Some(*port);
        service.protocol = Protocol::Tcp;
        if let Some(txt) = collected.txt.get(instance_key) {
            service.txt = txt.clone();
        }
        host.add_service(service);
        host.add_evidence(
            Evidence::inferred(
                "service",
                collected
                    .instance_types
                    .get(instance_key)
                    .cloned()
                    .unwrap_or_else(|| instance_key.clone()),
                "mdns",
                Confidence::High,
                EvidenceKind::DirectObservation,
                Utc::now(),
            )
            .with_note("service advertised over mDNS"),
        );
    }

    // Include hosts that only advertised address records.
    for (name, addresses) in &collected.addresses {
        if collected
            .srv
            .values()
            .any(|(_, target)| dns_key(target) == *name)
        {
            continue;
        }
        let Some(hostname) = display_hostname(name) else {
            continue;
        };
        let ip = choose_address(addresses, local_ip);
        if ip.is_none() {
            continue;
        }
        let host = by_target.entry(name.clone()).or_insert_with(|| {
            let mut host = DiscoveredHost::new(ip, context.interface.name.clone(), "mdns");
            host.hostname = Some(hostname.clone());
            host.add_evidence(Evidence::direct("hostname", hostname, "mdns", Utc::now()));
            if let Some(ip) = ip {
                host.add_evidence(Evidence::direct("ip", ip.to_string(), "mdns", Utc::now()));
            }
            host
        });
        if host.ip.is_none() {
            host.ip = ip;
        }
    }

    let mut hosts: Vec<DiscoveredHost> = by_target.into_values().collect();
    hosts.sort_by(|a, b| match (a.ip, b.ip) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.hostname.cmp(&b.hostname),
    });
    hosts
}

fn choose_address(addresses: &[IpAddr], local_ip: Option<IpAddr>) -> Option<IpAddr> {
    addresses
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4() && Some(*ip) != local_ip)
        .or_else(|| addresses.iter().copied().find(|ip| Some(*ip) != local_ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Evidence;

    fn context() -> DiscoveryContext {
        let mut interface = crate::network::InterfaceInfo {
            name: "wlan0".to_string(),
            kind: crate::network::InterfaceKind::Wireless,
            state: "up".to_string(),
            up: true,
            mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 25)],
            ipv6: Vec::new(),
            subnet: Some(crate::network::Subnet::parse("192.168.1.0/24").unwrap()),
            netmask: None,
            broadcast: None,
            mtu: None,
            is_default: true,
        };
        interface.mac = crate::network::interface::normalise_mac("AA:BB:CC:DD:EE:FF");
        DiscoveryContext {
            interface,
            subnet: Some(crate::network::Subnet::parse("192.168.1.0/24").unwrap()),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            timeout: Duration::from_secs(2),
            now: Utc::now(),
            max_hosts: 4096,
        }
    }

    #[test]
    fn builds_hosts_from_srv_txt_and_a_records() {
        let mut collected = Collected::default();
        collected.instance_types.insert(
            "printer._ipp._tcp.local".to_string(),
            "_ipp._tcp.local".to_string(),
        );
        collected.srv.insert(
            "printer._ipp._tcp.local".to_string(),
            (631, "printer.local".to_string()),
        );
        collected.txt.insert(
            "printer._ipp._tcp.local".to_string(),
            BTreeMap::from([("note".to_string(), "office".to_string())]),
        );
        collected.addresses.insert(
            "printer.local".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))],
        );

        let hosts = build_hosts(&context(), &collected);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname.as_deref(), Some("printer"));
        assert_eq!(
            hosts[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
        );
        assert_eq!(hosts[0].services.len(), 1);
        assert_eq!(hosts[0].services[0].port, Some(631));
        assert_eq!(
            hosts[0].services[0].txt.get("note").map(String::as_str),
            Some("office")
        );
        assert!(hosts[0]
            .evidence
            .iter()
            .any(|evidence| evidence.property == "service"));
    }

    #[test]
    fn skips_the_local_address() {
        let mut collected = Collected::default();
        collected.addresses.insert(
            "self.local".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 26)),
            ],
        );
        let hosts = build_hosts(&context(), &collected);
        assert_eq!(
            hosts[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 26)))
        );
    }

    #[test]
    fn ignores_generic_names() {
        assert_eq!(display_hostname("localhost"), None);
        assert_eq!(
            display_hostname("printer.local"),
            Some("printer".to_string())
        );
    }

    #[test]
    fn evidence_type_is_available() {
        // Keep the import used in tests meaningful.
        let _ = Evidence::direct("ip", "192.168.1.1", "test", Utc::now());
    }
}
