//! IPv4 subnet calculations.
//!
//! `ipnet` provides the CIDR type; this module adds the host-iteration and
//! netmask behaviour findarat needs, with explicit handling for /31 and /32.

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subnet {
    net: Ipv4Net,
}

impl Subnet {
    pub fn new(net: Ipv4Net) -> Self {
        Self { net: net.trunc() }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        value
            .parse::<Ipv4Net>()
            .map(Self::new)
            .map_err(|err| format!("invalid IPv4 CIDR {value:?}: {err}"))
    }

    pub fn from_ip_netmask(ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, String> {
        let mask = u32::from(netmask);
        let prefix = mask.leading_ones() as u8;
        let expected = match prefix {
            0 => 0,
            32 => u32::MAX,
            n => u32::MAX << (32 - n),
        };
        if mask != expected {
            return Err(format!("non-contiguous netmask: {netmask}"));
        }
        Ipv4Net::new(ip, prefix)
            .map(Self::new)
            .map_err(|err| format!("invalid subnet {ip}/{prefix}: {err}"))
    }

    pub fn from_ip_prefix(ip: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        Ipv4Net::new(ip, prefix)
            .map(Self::new)
            .map_err(|err| format!("invalid subnet {ip}/{prefix}: {err}"))
    }

    pub fn network(&self) -> Ipv4Addr {
        self.net.network()
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        self.net.broadcast()
    }

    pub fn prefix_len(&self) -> u8 {
        self.net.prefix_len()
    }

    pub fn netmask(&self) -> Ipv4Addr {
        let prefix = self.prefix_len();
        let mask = match prefix {
            0 => 0,
            32 => u32::MAX,
            n => u32::MAX << (32 - n),
        };
        Ipv4Addr::from(mask)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.net.contains(&ip)
    }

    /// Number of addresses that are usable as host addresses.
    ///
    /// /31 is treated as two usable hosts (RFC 3021) and /32 as one.
    pub fn host_count(&self) -> u64 {
        match self.prefix_len() {
            32 => 1,
            31 => 2,
            prefix => (1u64 << (32 - prefix)) - 2,
        }
    }

    pub fn hosts(&self) -> HostIter {
        let prefix = self.prefix_len();
        let network = u32::from(self.network());
        let broadcast = u32::from(self.broadcast());
        match prefix {
            32 => HostIter {
                next: network,
                last: network,
                finished: false,
            },
            31 => HostIter {
                next: network,
                last: broadcast,
                finished: false,
            },
            _ => HostIter {
                next: network.saturating_add(1),
                last: broadcast.saturating_sub(1),
                finished: false,
            },
        }
    }

    /// Iterate hosts while excluding a set of addresses (typically the local
    /// address and gateway).
    pub fn hosts_excluding(&self, excluded: &[Ipv4Addr]) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let excluded = excluded.to_vec();
        self.hosts().filter(move |ip| !excluded.contains(ip))
    }

    pub fn is_point_to_point(&self) -> bool {
        self.prefix_len() >= 31
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.net)
    }
}

impl FromStr for Subnet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

pub struct HostIter {
    next: u32,
    last: u32,
    finished: bool,
}

impl Iterator for HostIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.next > self.last {
            self.finished = true;
            return None;
        }
        let current = self.next;
        if current == self.last {
            self.finished = true;
        } else {
            self.next = current + 1;
        }
        Some(Ipv4Addr::from(current))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished || self.next > self.last {
            return (0, Some(0));
        }
        let remaining = (self.last - self.next) as u64 + 1;
        let capped = remaining.min(usize::MAX as u64) as usize;
        (capped, Some(capped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_reports_bounds() {
        let subnet = Subnet::parse("192.168.1.0/24").unwrap();
        assert_eq!(subnet.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnet.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(subnet.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet.prefix_len(), 24);
        assert_eq!(subnet.host_count(), 254);
    }

    #[test]
    fn normalises_network_address() {
        let subnet = Subnet::parse("192.168.1.77/24").unwrap();
        assert_eq!(subnet.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(subnet.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn contains_addresses_in_range() {
        let subnet = Subnet::parse("10.0.5.0/24").unwrap();
        assert!(subnet.contains(Ipv4Addr::new(10, 0, 5, 1)));
        assert!(subnet.contains(Ipv4Addr::new(10, 0, 5, 254)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 0, 6, 1)));
        assert!(!subnet.contains(Ipv4Addr::new(10, 0, 4, 255)));
    }

    #[test]
    fn host_iteration_excludes_network_and_broadcast() {
        let subnet = Subnet::parse("192.168.1.0/30").unwrap();
        let hosts: Vec<_> = subnet.hosts().collect();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
        );
        assert_eq!(subnet.host_count(), 2);
    }

    #[test]
    fn slash_31_and_32_are_usable() {
        let p2p = Subnet::parse("192.0.2.4/31").unwrap();
        assert_eq!(p2p.host_count(), 2);
        assert_eq!(
            p2p.hosts().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 0, 2, 4), Ipv4Addr::new(192, 0, 2, 5)]
        );

        let single = Subnet::parse("192.0.2.9/32").unwrap();
        assert_eq!(single.host_count(), 1);
        assert_eq!(
            single.hosts().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 0, 2, 9)]
        );
    }

    #[test]
    fn derives_subnet_from_netmask() {
        let subnet = Subnet::from_ip_netmask(
            Ipv4Addr::new(192, 168, 1, 25),
            Ipv4Addr::new(255, 255, 255, 0),
        )
        .unwrap();
        assert_eq!(subnet.to_string(), "192.168.1.0/24");
        assert_eq!(subnet.network(), Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn rejects_non_contiguous_netmask() {
        let err = Subnet::from_ip_netmask(
            Ipv4Addr::new(192, 168, 1, 25),
            Ipv4Addr::new(255, 0, 255, 0),
        )
        .unwrap_err();
        assert!(err.contains("non-contiguous"));
    }

    #[test]
    fn excludes_requested_hosts() {
        let subnet = Subnet::parse("192.168.1.0/29").unwrap();
        let hosts: Vec<_> = subnet
            .hosts_excluding(&[Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 4)])
            .collect();
        assert_eq!(
            hosts,
            vec![
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 3),
                Ipv4Addr::new(192, 168, 1, 5),
                Ipv4Addr::new(192, 168, 1, 6)
            ]
        );
    }
}
