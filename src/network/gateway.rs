//! Linux route table parsing.
//!
//! `/proc/net/route` is used instead of shelling out to `ip`. It is available
//! to regular users and sufficient for IPv4 default-gateway detection.

use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub interface: String,
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub flags: u32,
    pub metric: u32,
}

impl RouteEntry {
    pub fn is_default(&self) -> bool {
        self.destination == Ipv4Addr::UNSPECIFIED && (self.flags & 0x2) != 0
    }
}

/// Parse the text content of `/proc/net/route`.
pub fn parse_proc_net_route(content: &str) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let interface = fields[0].to_string();
        let (Ok(destination), Ok(gateway)) = (
            u32::from_str_radix(fields[1], 16),
            u32::from_str_radix(fields[2], 16),
        ) else {
            continue;
        };
        let Ok(flags) = u32::from_str_radix(fields[3], 16) else {
            continue;
        };
        let metric = fields[6].parse::<u32>().unwrap_or(0);
        routes.push(RouteEntry {
            interface,
            // /proc/net/route stores addresses in host byte order (little
            // endian on all Linux targets findarat supports).
            destination: Ipv4Addr::from(destination.to_le_bytes()),
            gateway: Ipv4Addr::from(gateway.to_le_bytes()),
            flags,
            metric,
        });
    }
    routes
}

/// Read the current IPv4 route table. Missing `/proc/net/route` is not fatal;
/// callers receive an empty list.
pub fn routes() -> Vec<RouteEntry> {
    match fs::read_to_string("/proc/net/route") {
        Ok(content) => parse_proc_net_route(&content),
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Ipv4Addr,
}

/// Return the lowest-metric IPv4 default route, if one exists.
pub fn default_route() -> Option<DefaultRoute> {
    routes()
        .into_iter()
        .filter(RouteEntry::is_default)
        .min_by_key(|route| route.metric)
        .map(|route| DefaultRoute {
            interface: route.interface,
            gateway: route.gateway,
        })
}

/// Parse `/etc/resolv.conf` and return unique nameserver addresses.
pub fn parse_resolv_conf(content: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        if let Some(value) = parts.next() {
            if let Ok(ip) = Ipv4Addr::from_str(value) {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }
    servers
}

/// Read configured IPv4 DNS servers. IPv6 resolvers are intentionally not
/// returned by this IPv4-focused helper.
pub fn dns_servers() -> Vec<Ipv4Addr> {
    fs::read_to_string("/etc/resolv.conf")
        .map(|content| parse_resolv_conf(&content))
        .unwrap_or_default()
}

impl fmt::Display for DefaultRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.gateway, self.interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlo1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlo1\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn parses_default_route_and_gateway_byte_order() {
        let routes = parse_proc_net_route(ROUTE);
        assert_eq!(routes.len(), 2);
        assert!(routes[0].is_default());
        assert_eq!(routes[0].gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(routes[0].interface, "wlo1");
        assert_eq!(routes[1].destination, Ipv4Addr::new(192, 168, 1, 0));
        assert!(!routes[1].is_default());
    }

    #[test]
    fn chooses_lowest_metric_default() {
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
";
        let routes = parse_proc_net_route(content);
        let default = routes
            .into_iter()
            .filter(RouteEntry::is_default)
            .min_by_key(|r| r.metric)
            .unwrap();
        assert_eq!(default.interface, "eth0");
    }

    #[test]
    fn parses_nameservers() {
        let content = "\
# comment
nameserver 192.168.1.1
nameserver 1.1.1.1
nameserver 192.168.1.1
search lan
";
        assert_eq!(
            parse_resolv_conf(content),
            vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(1, 1, 1, 1)]
        );
    }

    #[test]
    fn malformed_route_lines_are_skipped() {
        let content = "header\nbad line\neth0 zzzz 00000000 0003 0 0 100 00000000 0 0 0\n";
        assert!(parse_proc_net_route(content).is_empty());
    }
}
