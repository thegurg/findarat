//! Linux network interface inspection.
//!
//! Address information comes from `getifaddrs` (via `if-addrs`); link-layer
//! metadata comes from sysfs. All of this is available without root.

use if_addrs::{get_if_addrs, IfAddr};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::subnet::Subnet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Loopback,
    Ethernet,
    Wireless,
    Other,
}

impl InterfaceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ethernet => "ethernet",
            Self::Wireless => "wireless",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub kind: InterfaceKind,
    pub state: String,
    pub up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv4: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv6: Vec<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<Subnet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmask: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub is_default: bool,
}

impl InterfaceInfo {
    pub fn primary_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4.first().copied()
    }

    /// Human-readable address list, e.g. `192.168.1.25/24`.
    pub fn address_summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ip) = self.primary_ipv4() {
            if let Some(subnet) = self.subnet {
                parts.push(format!("{ip}/{}", subnet.prefix_len()));
            } else {
                parts.push(ip.to_string());
            }
        }
        if parts.is_empty() {
            if let Some(ip) = self.ipv6.first() {
                parts.push(ip.to_string());
            }
        }
        if parts.is_empty() {
            "no address".to_string()
        } else {
            parts.join(", ")
        }
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Normalise and validate a MAC address, returning uppercase colon-separated
/// form. All-zero addresses are treated as absent.
pub fn normalise_mac(value: &str) -> Option<String> {
    let hex: String = value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() != 12 {
        return None;
    }
    let octets: Vec<&str> = (0..6).map(|i| &hex[i * 2..i * 2 + 2]).collect();
    if octets.iter().all(|octet| *octet == "00") {
        return None;
    }
    Some(octets.join(":"))
}

pub fn is_locally_administered(mac: &str) -> bool {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() < 2 {
        return false;
    }
    u8::from_str_radix(&hex[0..2], 16)
        .map(|first| (first & 0b10) != 0)
        .unwrap_or(false)
}

fn interface_kind(name: &str) -> InterfaceKind {
    if name == "lo" {
        return InterfaceKind::Loopback;
    }
    if let Some(ty) = read_trimmed(format!("/sys/class/net/{name}/type")) {
        if ty == "772" {
            return InterfaceKind::Loopback;
        }
    }
    if Path::new(&format!("/sys/class/net/{name}/wireless")).exists()
        || Path::new(&format!("/sys/class/net/{name}/phy80211")).exists()
    {
        return InterfaceKind::Wireless;
    }
    match read_trimmed(format!("/sys/class/net/{name}/type")).as_deref() {
        Some("1") => InterfaceKind::Ethernet,
        _ => InterfaceKind::Other,
    }
}

fn interface_up(name: &str) -> bool {
    if let Some(flags) = read_trimmed(format!("/sys/class/net/{name}/flags")) {
        let flags = flags.trim_start_matches("0x");
        if let Ok(value) = u32::from_str_radix(flags, 16) {
            return (value & 0x1) != 0;
        }
    }
    matches!(
        read_trimmed(format!("/sys/class/net/{name}/operstate")).as_deref(),
        Some("up")
    )
}

fn blank_interface(name: &str) -> InterfaceInfo {
    let mac = read_trimmed(format!("/sys/class/net/{name}/address"))
        .and_then(|value| normalise_mac(&value));
    let state = read_trimmed(format!("/sys/class/net/{name}/operstate"))
        .unwrap_or_else(|| "unknown".to_string());
    let mtu = read_trimmed(format!("/sys/class/net/{name}/mtu")).and_then(|v| v.parse().ok());
    InterfaceInfo {
        name: name.to_string(),
        kind: interface_kind(name),
        state,
        up: interface_up(name),
        mac,
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        subnet: None,
        netmask: None,
        broadcast: None,
        mtu,
        is_default: false,
    }
}

/// Enumerate all interfaces known to the kernel, including those without an
/// address. Addresses are attached from `getifaddrs`.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces: BTreeMap<String, InterfaceInfo> = BTreeMap::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                interfaces.insert(name.to_string(), blank_interface(name));
            }
        }
    }

    if let Ok(addresses) = get_if_addrs() {
        for address in addresses {
            let name = address.name.clone();
            let info = interfaces
                .entry(name.clone())
                .or_insert_with(|| blank_interface(&name));
            match address.addr {
                IfAddr::V4(v4) => {
                    if !info.ipv4.contains(&v4.ip) {
                        info.ipv4.push(v4.ip);
                    }
                    if info.subnet.is_none() {
                        info.subnet = Subnet::from_ip_netmask(v4.ip, v4.netmask).ok();
                        info.netmask = Some(v4.netmask);
                        info.broadcast = v4.broadcast;
                    }
                }
                IfAddr::V6(v6) => {
                    if !info.ipv6.contains(&v6.ip) {
                        info.ipv6.push(v6.ip);
                    }
                }
            }
        }
    }

    let default = super::gateway::default_route();
    let mut result: Vec<InterfaceInfo> = interfaces.into_values().collect();
    for info in &mut result {
        info.ipv4.sort();
        info.ipv6.sort();
        if let Some(default) = &default {
            info.is_default = default.interface == info.name;
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Find an interface by name.
pub fn find_interface(name: &str) -> Option<InterfaceInfo> {
    list_interfaces().into_iter().find(|info| info.name == name)
}

/// Choose the interface a scan should use when the user did not specify one.
pub fn detect_active_interface(interfaces: &[InterfaceInfo]) -> Option<InterfaceInfo> {
    if let Some(default) = interfaces.iter().find(|info| info.is_default) {
        if !default.ipv4.is_empty() {
            return Some(default.clone());
        }
    }
    interfaces
        .iter()
        .find(|info| info.up && info.kind != InterfaceKind::Loopback && !info.ipv4.is_empty())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_mac_formats() {
        assert_eq!(
            normalise_mac("aa-bb-cc-dd-ee-ff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalise_mac("aabb.ccdd.eeff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(normalise_mac("00:00:00:00:00:00"), None);
        assert_eq!(normalise_mac("not-a-mac"), None);
    }

    #[test]
    fn detects_locally_administered_bit() {
        assert!(is_locally_administered("02:11:22:33:44:55"));
        assert!(!is_locally_administered("00:11:22:33:44:55"));
        assert!(!is_locally_administered("ac:de:48:00:11:22"));
    }

    #[test]
    fn lists_at_least_loopback_on_linux() {
        let interfaces = list_interfaces();
        assert!(interfaces.iter().any(|i| i.name == "lo"));
        assert!(interfaces.iter().any(|i| i.kind == InterfaceKind::Loopback));
    }
}
