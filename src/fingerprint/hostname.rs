//! Hostname handling and hostname-based heuristics.

use std::net::IpAddr;
use std::str::FromStr;

use crate::models::{Confidence, DeviceType};

/// Clean a name advertised by a device. This is intentionally more permissive
/// than a DNS hostname because SSDP `friendlyName` values often contain spaces.
pub fn clean_display_name(value: &str) -> Option<String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let cleaned = cleaned.trim().trim_end_matches('.').trim();
    if cleaned.is_empty() || is_generic_name(cleaned) {
        return None;
    }
    let mut out = cleaned.to_string();
    if out.len() > 120 {
        out.truncate(120);
    }
    Some(out)
}

/// Normalise a DNS/mDNS hostname. Returns lowercase without a trailing `.local`
/// suffix.
pub fn normalise_hostname(value: &str) -> Option<String> {
    let cleaned = clean_display_name(value)?;
    let cleaned = if cleaned.len() > 6 && cleaned.to_ascii_lowercase().ends_with(".local") {
        cleaned[..cleaned.len() - 6].to_string()
    } else {
        cleaned
    };
    let cleaned = cleaned.trim_end_matches('.').trim();
    if cleaned.is_empty() || is_generic_name(cleaned) {
        return None;
    }
    if IpAddr::from_str(cleaned).is_ok() {
        return None;
    }
    if cleaned.contains(char::is_whitespace) {
        // Spaces are valid in SSDP names but not in DNS hostnames.
        return Some(cleaned.to_ascii_lowercase());
    }
    Some(cleaned.to_ascii_lowercase())
}

pub fn is_generic_name(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "localhost"
            | "localhost.localdomain"
            | "local"
            | "unknown"
            | "_gateway"
            | "_gateway._tcp.local"
            | "gateway"
            | "router"
            | "android"
    )
}

/// Reverse DNS lookup. This call can block on the system resolver, so callers
/// should run it off the UI thread and apply a timeout where possible.
pub fn resolve_ptr(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip)
        .ok()
        .and_then(|name| normalise_hostname(&name))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameHint {
    pub device_type: DeviceType,
    pub confidence: Confidence,
    pub pattern: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsHint {
    pub os: &'static str,
    pub confidence: Confidence,
    pub reason: String,
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut offset = 0;
    while let Some(position) = haystack[offset..].find(needle) {
        let start = offset + position;
        let end = start + needle.len();
        let before_ok = start == 0 || !haystack.as_bytes()[start - 1].is_ascii_alphanumeric();
        let after_ok = end == haystack.len() || !haystack.as_bytes()[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        offset = end;
    }
    false
}

/// Produce device-type hints from a hostname. All matching hints are returned;
/// the caller chooses the strongest and records the rest as evidence.
pub fn hostname_hints(hostname: &str) -> Vec<HostnameHint> {
    let lower = hostname.to_ascii_lowercase();
    let mut hints = Vec::new();

    let mut push = |device_type, confidence, pattern, reason: &str| {
        hints.push(HostnameHint {
            device_type,
            confidence,
            pattern,
            reason: reason.to_string(),
        });
    };

    if lower.contains("iphone") || lower.contains("ipad") || contains_word(&lower, "ios") {
        push(
            DeviceType::Smartphone,
            Confidence::Medium,
            "iphone/ipad",
            "hostname contains an Apple mobile device name",
        );
    }
    if lower.contains("androidtv") || lower.contains("android-tv") || lower.contains("googletv") {
        push(
            DeviceType::SmartTv,
            Confidence::Medium,
            "androidtv",
            "hostname indicates an Android TV device",
        );
    } else if lower.contains("android")
        || lower.contains("pixel")
        || lower.contains("galaxy")
        || lower.contains("oneplus")
        || lower.contains("redmi")
        || lower.contains("poco")
        || lower.contains("moto")
    {
        push(
            DeviceType::Smartphone,
            Confidence::Medium,
            "android/phone",
            "hostname contains a phone model or platform name",
        );
    }

    if lower.contains("macbook")
        || lower.contains("thinkpad")
        || lower.contains("latitude")
        || lower.contains("ideapad")
        || lower.contains("notebook")
        || contains_word(&lower, "laptop")
    {
        push(
            DeviceType::Laptop,
            Confidence::Medium,
            "laptop",
            "hostname contains a laptop model or label",
        );
    }
    if lower.contains("imac")
        || lower.contains("mac-mini")
        || lower.contains("macmini")
        || contains_word(&lower, "desktop")
        || contains_word(&lower, "workstation")
    {
        push(
            DeviceType::Desktop,
            Confidence::Low,
            "desktop",
            "hostname suggests a desktop or workstation",
        );
    }

    if lower.contains("printer")
        || lower.contains("brother")
        || lower.contains("epson")
        || lower.contains("canon")
        || lower.contains("xerox")
        || lower.starts_with("hp-")
    {
        push(
            DeviceType::Printer,
            Confidence::Medium,
            "printer",
            "hostname contains a printer vendor or label",
        );
    }

    if lower.contains("appletv")
        || lower.contains("apple-tv")
        || lower.contains("chromecast")
        || lower.contains("googletv")
        || lower.contains("firetv")
        || lower.contains("fire-tv")
        || lower.contains("roku")
        || lower.contains("bravia")
        || lower.contains("webostv")
        || lower.contains("samsung-tv")
        || lower.contains("androidtv")
        || contains_word(&lower, "tv")
    {
        push(
            DeviceType::SmartTv,
            Confidence::Medium,
            "tv",
            "hostname contains a television or media-player label",
        );
    }

    if lower.contains("synology")
        || lower.contains("qnap")
        || lower.contains("truenas")
        || lower.contains("unraid")
        || lower.contains("proxmox")
        || lower.contains("raspberrypi")
        || lower.contains("raspberry-pi")
        || contains_word(&lower, "nas")
        || contains_word(&lower, "server")
    {
        push(
            DeviceType::Server,
            Confidence::Low,
            "server/nas",
            "hostname suggests a server or network storage device",
        );
    }

    if lower.contains("fritzbox")
        || lower.contains("openwrt")
        || lower.contains("pfsense")
        || lower.contains("opnsense")
        || lower.contains("mikrotik")
        || lower.contains("router")
        || lower.contains("gateway")
        || lower.contains("archer")
        || lower.contains("nighthawk")
    {
        push(
            DeviceType::Router,
            Confidence::Medium,
            "router",
            "hostname contains a router brand or role",
        );
    }

    if lower.contains("unifi")
        || lower.contains("accesspoint")
        || lower.contains("access-point")
        || lower.contains("deco")
        || lower.contains("orbi")
        || lower.contains("eero")
    {
        push(
            DeviceType::AccessPoint,
            Confidence::Medium,
            "access_point",
            "hostname contains an access-point brand or role",
        );
    }

    if lower.contains("esphome")
        || lower.contains("tasmota")
        || lower.contains("shelly")
        || lower.contains("sonoff")
        || lower.contains("tuya")
        || contains_word(&lower, "camera")
        || contains_word(&lower, "cam")
        || contains_word(&lower, "bulb")
        || contains_word(&lower, "plug")
        || contains_word(&lower, "sensor")
        || contains_word(&lower, "thermostat")
    {
        push(
            DeviceType::Iot,
            Confidence::Medium,
            "iot",
            "hostname contains an IoT device or platform label",
        );
    }

    hints
}

/// Infer an operating system from a hostname.
pub fn hostname_os_hint(hostname: &str) -> Option<OsHint> {
    let lower = hostname.to_ascii_lowercase();
    let (os, confidence, reason) =
        if lower.contains("iphone") || lower.contains("ipad") || contains_word(&lower, "ios") {
            (
                "iOS",
                Confidence::Medium,
                "hostname indicates an Apple mobile device",
            )
        } else if lower.contains("android")
            || lower.contains("pixel")
            || lower.contains("galaxy")
            || lower.contains("redmi")
        {
            (
                "Android",
                Confidence::Medium,
                "hostname indicates an Android device",
            )
        } else if lower.contains("macbook") || lower.contains("imac") || lower.contains("mac-mini")
        {
            (
                "macOS",
                Confidence::Medium,
                "hostname indicates an Apple computer",
            )
        } else if lower.contains("openwrt") {
            ("Linux", Confidence::Low, "OpenWrt hostname")
        } else if lower.contains("pfsense") || lower.contains("opnsense") {
            ("FreeBSD", Confidence::Low, "pfSense/OPNsense hostname")
        } else if lower.contains("ubuntu")
            || lower.contains("debian")
            || lower.contains("raspbian")
            || lower.contains("fedora")
            || lower.contains("archlinux")
        {
            (
                "Linux",
                Confidence::Medium,
                "hostname indicates a Linux distribution",
            )
        } else {
            return None;
        };
    Some(OsHint {
        os,
        confidence,
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_local_suffix_and_case() {
        assert_eq!(
            normalise_hostname("MyLaptop.local.").as_deref(),
            Some("mylaptop")
        );
        assert_eq!(normalise_hostname("192.168.1.1"), None);
        assert_eq!(normalise_hostname("localhost"), None);
    }

    #[test]
    fn detects_phone_hostnames() {
        let hints = hostname_hints("redmi-note-12");
        assert!(hints
            .iter()
            .any(|hint| hint.device_type == DeviceType::Smartphone));
    }

    #[test]
    fn detects_router_hostnames() {
        let hints = hostname_hints("fritzbox-7530");
        assert!(hints
            .iter()
            .any(|hint| hint.device_type == DeviceType::Router));
    }

    #[test]
    fn does_not_match_substrings_inside_words() {
        // "steve" contains "tv" as a substring but not as a word.
        let hints = hostname_hints("steve");
        assert!(hints.is_empty());
    }

    #[test]
    fn infers_os() {
        assert_eq!(
            hostname_os_hint("pixel-7").map(|hint| hint.os),
            Some("Android")
        );
        assert_eq!(hostname_os_hint("printer-1"), None);
    }
}
