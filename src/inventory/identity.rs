//! Device identity matching.
//!
//! An IP address is not an identity. Matching order is:
//!   1. exact MAC (strong; weaker for locally administered/randomised MACs)
//!   2. exact normalised hostname (medium, only when unambiguous)
//!   3. exact IP (low, only when no MAC conflicts and the observation is recent)
//!
//! The database layer supplies candidates; this module owns the ranking rules so
//! they can be unit tested without SQLite.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::models::Confidence;
use crate::network::interface::{is_locally_administered, normalise_mac};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchBasis {
    Ip,
    Hostname,
    Mac,
}

impl MatchBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Hostname => "hostname",
            Self::Ip => "ip",
        }
    }
}

impl fmt::Display for MatchBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMatch {
    pub device_id: i64,
    pub basis: MatchBasis,
    pub confidence: Confidence,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedIdentity {
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<IpAddr>,
}

impl ObservedIdentity {
    pub fn new(mac: Option<&str>, hostname: Option<&str>, ip: Option<IpAddr>) -> Self {
        Self {
            mac: mac.and_then(normalise_mac),
            hostname: hostname.and_then(hostname_key),
            ip,
        }
    }
}

/// Normalise a hostname for identity comparison. Returns `None` for generic
/// names that would create false matches.
pub fn hostname_key(hostname: &str) -> Option<String> {
    let trimmed = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let trimmed = trimmed
        .strip_suffix(".local")
        .unwrap_or(&trimmed)
        .trim()
        .to_string();
    if trimmed.is_empty()
        || matches!(
            trimmed.as_str(),
            "localhost" | "localhost.localdomain" | "unknown" | "_gateway" | "gateway"
        )
        || trimmed.parse::<IpAddr>().is_ok()
    {
        None
    } else {
        Some(trimmed)
    }
}

pub fn mac_confidence(mac: &str) -> Confidence {
    if is_locally_administered(mac) {
        Confidence::Medium
    } else {
        Confidence::High
    }
}

/// IP-only matching is allowed only when neither side already has a different
/// MAC and the previous sighting is recent enough to be plausible.
pub fn ip_match_allowed(
    existing_has_mac: bool,
    observed_has_mac: bool,
    last_seen_age: Duration,
) -> bool {
    !(existing_has_mac && observed_has_mac) && last_seen_age <= Duration::from_secs(7 * 24 * 3600)
}

/// Pick the strongest candidate. Ties prefer MAC, then hostname, then IP.
pub fn choose(candidates: Vec<IdentityMatch>) -> Option<IdentityMatch> {
    candidates.into_iter().max_by(|a, b| {
        a.confidence
            .rank()
            .cmp(&b.confidence.rank())
            .then_with(|| a.basis.cmp(&b.basis))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(device_id: i64, basis: MatchBasis, confidence: Confidence) -> IdentityMatch {
        IdentityMatch {
            device_id,
            basis,
            confidence,
            reason: String::new(),
        }
    }

    #[test]
    fn normalises_mac_and_hostname() {
        let identity = ObservedIdentity::new(
            Some("aa-bb-cc-dd-ee-ff"),
            Some("MyLaptop.local."),
            Some("192.168.1.10".parse().unwrap()),
        );
        assert_eq!(identity.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(identity.hostname.as_deref(), Some("mylaptop"));
    }

    #[test]
    fn rejects_generic_and_ip_like_hostnames() {
        assert_eq!(hostname_key("localhost"), None);
        assert_eq!(hostname_key("192.168.1.1"), None);
        assert_eq!(hostname_key("gateway"), None);
        assert_eq!(hostname_key("printer.local"), Some("printer".to_string()));
    }

    #[test]
    fn mac_beats_hostname_beats_ip() {
        let chosen = choose(vec![
            candidate(1, MatchBasis::Ip, Confidence::Low),
            candidate(2, MatchBasis::Hostname, Confidence::Medium),
            candidate(3, MatchBasis::Mac, Confidence::High),
        ])
        .unwrap();
        assert_eq!(chosen.device_id, 3);
        assert_eq!(chosen.basis, MatchBasis::Mac);
    }

    #[test]
    fn tie_prefers_mac() {
        let chosen = choose(vec![
            candidate(1, MatchBasis::Hostname, Confidence::Medium),
            candidate(2, MatchBasis::Mac, Confidence::Medium),
        ])
        .unwrap();
        assert_eq!(chosen.device_id, 2);
    }

    #[test]
    fn locally_administered_mac_is_medium_confidence() {
        assert_eq!(mac_confidence("02:11:22:33:44:55"), Confidence::Medium);
        assert_eq!(mac_confidence("B8:27:EB:12:34:56"), Confidence::High);
    }

    #[test]
    fn ip_matching_requires_recent_observation_and_no_mac_conflict() {
        assert!(ip_match_allowed(false, false, Duration::from_secs(3600)));
        assert!(ip_match_allowed(true, false, Duration::from_secs(3600)));
        assert!(!ip_match_allowed(true, true, Duration::from_secs(3600)));
        assert!(!ip_match_allowed(
            false,
            false,
            Duration::from_secs(30 * 24 * 3600)
        ));
    }
}
