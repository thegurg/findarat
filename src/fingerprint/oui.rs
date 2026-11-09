//! IEEE OUI vendor lookup.
//!
//! The embedded table is a snapshot of the public IEEE MA-L registry
//! (`data/oui.tsv`, assignment prefix + organisation). It identifies the
//! organisation that registered a 24-bit prefix. It does **not** identify a
//! device model, and it is unreliable for randomised MAC addresses.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::network::interface::{is_locally_administered, normalise_mac};

static OUI_TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn table() -> &'static HashMap<&'static str, &'static str> {
    OUI_TABLE.get_or_init(|| {
        let mut map = HashMap::with_capacity(41_000);
        for line in include_str!("../../data/oui.tsv").lines() {
            if let Some((prefix, vendor)) = line.split_once('\t') {
                if prefix.len() == 6 {
                    map.insert(prefix, vendor);
                }
            }
        }
        map
    })
}

/// Return the six-hex-digit OUI prefix for a MAC address.
pub fn oui_prefix(mac: &str) -> Option<String> {
    let normalised = normalise_mac(mac)?;
    Some(
        normalised
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(6)
            .collect::<String>()
            .to_ascii_uppercase(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorMatch {
    pub prefix: String,
    pub vendor: &'static str,
    pub locally_administered: bool,
}

/// Look up a MAC address in the embedded OUI table.
pub fn lookup(mac: &str) -> Option<VendorMatch> {
    let prefix = oui_prefix(mac)?;
    let vendor = table().get(prefix.as_str())?;
    Some(VendorMatch {
        prefix,
        vendor,
        locally_administered: is_locally_administered(mac),
    })
}

pub fn table_size() -> usize {
    table().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_loaded() {
        assert!(table_size() > 30_000);
    }

    #[test]
    fn looks_up_known_prefixes() {
        let raspberry = lookup("B8:27:EB:12:34:56").unwrap();
        assert_eq!(raspberry.prefix, "B827EB");
        assert!(raspberry.vendor.contains("Raspberry Pi"));
        assert!(!raspberry.locally_administered);

        let google = lookup("00:1a:11:00:00:01").unwrap();
        assert!(google.vendor.contains("Google"));
    }

    #[test]
    fn unknown_prefix_returns_none() {
        assert!(lookup("02:00:00:00:00:01").is_none());
    }

    #[test]
    fn rejects_invalid_mac() {
        assert!(lookup("nonsense").is_none());
    }
}
