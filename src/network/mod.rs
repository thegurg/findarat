//! Network environment detection.

pub mod gateway;
pub mod interface;
pub mod subnet;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::error::FindaratError;

pub use gateway::{DefaultRoute, RouteEntry};
pub use interface::{InterfaceInfo, InterfaceKind};
pub use subnet::Subnet;

/// Snapshot of the local network environment at one point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub interfaces: Vec<InterfaceInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<InterfaceInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<Ipv4Addr>,
}

impl NetworkContext {
    /// Detect interfaces, the default route, and DNS configuration. If
    /// `requested` is provided it must name an existing interface.
    pub fn detect(requested: Option<&str>) -> anyhow::Result<Self> {
        let interfaces = interface::list_interfaces();
        let active = match requested {
            Some(name) => Some(
                interfaces
                    .iter()
                    .find(|info| info.name == name)
                    .cloned()
                    .ok_or_else(|| {
                        FindaratError::Validation(format!(
                            "network interface {name:?} does not exist; run `findarat interfaces`"
                        ))
                    })?,
            ),
            None => interface::detect_active_interface(&interfaces),
        };

        let default = gateway::default_route();
        let gateway = match (&active, &default) {
            (Some(active), Some(default)) if active.name == default.interface => {
                Some(default.gateway)
            }
            _ => None,
        };

        Ok(Self {
            interfaces,
            active,
            gateway,
            dns_servers: gateway::dns_servers(),
        })
    }

    pub fn active(&self) -> anyhow::Result<&InterfaceInfo> {
        self.active.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "no active IPv4 network interface found; connect to a network or pass --interface <name>"
            )
        })
    }

    pub fn active_subnet(&self) -> anyhow::Result<Subnet> {
        let active = self.active()?;
        active.subnet.ok_or_else(|| {
            anyhow::anyhow!(
                "interface {} has no IPv4 subnet; findarat currently discovers IPv4 networks",
                active.name
            )
        })
    }

    pub fn active_ipv4(&self) -> anyhow::Result<Ipv4Addr> {
        self.active()?
            .primary_ipv4()
            .context("active interface has no IPv4 address")
    }

    pub fn default_interface_name(&self) -> Option<&str> {
        self.interfaces
            .iter()
            .find(|info| info.is_default)
            .map(|info| info.name.as_str())
    }

    /// One-line network summary used by the CLI and TUI header.
    pub fn summary(&self) -> String {
        match (&self.active, self.gateway) {
            (Some(active), Some(gateway)) => format!(
                "{} | {} | gateway {}",
                active.name,
                active
                    .subnet
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| active.address_summary()),
                gateway
            ),
            (Some(active), None) => format!(
                "{} | {}",
                active.name,
                active
                    .subnet
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| active.address_summary())
            ),
            (None, _) => "no active interface".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_does_not_require_root_and_finds_interfaces() {
        let context = NetworkContext::detect(None).expect("network detection should not fail");
        assert!(context
            .interfaces
            .iter()
            .any(|interface| interface.name == "lo"));
    }

    #[test]
    fn unknown_requested_interface_is_validation_error() {
        let error = NetworkContext::detect(Some("findarat-no-such-iface")).unwrap_err();
        let findarat = error
            .downcast_ref::<FindaratError>()
            .expect("expected FindaratError");
        assert!(matches!(findarat, FindaratError::Validation(_)));
    }
}
