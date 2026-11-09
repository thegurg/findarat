//! Network discovery providers and result merging.
//!
//! Providers are independent. One provider failing or timing out is recorded in
//! the scan report and never prevents the others from producing results.

pub mod arp;
pub mod dns;
pub mod mdns;
pub mod netbios;
pub mod ssdp;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::models::{Evidence, Protocol, ProviderReport, ProviderStatus};
use crate::network::{InterfaceInfo, Subnet};

#[derive(Debug, Clone)]
pub struct DiscoveryContext {
    pub interface: InterfaceInfo,
    pub subnet: Option<Subnet>,
    pub gateway: Option<std::net::Ipv4Addr>,
    pub timeout: Duration,
    pub now: DateTime<Utc>,
    /// Safety cap for subnet-wide probing (ARP priming).
    pub max_hosts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub txt: BTreeMap<String, String>,
    pub source: String,
}

impl DiscoveredService {
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            service_type: None,
            port: None,
            protocol: Protocol::Tcp,
            txt: BTreeMap::new(),
            source: source.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub interface: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<DiscoveredService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssdp_device_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdp_manufacturer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdp_model: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub netbios_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netbios_workgroup: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl DiscoveredHost {
    pub fn new(
        ip: Option<IpAddr>,
        interface: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            interface: interface.into(),
            sources: vec![source.into()],
            services: Vec::new(),
            evidence: Vec::new(),
            ssdp_device_types: Vec::new(),
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_names: Vec::new(),
            netbios_workgroup: None,
            details: serde_json::Value::Null,
        }
    }

    pub fn add_source(&mut self, source: impl Into<String>) {
        let source = source.into();
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    pub fn add_service(&mut self, service: DiscoveredService) {
        let duplicate = self.services.iter().any(|existing| {
            existing.name == service.name
                && existing.port == service.port
                && existing.source == service.source
        });
        if !duplicate {
            self.services.push(service);
        }
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        let duplicate = self.evidence.iter().any(|existing| {
            existing.property == evidence.property
                && existing.value == evidence.value
                && existing.source == evidence.source
        });
        if !duplicate {
            self.evidence.push(evidence);
        }
    }

    /// Merge another observation of the same host into this one. Conflicting
    /// hostnames are preserved as evidence; the first value remains primary.
    pub fn merge(&mut self, other: DiscoveredHost) {
        if self.ip.is_none() {
            self.ip = other.ip;
        }
        if self.mac.is_none() {
            self.mac = other.mac;
        }
        if self.hostname.is_none() {
            self.hostname = other.hostname;
        } else if let Some(other_hostname) = other.hostname {
            if self.hostname.as_deref() != Some(other_hostname.as_str()) {
                self.add_evidence(
                    Evidence::inferred(
                        "hostname",
                        other_hostname,
                        "discovery_conflict",
                        crate::models::Confidence::Low,
                        crate::models::EvidenceKind::DirectObservation,
                        Utc::now(),
                    )
                    .with_note("conflicting advertised name; primary name retained"),
                );
            }
        }
        for source in other.sources {
            self.add_source(source);
        }
        for service in other.services {
            self.add_service(service);
        }
        for evidence in other.evidence {
            self.add_evidence(evidence);
        }
        for device_type in other.ssdp_device_types {
            if !self.ssdp_device_types.contains(&device_type) {
                self.ssdp_device_types.push(device_type);
            }
        }
        if self.ssdp_manufacturer.is_none() {
            self.ssdp_manufacturer = other.ssdp_manufacturer;
        }
        if self.ssdp_model.is_none() {
            self.ssdp_model = other.ssdp_model;
        }
        for name in other.netbios_names {
            if !self.netbios_names.contains(&name) {
                self.netbios_names.push(name);
            }
        }
        if self.netbios_workgroup.is_none() {
            self.netbios_workgroup = other.netbios_workgroup;
        }
        merge_json(&mut self.details, other.details);
    }
}

fn merge_json(target: &mut serde_json::Value, other: serde_json::Value) {
    match (target, other) {
        (serde_json::Value::Object(target), serde_json::Value::Object(other)) => {
            for (key, value) in other {
                target.entry(key).or_insert(value);
            }
        }
        (target, other) if target.is_null() => *target = other,
        _ => {}
    }
}

#[derive(Debug, Clone)]
pub struct ProviderOutput {
    pub hosts: Vec<DiscoveredHost>,
    pub note: Option<String>,
}

impl ProviderOutput {
    pub fn new(hosts: Vec<DiscoveredHost>) -> Self {
        Self { hosts, note: None }
    }
}

#[async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub arp: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub netbios: bool,
    pub timeout: Duration,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            arp: true,
            mdns: true,
            ssdp: true,
            netbios: true,
            timeout: Duration::from_millis(2500),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryOutcome {
    pub hosts: Vec<DiscoveredHost>,
    pub reports: Vec<ProviderReport>,
}

/// Run enabled providers concurrently and merge their results.
pub async fn run_discovery(
    context: &DiscoveryContext,
    options: &DiscoveryOptions,
) -> DiscoveryOutcome {
    let mut providers: Vec<Arc<dyn DiscoveryProvider>> = Vec::new();
    if options.arp {
        providers.push(Arc::new(arp::ArpDiscovery));
    }
    if options.mdns {
        providers.push(Arc::new(mdns::MdnsDiscovery));
    }
    if options.ssdp {
        providers.push(Arc::new(ssdp::SsdpDiscovery));
    }
    if options.netbios {
        providers.push(Arc::new(netbios::NetbiosDiscovery));
    }

    let mut tasks = JoinSet::new();
    for provider in providers {
        let name = provider.name().to_string();
        let context = context.clone();
        let timeout_duration = options.timeout;
        tasks.spawn(async move {
            let started = Instant::now();
            let result = timeout(timeout_duration, provider.discover(&context)).await;
            (name, result, started.elapsed())
        });
    }

    let mut hosts = Vec::new();
    let mut reports = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((name, result, duration)) => match result {
                Ok(Ok(output)) => {
                    let count = output.hosts.len();
                    hosts.extend(output.hosts);
                    reports.push(ProviderReport {
                        name,
                        status: ProviderStatus::Ok,
                        hosts_found: count,
                        error: output.note,
                        duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
                    });
                }
                Ok(Err(error)) => reports.push(ProviderReport {
                    name,
                    status: ProviderStatus::Failed,
                    hosts_found: 0,
                    error: Some(format!("{error:#}")),
                    duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
                }),
                Err(_) => reports.push(ProviderReport {
                    name,
                    status: ProviderStatus::Failed,
                    hosts_found: 0,
                    error: Some(format!(
                        "provider timed out after {} ms",
                        options.timeout.as_millis()
                    )),
                    duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
                }),
            },
            Err(error) => reports.push(ProviderReport {
                name: "unknown".to_string(),
                status: ProviderStatus::Failed,
                hosts_found: 0,
                error: Some(format!("provider task failed: {error}")),
                duration_ms: 0,
            }),
        }
    }

    if !options.arp {
        reports.push(skipped("arp"));
    }
    if !options.mdns {
        reports.push(skipped("mdns"));
    }
    if !options.ssdp {
        reports.push(skipped("ssdp"));
    }
    if !options.netbios {
        reports.push(skipped("netbios"));
    }
    reports.sort_by(|a, b| a.name.cmp(&b.name));

    DiscoveryOutcome {
        hosts: merge_hosts(hosts),
        reports,
    }
}

fn skipped(name: &str) -> ProviderReport {
    ProviderReport {
        name: name.to_string(),
        status: ProviderStatus::Skipped,
        hosts_found: 0,
        error: None,
        duration_ms: 0,
    }
}

/// Merge observations that refer to the same host. Matching is deliberately
/// conservative: MAC first, then IP, then hostname.
pub fn merge_hosts(hosts: Vec<DiscoveredHost>) -> Vec<DiscoveredHost> {
    let mut merged: Vec<DiscoveredHost> = Vec::new();
    for host in hosts {
        let position = merged.iter().position(|existing| {
            (host.mac.is_some() && existing.mac.is_some() && host.mac == existing.mac)
                || (host.ip.is_some() && existing.ip.is_some() && host.ip == existing.ip)
                || (host.hostname.is_some()
                    && existing.hostname.is_some()
                    && host.hostname == existing.hostname)
        });
        match position {
            Some(index) => merged[index].merge(host),
            None => merged.push(host),
        }
    }
    merged.sort_by(|a, b| match (a.ip, b.ip) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.hostname.cmp(&b.hostname),
    });
    merged
}

/// Names of all providers known to this build.
pub fn provider_names() -> BTreeSet<&'static str> {
    ["arp", "mdns", "ssdp", "netbios"].into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, mac: Option<&str>, hostname: Option<&str>, source: &str) -> DiscoveredHost {
        let mut host = DiscoveredHost::new(Some(ip.parse().unwrap()), "wlan0", source);
        host.mac = mac.map(str::to_string);
        host.hostname = hostname.map(str::to_string);
        host
    }

    #[test]
    fn merges_by_ip_and_preserves_conflicting_names() {
        let arp = host("192.168.1.10", Some("AA:BB:CC:DD:EE:FF"), None, "arp");
        let mdns = host("192.168.1.10", None, Some("printer"), "mdns");
        let merged = merge_hosts(vec![arp, mdns]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(merged[0].hostname.as_deref(), Some("printer"));
        assert_eq!(merged[0].sources.len(), 2);
    }

    #[test]
    fn conflicting_hostnames_are_preserved_as_evidence() {
        let first = host("192.168.1.10", None, Some("alpha"), "mdns");
        let second = host("192.168.1.10", None, Some("beta"), "ssdp");
        let merged = merge_hosts(vec![first, second]);
        assert_eq!(merged[0].hostname.as_deref(), Some("alpha"));
        assert!(merged[0]
            .evidence
            .iter()
            .any(|evidence| evidence.value == "beta"));
    }

    #[test]
    fn merges_by_mac_even_when_ip_changes() {
        let first = host("192.168.1.10", Some("AA:BB:CC:DD:EE:FF"), None, "arp");
        let second = host("192.168.1.11", Some("AA:BB:CC:DD:EE:FF"), None, "arp");
        let merged = merge_hosts(vec![first, second]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].ip.unwrap().to_string(), "192.168.1.10");
    }

    #[test]
    fn merges_by_hostname_when_no_address_exists() {
        let mut first = DiscoveredHost::new(None, "wlan0", "mdns");
        first.hostname = Some("nas.local".to_string());
        let mut second = DiscoveredHost::new(None, "wlan0", "ssdp");
        second.hostname = Some("nas.local".to_string());
        assert_eq!(merge_hosts(vec![first, second]).len(), 1);
    }

    #[test]
    fn duplicate_services_are_removed() {
        let mut first = host("192.168.1.10", None, None, "mdns");
        first.add_service(DiscoveredService::new("ssh", "mdns"));
        let mut second = host("192.168.1.10", None, None, "mdns");
        second.add_service(DiscoveredService::new("ssh", "mdns"));
        let merged = merge_hosts(vec![first, second]);
        assert_eq!(merged[0].services.len(), 1);
    }
}
