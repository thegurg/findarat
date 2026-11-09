//! Application orchestration shared by the CLI and the TUI.
//!
//! Everything here works without a terminal. The TUI is a thin presentation
//! layer over the same [`ScanRequest`], [`run_scan`], and [`Database`] used by
//! the command line.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::discovery::{
    self, DiscoveredHost, DiscoveredService, DiscoveryContext, DiscoveryOptions,
};
use crate::error::FindaratError;
use crate::fingerprint::{self, hostname, FingerprintInput};
use crate::inventory::{Database, UpsertOptions};
use crate::models::{
    Change, Confidence, Device, Evidence, Identifier, IdentifierKind, Observation, PortObservation,
    ProviderReport, ProviderStatus, ScanSession, ScanStatus, ServiceObservation,
};
use crate::network::{InterfaceInfo, NetworkContext, Subnet};
use crate::scanner::{self, ScanOptions, ScanProgress};

/// Everything needed to run one scan. Values are fully resolved before the
/// scan starts so progress reporting and the TUI can be deterministic.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub interface: Option<String>,
    /// Explicit CIDR to scan instead of the active interface subnet.
    pub subnet: Option<Subnet>,
    pub discovery: DiscoveryOptions,
    pub resolve_hostnames: bool,
    /// `None` disables TCP port scanning. An empty list is also treated as a
    /// no-op, but callers should prefer `None`.
    pub ports: Option<Vec<u16>>,
    pub scan_options: ScanOptions,
    /// Safety cap for both subnet-wide probing and the TCP host list.
    pub max_hosts: usize,
}

impl ScanRequest {
    pub fn from_config(config: &Config) -> Result<Self> {
        let ports = scanner::parse_ports(&config.scanner.default_ports).map_err(|error| {
            FindaratError::Config(format!("invalid scanner.default_ports: {error}"))
        })?;
        Ok(Self {
            interface: config.general.interface.clone(),
            subnet: None,
            discovery: DiscoveryOptions {
                arp: config.discovery.arp,
                mdns: config.discovery.mdns,
                ssdp: config.discovery.ssdp,
                netbios: config.discovery.netbios,
                timeout: Duration::from_millis(config.discovery.timeout_ms),
            },
            resolve_hostnames: config.discovery.resolve_hostnames,
            ports: Some(ports),
            scan_options: ScanOptions {
                timeout: Duration::from_millis(config.scanner.timeout_ms),
                concurrency: config.scanner.concurrency,
                rate_limit_per_sec: config.scanner.rate_limit_per_sec,
                banner_grab: config.scanner.banner_grab,
            },
            max_hosts: config.scanner.max_hosts,
        })
    }
}

/// Events emitted while a scan is running. They are advisory: the final report
/// is authoritative and is returned by [`run_scan`].
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Stage(String),
    Provider(ProviderReport),
    HostsDiscovered(usize),
    PortScan(ScanProgress),
    Persisted {
        devices: usize,
        changes: usize,
    },
    Finished {
        devices: usize,
        open_ports: usize,
        changes: usize,
    },
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub session: ScanSession,
    pub session_id: Option<i64>,
    pub devices: Vec<Device>,
    pub changes: Vec<Change>,
    pub reports: Vec<ProviderReport>,
    pub interface: Option<String>,
    pub subnet: Option<String>,
    pub open_ports: usize,
    pub elapsed: Duration,
    pub warnings: Vec<String>,
}

/// Run discovery, optional TCP scanning, fingerprinting, and persistence.
pub async fn run_scan(
    request: &ScanRequest,
    database: &mut Database,
    progress: Option<mpsc::UnboundedSender<ScanEvent>>,
) -> Result<ScanReport> {
    let started = Instant::now();
    emit(&progress, ScanEvent::Stage("detecting network".to_string()));

    let network = NetworkContext::detect(request.interface.as_deref())?;
    let active = network.active()?.clone();
    let subnet = match request.subnet {
        Some(subnet) => subnet,
        None => network.active_subnet()?,
    };
    let gateway = network.gateway;
    let now = Utc::now();

    let context = DiscoveryContext {
        interface: active.clone(),
        subnet: Some(subnet),
        gateway,
        timeout: request.discovery.timeout,
        now,
        max_hosts: request.max_hosts,
    };

    emit(
        &progress,
        ScanEvent::Stage(format!("discovering hosts on {} ({})", subnet, active.name)),
    );
    let mut outcome = discovery::run_discovery(&context, &request.discovery).await;
    for report in &outcome.reports {
        emit(&progress, ScanEvent::Provider(report.clone()));
    }
    emit(&progress, ScanEvent::HostsDiscovered(outcome.hosts.len()));

    if request.resolve_hostnames {
        emit(
            &progress,
            ScanEvent::Stage("resolving hostnames".to_string()),
        );
        resolve_missing_hostnames(&mut outcome.hosts).await;
    }

    let mut devices: Vec<Device> = outcome
        .hosts
        .iter()
        .map(|host| build_device(host, now, gateway))
        .collect();

    let mut warnings = Vec::new();
    let mut reports = outcome.reports.clone();
    let mut open_ports = 0usize;
    let mut tcp_scanned_ips: HashSet<IpAddr> = HashSet::new();

    match &request.ports {
        Some(ports) if !ports.is_empty() => {
            let mut ips: Vec<IpAddr> = devices.iter().filter_map(|device| device.last_ip).collect();
            ips.sort();
            ips.dedup();
            if ips.len() > request.max_hosts {
                warnings.push(format!(
                    "TCP scan limited to {} of {} hosts (scanner.max_hosts = {})",
                    request.max_hosts,
                    ips.len(),
                    request.max_hosts
                ));
                ips.truncate(request.max_hosts);
            }
            if ips.is_empty() {
                warnings.push("no IPv4 hosts were discovered; TCP scan skipped".to_string());
                reports.push(tcp_report(ProviderStatus::Skipped, 0, 0, None));
            } else {
                emit(
                    &progress,
                    ScanEvent::Stage(format!(
                        "scanning {} host(s) on {} TCP port(s)",
                        ips.len(),
                        ports.len()
                    )),
                );
                tcp_scanned_ips.extend(ips.iter().copied());
                let scan_started = Instant::now();
                let results =
                    scan_with_progress(&ips, ports, &request.scan_options, &progress).await;
                for result in &results {
                    open_ports += result.open_ports.len();
                    attach_ports(&mut devices, result, now);
                }
                let duration_ms =
                    scan_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                reports.push(tcp_report(
                    ProviderStatus::Ok,
                    ips.len(),
                    duration_ms,
                    warnings.last().cloned(),
                ));
            }
        }
        _ => {
            reports.push(tcp_report(ProviderStatus::Skipped, 0, 0, None));
        }
    }

    emit(
        &progress,
        ScanEvent::Stage("fingerprinting devices".to_string()),
    );
    for (index, host) in outcome.hosts.iter().enumerate() {
        let Some(device) = devices.get_mut(index) else {
            continue;
        };
        let services: Vec<ServiceObservation> = host
            .services
            .iter()
            .map(|service| service_observation(service, now))
            .collect();
        let is_gateway = match (device.last_ip, gateway) {
            (Some(IpAddr::V4(ip)), Some(gateway)) => ip == gateway,
            _ => false,
        };
        let input = FingerprintInput {
            observed_at: now,
            is_gateway,
            services: &services,
            ssdp_device_types: &host.ssdp_device_types,
            ssdp_manufacturer: host.ssdp_manufacturer.as_deref(),
            ssdp_model: host.ssdp_model.as_deref(),
            netbios_present: !host.netbios_names.is_empty(),
        };
        fingerprint::apply(device, &input);
    }

    emit(&progress, ScanEvent::Stage("saving inventory".to_string()));
    let mut session =
        ScanSession::started(now, Some(active.name.clone()), Some(subnet.to_string()));
    session.providers = reports.clone();

    let session_id = database
        .create_scan_session(&session)
        .context("failed to create scan session")?;
    session.id = Some(session_id);

    let mut changes = Vec::new();
    let mut seen = HashSet::new();
    for device in &mut devices {
        let ports_scanned = device
            .last_ip
            .map(|ip| tcp_scanned_ips.contains(&ip))
            .unwrap_or(false);
        let outcome = database
            .upsert_device_with_options(
                device,
                &UpsertOptions {
                    scan_id: Some(session_id),
                    ports_scanned,
                    record_changes: true,
                    preserve_active: false,
                    synthesize_observations: false,
                },
            )
            .with_context(|| format!("failed to persist device {}", device.display_name()))?;
        device.id = Some(outcome.device_id);
        seen.insert(outcome.device_id);
        changes.extend(outcome.changes);
    }

    let discovery_ok = outcome
        .reports
        .iter()
        .any(|report| report.status == ProviderStatus::Ok);
    if discovery_ok {
        let disappeared = database
            .mark_disappeared(Some(session_id), &seen, Some(&active.name), now, Utc::now())
            .context("failed to record disappeared devices")?;
        changes.extend(disappeared);
    } else {
        warnings.push(
            "no discovery provider succeeded; disappeared-device detection was skipped".to_string(),
        );
    }

    let finished_at = Utc::now();
    database
        .finish_scan_session(
            session_id,
            ScanStatus::Completed,
            &reports,
            devices.len(),
            finished_at,
        )
        .context("failed to finish scan session")?;

    session.finished_at = Some(finished_at);
    session.status = ScanStatus::Completed;
    session.device_count = devices.len();
    session.providers = reports.clone();

    emit(
        &progress,
        ScanEvent::Persisted {
            devices: devices.len(),
            changes: changes.len(),
        },
    );
    emit(
        &progress,
        ScanEvent::Finished {
            devices: devices.len(),
            open_ports,
            changes: changes.len(),
        },
    );

    Ok(ScanReport {
        session,
        session_id: Some(session_id),
        devices,
        changes,
        reports,
        interface: Some(active.name),
        subnet: Some(subnet.to_string()),
        open_ports,
        elapsed: started.elapsed(),
        warnings,
    })
}

/// Build the in-memory device snapshot for one discovered host. Fingerprinting
/// happens later, once TCP results are known.
pub fn build_device(
    host: &DiscoveredHost,
    observed_at: DateTime<Utc>,
    gateway: Option<Ipv4Addr>,
) -> Device {
    let mut device = Device::new(observed_at, observed_at);
    device.last_ip = host.ip;
    device.mac = host
        .mac
        .as_deref()
        .and_then(crate::network::interface::normalise_mac)
        .or_else(|| host.mac.clone());
    device.hostname = host.hostname.clone();
    device.interface = Some(host.interface.clone());

    if let Some(mac) = device.mac.clone() {
        device.add_identifier(Identifier::new(
            IdentifierKind::Mac,
            mac.clone(),
            crate::inventory::identity::mac_confidence(&mac),
            observed_at,
            observed_at,
        ));
        device.add_evidence(Evidence::direct("mac", mac, "discovery", observed_at));
    }
    if let Some(ip) = device.last_ip {
        device.add_identifier(Identifier::new(
            IdentifierKind::Ip,
            ip.to_string(),
            Confidence::High,
            observed_at,
            observed_at,
        ));
        device.add_evidence(Evidence::direct(
            "ip",
            ip.to_string(),
            "discovery",
            observed_at,
        ));
        if let IpAddr::V4(ip) = ip {
            if gateway == Some(ip) {
                device.add_evidence(
                    Evidence::inferred(
                        "network_role",
                        "gateway",
                        "route_table",
                        Confidence::High,
                        crate::models::EvidenceKind::DirectObservation,
                        observed_at,
                    )
                    .with_note("this address is the default IPv4 gateway"),
                );
            }
        }
    }
    if let Some(hostname) = device.hostname.as_deref() {
        if let Some(key) = crate::inventory::identity::hostname_key(hostname) {
            device.add_identifier(Identifier::new(
                IdentifierKind::Hostname,
                key,
                Confidence::Medium,
                observed_at,
                observed_at,
            ));
        }
    }
    for name in &host.netbios_names {
        if let Some(key) = crate::inventory::identity::hostname_key(name) {
            device.add_identifier(Identifier::new(
                IdentifierKind::NetbiosName,
                key,
                Confidence::Medium,
                observed_at,
                observed_at,
            ));
        }
    }

    for evidence in &host.evidence {
        device.add_evidence(evidence.clone());
    }

    let mut sources = host.sources.clone();
    if sources.is_empty() {
        sources.push("discovery".to_string());
    }
    for source in sources {
        let mut observation = Observation::new(observed_at, source);
        observation.interface = Some(host.interface.clone());
        observation.ip = host.ip;
        observation.mac = device.mac.clone();
        observation.hostname = host.hostname.clone();
        if !host.details.is_null() {
            observation.details = Some(host.details.clone());
        }
        device.observations.push(observation);
    }

    device
}

fn attach_ports(
    devices: &mut [Device],
    result: &scanner::HostScanResult,
    observed_at: DateTime<Utc>,
) {
    let mut matched = false;
    for device in devices.iter_mut() {
        if device.last_ip != Some(result.ip) {
            continue;
        }
        matched = true;
        device.ports.extend(result.open_ports.iter().cloned());
        let mut observation = Observation::new(observed_at, "tcp_scan");
        observation.interface = device.interface.clone();
        observation.ip = device.last_ip;
        observation.mac = device.mac.clone();
        observation.hostname = device.hostname.clone();
        observation.details = Some(serde_json::json!({
            "attempted": result.attempted,
            "open_ports": result
                .open_ports
                .iter()
                .map(|port| format!("{}/{}", port.protocol, port.port))
                .collect::<Vec<_>>(),
        }));
        device.observations.push(observation);
    }
    if !matched {
        tracing::debug!(ip = %result.ip, "TCP result had no matching discovered device");
    }
}

fn service_observation(
    service: &DiscoveredService,
    observed_at: DateTime<Utc>,
) -> ServiceObservation {
    let mut observation = ServiceObservation::new(
        service.name.clone(),
        service.port,
        service.protocol,
        service.source.clone(),
        observed_at,
    );
    observation.version = service
        .txt
        .get("version")
        .or_else(|| service.txt.get("product"))
        .cloned();
    observation
}

async fn resolve_missing_hostnames(hosts: &mut [DiscoveredHost]) {
    let mut tasks = JoinSet::new();
    for (index, host) in hosts.iter().enumerate() {
        if host.hostname.is_some() {
            continue;
        }
        let Some(ip) = host.ip else {
            continue;
        };
        tasks.spawn_blocking(move || (index, hostname::resolve_ptr(ip)));
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok((index, Some(name))) = joined {
            if let Some(host) = hosts.get_mut(index) {
                if host.hostname.is_none() {
                    host.hostname = Some(name);
                }
            }
        }
    }
}

async fn scan_with_progress(
    ips: &[IpAddr],
    ports: &[u16],
    options: &ScanOptions,
    progress: &Option<mpsc::UnboundedSender<ScanEvent>>,
) -> Vec<scanner::HostScanResult> {
    let Some(progress) = progress.clone() else {
        return scanner::scan_hosts(ips, ports, options, None).await;
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let forward = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if progress.send(ScanEvent::PortScan(event)).is_err() {
                break;
            }
        }
    });
    let results = scanner::scan_hosts(ips, ports, options, Some(tx)).await;
    if let Err(error) = forward.await {
        tracing::debug!(%error, "scan progress forwarder failed");
    }
    results
}

fn tcp_report(
    status: ProviderStatus,
    hosts_found: usize,
    duration_ms: u64,
    note: Option<String>,
) -> ProviderReport {
    ProviderReport {
        name: "tcp_scan".to_string(),
        status,
        hosts_found,
        error: note,
        duration_ms,
    }
}

fn emit(progress: &Option<mpsc::UnboundedSender<ScanEvent>>, event: ScanEvent) {
    if let Some(sender) = progress {
        let _ = sender.send(event);
    }
}

/// Convenience wrapper used by the default overview and the TUI dashboard.
pub fn network_summary(config: &Config) -> Result<NetworkContext> {
    NetworkContext::detect(config.general.interface.as_deref())
}

/// Human-readable summary of a finished scan for the CLI.
pub fn summarise_report(report: &ScanReport) -> String {
    format!(
        "scan {}: {} device(s), {} open port(s), {} change(s) in {:.1}s",
        report
            .session_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string()),
        report.devices.len(),
        report.open_ports,
        report.changes.len(),
        report.elapsed.as_secs_f64()
    )
}

/// Select the interface snapshot used by a scan. Kept public for callers that
/// want to show the same information before starting a scan.
pub fn active_interface(request: &ScanRequest) -> Result<InterfaceInfo> {
    NetworkContext::detect(request.interface.as_deref())?
        .active()
        .cloned()
}

/// Parse an optional subnet override for the CLI/TUI.
pub fn parse_subnet(value: Option<&str>) -> Result<Option<Subnet>> {
    value
        .map(Subnet::parse)
        .transpose()
        .map_err(|error| FindaratError::Validation(error).into())
}

/// Format a device's open ports for tables.
pub fn port_list(ports: &[PortObservation]) -> String {
    let mut values: Vec<u16> = ports
        .iter()
        .filter(|port| port.state == crate::models::PortState::Open)
        .map(|port| port.port)
        .collect();
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        "—".to_string()
    } else {
        values
            .iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveredService;
    use crate::models::Protocol;

    fn host() -> DiscoveredHost {
        let mut host = DiscoveredHost::new(Some("192.168.1.10".parse().unwrap()), "wlan0", "arp");
        host.mac = Some("AA:BB:CC:DD:EE:01".to_string());
        host.hostname = Some("alpha".to_string());
        host
    }

    #[test]
    fn builds_identity_and_observation_history() {
        let now = Utc::now();
        let device = build_device(&host(), now, None);
        assert_eq!(device.last_ip, Some("192.168.1.10".parse().unwrap()));
        assert!(device
            .identifiers
            .iter()
            .any(|identifier| identifier.kind == IdentifierKind::Mac));
        assert!(device
            .identifiers
            .iter()
            .any(|identifier| identifier.kind == IdentifierKind::Ip));
        assert_eq!(device.observations.len(), 1);
        assert_eq!(device.observations[0].source, "arp");
    }

    #[test]
    fn gateway_is_annotated_with_evidence() {
        let now = Utc::now();
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let mut host = host();
        host.ip = Some(IpAddr::V4(gateway));
        let device = build_device(&host, now, Some(gateway));
        assert!(device
            .evidence
            .iter()
            .any(|evidence| evidence.property == "network_role" && evidence.value == "gateway"));
    }

    #[test]
    fn services_carry_txt_metadata() {
        let now = Utc::now();
        let mut service = DiscoveredService::new("http", "mdns");
        service.port = Some(80);
        service.protocol = Protocol::Tcp;
        service
            .txt
            .insert("version".to_string(), "nginx/1.25".to_string());
        let observation = service_observation(&service, now);
        assert_eq!(observation.version.as_deref(), Some("nginx/1.25"));
        assert_eq!(observation.port, Some(80));
    }

    #[test]
    fn parse_subnet_rejects_invalid_cidr() {
        assert!(parse_subnet(Some("192.168.1.0/33")).is_err());
        assert!(parse_subnet(Some("192.168.1.0/24")).unwrap().is_some());
        assert!(parse_subnet(None).unwrap().is_none());
    }

    #[test]
    fn request_from_config_uses_configured_ports() {
        let config = Config::default();
        let request = ScanRequest::from_config(&config).unwrap();
        assert!(request.ports.is_some());
        assert!(!request.ports.unwrap().is_empty());
    }

    #[test]
    fn summary_mentions_counts() {
        let now = Utc::now();
        let report = ScanReport {
            session: ScanSession::started(now, None, None),
            session_id: Some(7),
            devices: Vec::new(),
            changes: Vec::new(),
            reports: Vec::new(),
            interface: None,
            subnet: None,
            open_ports: 2,
            elapsed: Duration::from_millis(1500),
            warnings: Vec::new(),
        };
        let text = summarise_report(&report);
        assert!(text.contains("scan 7"));
        assert!(text.contains("2 open"));
    }
}
