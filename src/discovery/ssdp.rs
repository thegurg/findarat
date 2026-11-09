//! SSDP / UPnP discovery.
//!
//! A single M-SEARCH is multicast to the standard SSDP group. Responses are
//! parsed for device/service types and, when a description URL is available,
//! the XML description is fetched to obtain a friendly name and manufacturer.
//! Description fetches are bounded in number and time.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::fingerprint::hostname::clean_display_name;
use crate::models::{Confidence, Evidence, EvidenceKind, Protocol};

use super::{
    DiscoveredHost, DiscoveredService, DiscoveryContext, DiscoveryProvider, ProviderOutput,
};

const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const MAX_DESCRIPTION_FETCHES: usize = 16;

pub struct SsdpDiscovery;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpResponse {
    pub source: Ipv4Addr,
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Option<String>,
    pub usn: Option<String>,
    pub nt: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceDescription {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    pub device_type: Option<String>,
    pub udn: Option<String>,
}

/// Parse a single SSDP response. Headers are case-insensitive.
pub fn parse_response(source: Ipv4Addr, text: &str) -> Option<SsdpResponse> {
    let mut lines = text.lines();
    let status = lines.next()?.trim();
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }
    let headers = parse_headers(lines);
    Some(SsdpResponse {
        source,
        location: headers.get("location").cloned(),
        server: headers.get("server").cloned(),
        st: headers.get("st").cloned(),
        usn: headers.get("usn").cloned(),
        nt: headers.get("nt").cloned(),
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if !key.is_empty() && !value.is_empty() {
                headers.entry(key).or_insert(value);
            }
        }
    }
    headers
}

#[async_trait]
impl DiscoveryProvider for SsdpDiscovery {
    fn name(&self) -> &'static str {
        "ssdp"
    }

    async fn discover(&self, context: &DiscoveryContext) -> anyhow::Result<ProviderOutput> {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| anyhow::anyhow!("failed to open SSDP socket: {error}"))?;
        let request = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 1\r\n\
             ST: ssdp:all\r\n\
             USER-AGENT: findarat/{}\r\n\r\n",
            crate::VERSION
        );
        let destination = SocketAddr::V4(SocketAddrV4::new(SSDP_GROUP, SSDP_PORT));
        socket
            .send_to(request.as_bytes(), destination)
            .await
            .map_err(|error| anyhow::anyhow!("failed to send SSDP M-SEARCH: {error}"))?;

        let deadline = Instant::now() + Duration::from_millis(1200);
        let mut buffer = [0u8; 4096];
        let mut responses: HashMap<(Ipv4Addr, String), SsdpResponse> = HashMap::new();
        while Instant::now() < deadline {
            let wait = deadline.saturating_duration_since(Instant::now());
            match timeout(wait, socket.recv_from(&mut buffer)).await {
                Ok(Ok((length, source))) => {
                    let IpAddr::V4(source_ip) = source.ip() else {
                        continue;
                    };
                    if let Some(subnet) = context.subnet {
                        if !subnet.contains(source_ip) {
                            continue;
                        }
                    }
                    let text = String::from_utf8_lossy(&buffer[..length]);
                    if let Some(response) = parse_response(source_ip, &text) {
                        let key = (
                            source_ip,
                            response
                                .usn
                                .clone()
                                .or_else(|| response.location.clone())
                                .unwrap_or_else(|| "unknown".to_string()),
                        );
                        responses.entry(key).or_insert(response);
                    }
                }
                Ok(Err(error)) => {
                    tracing::debug!(%error, "SSDP receive failed");
                    break;
                }
                Err(_) => {}
            }
        }

        // Fetch descriptions for unique locations.
        let mut locations: Vec<(Ipv4Addr, String)> = Vec::new();
        for response in responses.values() {
            if let Some(location) = &response.location {
                if !locations.iter().any(|(_, existing)| existing == location) {
                    locations.push((response.source, location.clone()));
                }
            }
        }
        locations.truncate(MAX_DESCRIPTION_FETCHES);

        let mut descriptions: HashMap<String, DeviceDescription> = HashMap::new();
        let mut fetches = tokio::task::JoinSet::new();
        for (_, location) in locations {
            let location_for_fetch = location.clone();
            fetches.spawn(async move {
                let fetched = timeout(
                    Duration::from_millis(900),
                    tokio::task::spawn_blocking(move || {
                        http_get(&location_for_fetch, Duration::from_millis(800))
                    }),
                )
                .await;
                (location, fetched)
            });
        }
        while let Some(joined) = fetches.join_next().await {
            if let Ok((location, Ok(Ok(Ok(body))))) = joined {
                descriptions.insert(location, parse_device_description(&body));
            }
        }

        let mut by_ip: HashMap<Ipv4Addr, DiscoveredHost> = HashMap::new();
        for response in responses.into_values() {
            let host = by_ip.entry(response.source).or_insert_with(|| {
                let mut host = DiscoveredHost::new(
                    Some(IpAddr::V4(response.source)),
                    context.interface.name.clone(),
                    "ssdp",
                );
                host.add_evidence(Evidence::direct(
                    "ip",
                    response.source.to_string(),
                    "ssdp",
                    Utc::now(),
                ));
                host
            });

            if let Some(server) = &response.server {
                host.add_evidence(
                    Evidence::inferred(
                        "server",
                        server.clone(),
                        "ssdp",
                        Confidence::Medium,
                        EvidenceKind::DirectObservation,
                        Utc::now(),
                    )
                    .with_note("SSDP SERVER header; self-reported by the device"),
                );
            }
            let device_type = response.st.clone().or_else(|| response.nt.clone());
            if let Some(device_type) = device_type {
                if !host.ssdp_device_types.contains(&device_type) {
                    host.ssdp_device_types.push(device_type.clone());
                }
                let mut service = DiscoveredService::new(device_type.clone(), "ssdp");
                service.service_type = Some(device_type.clone());
                service.protocol = Protocol::Tcp;
                host.add_service(service);
            }

            if let Some(location) = &response.location {
                if let Some(description) = descriptions.get(location) {
                    if host.hostname.is_none() {
                        host.hostname = description
                            .friendly_name
                            .as_deref()
                            .and_then(clean_display_name);
                        if let Some(hostname) = &host.hostname {
                            host.add_evidence(
                                Evidence::inferred(
                                    "hostname",
                                    hostname.clone(),
                                    "ssdp",
                                    Confidence::Medium,
                                    EvidenceKind::DirectObservation,
                                    Utc::now(),
                                )
                                .with_note(
                                    "UPnP friendlyName; self-reported and not a verified identity",
                                ),
                            );
                        }
                    }
                    if host.ssdp_manufacturer.is_none() {
                        host.ssdp_manufacturer = description.manufacturer.clone();
                        if let Some(manufacturer) = &host.ssdp_manufacturer {
                            host.add_evidence(Evidence::inferred(
                                "manufacturer",
                                manufacturer.clone(),
                                "ssdp",
                                Confidence::Medium,
                                EvidenceKind::DirectObservation,
                                Utc::now(),
                            ));
                        }
                    }
                    if host.ssdp_model.is_none() {
                        host.ssdp_model = description.model_name.clone();
                        if let Some(model) = &host.ssdp_model {
                            host.add_evidence(Evidence::inferred(
                                "model",
                                model.clone(),
                                "ssdp",
                                Confidence::Medium,
                                EvidenceKind::DirectObservation,
                                Utc::now(),
                            ));
                        }
                    }
                    if let Some(device_type) = &description.device_type {
                        if !host.ssdp_device_types.contains(device_type) {
                            host.ssdp_device_types.push(device_type.clone());
                        }
                    }
                    let mut details = serde_json::Map::new();
                    details.insert(
                        "location".to_string(),
                        serde_json::Value::String(location.clone()),
                    );
                    if let Some(udn) = &description.udn {
                        details.insert("udn".to_string(), serde_json::Value::String(udn.clone()));
                    }
                    if let Some(model) = &description.model_description {
                        details.insert(
                            "model_description".to_string(),
                            serde_json::Value::String(model.clone()),
                        );
                    }
                    host.details = serde_json::Value::Object(details);
                }
            }
        }

        let mut hosts: Vec<DiscoveredHost> = by_ip.into_values().collect();
        hosts.sort_by_key(|host| host.ip);
        let note = if hosts.is_empty() {
            Some("no SSDP responses; UPnP may be disabled or blocked".to_string())
        } else {
            None
        };
        Ok(ProviderOutput { hosts, note })
    }
}

fn http_get(url: &str, timeout_duration: Duration) -> anyhow::Result<String> {
    use std::net::ToSocketAddrs;

    let (host, port, path) = parse_http_url(url)?;
    let address = format!("{host}:{port}");
    let socket = address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {address}"))?;
    let mut stream = TcpStream::connect_timeout(&socket, timeout_duration)
        .map_err(|error| anyhow::anyhow!("failed to connect to {address}: {error}"))?;
    stream.set_read_timeout(Some(timeout_duration))?;
    stream.set_write_timeout(Some(timeout_duration))?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: findarat/{}\r\nConnection: close\r\n\r\n",
        crate::VERSION
    );
    stream.write_all(request.as_bytes())?;

    let mut data = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0usize;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total += read;
                if total > 256 * 1024 {
                    break;
                }
                data.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
            Err(error) => return Err(error.into()),
        }
    }
    let text = String::from_utf8_lossy(&data);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&text);
    Ok(body.to_string())
}

fn parse_http_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// UPnP description URLs are supported"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(anyhow::anyhow!("UPnP description URL has no host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), port.parse::<u16>()?)
        }
        _ => (authority.to_string(), 80),
    };
    Ok((host, port, path))
}

/// Parse a UPnP device description with quick-xml. Only a small set of fields
/// is extracted; malformed XML yields an empty description.
pub fn parse_device_description(xml: &str) -> DeviceDescription {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut description = DeviceDescription::default();
    let mut current = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = event.local_name().as_ref().to_string();
            }
            Ok(Event::Text(text)) => {
                let Ok(value) = quick_xml::escape::unescape(text.as_ref()) else {
                    continue;
                };
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                match current.as_str() {
                    "friendlyName" if description.friendly_name.is_none() => {
                        description.friendly_name = Some(value.to_string());
                    }
                    "manufacturer" if description.manufacturer.is_none() => {
                        description.manufacturer = Some(value.to_string());
                    }
                    "modelName" if description.model_name.is_none() => {
                        description.model_name = Some(value.to_string());
                    }
                    "modelDescription" if description.model_description.is_none() => {
                        description.model_description = Some(value.to_string());
                    }
                    "deviceType" if description.device_type.is_none() => {
                        description.device_type = Some(value.to_string());
                    }
                    "UDN" if description.udn.is_none() => {
                        description.udn = Some(value.to_string());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(_)) => current.clear(),
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    description
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_m_search_response_headers() {
        let response = "\
HTTP/1.1 200 OK\r
CACHE-CONTROL: max-age=120\r
LOCATION: http://192.168.1.1:1900/rootDesc.xml\r
SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
USN: uuid:abcd::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
\r
";
        let parsed = parse_response(Ipv4Addr::new(192, 168, 1, 1), response).unwrap();
        assert_eq!(parsed.source, Ipv4Addr::new(192, 168, 1, 1));
        assert!(parsed.location.unwrap().contains("rootDesc.xml"));
        assert!(parsed.server.unwrap().contains("MiniUPnPd"));
        assert!(parsed.st.unwrap().contains("InternetGatewayDevice"));
    }

    #[test]
    fn rejects_non_200_responses() {
        assert!(parse_response(
            Ipv4Addr::new(192, 168, 1, 1),
            "NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n"
        )
        .is_none());
    }

    #[test]
    fn parses_description_xml() {
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <manufacturer>Example Networks</manufacturer>
    <modelName>EX-1000</modelName>
    <UDN>uuid:1234</UDN>
  </device>
</root>"#;
        let description = parse_device_description(xml);
        assert_eq!(description.friendly_name.as_deref(), Some("Home Router"));
        assert_eq!(
            description.manufacturer.as_deref(),
            Some("Example Networks")
        );
        assert_eq!(description.model_name.as_deref(), Some("EX-1000"));
        assert!(description
            .device_type
            .unwrap()
            .contains("InternetGatewayDevice"));
    }

    #[test]
    fn parses_http_urls() {
        assert_eq!(
            parse_http_url("http://192.168.1.1:1900/root.xml").unwrap(),
            ("192.168.1.1".to_string(), 1900, "/root.xml".to_string())
        );
        assert_eq!(
            parse_http_url("http://example.local/").unwrap(),
            ("example.local".to_string(), 80, "/".to_string())
        );
        assert!(parse_http_url("https://example.local/").is_err());
    }
}
