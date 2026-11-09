//! Well-known service hints and banner parsing.
//!
//! A port number is a hint, not proof. Banner text is stronger evidence and is
//! always recorded with its source so the user can judge it.

use crate::models::Confidence;

/// Ports scanned by `--ports common`. Chosen for typical home/small-office
/// devices rather than exhaustive coverage.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 548, 554, 587, 631, 993, 995,
    1883, 1900, 2049, 3000, 3306, 3389, 5000, 5353, 5432, 5900, 6379, 7547, 8000, 8080, 8443, 8888,
    9100, 32400,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Send a minimal HTTP HEAD request and read the response headers.
    Http,
    /// Read a server banner without sending application data.
    Read,
    /// TLS or binary protocol: do not send plaintext probes.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortHint {
    pub service: &'static str,
    pub probe: Probe,
    pub tls: bool,
}

/// Map a TCP port to a conservative service hint.
pub fn port_hint(port: u16) -> Option<PortHint> {
    let hint = match port {
        21 => PortHint {
            service: "ftp",
            probe: Probe::Read,
            tls: false,
        },
        22 => PortHint {
            service: "ssh",
            probe: Probe::Read,
            tls: false,
        },
        23 => PortHint {
            service: "telnet",
            probe: Probe::Read,
            tls: false,
        },
        25 => PortHint {
            service: "smtp",
            probe: Probe::Read,
            tls: false,
        },
        53 => PortHint {
            service: "dns",
            probe: Probe::None,
            tls: false,
        },
        80 => PortHint {
            service: "http",
            probe: Probe::Http,
            tls: false,
        },
        110 => PortHint {
            service: "pop3",
            probe: Probe::Read,
            tls: false,
        },
        111 => PortHint {
            service: "rpcbind",
            probe: Probe::None,
            tls: false,
        },
        135 => PortHint {
            service: "msrpc",
            probe: Probe::None,
            tls: false,
        },
        139 => PortHint {
            service: "netbios-ssn",
            probe: Probe::None,
            tls: false,
        },
        143 => PortHint {
            service: "imap",
            probe: Probe::Read,
            tls: false,
        },
        443 => PortHint {
            service: "https",
            probe: Probe::None,
            tls: true,
        },
        445 => PortHint {
            service: "smb",
            probe: Probe::None,
            tls: false,
        },
        515 => PortHint {
            service: "lpd",
            probe: Probe::None,
            tls: false,
        },
        548 => PortHint {
            service: "afp",
            probe: Probe::None,
            tls: false,
        },
        554 => PortHint {
            service: "rtsp",
            probe: Probe::Read,
            tls: false,
        },
        587 => PortHint {
            service: "submission",
            probe: Probe::Read,
            tls: false,
        },
        631 => PortHint {
            service: "ipp",
            probe: Probe::Http,
            tls: false,
        },
        993 => PortHint {
            service: "imaps",
            probe: Probe::None,
            tls: true,
        },
        995 => PortHint {
            service: "pop3s",
            probe: Probe::None,
            tls: true,
        },
        1883 => PortHint {
            service: "mqtt",
            probe: Probe::None,
            tls: false,
        },
        2049 => PortHint {
            service: "nfs",
            probe: Probe::None,
            tls: false,
        },
        3000 => PortHint {
            service: "http-alt",
            probe: Probe::Http,
            tls: false,
        },
        3306 => PortHint {
            service: "mysql",
            probe: Probe::None,
            tls: false,
        },
        3389 => PortHint {
            service: "rdp",
            probe: Probe::None,
            tls: false,
        },
        5000 => PortHint {
            service: "http-alt",
            probe: Probe::Http,
            tls: false,
        },
        5432 => PortHint {
            service: "postgresql",
            probe: Probe::None,
            tls: false,
        },
        5900 => PortHint {
            service: "vnc",
            probe: Probe::Read,
            tls: false,
        },
        6379 => PortHint {
            service: "redis",
            probe: Probe::None,
            tls: false,
        },
        7547 => PortHint {
            service: "cwmp",
            probe: Probe::Http,
            tls: false,
        },
        8000 => PortHint {
            service: "http-alt",
            probe: Probe::Http,
            tls: false,
        },
        8080 => PortHint {
            service: "http-alt",
            probe: Probe::Http,
            tls: false,
        },
        8443 => PortHint {
            service: "https-alt",
            probe: Probe::None,
            tls: true,
        },
        8888 => PortHint {
            service: "http-alt",
            probe: Probe::Http,
            tls: false,
        },
        9100 => PortHint {
            service: "jetdirect",
            probe: Probe::None,
            tls: false,
        },
        32400 => PortHint {
            service: "plex",
            probe: Probe::Http,
            tls: false,
        },
        _ => return None,
    };
    Some(hint)
}

pub fn service_name_for_port(port: u16) -> Option<&'static str> {
    port_hint(port).map(|hint| hint.service)
}

/// A banner-derived service claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerFinding {
    pub service: String,
    pub version: Option<String>,
    pub confidence: Confidence,
}

/// Parse a text banner. Returns `None` when no useful claim can be made.
pub fn parse_banner(port: u16, banner: &str) -> Option<BannerFinding> {
    let trimmed = banner.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("SSH-") {
        // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
        let version = rest
            .split_once('-')
            .map(|(_, software)| software)
            .unwrap_or(rest);
        let version = version.split_whitespace().next().unwrap_or(version);
        return Some(BannerFinding {
            service: "ssh".to_string(),
            version: Some(version.to_string()),
            confidence: Confidence::High,
        });
    }

    if trimmed.starts_with("HTTP/") {
        let server = header_value(trimmed, "server");
        let (service, version) = match server {
            Some(server) => ("http".to_string(), Some(server)),
            None => ("http".to_string(), None),
        };
        return Some(BannerFinding {
            service,
            version,
            confidence: if header_value(trimmed, "server").is_some() {
                Confidence::High
            } else {
                Confidence::Medium
            },
        });
    }

    let lower = trimmed.to_ascii_lowercase();
    let (service, confidence) = if lower.starts_with("220") && lower.contains("ftp") {
        ("ftp", Confidence::Medium)
    } else if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("mail")) {
        ("smtp", Confidence::Medium)
    } else if lower.starts_with("220") {
        ("ftp", Confidence::Low)
    } else if lower.starts_with("+ok") {
        ("pop3", Confidence::Medium)
    } else if lower.starts_with("* ok") {
        ("imap", Confidence::Medium)
    } else if lower.starts_with("rtsp/") {
        ("rtsp", Confidence::Medium)
    } else if lower.contains("rfb") {
        ("vnc", Confidence::Medium)
    } else if lower.starts_with("http/") {
        ("http", Confidence::Medium)
    } else {
        return port_hint(port).map(|hint| BannerFinding {
            service: hint.service.to_string(),
            version: None,
            confidence: Confidence::Low,
        });
    };

    let version = first_line(trimmed);
    Some(BannerFinding {
        service: service.to_string(),
        version: if version.is_empty() {
            None
        } else {
            Some(version.to_string())
        },
        confidence,
    })
}

fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        } else {
            None
        }
    })
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("").trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_ports_are_sorted_and_unique() {
        let mut sorted = COMMON_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, COMMON_PORTS.to_vec());
    }

    #[test]
    fn parses_ssh_banner() {
        let finding = parse_banner(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").unwrap();
        assert_eq!(finding.service, "ssh");
        assert_eq!(finding.version.as_deref(), Some("OpenSSH_9.6p1"));
        assert_eq!(finding.confidence, Confidence::High);
    }

    #[test]
    fn parses_http_server_header() {
        let finding = parse_banner(
            80,
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(finding.service, "http");
        assert_eq!(finding.version.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(finding.confidence, Confidence::High);
    }

    #[test]
    fn empty_banner_yields_nothing() {
        assert!(parse_banner(80, " \r\n\0").is_none());
    }

    #[test]
    fn known_port_without_banner_is_a_low_confidence_hint() {
        let finding = parse_banner(445, "garbage").unwrap();
        assert_eq!(finding.service, "smb");
        assert_eq!(finding.confidence, Confidence::Low);
    }
}
