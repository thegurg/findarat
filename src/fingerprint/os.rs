//! Evidence-based operating-system inference.
//!
//! This module is deliberately conservative. It only reports an OS when a
//! banner, advertised model, or hostname provides a specific hint. Vendor
//! alone is not enough.

use crate::models::Confidence;

use super::hostname::hostname_os_hint;

#[derive(Debug, Clone)]
pub struct OsInput<'a> {
    pub hostname: Option<&'a str>,
    /// SSH software strings, e.g. `OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
    pub ssh_banners: &'a [String],
    /// HTTP `Server` header values.
    pub http_servers: &'a [String],
    pub ssdp_manufacturer: Option<&'a str>,
    pub ssdp_model: Option<&'a str>,
    pub netbios_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsFinding {
    pub os: &'static str,
    pub confidence: Confidence,
    pub source: &'static str,
    pub reason: String,
}

pub fn infer_os(input: &OsInput<'_>) -> Vec<OsFinding> {
    let mut findings = Vec::new();
    let mut push = |os, confidence, source, reason: &str| {
        findings.push(OsFinding {
            os,
            confidence,
            source,
            reason: reason.to_string(),
        });
    };

    for banner in input.ssh_banners {
        let lower = banner.to_ascii_lowercase();
        if lower.contains("ubuntu") || lower.contains("debian") || lower.contains("raspbian") {
            push(
                "Linux",
                Confidence::Medium,
                "ssh_banner",
                "SSH banner names a Linux distribution",
            );
        } else if lower.contains("freebsd") {
            push(
                "FreeBSD",
                Confidence::Medium,
                "ssh_banner",
                "SSH banner names FreeBSD",
            );
        } else if lower.contains("openbsd") {
            push(
                "OpenBSD",
                Confidence::Medium,
                "ssh_banner",
                "SSH banner names OpenBSD",
            );
        } else if lower.contains("windows") {
            push(
                "Windows",
                Confidence::Medium,
                "ssh_banner",
                "SSH banner names Windows",
            );
        } else if lower.contains("openssh") {
            push(
                "Unix-like",
                Confidence::Low,
                "ssh_banner",
                "OpenSSH is present; the underlying OS is not identified",
            );
        }
    }

    for server in input.http_servers {
        let lower = server.to_ascii_lowercase();
        if lower.contains("ubuntu") || lower.contains("debian") || lower.contains("linux") {
            push(
                "Linux",
                Confidence::Medium,
                "http_server",
                "HTTP Server header names Linux",
            );
        } else if lower.contains("windows") || lower.contains("iis") {
            push(
                "Windows",
                Confidence::Medium,
                "http_server",
                "HTTP Server header names Windows/IIS",
            );
        } else if lower.contains("darwin") || lower.contains("macos") {
            push(
                "macOS",
                Confidence::Medium,
                "http_server",
                "HTTP Server header names macOS",
            );
        }
    }

    if let Some(hostname) = input.hostname {
        if let Some(hint) = hostname_os_hint(hostname) {
            push(hint.os, hint.confidence, "hostname", &hint.reason);
        }
    }

    if let Some(model) = input.ssdp_model {
        let lower = model.to_ascii_lowercase();
        if lower.contains("roku") {
            push(
                "Roku OS",
                Confidence::Low,
                "ssdp",
                "UPnP model names a Roku device",
            );
        } else if lower.contains("apple tv") || lower.contains("appletv") {
            push(
                "tvOS",
                Confidence::Low,
                "ssdp",
                "UPnP model names an Apple TV",
            );
        } else if lower.contains("android") {
            push(
                "Android",
                Confidence::Low,
                "ssdp",
                "UPnP model names Android",
            );
        }
    }
    if let Some(manufacturer) = input.ssdp_manufacturer {
        let lower = manufacturer.to_ascii_lowercase();
        if lower.contains("roku") {
            push(
                "Roku OS",
                Confidence::Low,
                "ssdp",
                "UPnP manufacturer is Roku",
            );
        } else if lower.contains("sonos") {
            push(
                "Sonos OS",
                Confidence::Low,
                "ssdp",
                "UPnP manufacturer is Sonos",
            );
        }
    }

    if input.netbios_present {
        push(
            "Windows or Samba",
            Confidence::Low,
            "netbios",
            "host answers NetBIOS name queries; Samba is indistinguishable from Windows here",
        );
    }

    findings.sort_by(|a, b| {
        b.confidence
            .rank()
            .cmp(&a.confidence.rank())
            .then_with(|| a.os.cmp(b.os))
    });
    findings
}

pub fn best(findings: &[OsFinding]) -> Option<&OsFinding> {
    findings.first()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_ubuntu_banner_infers_linux() {
        let banners = vec!["OpenSSH_9.6p1 Ubuntu-3ubuntu13".to_string()];
        let input = OsInput {
            hostname: None,
            ssh_banners: &banners,
            http_servers: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        let findings = infer_os(&input);
        let best = best(&findings).unwrap();
        assert_eq!(best.os, "Linux");
        assert_eq!(best.confidence, Confidence::Medium);
    }

    #[test]
    fn netbios_alone_is_low_confidence_and_ambiguous() {
        let input = OsInput {
            hostname: None,
            ssh_banners: &[],
            http_servers: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: true,
        };
        let findings = infer_os(&input);
        let best = best(&findings).unwrap();
        assert_eq!(best.confidence, Confidence::Low);
        assert!(best.os.contains("Samba"));
    }

    #[test]
    fn no_evidence_produces_no_os() {
        let input = OsInput {
            hostname: None,
            ssh_banners: &[],
            http_servers: &[],
            ssdp_manufacturer: None,
            ssdp_model: None,
            netbios_present: false,
        };
        assert!(infer_os(&input).is_empty());
    }
}
