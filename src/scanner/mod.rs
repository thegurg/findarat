//! TCP scanning and port-spec parsing.

pub mod tcp;

use std::collections::BTreeSet;

pub use tcp::{scan_hosts, HostScanResult, ScanOptions, ScanProgress};

/// Parse a port specification.
///
/// Accepted forms: `common`, `all`, a single port (`22`), a range
/// (`1-1024`), or a comma-separated combination (`22,80,443,8000-8100`).
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("port specification must not be empty".into());
    }
    let lower = spec.to_ascii_lowercase();
    if lower == "common" {
        return Ok(crate::fingerprint::services::COMMON_PORTS.to_vec());
    }
    if lower == "all" {
        return Ok((1..=u16::MAX).collect());
    }

    let mut ports = BTreeSet::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err("empty entry in port list".into());
        }
        if let Some((start, end)) = token.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("port range {token} is reversed"));
            }
            for port in start..=end {
                ports.insert(port);
            }
        } else {
            ports.insert(parse_port(token)?);
        }
    }

    if ports.is_empty() {
        return Err("port specification contains no ports".into());
    }
    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty port number".into());
    }
    let port: u32 = value
        .parse()
        .map_err(|_| format!("invalid port number {value:?}"))?;
    if !(1..=u32::from(u16::MAX)).contains(&port) {
        return Err(format!("port {port} is outside 1-65535"));
    }
    Ok(port as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common() {
        let ports = parse_ports("common").unwrap();
        assert!(ports.contains(&22));
        assert!(ports.contains(&443));
        assert!(ports.windows(2).all(|window| window[0] < window[1]));
    }

    #[test]
    fn parses_ranges_and_lists() {
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_ports("443,22,80,22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("22, 80-82").unwrap(), vec![22, 80, 81, 82]);
    }

    #[test]
    fn parses_all() {
        let ports = parse_ports("all").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&65535));
    }

    #[test]
    fn rejects_invalid_specs() {
        for spec in ["", "0", "65536", "80-22", "1,,2", "abc", "1-"] {
            assert!(parse_ports(spec).is_err(), "{spec:?} should be rejected");
        }
    }

    #[test]
    fn canonicalises_whitespace_and_case() {
        assert_eq!(
            parse_ports("  COMMON ").unwrap(),
            parse_ports("common").unwrap()
        );
    }
}
