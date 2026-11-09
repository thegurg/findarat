//! Minimal DNS wire-format support for mDNS.
//!
//! Only the record types needed for service discovery are decoded: A, AAAA,
//! PTR, SRV, and TXT. Unknown records are skipped safely.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;

pub const CLASS_IN: u16 = 1;
pub const CLASS_QU: u16 = 0x8000;

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS packet is truncated")]
    Truncated,
    #[error("invalid DNS name encoding")]
    InvalidName,
    #[error("DNS name compression pointer loop")]
    PointerLoop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt(Vec<String>),
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub records: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// Encode a DNS query. `unicast_response` sets the mDNS QU bit.
pub fn build_query(name: &str, qtype: u16, unicast_response: bool) -> Result<Vec<u8>, DnsError> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&0u16.to_be_bytes()); // transaction id
    packet.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    packet.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    packet.extend_from_slice(&0u16.to_be_bytes()); // ancount
    packet.extend_from_slice(&0u16.to_be_bytes()); // nscount
    packet.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(name, &mut packet)?;
    packet.extend_from_slice(&qtype.to_be_bytes());
    let qclass = CLASS_IN | if unicast_response { CLASS_QU } else { 0 };
    packet.extend_from_slice(&qclass.to_be_bytes());
    Ok(packet)
}

pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

pub fn parse_message(data: &[u8]) -> Result<DnsMessage, DnsError> {
    if data.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut position = 12usize;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let (name, next) = read_name(data, position)?;
        position = next;
        if position + 4 > data.len() {
            return Err(DnsError::Truncated);
        }
        let qtype = u16::from_be_bytes([data[position], data[position + 1]]);
        let qclass = u16::from_be_bytes([data[position + 2], data[position + 3]]);
        position += 4;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    let total_records = ancount.saturating_add(nscount).saturating_add(arcount);
    let mut records = Vec::with_capacity(total_records);
    for _ in 0..total_records {
        let (name, next) = read_name(data, position)?;
        position = next;
        if position + 10 > data.len() {
            return Err(DnsError::Truncated);
        }
        let record_type = u16::from_be_bytes([data[position], data[position + 1]]);
        let class = u16::from_be_bytes([data[position + 2], data[position + 3]]);
        let ttl = u32::from_be_bytes([
            data[position + 4],
            data[position + 5],
            data[position + 6],
            data[position + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[position + 8], data[position + 9]]) as usize;
        position += 10;
        if position + rdlength > data.len() {
            return Err(DnsError::Truncated);
        }
        let rdata = &data[position..position + rdlength];
        let parsed = parse_rdata(record_type, rdata, data, position)?;
        records.push(DnsRecord {
            name,
            record_type,
            class,
            ttl,
            data: parsed,
        });
        position += rdlength;
    }

    Ok(DnsMessage {
        id,
        flags,
        questions,
        records,
    })
}

fn parse_rdata(
    record_type: u16,
    rdata: &[u8],
    packet: &[u8],
    rdata_position: usize,
) -> Result<RData, DnsError> {
    match record_type {
        TYPE_A => {
            if rdata.len() != 4 {
                return Err(DnsError::Truncated);
            }
            Ok(RData::A(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )))
        }
        TYPE_AAAA => {
            if rdata.len() != 16 {
                return Err(DnsError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ok(RData::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_PTR => {
            let (name, _) = read_name(packet, rdata_position)?;
            Ok(RData::Ptr(name))
        }
        TYPE_SRV => {
            if rdata.len() < 7 {
                return Err(DnsError::Truncated);
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, _) = read_name(packet, rdata_position + 6)?;
            Ok(RData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        TYPE_TXT => {
            let mut strings = Vec::new();
            let mut cursor = 0usize;
            while cursor < rdata.len() {
                let len = rdata[cursor] as usize;
                cursor += 1;
                if cursor + len > rdata.len() {
                    return Err(DnsError::Truncated);
                }
                strings.push(String::from_utf8_lossy(&rdata[cursor..cursor + len]).into_owned());
                cursor += len;
            }
            Ok(RData::Txt(strings))
        }
        _ => Ok(RData::Other(rdata.to_vec())),
    }
}

pub(crate) fn read_name(data: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = start;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        if cursor >= data.len() {
            return Err(DnsError::Truncated);
        }
        let length = data[cursor];
        if length == 0 {
            cursor += 1;
            if !jumped {
                end = cursor;
            }
            break;
        }
        if length & 0xC0 == 0xC0 {
            if cursor + 1 >= data.len() {
                return Err(DnsError::Truncated);
            }
            let pointer = (((length & 0x3F) as usize) << 8) | data[cursor + 1] as usize;
            if !jumped {
                end = cursor + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > 32 || pointer >= data.len() {
                return Err(DnsError::PointerLoop);
            }
            cursor = pointer;
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(DnsError::InvalidName);
        }
        let length = length as usize;
        if cursor + 1 + length > data.len() {
            return Err(DnsError::Truncated);
        }
        let label = std::str::from_utf8(&data[cursor + 1..cursor + 1 + length])
            .map_err(|_| DnsError::InvalidName)?;
        labels.push(label.to_string());
        cursor += 1 + length;
        if !jumped {
            end = cursor;
        }
    }

    Ok((labels.join("."), end))
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::Aaaa(ip) => write!(f, "{ip}"),
            Self::Ptr(name) => write!(f, "{name}"),
            Self::Srv { port, target, .. } => write!(f, "{target}:{port}"),
            Self::Txt(values) => write!(f, "{}", values.join(" ")),
            Self::Other(bytes) => write!(f, "<{} bytes>", bytes.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_query() {
        let packet = build_query("_http._tcp.local", TYPE_PTR, true).unwrap();
        assert_eq!(packet[4..6], [0, 1]);
        let message = parse_message(&packet).unwrap();
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "_http._tcp.local");
        assert_eq!(message.questions[0].qtype, TYPE_PTR);
        assert_eq!(message.questions[0].qclass, CLASS_IN | CLASS_QU);
    }

    #[test]
    fn parses_compressed_ptr_srv_txt_and_a_records() {
        // Hand-built mDNS response:
        // header, no questions, 4 answers.
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0x8400u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Answer 1: _http._tcp.local PTR "printer._http._tcp.local"
        encode_name("_http._tcp.local", &mut packet).unwrap();
        packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name("printer._http._tcp.local", &mut rdata).unwrap();
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);

        // Answer 2: printer._http._tcp.local SRV target printer.local:80
        let srv_name_offset = packet.len();
        encode_name("printer._http._tcp.local", &mut packet).unwrap();
        packet.extend_from_slice(&TYPE_SRV.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let mut srv = Vec::new();
        srv.extend_from_slice(&0u16.to_be_bytes());
        srv.extend_from_slice(&0u16.to_be_bytes());
        srv.extend_from_slice(&80u16.to_be_bytes());
        encode_name("printer.local", &mut srv).unwrap();
        packet.extend_from_slice(&(srv.len() as u16).to_be_bytes());
        packet.extend_from_slice(&srv);

        // Answer 3: TXT with a compression pointer to the SRV name.
        packet.push(0xC0);
        packet.push(srv_name_offset as u8);
        packet.extend_from_slice(&TYPE_TXT.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        let txt = [9u8, b'k', b'e', b'y', b'=', b'v', b'a', b'l', b'u', b'e'];
        packet.extend_from_slice(&(txt.len() as u16).to_be_bytes());
        packet.extend_from_slice(&txt);

        // Answer 4: printer.local A 192.168.1.50
        encode_name("printer.local", &mut packet).unwrap();
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 168, 1, 50]);

        let message = parse_message(&packet).unwrap();
        assert_eq!(message.records.len(), 4);
        assert_eq!(
            message.records[0].data,
            RData::Ptr("printer._http._tcp.local".to_string())
        );
        assert_eq!(
            message.records[1].data,
            RData::Srv {
                priority: 0,
                weight: 0,
                port: 80,
                target: "printer.local".to_string()
            }
        );
        assert_eq!(
            message.records[2].data,
            RData::Txt(vec!["key=value".to_string()])
        );
        assert_eq!(
            message.records[3].data,
            RData::A(Ipv4Addr::new(192, 168, 1, 50))
        );
    }

    #[test]
    fn rejects_truncated_packets() {
        assert!(parse_message(&[0u8; 4]).is_err());
    }

    #[test]
    fn rejects_bad_labels() {
        let mut out = Vec::new();
        assert!(encode_name("bad..name", &mut out).is_err());
    }
}
