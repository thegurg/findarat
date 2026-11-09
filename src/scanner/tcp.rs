//! Configurable, bounded TCP port scanning.
//!
//! The scanner uses ordinary TCP connects, which do not require elevated
//! privileges. It never sends exploit payloads. Banner collection is limited
//! to a HEAD request for plaintext HTTP and a passive read for services that
//! greet clients.

use chrono::Utc;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::fingerprint::services::{parse_banner, port_hint, Probe};
use crate::models::{Confidence, PortObservation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub concurrency: usize,
    pub rate_limit_per_sec: u32,
    pub banner_grab: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            concurrency: 100,
            rate_limit_per_sec: 0,
            banner_grab: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostScanResult {
    pub ip: IpAddr,
    pub open_ports: Vec<PortObservation>,
    pub attempted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanProgress {
    Started {
        total: usize,
    },
    Progress {
        completed: usize,
        total: usize,
        open_ports: usize,
    },
    Finished {
        total: usize,
        open_ports: usize,
    },
}

struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    fn new(rate_per_sec: u32) -> Self {
        let interval = Duration::from_secs_f64(1.0 / f64::from(rate_per_sec.max(1)));
        Self {
            interval,
            next: Mutex::new(Instant::now()),
        }
    }

    async fn wait(&self) {
        let mut next = self.next.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = Instant::now() + self.interval;
    }
}

/// Scan the cartesian product of `ips` and `ports`, bounded by
/// `options.concurrency`. Results contain only open ports.
pub async fn scan_hosts(
    ips: &[IpAddr],
    ports: &[u16],
    options: &ScanOptions,
    progress: Option<mpsc::UnboundedSender<ScanProgress>>,
) -> Vec<HostScanResult> {
    let mut ips = ips.to_vec();
    ips.sort();
    ips.dedup();
    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();

    if ips.is_empty() || ports.is_empty() {
        return Vec::new();
    }

    let total = ips.len().saturating_mul(ports.len());
    let concurrency = options.concurrency.max(1);
    let limiter = if options.rate_limit_per_sec > 0 {
        Some(Arc::new(RateLimiter::new(options.rate_limit_per_sec)))
    } else {
        None
    };

    if let Some(tx) = &progress {
        let _ = tx.send(ScanProgress::Started { total });
    }

    let mut tasks: JoinSet<Option<PortObservation>> = JoinSet::new();
    let mut index = 0usize;
    let mut completed = 0usize;
    let mut open_count = 0usize;
    let mut results: HashMap<IpAddr, Vec<PortObservation>> = HashMap::new();

    while index < total || !tasks.is_empty() {
        while tasks.len() < concurrency && index < total {
            let ip = ips[index / ports.len()];
            let port = ports[index % ports.len()];
            index += 1;
            let options = options.clone();
            let limiter = limiter.clone();
            tasks.spawn(async move {
                if let Some(limiter) = limiter {
                    limiter.wait().await;
                }
                probe(ip, port, &options).await
            });
        }

        let Some(joined) = tasks.join_next().await else {
            break;
        };
        completed += 1;
        match joined {
            Ok(Some(observation)) => {
                open_count += 1;
                results.entry(observation.ip).or_default().push(observation);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(%error, "port probe task failed");
            }
        }

        if let Some(tx) = &progress {
            if completed == total || completed.is_multiple_of(16) {
                let _ = tx.send(ScanProgress::Progress {
                    completed,
                    total,
                    open_ports: open_count,
                });
            }
        }
    }

    if let Some(tx) = &progress {
        let _ = tx.send(ScanProgress::Finished {
            total,
            open_ports: open_count,
        });
    }

    let mut output: Vec<HostScanResult> = results
        .into_iter()
        .map(|(ip, mut open_ports)| {
            open_ports.sort_by_key(|port| port.port);
            HostScanResult {
                ip,
                open_ports,
                attempted: ports.len(),
            }
        })
        .collect();
    output.sort_by_key(|result| result.ip);
    output
}

async fn probe(ip: IpAddr, port: u16, options: &ScanOptions) -> Option<PortObservation> {
    let address = SocketAddr::new(ip, port);
    let mut stream = match timeout(options.timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::trace!(%ip, port, %error, "connect failed");
            return None;
        }
        Err(_) => {
            tracing::trace!(%ip, port, "connect timed out");
            return None;
        }
    };

    let now = Utc::now();
    let mut observation = PortObservation::open(ip, port, now);

    if let Some(hint) = port_hint(port) {
        observation.service = Some(hint.service.to_string());
        observation.confidence = Confidence::Medium;
    }

    if options.banner_grab {
        if let Some(banner) = grab_banner(&mut stream, ip, port, options.timeout).await {
            if let Some(finding) = parse_banner(port, &banner) {
                if finding.confidence.rank() >= observation.confidence.rank() {
                    observation.service = Some(finding.service);
                    observation.version = finding.version;
                    observation.confidence = finding.confidence;
                }
            }
            observation.banner = Some(banner);
        }
    }

    Some(observation)
}

async fn grab_banner(
    stream: &mut TcpStream,
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Option<String> {
    let probe = port_hint(port).map(|hint| hint.probe);
    match probe {
        Some(Probe::None) => None,
        Some(Probe::Http) => {
            let request = format!(
                "HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: findarat/{}\r\nConnection: close\r\n\r\n",
                crate::VERSION
            );
            timeout(timeout_duration, stream.write_all(request.as_bytes()))
                .await
                .ok()
                .and_then(Result::ok)?;
            read_banner(stream, timeout_duration).await
        }
        Some(Probe::Read) => read_banner(stream, timeout_duration).await,
        None => {
            // Unknown port: make a short passive attempt. This can identify a
            // service that greets clients, without sending application data.
            read_banner(stream, timeout_duration.min(Duration::from_millis(300))).await
        }
    }
}

async fn read_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    let mut buffer = [0u8; 512];
    match timeout(timeout_duration, stream.read(&mut buffer)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
        Ok(Ok(read)) => {
            let text: String = buffer[..read]
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || matches!(byte, b'\r' | b'\n' | b'\t' | b' ') {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                })
                .collect();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn finds_open_port_and_reads_ssh_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.9 test\r\n").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let options = ScanOptions {
            timeout: Duration::from_millis(500),
            concurrency: 4,
            rate_limit_per_sec: 0,
            banner_grab: true,
        };
        let results = scan_hosts(&[IpAddr::from([127, 0, 0, 1])], &[port], &options, None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].open_ports.len(), 1);
        let observation = &results[0].open_ports[0];
        assert_eq!(observation.service.as_deref(), Some("ssh"));
        assert_eq!(observation.version.as_deref(), Some("OpenSSH_9.9"));
        assert_eq!(observation.confidence, Confidence::High);
    }

    #[tokio::test]
    async fn closed_port_is_not_reported() {
        // Bind then drop to obtain a very likely closed port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let options = ScanOptions {
            timeout: Duration::from_millis(200),
            concurrency: 1,
            rate_limit_per_sec: 0,
            banner_grab: false,
        };
        let results = scan_hosts(&[IpAddr::from([127, 0, 0, 1])], &[port], &options, None).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn reports_progress() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let options = ScanOptions {
            timeout: Duration::from_millis(100),
            concurrency: 2,
            rate_limit_per_sec: 0,
            banner_grab: false,
        };
        let _ = scan_hosts(&[IpAddr::from([127, 0, 0, 1])], &[1, 2], &options, Some(tx)).await;
        let mut saw_started = false;
        let mut saw_finished = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                ScanProgress::Started { .. } => saw_started = true,
                ScanProgress::Finished { .. } => saw_finished = true,
                ScanProgress::Progress { .. } => {}
            }
        }
        assert!(saw_started);
        assert!(saw_finished);
    }
}
