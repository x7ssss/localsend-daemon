//! Active Unicast Subnet HTTP Probe Scanner
//!
//! Provides proactive subnet sweeping fallback for networks where UDP multicast
//! is dropped due to Access Point (AP) isolation or aggressive IGMP snooping.
//! Sweeps local /24 subnets concurrently with bounded in-flight probes.

use crate::interfaces::{self, NetworkInterfaceInfo};
use crate::registry::PeerRegistry;
use localsend_protocol::{InfoResponseDto, RegisterDto};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Maximum concurrent in-flight HTTP probe requests.
pub const MAX_CONCURRENT_PROBES: usize = 64;

/// Connection and read timeout per HTTP probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(750);

/// Default LocalSend TCP port.
pub const DEFAULT_PORT: u16 = 53317;

/// Errors that can occur during subnet scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// HTTP client build error.
    #[error("HTTP client initialization failed: {0}")]
    HttpClient(#[from] reqwest::Error),
    /// Interface enumeration error.
    #[error("Interface resolution failed: {0}")]
    Interface(#[from] interfaces::InterfaceError),
}

/// Fallback active subnet scanner probing host IPs.
#[derive(Clone)]
pub struct SubnetScanner {
    client: reqwest::Client,
    registry: PeerRegistry,
    port: u16,
    max_concurrency: usize,
}

impl SubnetScanner {
    /// Creates a new SubnetScanner instance.
    pub fn new(registry: PeerRegistry, port: u16) -> Result<Self, ScannerError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .connect_timeout(PROBE_TIMEOUT)
            .timeout(PROBE_TIMEOUT)
            .build()?;

        Ok(Self {
            client,
            registry,
            port,
            max_concurrency: MAX_CONCURRENT_PROBES,
        })
    }

    /// Sets the maximum concurrent probes (default: 64).
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.max_concurrency = concurrency;
        self
    }

    /// Computes candidate host IPv4 addresses across all connected /24 subnets.
    pub fn enumerate_candidate_ips(interfaces: &[NetworkInterfaceInfo]) -> Vec<Ipv4Addr> {
        let mut candidates = HashSet::new();

        for iface in interfaces {
            let [a, b, c, own_host] = iface.ip.octets();
            for host in 1..=254 {
                if host == own_host {
                    continue; // Skip our own IP
                }
                candidates.insert(Ipv4Addr::new(a, b, c, host));
            }
        }

        let mut list: Vec<_> = candidates.into_iter().collect();
        list.sort();
        list
    }

    /// Probes a single host IP via LocalSend v2 HTTP/HTTPS endpoints.
    async fn probe_host(
        client: reqwest::Client,
        target_ip: Ipv4Addr,
        port: u16,
        our_registration: RegisterDto,
        registry: PeerRegistry,
    ) {
        let register_url = format!("https://{target_ip}:{port}/api/localsend/v2/register");

        // Attempt POST /register
        let res = client
            .post(&register_url)
            .json(&our_registration)
            .send()
            .await;

        if let Ok(response) = res
            && response.status().is_success()
        {
            // If the response body contains registration or device info, parse it
            if let Ok(reg_dto) = response.json::<RegisterDto>().await {
                let addr = SocketAddr::new(IpAddr::V4(target_ip), port);
                registry.upsert_from_register(&reg_dto, addr).await;
                return;
            }

            // If body was empty, query GET /info
            let info_url = format!("https://{target_ip}:{port}/api/localsend/v2/info");
            if let Ok(info_res) = client.get(&info_url).send().await
                && let Ok(info_dto) = info_res.json::<InfoResponseDto>().await
            {
                let reg = RegisterDto {
                    alias: info_dto.alias,
                    version: info_dto.version,
                    device_model: info_dto.device_model,
                    device_type: info_dto.device_type,
                    fingerprint: info_dto.fingerprint,
                    port: info_dto.port,
                    protocol: info_dto.protocol,
                    download: info_dto.download,
                };
                let addr = SocketAddr::new(IpAddr::V4(target_ip), port);
                registry.upsert_from_register(&reg, addr).await;
            }
        }
    }

    /// Concurrently sweep all connected /24 subnets, registering responding peers.
    pub async fn sweep_subnets(
        &self,
        our_registration: RegisterDto,
    ) -> Result<usize, ScannerError> {
        let interfaces = interfaces::get_eligible_interfaces().unwrap_or_default();
        let targets = Self::enumerate_candidate_ips(&interfaces);

        if targets.is_empty() {
            return Ok(0);
        }

        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = Vec::with_capacity(targets.len());

        for target_ip in targets {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let client = self.client.clone();
            let port = self.port;
            let reg = our_registration.clone();
            let registry = self.registry.clone();

            tasks.push(tokio::spawn(async move {
                Self::probe_host(client, target_ip, port, reg, registry).await;
                drop(permit);
            }));
        }

        for task in tasks {
            let _ = task.await;
        }

        Ok(self.registry.len().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_candidate_ips_skips_own_ip() {
        let ifaces = vec![NetworkInterfaceInfo {
            name: "eth0".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 50),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
        }];

        let candidates = SubnetScanner::enumerate_candidate_ips(&ifaces);
        // 254 total host IPs minus own IP (.50) = 253 candidate IPs
        assert_eq!(candidates.len(), 253);
        assert!(!candidates.contains(&Ipv4Addr::new(192, 168, 1, 50)));
        assert!(candidates.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(candidates.contains(&Ipv4Addr::new(192, 168, 1, 254)));
    }
}
