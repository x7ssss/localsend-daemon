//! Multi-NIC Multicast UDP Discovery Engine
//!
//! Handles passive discovery via IPv4 (224.0.0.167:53317) and IPv6 (ff12::fd3a:e420:53317).
//! Binds dedicated per-NIC egress sockets, joins multicast groups across all physical adapters,
//! and executes zero-allocation filtered reception and announcement bursts.

use crate::filter;
use crate::interfaces::{self, NetworkInterfaceInfo};
use crate::registry::PeerRegistry;
use localsend_protocol::MulticastAnnouncement;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Default LocalSend discovery port.
pub const DEFAULT_PORT: u16 = 53317;

/// Primary LocalSend IPv4 Multicast Group.
pub const MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 167);

/// Secondary LocalSend IPv6 Multicast Group.
pub const MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff12, 0, 0, 0, 0, 0, 0xfd3a, 0xe420);

/// Errors encountered in the multicast discovery engine.
#[derive(Debug, thiserror::Error)]
pub enum MulticastError {
    /// Socket creation or I/O failure.
    #[error("Socket I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// Interface enumeration error.
    #[error("Interface query failure: {0}")]
    Interface(#[from] interfaces::InterfaceError),
    /// Serialization error.
    #[error("Serialization failure: {0}")]
    Json(#[from] serde_json::Error),
}

/// Configuration parameters for the multicast engine.
#[derive(Debug, Clone)]
pub struct MulticastConfig {
    /// Listening and broadcast port (default: 53317).
    pub port: u16,
    /// Local node's uppercase fingerprint for self-echo loopback suppression.
    pub local_fingerprint: String,
    /// Periodic idle announcement heartbeat interval (default: 60s).
    pub heartbeat_interval: Duration,
}

impl Default for MulticastConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            local_fingerprint: String::new(),
            heartbeat_interval: Duration::from_secs(60),
        }
    }
}

/// Multi-NIC UDP Multicast discovery engine.
pub struct MulticastEngine {
    config: MulticastConfig,
    ingress: Arc<UdpSocket>,
    egress_sockets: Vec<Arc<UdpSocket>>,
    registry: PeerRegistry,
    cancel_token: CancellationToken,
}

impl MulticastEngine {
    /// Initialize the multicast discovery engine across all eligible system interfaces.
    pub fn new(
        config: MulticastConfig,
        registry: PeerRegistry,
    ) -> Result<Self, MulticastError> {
        let interfaces = interfaces::get_eligible_interfaces().unwrap_or_default();
        let ingress = Arc::new(Self::create_ingress_socket(config.port, &interfaces)?);
        let egress_sockets = Self::create_egress_sockets(&interfaces)?;

        Ok(Self {
            config,
            ingress,
            egress_sockets,
            registry,
            cancel_token: CancellationToken::new(),
        })
    }

    /// Creates the ingress listener UDP socket with SO_REUSEADDR and multi-NIC group joins.
    fn create_ingress_socket(
        port: u16,
        interfaces: &[NetworkInterfaceInfo],
    ) -> Result<UdpSocket, std::io::Error> {
        let domain = socket2::Domain::IPV4;
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true)?;

        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        let _ = socket.set_reuse_port(true);

        socket.set_nonblocking(true)?;

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        socket.bind(&socket2::SockAddr::from(bind_addr))?;

        // Attempt joining with 0.0.0.0 default route
        let _ = socket.join_multicast_v4(&MULTICAST_IPV4, &Ipv4Addr::UNSPECIFIED);

        // Explicitly join across every eligible physical interface
        for iface in interfaces {
            if let Err(e) = socket.join_multicast_v4(&MULTICAST_IPV4, &iface.ip) {
                tracing::debug!("Join multicast on {} failed: {e}", iface.ip);
            }
        }

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }

    /// Creates egress sockets per eligible interface for multi-homed broadcasting.
    fn create_egress_sockets(
        interfaces: &[NetworkInterfaceInfo],
    ) -> Result<Vec<Arc<UdpSocket>>, std::io::Error> {
        let mut sockets = Vec::new();

        for iface in interfaces {
            let domain = socket2::Domain::IPV4;
            let socket = match socket2::Socket::new(
                domain,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let _ = socket.set_reuse_address(true);
            #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
            let _ = socket.set_reuse_port(true);

            let _ = socket.set_multicast_if_v4(&iface.ip);
            let _ = socket.set_multicast_loop_v4(true);
            let _ = socket.set_multicast_ttl_v4(1);
            let _ = socket.set_nonblocking(true);

            let bind_addr = SocketAddrV4::new(iface.ip, 0);
            if socket.bind(&socket2::SockAddr::from(bind_addr)).is_ok() {
                let std_sock: std::net::UdpSocket = socket.into();
                if let Ok(tokio_sock) = UdpSocket::from_std(std_sock) {
                    sockets.push(Arc::new(tokio_sock));
                }
            }
        }

        // If no per-interface socket succeeded, create a wildcard fallback socket
        if sockets.is_empty() {
            let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
            std_sock.set_nonblocking(true)?;
            let _ = std_sock.set_multicast_loop_v4(true);
            let _ = std_sock.set_multicast_ttl_v4(1);
            let tokio_sock = UdpSocket::from_std(std_sock)?;
            sockets.push(Arc::new(tokio_sock));
        }

        Ok(sockets)
    }

    /// Broadcast a single announcement datagram across all egress sockets.
    pub async fn broadcast(&self, announcement: &MulticastAnnouncement) -> usize {
        let payload = match serde_json::to_vec(announcement) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to serialize announcement: {e}");
                return 0;
            }
        };

        let target = SocketAddr::V4(SocketAddrV4::new(MULTICAST_IPV4, self.config.port));
        let mut count = 0;

        for socket in &self.egress_sockets {
            if socket.send_to(&payload, target).await.is_ok() {
                count += 1;
            }
        }

        count
    }

    /// Execute initial announcement burst: 3 datagrams at 0ms, 100ms, and 500ms.
    pub async fn broadcast_burst(&self, announcement: &MulticastAnnouncement) {
        // Burst 1: 0ms
        self.broadcast(announcement).await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        // Burst 2: 100ms
        self.broadcast(announcement).await;

        tokio::time::sleep(Duration::from_millis(400)).await;
        // Burst 3: 500ms from start
        self.broadcast(announcement).await;
    }

    /// Spawn continuous background receiver and periodic heartbeat announcer tasks.
    pub fn start(
        &self,
        announcement: MulticastAnnouncement,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let ingress = Arc::clone(&self.ingress);
        let registry = self.registry.clone();
        let local_fp = self.config.local_fingerprint.clone();
        let cancel_rx = self.cancel_token.clone();

        // Ingress receiver task
        let rx_handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = cancel_rx.cancelled() => break,
                    recv_res = ingress.recv_from(&mut buf) => {
                        let (len, src_addr) = match recv_res {
                            Ok(val) => val,
                            Err(e) => {
                                tracing::debug!("UDP recv_from error: {e}");
                                continue;
                            }
                        };

                        let packet = &buf[..len];
                        if !filter::should_process_packet(packet, &local_fp) {
                            continue;
                        }

                        if let Ok(peer_ann) = serde_json::from_slice::<MulticastAnnouncement>(packet) {
                            registry.upsert_from_announcement(&peer_ann, src_addr).await;
                        }
                    }
                }
            }
        });

        // Periodic heartbeat announcer task
        let egress = self.egress_sockets.clone();
        let port = self.config.port;
        let heartbeat_interval = self.config.heartbeat_interval;
        let cancel_tx = self.cancel_token.clone();

        let tx_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(heartbeat_interval);
            let target = SocketAddr::V4(SocketAddrV4::new(MULTICAST_IPV4, port));

            loop {
                tokio::select! {
                    _ = cancel_tx.cancelled() => break,
                    _ = ticker.tick() => {
                        if let Ok(payload) = serde_json::to_vec(&announcement) {
                            for socket in &egress {
                                let _ = socket.send_to(&payload, target).await;
                            }
                        }
                    }
                }
            }
        });

        (rx_handle, tx_handle)
    }

    /// Stop the background receiver and heartbeat tasks.
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }
}
