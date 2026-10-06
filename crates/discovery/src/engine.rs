//! High-Level Discovery Engine Coordinator
//!
//! Orchestrates passive multicast UDP listening/announcing, in-memory peer
//! caching, and fallback active subnet sweeping.

use crate::multicast::{MulticastConfig, MulticastEngine, MulticastError};
use crate::registry::PeerRegistry;
use crate::scanner::{ScannerError, SubnetScanner};
use localsend_protocol::{MulticastAnnouncement, RegisterDto};

/// Coordinated dual-path discovery engine.
pub struct DiscoveryEngine {
    multicast: MulticastEngine,
    scanner: SubnetScanner,
    registry: PeerRegistry,
}

impl DiscoveryEngine {
    /// Creates a new discovery engine with the given multicast configuration and peer registry.
    pub fn new(config: MulticastConfig, registry: PeerRegistry) -> Result<Self, MulticastError> {
        let port = config.port;
        let multicast = MulticastEngine::new(config, registry.clone())?;
        let scanner = SubnetScanner::new(registry.clone(), port).map_err(|e| match e {
            ScannerError::HttpClient(he) => {
                MulticastError::Io(std::io::Error::new(std::io::ErrorKind::Other, he.to_string()))
            }
            ScannerError::Interface(ie) => MulticastError::Interface(ie),
        })?;

        Ok(Self {
            multicast,
            scanner,
            registry,
        })
    }

    /// Access the underlying peer registry.
    pub fn registry(&self) -> &PeerRegistry {
        &self.registry
    }

    /// Access the multicast engine.
    pub fn multicast(&self) -> &MulticastEngine {
        &self.multicast
    }

    /// Access the subnet scanner.
    pub fn scanner(&self) -> &SubnetScanner {
        &self.scanner
    }

    /// Broadcast the initial announcement burst across all network interfaces.
    pub async fn broadcast_burst(&self, announcement: &MulticastAnnouncement) {
        self.multicast.broadcast_burst(announcement).await;
    }

    /// Execute an active HTTP sweep of all local /24 subnets.
    pub async fn sweep_subnets(
        &self,
        our_registration: RegisterDto,
    ) -> Result<usize, ScannerError> {
        self.scanner.sweep_subnets(our_registration).await
    }

    /// Start the background receiver and heartbeat tasks.
    pub fn start(
        &self,
        announcement: MulticastAnnouncement,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        self.multicast.start(announcement)
    }

    /// Stop all background multicast tasks.
    pub fn stop(&self) {
        self.multicast.stop();
    }
}
