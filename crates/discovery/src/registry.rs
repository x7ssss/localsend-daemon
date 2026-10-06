//! In-Memory Thread-Safe Peer Registry
//!
//! Tracks active LocalSend peers discovered via multicast UDP or active subnet sweep.
//! Implements TTL-based eviction for stale nodes and event notifications.

use localsend_protocol::{DeviceType, MulticastAnnouncement, ProtocolType, RegisterDto};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};

/// Metadata and network location of a discovered LocalSend peer.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredPeer {
    /// Canonical uppercase SHA-256 certificate fingerprint.
    pub fingerprint: String,
    /// Human-friendly display alias.
    pub alias: String,
    /// Hardware/device model name.
    pub device_model: Option<String>,
    /// Device category.
    pub device_type: Option<DeviceType>,
    /// Network IP address of peer.
    pub ip: IpAddr,
    /// HTTP/HTTPS TCP port.
    pub port: u16,
    /// Transport protocol (HTTP / HTTPS).
    pub protocol: ProtocolType,
    /// Whether the peer accepts incoming file downloads.
    pub download: bool,
    /// Timestamp of most recent discovery or announcement receipt.
    pub last_seen: Instant,
}

/// Events emitted when peer state transitions occur in the registry.
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryEvent {
    /// A new peer was discovered.
    Discovered(DiscoveredPeer),
    /// An existing peer was updated.
    Updated(DiscoveredPeer),
    /// A peer was evicted due to inactivity.
    Evicted(String),
}

/// Thread-safe concurrent registry of discovered peers.
#[derive(Debug, Clone)]
pub struct PeerRegistry {
    peers: Arc<RwLock<HashMap<String, DiscoveredPeer>>>,
    notifier: broadcast::Sender<RegistryEvent>,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    /// Creates a new empty peer registry.
    pub fn new() -> Self {
        let (notifier, _) = broadcast::channel(64);
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            notifier,
        }
    }

    /// Subscribe to real-time peer state transitions.
    pub fn subscribe(&self) -> broadcast::Receiver<RegistryEvent> {
        self.notifier.subscribe()
    }

    /// Number of peers currently recorded in the registry.
    pub async fn len(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Whether the registry is currently empty.
    pub async fn is_empty(&self) -> bool {
        self.peers.read().await.is_empty()
    }

    /// Retrieve a peer by canonical fingerprint.
    pub async fn get(&self, fingerprint: &str) -> Option<DiscoveredPeer> {
        let normalized = fingerprint.to_ascii_uppercase();
        self.peers.read().await.get(&normalized).cloned()
    }

    /// Retrieve a snapshot of all active peers.
    pub async fn list(&self) -> Vec<DiscoveredPeer> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Insert or update a peer entry. Returns `true` if newly discovered, `false` if updated.
    pub async fn upsert(&self, mut peer: DiscoveredPeer) -> bool {
        peer.fingerprint = peer.fingerprint.to_ascii_uppercase();
        let mut map = self.peers.write().await;
        let is_new = !map.contains_key(&peer.fingerprint);

        map.insert(peer.fingerprint.clone(), peer.clone());
        drop(map);

        let event = if is_new {
            RegistryEvent::Discovered(peer)
        } else {
            RegistryEvent::Updated(peer)
        };
        let _ = self.notifier.send(event);

        is_new
    }

    /// Upsert a peer from a received multicast announcement.
    pub async fn upsert_from_announcement(
        &self,
        ann: &MulticastAnnouncement,
        src_addr: SocketAddr,
    ) -> bool {
        let peer = DiscoveredPeer {
            fingerprint: ann.fingerprint.to_ascii_uppercase(),
            alias: ann.alias.clone(),
            device_model: ann.device_model.clone(),
            device_type: ann.device_type,
            ip: src_addr.ip(),
            port: ann.port,
            protocol: ann.protocol,
            download: ann.download,
            last_seen: Instant::now(),
        };
        self.upsert(peer).await
    }

    /// Upsert a peer from a received register DTO.
    pub async fn upsert_from_register(&self, reg: &RegisterDto, src_addr: SocketAddr) -> bool {
        let peer = DiscoveredPeer {
            fingerprint: reg.fingerprint.to_ascii_uppercase(),
            alias: reg.alias.clone(),
            device_model: reg.device_model.clone(),
            device_type: reg.device_type,
            ip: src_addr.ip(),
            port: reg.port,
            protocol: reg.protocol,
            download: reg.download,
            last_seen: Instant::now(),
        };
        self.upsert(peer).await
    }

    /// Evicts peers that have not been observed within the specified TTL window.
    ///
    /// Returns the number of peers evicted.
    pub async fn prune_stale(&self, ttl: Duration) -> usize {
        let mut map = self.peers.write().await;
        let mut evicted_fingerprints = Vec::new();

        map.retain(|fingerprint, peer| {
            if peer.last_seen.elapsed() > ttl {
                evicted_fingerprints.push(fingerprint.clone());
                false
            } else {
                true
            }
        });

        let count = evicted_fingerprints.len();
        drop(map);

        for fp in evicted_fingerprints {
            let _ = self.notifier.send(RegistryEvent::Evicted(fp));
        }

        count
    }

    /// Explicitly remove a peer by fingerprint.
    pub async fn remove(&self, fingerprint: &str) -> Option<DiscoveredPeer> {
        let normalized = fingerprint.to_ascii_uppercase();
        let mut map = self.peers.write().await;
        let removed = map.remove(&normalized);
        drop(map);

        if removed.is_some() {
            let _ = self.notifier.send(RegistryEvent::Evicted(normalized));
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_registry_upsert_and_retrieve() {
        let registry = PeerRegistry::new();
        let mut rx = registry.subscribe();

        let peer = DiscoveredPeer {
            fingerprint: "abc123def456".to_string(),
            alias: "Test Node".to_string(),
            device_model: Some("Laptop".to_string()),
            device_type: Some(DeviceType::Desktop),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            port: 53317,
            protocol: ProtocolType::Https,
            download: true,
            last_seen: Instant::now(),
        };

        let is_new = registry.upsert(peer.clone()).await;
        assert!(is_new);
        assert_eq!(registry.len().await, 1);

        // Event notification received
        let event = rx.recv().await.unwrap();
        match event {
            RegistryEvent::Discovered(p) => {
                assert_eq!(p.fingerprint, "ABC123DEF456");
            }
            _ => panic!("Expected Discovered event"),
        }

        // Retrieve with different case
        let fetched = registry.get("ABC123def456").await.unwrap();
        assert_eq!(fetched.alias, "Test Node");

        // Update
        let mut updated = peer.clone();
        updated.alias = "Updated Node".to_string();
        let is_new_update = registry.upsert(updated).await;
        assert!(!is_new_update);

        let event = rx.recv().await.unwrap();
        match event {
            RegistryEvent::Updated(p) => {
                assert_eq!(p.alias, "Updated Node");
            }
            _ => panic!("Expected Updated event"),
        }
    }

    #[tokio::test]
    async fn test_registry_pruning() {
        let registry = PeerRegistry::new();

        let peer = DiscoveredPeer {
            fingerprint: "STALE_PEER".to_string(),
            alias: "Old Node".to_string(),
            device_model: None,
            device_type: None,
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            port: 53317,
            protocol: ProtocolType::Https,
            download: true,
            // Last seen 10 seconds ago
            last_seen: Instant::now() - Duration::from_secs(10),
        };

        registry.upsert(peer).await;
        assert_eq!(registry.len().await, 1);

        // Pruning with 5s TTL will evict
        let evicted = registry.prune_stale(Duration::from_secs(5)).await;
        assert_eq!(evicted, 1);
        assert_eq!(registry.len().await, 0);
    }
}
