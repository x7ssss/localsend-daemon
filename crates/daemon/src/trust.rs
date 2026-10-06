//! Trust Policy Engine & Persistent YAML Device Store
//!
//! Evaluates incoming transfer requests against auto-accept policies, pinned SHA-256
//! fingerprints, allowed subnet CIDRs, and constant-time PIN gates.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

/// Policy controlling how inbound transfer requests are evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoAcceptMode {
    /// All transfers require explicit interactive approval via IPC.
    Never,
    /// Transfers are automatically accepted only if the peer's fingerprint is in the trust store
    /// or the sender IP belongs to an allowed CIDR subnet.
    TrustedOnly,
    /// All incoming transfers are automatically accepted (subject to valid PIN if configured).
    Always,
}

impl Default for AutoAcceptMode {
    fn default() -> Self {
        Self::TrustedOnly
    }
}

/// A trusted remote peer device record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedPeer {
    /// Canonical uppercase SHA-256 certificate fingerprint.
    pub fingerprint: String,
    /// Human-friendly peer alias.
    pub alias: String,
    /// Timestamp when peer was added to trust store (ISO-8601).
    pub added_at: String,
    /// Last observed IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ip: Option<IpAddr>,
}

/// Errors returned by the trust store.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// Filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// YAML parsing or serialization error.
    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// YAML-persisted trust store schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustStoreData {
    /// Current auto-acceptance mode.
    pub auto_accept_mode: AutoAcceptMode,
    /// Optional authorization PIN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Subnet CIDRs permitted for auto-acceptance.
    pub allowed_cidrs: Vec<ipnet::IpNet>,
    /// Explicitly trusted peer fingerprints.
    pub trusted_peers: Vec<TrustedPeer>,
}

impl Default for TrustStoreData {
    fn default() -> Self {
        Self {
            auto_accept_mode: AutoAcceptMode::TrustedOnly,
            pin: None,
            allowed_cidrs: Vec::new(),
            trusted_peers: Vec::new(),
        }
    }
}

/// Persistent device trust store.
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    data: TrustStoreData,
}

impl TrustStore {
    /// Default system configuration path.
    pub const DEFAULT_PATH: &'static str = "/etc/localsend/trusted_devices.yaml";

    /// Load trust store from disk or create default if not found.
    pub fn load_or_create(path: &Path) -> Result<Self, TrustError> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let data: TrustStoreData = serde_yaml::from_str(&content)?;
            Ok(Self {
                path: path.to_path_buf(),
                data,
            })
        } else {
            let store = Self {
                path: path.to_path_buf(),
                data: TrustStoreData::default(),
            };
            store.save()?;
            Ok(store)
        }
    }

    /// Read-only reference to underlying trust store data.
    pub fn data(&self) -> &TrustStoreData {
        &self.data
    }

    /// Path to trust store file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Access the current auto-accept policy mode.
    pub fn auto_accept_mode(&self) -> AutoAcceptMode {
        self.data.auto_accept_mode
    }

    /// Set auto-accept policy mode.
    pub fn set_auto_accept_mode(&mut self, mode: AutoAcceptMode) -> Result<(), TrustError> {
        self.data.auto_accept_mode = mode;
        self.save()
    }

    /// Alias for `set_auto_accept_mode`.
    pub fn set_mode(&mut self, mode: AutoAcceptMode) -> Result<(), TrustError> {
        self.set_auto_accept_mode(mode)
    }

    /// Check if a peer is trusted via pinned certificate fingerprint OR allowed CIDR subnet.
    pub fn is_trusted(&self, ip: IpAddr, fingerprint: Option<&str>) -> bool {
        // 1. Check pinned fingerprints if provided
        if let Some(fp) = fingerprint {
            let clean_fp = fp.replace([':', ' ', '-'], "").to_ascii_uppercase();
            if self
                .data
                .trusted_peers
                .iter()
                .any(|p| p.fingerprint.eq_ignore_ascii_case(&clean_fp))
            {
                return true;
            }
        }

        // 2. Check allowed CIDR subnets
        if self.data.allowed_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            return true;
        }

        false
    }

    /// Verify candidate PIN in constant time.
    ///
    /// If no PIN is configured, returns true.
    pub fn verify_pin(&self, candidate_pin: Option<&str>) -> bool {
        match (&self.data.pin, candidate_pin) {
            (None, _) => true,
            (Some(expected), Some(candidate)) => {
                if expected.len() != candidate.len() {
                    return false;
                }
                expected.as_bytes().ct_eq(candidate.as_bytes()).into()
            }
            (Some(_), None) => false,
        }
    }

    /// Set or clear the authorization PIN.
    pub fn set_pin(&mut self, pin: Option<String>) -> Result<(), TrustError> {
        self.data.pin = pin;
        self.save()
    }

    /// Add or update a trusted peer and persist atomically.
    pub fn add_peer(&mut self, fingerprint: String, alias: String) -> Result<(), TrustError> {
        let clean_fp = fingerprint.replace([':', ' ', '-'], "").to_ascii_uppercase();
        let now = OffsetDateTime::now_utc();
        let added_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());

        if let Some(existing) = self
            .data
            .trusted_peers
            .iter_mut()
            .find(|p| p.fingerprint.eq_ignore_ascii_case(&clean_fp))
        {
            existing.alias = alias;
            existing.added_at = added_at;
        } else {
            self.data.trusted_peers.push(TrustedPeer {
                fingerprint: clean_fp,
                alias,
                added_at,
                last_seen_ip: None,
            });
        }

        self.save()
    }

    /// Remove a trusted peer by fingerprint.
    pub fn remove_peer(&mut self, fingerprint: &str) -> Result<bool, TrustError> {
        let clean_fp = fingerprint.replace([':', ' ', '-'], "").to_ascii_uppercase();
        let initial_len = self.data.trusted_peers.len();
        self.data
            .trusted_peers
            .retain(|p| !p.fingerprint.eq_ignore_ascii_case(&clean_fp));
        let changed = self.data.trusted_peers.len() != initial_len;
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Add fingerprint with optional alias.
    pub fn add_fingerprint(
        &mut self,
        fingerprint: String,
        alias: Option<String>,
    ) -> Result<(), TrustError> {
        self.add_peer(fingerprint, alias.unwrap_or_else(|| "unnamed".to_string()))
    }

    /// Remove fingerprint.
    pub fn remove_fingerprint(&mut self, fingerprint: &str) -> Result<bool, TrustError> {
        self.remove_peer(fingerprint)
    }

    /// Add an allowed CIDR subnet.
    pub fn add_cidr(&mut self, cidr: ipnet::IpNet) -> Result<(), TrustError> {
        if !self.data.allowed_cidrs.contains(&cidr) {
            self.data.allowed_cidrs.push(cidr);
            self.save()?;
        }
        Ok(())
    }

    /// Remove an allowed CIDR subnet.
    pub fn remove_cidr(&mut self, cidr: &ipnet::IpNet) -> Result<bool, TrustError> {
        let initial_len = self.data.allowed_cidrs.len();
        self.data.allowed_cidrs.retain(|c| c != cidr);
        let changed = self.data.allowed_cidrs.len() != initial_len;
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Alias for `add_cidr`.
    pub fn add_subnet(&mut self, cidr: ipnet::IpNet) -> Result<(), TrustError> {
        self.add_cidr(cidr)
    }

    /// Alias for `remove_cidr`.
    pub fn remove_subnet(&mut self, cidr: &ipnet::IpNet) -> Result<bool, TrustError> {
        self.remove_cidr(cidr)
    }

    /// Atomic write to disk using temp file and rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), TrustError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let serialized = serde_yaml::to_string(&self.data)?;
        let temp_path = path.with_extension("yaml.tmp");

        std::fs::write(&temp_path, serialized.as_bytes())?;
        std::fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Save to current path atomically.
    pub fn save(&self) -> Result<(), TrustError> {
        self.save_atomic(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_trust_store_lifecycle_and_rules() {
        let temp_dir = std::env::temp_dir().join(format!("trust_test_{}", uuid::Uuid::new_v4()));
        let config_file = temp_dir.join("trusted_devices.yaml");

        let mut store = TrustStore::load_or_create(&config_file).unwrap();
        assert_eq!(store.auto_accept_mode(), AutoAcceptMode::TrustedOnly);

        let fp = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF";
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));

        // Untrusted initially
        assert!(!store.is_trusted(ip, Some(fp)));

        // Add trusted peer
        store.add_peer(fp.to_string(), "Phone".to_string()).unwrap();
        assert!(store.is_trusted(ip, Some(fp)));

        // Reload from disk to verify persistence
        let mut reloaded = TrustStore::load_or_create(&config_file).unwrap();
        assert!(reloaded.is_trusted(ip, Some(fp)));

        // Remove trusted peer
        assert!(reloaded.remove_fingerprint(fp).unwrap());
        assert!(!reloaded.is_trusted(ip, Some(fp)));

        // Test CIDR subnet
        let cidr = ipnet::IpNet::from_str("10.0.0.0/24").unwrap();
        store.add_subnet(cidr).unwrap();
        assert!(store.is_trusted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), None));
        assert!(!store.is_trusted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), None));

        // Remove CIDR subnet
        assert!(store.remove_subnet(&cidr).unwrap());
        assert!(!store.is_trusted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), None));

        // Test PIN verification
        assert!(store.verify_pin(None)); // No PIN configured
        store.set_pin(Some("123456".to_string())).unwrap();
        assert!(!store.verify_pin(None));
        assert!(!store.verify_pin(Some("000000")));
        assert!(store.verify_pin(Some("123456")));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
