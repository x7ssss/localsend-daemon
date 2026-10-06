//! LocalSend Discovery Engine
//!
//! Provides dual-path discovery (Multicast UDP and HTTP subnet fallback)
//! and in-memory peer registry management.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub use localsend_protocol as protocol;

/// Discovery engine placeholder state.
#[derive(Debug, Default)]
pub struct DiscoveryEngine;

impl DiscoveryEngine {
    /// Creates a new uninitialized discovery engine instance.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_init() {
        let engine = DiscoveryEngine::new();
        assert!(format!("{engine:?}").contains("DiscoveryEngine"));
    }
}
