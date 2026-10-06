//! LocalSend Discovery Engine
//!
//! Provides dual-path discovery (Multicast UDP and HTTP subnet fallback)
//! and in-memory peer registry management.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod engine;
pub mod filter;
pub mod interfaces;
pub mod multicast;
pub mod registry;
pub mod scanner;

pub use engine::DiscoveryEngine;
pub use filter::{contains_subslice, should_process_packet};
pub use interfaces::{
    InterfaceError, NetworkInterfaceInfo, get_eligible_interfaces, is_eligible_interface_name,
    is_eligible_ipv4,
};
pub use multicast::{
    DEFAULT_PORT, MULTICAST_IPV4, MULTICAST_IPV6, MulticastConfig, MulticastEngine, MulticastError,
};
pub use registry::{DiscoveredPeer, PeerRegistry, RegistryEvent};
pub use scanner::{MAX_CONCURRENT_PROBES, PROBE_TIMEOUT, ScannerError, SubnetScanner};

pub use localsend_protocol as protocol;
