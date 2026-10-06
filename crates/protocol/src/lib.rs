//! LocalSend v2 Protocol Crate
//!
//! Provides protocol data models, JSON wire schemas, cryptographic identity utilities,
//! and filesystem path sanitization.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod models;
pub mod sanitize;

pub use crypto::{
    compute_fingerprint, generate_tls_identity, verify_fingerprint_constant_time, CryptoError,
    TlsIdentity,
};
pub use models::{
    DeviceType, FileMetadata, InfoResponseDto, MulticastAnnouncement, PrepareUploadRequest,
    PrepareUploadResponse, ProtocolType, RegisterDto, UploadParams,
};
pub use sanitize::{
    is_windows_reserved, resolve_collision, sanitize_filename, SanitizeError, MAX_FILENAME_BYTES,
};

/// Protocol version implemented by this crate.
pub const PROTOCOL_VERSION: &str = "2.0";

/// Default LocalSend multicast IPv4 address.
pub const MULTICAST_ADDRESS_V4: &str = "224.0.0.167";

/// Default LocalSend discovery and transfer port.
pub const DEFAULT_PORT: u16 = 53317;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PROTOCOL_VERSION, "2.0");
        assert_eq!(MULTICAST_ADDRESS_V4, "224.0.0.167");
        assert_eq!(DEFAULT_PORT, 53317);
    }
}
