//! TLS Configuration for LocalSend Receiver
//!
//! Generates the in-memory self-signed TLS server configuration with strictly enforced
//! HTTP/1.1 ALPN negotiation to guarantee 100% interoperability with official clients.

use localsend_protocol::TlsIdentity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;

/// Construct a `rustls::ServerConfig` configured for LocalSend v2.
///
/// Characteristics:
/// - Explicit `ring` crypto provider to prevent multi-provider runtime ambiguity.
/// - Zero client authentication (`with_no_client_auth`).
/// - Single self-signed RSA-2048 certificate matching the daemon's announced fingerprint.
/// - ALPN strictly pinned to `http/1.1`.
pub fn build_tls_server_config(
    identity: &TlsIdentity,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    // Ensure ring crypto provider is set for the process
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_der = CertificateDer::from(identity.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der_pkcs8.clone()));

    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    // Strictly enforce HTTP/1.1 for 100% mobile/desktop LocalSend client interoperability
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}
