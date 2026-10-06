//! Custom TLS Fingerprint Pinning Client
//!
//! Provides a `rustls::client::danger::ServerCertVerifier` implementation that:
//! - Disables WebPKI root store validation.
//! - Computes SHA-256 over `CertificateDer` bytes.
//! - Compares uppercase hex hash against expected_fingerprint in constant time.
//! - Verifies TLS 1.2 and TLS 1.3 handshake digital signatures using `rustls::crypto::ring::default_provider()`.
//! - Builds a `reqwest::Client` with ALPN strictly pinned to `[b"http/1.1"]`.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Error type for TLS client operations.
#[derive(Debug, thiserror::Error)]
pub enum TlsClientError {
    /// Reqwest error.
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),
    /// Rustls error.
    #[error("TLS configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A custom `ServerCertVerifier` that authenticates peers exclusively by pinned SHA-256 fingerprint.
#[derive(Debug)]
pub struct FingerprintVerifier {
    expected_fingerprint: String,
    supported_algorithms: WebPkiSupportedAlgorithms,
}

impl FingerprintVerifier {
    /// Creates a new fingerprint verifier with expected uppercase hex fingerprint.
    pub fn new(expected_fingerprint: &str) -> Self {
        let clean = expected_fingerprint
            .replace([':', ' ', '-'], "")
            .to_ascii_uppercase();
        let provider = rustls::crypto::ring::default_provider();
        Self {
            expected_fingerprint: clean,
            supported_algorithms: provider.signature_verification_algorithms,
        }
    }

    /// Access the normalized expected fingerprint.
    pub fn expected_fingerprint(&self) -> &str {
        &self.expected_fingerprint
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash = hasher.finalize();
        let cert_fp = hex::encode_upper(hash);

        if cert_fp.len() == self.expected_fingerprint.len()
            && cert_fp
                .as_bytes()
                .ct_eq(self.expected_fingerprint.as_bytes())
                .into()
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}

/// Constructs a `rustls::ClientConfig` pinned to the specified fingerprint with ALPN b"http/1.1".
pub fn build_pinned_tls_config(expected_fingerprint: &str) -> Result<ClientConfig, rustls::Error> {
    let verifier = Arc::new(FingerprintVerifier::new(expected_fingerprint));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Constructs a `reqwest::Client` pinned to the expected certificate fingerprint.
pub fn create_pinned_client(expected_fingerprint: &str) -> Result<reqwest::Client, TlsClientError> {
    let tls_config = build_pinned_tls_config(expected_fingerprint)?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()?;
    Ok(client)
}

/// Constructs a direct probe client (accepts any certificate) for initial handshake / fingerprint discovery.
pub fn create_probe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use localsend_protocol::crypto::generate_tls_identity;

    #[test]
    fn test_fingerprint_verifier_accepts_valid_leaf() {
        let identity = generate_tls_identity("TestNode", &[]).unwrap();
        let verifier = FingerprintVerifier::new(&identity.fingerprint);

        let cert_der = CertificateDer::from(identity.cert_der.clone());
        let server_name = ServerName::try_from("127.0.0.1").unwrap();
        let result = verifier.verify_server_cert(
            &cert_der,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "Expected valid certificate to be verified");
    }

    #[test]
    fn test_fingerprint_verifier_rejects_mismatched_leaf() {
        let id1 = generate_tls_identity("Node1", &[]).unwrap();
        let id2 = generate_tls_identity("Node2", &[]).unwrap();

        // Verifier configured with id1 fingerprint
        let verifier = FingerprintVerifier::new(&id1.fingerprint);

        // Presented certificate from id2
        let cert_der = CertificateDer::from(id2.cert_der.clone());
        let server_name = ServerName::try_from("127.0.0.1").unwrap();
        let result = verifier.verify_server_cert(
            &cert_der,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err(), "Expected mismatched certificate to be rejected");
    }
}
