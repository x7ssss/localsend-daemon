//! Cryptographic Identity & SHA-256 Fingerprint Engine
//!
//! Provides RSA-2048 self-signed X.509 certificate generation conforming to the LocalSend
//! specification and Apple ATS 825-day validity ceiling, alongside constant-time fingerprint
//! verification against timing side-channel attacks.

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_RSA_SHA256, SanType,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

/// Errors encountered during cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Certificate generation or encoding error.
    #[error("Certificate generation error: {0}")]
    Certificate(#[from] rcgen::Error),
    /// RSA key generation error.
    #[error("RSA key generation error: {0}")]
    Rsa(#[from] rsa::Error),
    /// PKCS#8 key encoding error.
    #[error("PKCS#8 encoding error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),
    /// System time query error.
    #[error("System clock error: {0}")]
    Time(String),
}

/// Self-signed TLS identity containing keys, certificates, and derived fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentity {
    /// DER-encoded X.509 certificate bytes.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key bytes.
    pub key_der_pkcs8: Vec<u8>,
    /// PEM-encoded certificate string.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key string.
    pub key_pem: String,
    /// Canonical 64-character uppercase hexadecimal SHA-256 fingerprint.
    pub fingerprint: String,
}

/// Compute canonical 64-character uppercase hexadecimal SHA-256 fingerprint from DER certificate bytes.
pub fn compute_fingerprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    hex::encode_upper(digest)
}

/// Verify that a candidate certificate DER matches the expected fingerprint in constant time.
///
/// Strips delimiters (colons, spaces, hyphens) and ignores case before comparison.
/// Uses `subtle::ConstantTimeEq` to protect against side-channel timing attacks.
pub fn verify_fingerprint_constant_time(expected: &str, candidate_der: &[u8]) -> bool {
    let candidate_fingerprint = compute_fingerprint(candidate_der);
    let normalized_expected = expected.replace([':', ' ', '-'], "").to_ascii_uppercase();

    if normalized_expected.len() != candidate_fingerprint.len() {
        return false;
    }

    normalized_expected
        .as_bytes()
        .ct_eq(candidate_fingerprint.as_bytes())
        .into()
}

/// Generate in-memory RSA-2048 self-signed TLS identity conforming to LocalSend v2.
///
/// Certificate parameters:
/// - Key Algorithm: RSA-2048 (`PKCS_RSA_SHA256`)
/// - Common Name (CN): "LocalSend"
/// - Organization (O): "LocalSend"
/// - Validity: [now - 1 day, now + 820 days] (satisfying Apple ATS 825-day limit)
/// - CA Constraint: Explicitly not a CA (`IsCa::ExplicitNoCa`)
/// - Key Usages: `DigitalSignature`, `KeyEncipherment`
/// - Extended Key Usages: `ServerAuth`
/// - Subject Alternative Names (SANs): `localhost`, `localsend.local`, `127.0.0.1`, plus provided `san_ips`
pub fn generate_tls_identity(
    _alias: &str,
    san_ips: &[std::net::IpAddr],
) -> Result<TlsIdentity, CryptoError> {
    let mut params = CertificateParams::default();

    // Subject DN
    params.distinguished_name.push(DnType::CommonName, "LocalSend");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "LocalSend");

    // Validity interval (820 days max validity + 1 day leeway)
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(820);

    // CA and Usages
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // Subject Alternative Names (SANs)
    let mut subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::DnsName("localsend.local".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let mut added_ips = std::collections::HashSet::new();
    added_ips.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    for &ip in san_ips {
        if added_ips.insert(ip) {
            subject_alt_names.push(SanType::IpAddress(ip));
        }
    }
    params.subject_alt_names = subject_alt_names;

    // Generate pure-Rust RSA-2048 keypair
    let mut rng = rsa::rand_core::OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pkcs8_doc = rsa_key.to_pkcs8_der()?;
    let key_der_pkcs8 = pkcs8_doc.as_bytes().to_vec();

    // Create rcgen keypair from PKCS#8 DER bytes
    let pkcs8_der = PrivatePkcs8KeyDer::from(key_der_pkcs8.as_slice());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &PKCS_RSA_SHA256)?;

    // Sign certificate
    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let fingerprint = compute_fingerprint(&cert_der);

    Ok(TlsIdentity {
        cert_der,
        key_der_pkcs8,
        cert_pem,
        key_pem,
        fingerprint,
    })
}
