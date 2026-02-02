//! CA and host certificate generation using rcgen.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};
use tracing::debug;

/// The result type for CA operations.
pub type CaResult<T> = Result<T, CaError>;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("failed to generate key pair: {0}")]
    KeyGeneration(#[from] rcgen::Error),
    #[error("failed to sign certificate")]
    Signing,
    #[error("failed to serialize key")]
    KeySerialization,
    #[error("failed to create signing key: {0}")]
    SigningKey(#[source] rustls::Error),
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
}

/// Ephemeral CA state for TLS MitM.
///
/// Generates a new CA certificate on creation (valid for 24 hours).
/// Used to sign host certificates on-demand.
pub struct CaState {
    /// The CA certificate in DER format.
    ca_cert_der: CertificateDer<'static>,
    /// The CA certificate in PEM format (for injection into child environment).
    ca_cert_pem: String,
    /// The CA key pair for signing host certificates.
    ca_key_pair: KeyPair,
    /// The CA certificate parameters (used for creating Issuer).
    ca_params: CertificateParams,
}

impl CaState {
    /// Generates a new ephemeral CA with 24-hour validity.
    pub fn generate() -> CaResult<Self> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "egress-filter CA");
        dn.push(DnType::OrganizationName, "egress-filter");

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Valid for 24 hours
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5); // Small buffer for clock skew
        params.not_after = now + Duration::hours(24);

        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;

        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        debug!("generated ephemeral CA certificate");

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            ca_key_pair: key_pair,
            ca_params: params,
        })
    }

    /// Returns the CA certificate in PEM format.
    /// Suitable for injection via environment variables.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the CA certificate in DER format.
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Generates a host certificate for the given SNI.
    /// The certificate is signed by this CA.
    pub fn generate_host_cert(&self, sni: &str) -> CaResult<CertifiedKey> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(
            sni.try_into()
                .map_err(|_| CaError::InvalidDnsName(sni.to_string()))?,
        )];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // Valid for 1 hour (short-lived for security)
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::hours(1);

        let host_key_pair = KeyPair::generate()?;
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key_pair);
        let host_cert = params.signed_by(&host_key_pair, &issuer)?;

        let cert_der = CertificateDer::from(host_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(host_key_pair.serialize_der()));

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(CaError::SigningKey)?;

        debug!("generated host certificate for {}", sni);

        Ok(CertifiedKey::new(vec![cert_der], signing_key))
    }
}

/// Cache for host certificates.
///
/// Stores generated host certificates keyed by SNI to avoid regenerating
/// certificates for repeated connections to the same host.
pub struct CertCache {
    ca: Arc<CaState>,
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertCache {
    /// Creates a new certificate cache backed by the given CA.
    pub fn new(ca: Arc<CaState>) -> Self {
        Self {
            ca,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Gets or generates a certified key for the given SNI.
    pub fn get_or_create(&self, sni: &str) -> CaResult<Arc<CertifiedKey>> {
        // Check cache first
        if let Ok(cache) = self.cache.read()
            && let Some(key) = cache.get(sni)
        {
            return Ok(Arc::clone(key));
        }

        // Generate new certificate
        let certified_key = Arc::new(self.ca.generate_host_cert(sni)?);

        // Store in cache
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(sni.to_string(), Arc::clone(&certified_key));
        }

        Ok(certified_key)
    }

    /// Returns a reference to the underlying CA state.
    pub fn ca(&self) -> &CaState {
        &self.ca
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests ephemeral CA certificate generation.
    /// Verifies that the CA cert is in valid PEM format.
    #[test]
    fn generate_ca() {
        let ca = CaState::generate().unwrap();
        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    /// Tests host certificate generation signed by the CA.
    /// Each host cert should contain at least one certificate in the chain.
    #[test]
    fn generate_host_cert() {
        let ca = CaState::generate().unwrap();
        let cert = ca.generate_host_cert("example.com").unwrap();
        assert!(!cert.cert.is_empty());
    }

    /// Tests that the certificate cache returns the same certificate
    /// for repeated requests to the same hostname.
    /// This avoids regenerating certificates for each connection.
    #[test]
    fn cert_cache() {
        let ca = Arc::new(CaState::generate().unwrap());
        let cache = CertCache::new(ca);

        // First request generates a new certificate
        let cert1 = cache.get_or_create("example.com").unwrap();
        // Second request returns the cached certificate
        let cert2 = cache.get_or_create("example.com").unwrap();

        // Verify pointer equality (same Arc instance)
        assert!(Arc::ptr_eq(&cert1, &cert2));
    }
}
