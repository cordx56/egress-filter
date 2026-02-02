//! TLS termination and certificate resolution.

use std::sync::Arc;

use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::debug;

use crate::ca::CertCache;

/// TLS acceptor that performs TLS handshake with dynamic certificate selection.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl TlsAcceptor {
    /// Creates a new TLS acceptor with the given certificate cache.
    pub fn new(cert_cache: Arc<CertCache>) -> Self {
        let config = Self::create_config(cert_cache);
        Self {
            inner: tokio_rustls::TlsAcceptor::from(config),
        }
    }

    /// Creates a rustls ServerConfig with dynamic certificate resolution.
    fn create_config(cert_cache: Arc<CertCache>) -> Arc<ServerConfig> {
        let resolver = Arc::new(CertResolver { cache: cert_cache });
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        Arc::new(config)
    }

    /// Accepts a TLS connection, performing the handshake.
    /// Returns the TLS stream and the SNI (if provided by client).
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(TlsStream<TcpStream>, Option<String>), std::io::Error> {
        let tls_stream = self.inner.accept(stream).await?;

        // Extract SNI from the connection
        let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());

        debug!("TLS handshake completed, SNI: {:?}", sni);

        Ok((tls_stream, sni))
    }
}

/// Custom certificate resolver that generates certificates on-demand based on SNI.
struct CertResolver {
    cache: Arc<CertCache>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        debug!("resolving certificate for SNI: {}", sni);
        match self.cache.get_or_create(sni) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::error!("failed to generate certificate for {}: {}", sni, e);
                None
            }
        }
    }
}
