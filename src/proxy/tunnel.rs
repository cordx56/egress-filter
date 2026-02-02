//! Bidirectional tunnel for non-DoH HTTPS traffic.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Bidirectional tunnel for proxying data between client and upstream server.
pub struct Tunnel {
    client_config: Arc<ClientConfig>,
}

impl Tunnel {
    /// Creates a new tunnel with default TLS client configuration.
    pub fn new() -> Self {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            client_config: Arc::new(config),
        }
    }

    /// Connects to the upstream server and returns the TLS stream.
    pub async fn connect_upstream(
        &self,
        addr: SocketAddr,
        sni: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TunnelError> {
        debug!("connecting to upstream {}:{}", sni, addr.port());

        let tcp_stream = TcpStream::connect(addr)
            .await
            .map_err(TunnelError::Connect)?;

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|_| TunnelError::InvalidSni(sni.to_string()))?;

        let connector = TlsConnector::from(Arc::clone(&self.client_config));
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(TunnelError::TlsHandshake)?;

        debug!("upstream TLS connection established to {}", sni);

        Ok(tls_stream)
    }

    /// Runs a bidirectional tunnel between two streams until one side closes.
    pub async fn run<C, U>(client: &mut C, upstream: &mut U) -> Result<(u64, u64), TunnelError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let result = copy_bidirectional(client, upstream)
            .await
            .map_err(TunnelError::Io)?;

        debug!(
            "tunnel closed: {} bytes client->upstream, {} bytes upstream->client",
            result.0, result.1
        );

        Ok(result)
    }

    /// Forwards a pre-built request to upstream and streams the response back.
    pub async fn forward_request<C, U>(
        client: &mut C,
        upstream: &mut U,
        request_bytes: &[u8],
    ) -> Result<(), TunnelError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        // Send request to upstream
        upstream
            .write_all(request_bytes)
            .await
            .map_err(TunnelError::Io)?;
        upstream.flush().await.map_err(TunnelError::Io)?;

        // Stream response back to client
        let mut buf = [0u8; 8192];
        loop {
            let n = upstream.read(&mut buf).await.map_err(TunnelError::Io)?;
            if n == 0 {
                break;
            }
            client.write_all(&buf[..n]).await.map_err(TunnelError::Io)?;
        }
        client.flush().await.map_err(TunnelError::Io)?;

        Ok(())
    }
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("failed to connect to upstream: {0}")]
    Connect(#[source] std::io::Error),
    #[error("invalid SNI: {0}")]
    InvalidSni(String),
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(#[source] std::io::Error),
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),
}
