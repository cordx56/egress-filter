//! HTTPS proxy server for DoH interception.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::doh::{DohDetector, DohResponse, create_refused_response};
use super::tls::TlsAcceptor;
use super::tunnel::{Tunnel, TunnelError};
use crate::ca::{CaState, CertCache};

/// Shared state for the proxy server.
pub struct ProxyState {
    /// Certificate cache for dynamic certificate generation.
    cert_cache: Arc<CertCache>,
    /// Tunnel for upstream connections.
    tunnel: Tunnel,
    /// Pending original destinations in connect() arrival order.
    pending_destinations: RwLock<VecDeque<SocketAddr>>,
    /// Callback for checking if a domain is allowed.
    allowlist_checker: Arc<dyn AllowListChecker + Send + Sync>,
    /// Callback for caching DoH resolution results.
    resolution_cache: Arc<dyn ResolutionCache + Send + Sync>,
}

/// Trait for checking if a domain is allowed.
pub trait AllowListChecker: Send + Sync {
    /// Checks if the domain is allowed for the given port.
    fn is_domain_allowed(&self, domain: &str, port: u16) -> bool;
}

/// Trait for caching DoH resolution results.
pub trait ResolutionCache: Send + Sync {
    /// Caches the resolved IP addresses for the domain.
    fn cache_resolution(&self, domain: &str, addresses: &[IpAddr], ports: Vec<u16>);
}

impl ProxyState {
    /// Creates a new proxy state.
    pub fn new(
        ca: Arc<CaState>,
        allowlist_checker: Arc<dyn AllowListChecker + Send + Sync>,
        resolution_cache: Arc<dyn ResolutionCache + Send + Sync>,
    ) -> Self {
        Self {
            cert_cache: Arc::new(CertCache::new(ca)),
            tunnel: Tunnel::new(),
            pending_destinations: RwLock::new(VecDeque::new()),
            allowlist_checker,
            resolution_cache,
        }
    }

    /// Registers a pending original destination intercepted from connect().
    pub async fn register_destination(&self, original: SocketAddr) {
        let mut pending = self.pending_destinations.write().await;
        pending.push_back(original);
        debug!("registered pending destination: {}", original);
    }

    /// Gets and removes the next pending original destination.
    pub async fn take_destination(&self) -> Option<SocketAddr> {
        let mut pending = self.pending_destinations.write().await;
        pending.pop_front()
    }

    /// Returns a reference to the certificate cache.
    pub fn cert_cache(&self) -> &Arc<CertCache> {
        &self.cert_cache
    }

    /// Returns the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> &str {
        self.cert_cache.ca().ca_cert_pem()
    }
}

/// The HTTPS proxy server.
pub struct ProxyServer {
    state: Arc<ProxyState>,
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl ProxyServer {
    /// Creates a new proxy server.
    /// Binds to localhost on an ephemeral port.
    pub async fn bind(state: Arc<ProxyState>) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        info!("proxy server listening on {}", local_addr);

        let tls_acceptor = TlsAcceptor::new(Arc::clone(&state.cert_cache));

        Ok(Self {
            state,
            listener,
            tls_acceptor,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Runs the proxy server, accepting connections forever.
    pub async fn run(self) -> Result<(), std::io::Error> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            debug!("accepted connection from {}", peer_addr);

            let state = Arc::clone(&self.state);
            let tls_acceptor = self.tls_acceptor.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, state, tls_acceptor).await {
                    error!("connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }
}

/// Handles a single proxy connection.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ProxyState>,
    tls_acceptor: TlsAcceptor,
) -> Result<(), ConnectionError> {
    debug!("connection from {}", peer_addr);

    // Perform TLS handshake
    let (tls_stream, sni) = tls_acceptor
        .accept(stream)
        .await
        .map_err(ConnectionError::TlsHandshake)?;

    let Some(ref server_name) = sni else {
        warn!("no SNI provided by client");
        return Err(ConnectionError::NoSni);
    };

    debug!("handling connection for server: {}", server_name);

    // Prefer the original destination captured at connect() rewrite time.
    // Fall back to SNI resolution if we don't have a pending destination.
    let upstream_addr = if let Some(original) = state.take_destination().await {
        debug!(
            "using captured original destination {} for {}",
            original, server_name
        );
        original
    } else {
        warn!(
            "missing captured destination for {}, falling back to DNS resolution",
            server_name
        );
        resolve_host(server_name, 443).await.ok_or_else(|| {
            warn!("failed to resolve upstream address for {}", server_name);
            ConnectionError::NoSni
        })?
    };

    debug!("upstream address for {}: {}", server_name, upstream_addr);

    // Handle HTTP/1.1 and HTTP/2
    let io = TokioIo::new(tls_stream);

    let server_name = server_name.clone();
    let state_clone = Arc::clone(&state);

    let service = service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state_clone);
        let server_name = server_name.clone();
        let upstream_addr = upstream_addr;
        async move { handle_request(req, state, server_name, upstream_addr).await }
    });

    ServerBuilder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await
        .map_err(ConnectionError::Http)?;

    Ok(())
}

/// Handles an HTTP request, checking for DoH.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    server_name: String,
    upstream_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let path = uri.path();

    debug!("request: {} {} (server: {})", method, uri, server_name);

    // Collect the body first (we need it for both DoH detection and forwarding)
    let body_bytes = req.collect().await?.to_bytes();

    // Check if this is a DoH request
    if DohDetector::is_doh_path(path)
        && let Some(doh_request) = DohDetector::extract(
            &Request::builder()
                .method(method.clone())
                .uri(uri.clone())
                .body(())
                .unwrap(),
            Some(&body_bytes),
        )
    {
        debug!(
            "DoH request detected for {} (type {})",
            doh_request.query.name, doh_request.query.qtype
        );

        // Check allowlist
        if state
            .allowlist_checker
            .is_domain_allowed(&doh_request.query.name, 443)
        {
            info!("DoH allowed: {}", doh_request.query.name);

            // Forward to upstream and cache the response
            return forward_doh_request(
                &state,
                &server_name,
                upstream_addr,
                &method,
                &uri,
                &body_bytes,
                &doh_request.query.name,
            )
            .await;
        } else {
            info!("DoH denied: {}", doh_request.query.name);
            eprintln!(
                "[egress-filter] DoH query blocked: {}",
                doh_request.query.name
            );

            // Return DNS REFUSED
            if let Some(refused) = create_refused_response(&doh_request.wire_bytes) {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/dns-message")
                    .body(Full::new(Bytes::from(refused)))
                    .unwrap());
            }

            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("DNS query refused")))
                .unwrap());
        }
    }

    // Not a DoH request - forward to upstream
    forward_non_doh_request(
        &state,
        &server_name,
        upstream_addr,
        &method,
        &uri,
        &headers,
        &body_bytes,
    )
    .await
}

/// Forwards a DoH request to upstream and caches the response.
async fn forward_doh_request(
    state: &ProxyState,
    server_name: &str,
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    body: &[u8],
    queried_domain: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Connect to upstream
    let mut upstream = match state
        .tunnel
        .connect_upstream(upstream_addr, server_name)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("failed to connect to upstream {}: {}", server_name, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "Failed to connect to upstream: {}",
                    e
                ))))
                .unwrap());
        }
    };

    // Build the HTTP request

    let request = if *method == http::Method::GET {
        format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Accept: application/dns-message\r\n\
             Connection: close\r\n\
             \r\n",
            method,
            uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
            server_name
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Accept: application/dns-message\r\n\
             Connection: close\r\n\
             \r\n",
            method,
            uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
            server_name,
            body.len()
        )
    };

    // Send request
    if let Err(e) = upstream.write_all(request.as_bytes()).await {
        error!("failed to send request: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request")))
            .unwrap());
    }

    if *method == http::Method::POST
        && !body.is_empty()
        && let Err(e) = upstream.write_all(body).await
    {
        error!("failed to send body: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send body")))
            .unwrap());
    }

    if let Err(e) = upstream.flush().await {
        error!("failed to flush: {}", e);
    }

    // Read response
    let mut response_buf = Vec::new();
    if let Err(e) = upstream.read_to_end(&mut response_buf).await {
        error!("failed to read response: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to read response")))
            .unwrap());
    }

    // Parse HTTP response
    let response_str = String::from_utf8_lossy(&response_buf);
    let header_end = response_str.find("\r\n\r\n").unwrap_or(response_buf.len());
    let body_start = header_end + 4;

    let dns_body = if body_start < response_buf.len() {
        &response_buf[body_start..]
    } else {
        &[]
    };

    // Parse DNS response and cache IPs
    if let Some(dns_response) = DohResponse::from_wire(dns_body) {
        debug!(
            "DoH response for {}: {:?} (TTL: {})",
            dns_response.name, dns_response.addresses, dns_response.ttl
        );
        state.resolution_cache.cache_resolution(
            queried_domain,
            &dns_response.addresses,
            vec![443], // Default to HTTPS port
        );
    }

    // Return DNS body to client
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/dns-message")
        .body(Full::new(Bytes::from(dns_body.to_vec())))
        .unwrap())
}

/// Forwards a non-DoH request to upstream.
async fn forward_non_doh_request(
    state: &ProxyState,
    server_name: &str,
    upstream_addr: SocketAddr,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Connect to upstream
    let mut upstream = match state
        .tunnel
        .connect_upstream(upstream_addr, server_name)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            error!("failed to connect to upstream {}: {}", server_name, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!(
                    "Failed to connect to upstream: {}",
                    e
                ))))
                .unwrap());
        }
    };

    // Build simple HTTP/1.1 request
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, server_name);

    // Headers to skip (case-insensitive comparison)
    // Also skip HTTP/2 pseudo-headers that start with ':'
    let skip_headers = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "http2-settings",
    ];

    for (name, value) in headers {
        let name_str = name.as_str();
        // Skip HTTP/2 pseudo-headers (start with ':')
        if name_str.starts_with(':') {
            continue;
        }
        let name_lower = name_str.to_lowercase();
        if !skip_headers.contains(&name_lower.as_str())
            && let Ok(v) = value.to_str()
        {
            request.push_str(&format!("{}: {}\r\n", name, v));
        }
    }

    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");

    debug!(
        "forwarding request to {}: {} {} ({} bytes body)",
        server_name,
        method,
        path,
        body.len()
    );
    debug!("request headers:\n{}", request);

    // Send request
    if let Err(e) = upstream.write_all(request.as_bytes()).await {
        error!("failed to send request: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request")))
            .unwrap());
    }
    if !body.is_empty()
        && let Err(e) = upstream.write_all(body).await
    {
        error!("failed to send body: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send body")))
            .unwrap());
    }
    if let Err(e) = upstream.flush().await {
        error!("failed to flush upstream write: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to flush request")))
            .unwrap());
    }

    // Read response
    let mut response_buf = Vec::new();
    if let Err(e) = upstream.read_to_end(&mut response_buf).await {
        error!("failed to read response: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to read response")))
            .unwrap());
    }

    // Parse and forward response
    let response_str = String::from_utf8_lossy(&response_buf);

    // Find status line
    let first_line_end = response_str.find("\r\n").unwrap_or(0);
    let status_line = &response_str[..first_line_end];
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(200);

    debug!("upstream response status: {}", status_code);

    // Find body
    let header_end = response_str.find("\r\n\r\n").unwrap_or(response_buf.len());
    let body_start = header_end + 4;

    let response_body = if body_start < response_buf.len() {
        response_buf[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok(Response::builder()
        .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK))
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

/// Resolves a hostname to a socket address.
async fn resolve_host(host: &str, port: u16) -> Option<SocketAddr> {
    use tokio::net::lookup_host;

    let addr_str = format!("{}:{}", host, port);
    match lookup_host(&addr_str).await {
        Ok(mut addrs) => addrs.next(),
        Err(e) => {
            warn!("DNS resolution failed for {}: {}", host, e);
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(#[source] std::io::Error),
    #[error("no SNI provided")]
    NoSni,
    #[error("HTTP error: {0}")]
    Http(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
}
