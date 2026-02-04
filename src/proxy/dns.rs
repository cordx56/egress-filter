//! UDP DNS proxy server.
//!
//! Intercepts DNS queries from the child process, forwards them to the
//! original DNS server, parses responses for A/AAAA records, and caches
//! the resolved IPs before returning the response to the child.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, error, warn};

use super::DohResponse;
use super::server::ResolutionCache;

/// DNS query pending proxy forwarding.
/// Registered by the seccomp handler before the query reaches the proxy.
pub struct PendingDnsQuery {
    /// The original DNS server address the child intended to reach.
    pub original_server: SocketAddr,
    /// The queried domain name.
    pub domain: Option<String>,
    /// Allowed ports from the allowlist rule.
    pub ports: Vec<u16>,
    /// DNS transaction ID.
    pub txid: u16,
}

struct PendingEntry {
    query: PendingDnsQuery,
    inserted_at: Instant,
}

/// Shared state for the DNS proxy, used by both the proxy server
/// and the seccomp handler (via `register_query`).
pub struct DnsProxyState {
    pending_queries: Mutex<HashMap<u16, VecDeque<PendingEntry>>>,
    resolution_cache: Arc<dyn ResolutionCache>,
}

impl DnsProxyState {
    pub fn new(resolution_cache: Arc<dyn ResolutionCache>) -> Self {
        Self {
            pending_queries: Mutex::new(HashMap::new()),
            resolution_cache,
        }
    }

    /// Registers a pending DNS query. Called synchronously from the
    /// seccomp notification handler.
    pub fn register_query(&self, query: PendingDnsQuery) {
        if let Ok(mut pending) = self.pending_queries.lock() {
            purge_expired(&mut pending);
            debug!(
                "registered DNS query: {} -> {} (txid={})",
                query.domain.as_deref().unwrap_or("<unknown>"),
                query.original_server,
                query.txid
            );
            let entry = PendingEntry {
                query,
                inserted_at: Instant::now(),
            };
            pending
                .entry(entry.query.txid)
                .or_default()
                .push_back(entry);
        }
    }

    /// Takes a pending query matching the txid (and optionally the domain name).
    fn take_query(&self, txid: u16, domain: Option<&str>) -> Option<PendingDnsQuery> {
        let mut pending = self.pending_queries.lock().ok()?;
        purge_expired(&mut pending);
        let entries = pending.get_mut(&txid)?;

        let index = domain.and_then(|name| {
            entries.iter().position(|entry| {
                entry
                    .query
                    .domain
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(name))
            })
        });

        let entry = if let Some(index) = index {
            entries.remove(index)
        } else {
            entries.pop_front()
        };

        if entries.is_empty() {
            pending.remove(&txid);
        }

        entry.map(|entry| entry.query)
    }
}

/// UDP DNS proxy server.
/// Listens on a local ephemeral port and forwards DNS queries to the
/// original upstream DNS server, caching A/AAAA records from responses.
pub struct DnsProxyServer {
    socket: Arc<UdpSocket>,
    state: Arc<DnsProxyState>,
}

/// Buffer size for DNS packets (EDNS0 supports up to 4096).
const DNS_BUF_SIZE: usize = 4096;

/// Timeout for upstream DNS responses.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time to keep pending DNS queries.
const PENDING_TTL: Duration = Duration::from_secs(10);

impl DnsProxyServer {
    /// Binds the proxy to `127.0.0.1` on the given port (0 for ephemeral).
    pub async fn bind(state: Arc<DnsProxyState>, port: u16) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(("127.0.0.1", port)).await?;
        Ok(Self {
            socket: Arc::new(socket),
            state,
        })
    }

    /// Returns the local address the proxy is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    /// Runs the proxy, receiving DNS queries from the child and forwarding
    /// them to the original DNS server.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let mut buf = [0u8; DNS_BUF_SIZE];

        loop {
            let (len, child_addr) = self.socket.recv_from(&mut buf).await?;
            let packet = buf[..len].to_vec();

            let (txid, name) = match parse_txid_and_name(&packet) {
                Ok((txid, name)) => (txid, name),
                Err(e) => {
                    warn!("DNS proxy received invalid packet: {}", e);
                    continue;
                }
            };
            let pending = self.state.take_query(txid, name.as_deref());
            let socket = Arc::clone(&self.socket);
            let state = Arc::clone(&self.state);

            tokio::spawn(async move {
                if let Err(e) =
                    handle_dns_query(&socket, &state, child_addr, &packet, pending).await
                {
                    error!("DNS proxy error: {}", e);
                }
            });
        }
    }
}

/// Handles a single DNS query: forwards to upstream, parses the response,
/// caches resolved IPs, and returns the response to the child.
async fn handle_dns_query(
    listen_socket: &UdpSocket,
    state: &DnsProxyState,
    child_addr: SocketAddr,
    packet: &[u8],
    pending: Option<PendingDnsQuery>,
) -> Result<(), std::io::Error> {
    let Some(query) = pending else {
        // No pending query registered — this shouldn't normally happen,
        // but could if ordering is off. Drop the packet.
        warn!(
            "DNS proxy received packet with no pending query (txid={}), dropping",
            extract_txid(packet).unwrap_or_default()
        );
        return Ok(());
    };

    debug!(
        "forwarding DNS query for {} to {}",
        query.domain.as_deref().unwrap_or("<unknown>"),
        query.original_server
    );

    // Create a new socket matching the upstream server's address family
    let bind_addr: SocketAddr = if query.original_server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let upstream_socket = UdpSocket::bind(bind_addr).await?;
    upstream_socket
        .send_to(packet, query.original_server)
        .await?;

    // Wait for the response with timeout
    let mut resp_buf = [0u8; DNS_BUF_SIZE];
    let resp_len = match tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        upstream_socket.recv_from(&mut resp_buf),
    )
    .await
    {
        Ok(Ok((len, _))) => len,
        Ok(Err(e)) => {
            error!(
                "upstream DNS recv error for {}: {}",
                query.domain.as_deref().unwrap_or("<unknown>"),
                e
            );
            return Err(e);
        }
        Err(_) => {
            warn!(
                "upstream DNS timeout for {} (server: {})",
                query.domain.as_deref().unwrap_or("<unknown>"),
                query.original_server
            );
            return Ok(());
        }
    };

    let response = &resp_buf[..resp_len];

    // Parse the DNS response and cache A/AAAA records
    if let Some(dns_response) = DohResponse::from_wire(response) {
        let response_txid = extract_txid(response);
        let txid_matches = response_txid == Some(query.txid);
        if !txid_matches {
            warn!(
                "DNS response txid mismatch (expected={}, got={})",
                query.txid,
                response_txid.unwrap_or_default()
            );
        }

        let response_name = extract_query_name(response);
        let name_matches = match (query.domain.as_deref(), response_name.as_deref()) {
            (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
            _ => false,
        };
        if query.domain.is_some() && response_name.is_some() && !name_matches {
            warn!(
                "DNS response name mismatch (expected={}, got={})",
                query.domain.as_deref().unwrap_or("<unknown>"),
                response_name.as_deref().unwrap_or("<unknown>")
            );
        }

        if txid_matches && name_matches {
            debug!(
                "DNS response for {}: {:?} (TTL: {})",
                query.domain.as_deref().unwrap_or("<unknown>"),
                dns_response.addresses,
                dns_response.ttl
            );
            if let Some(ref domain) = query.domain {
                state.resolution_cache.cache_resolution(
                    domain,
                    &dns_response.addresses,
                    query.ports,
                );
            }
        }
    }

    // Send the original response back to the child
    listen_socket.send_to(response, child_addr).await?;

    Ok(())
}

fn purge_expired(pending: &mut HashMap<u16, VecDeque<PendingEntry>>) {
    let now = Instant::now();
    pending.retain(|_, entries| {
        entries.retain(|entry| now.duration_since(entry.inserted_at) <= PENDING_TTL);
        !entries.is_empty()
    });
}

fn parse_txid_and_name(packet: &[u8]) -> Result<(u16, Option<String>), &'static str> {
    let txid = extract_txid(packet).ok_or("packet too short for txid")?;
    let name = extract_query_name(packet);
    Ok((txid, name))
}

fn extract_txid(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

fn extract_query_name(packet: &[u8]) -> Option<String> {
    crate::network::DnsNameParser::parse_query(packet)
        .ok()
        .map(|query| query.name)
}
