//! UDP DNS proxy server.
//!
//! Intercepts DNS queries from the child process, forwards them to the
//! original DNS server, parses responses for A/AAAA records, and caches
//! the resolved IPs before returning the response to the child.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    inflight_queries: Mutex<HashMap<u16, InflightEntry>>,
    next_internal_txid: AtomicUsize,
    resolution_cache: Arc<dyn ResolutionCache>,
}

impl DnsProxyState {
    pub fn new(resolution_cache: Arc<dyn ResolutionCache>) -> Self {
        Self {
            pending_queries: Mutex::new(HashMap::new()),
            inflight_queries: Mutex::new(HashMap::new()),
            next_internal_txid: AtomicUsize::new(0),
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

    fn insert_inflight(&self, entry: InflightEntry) -> Option<u16> {
        let mut inflight = self.inflight_queries.lock().ok()?;
        purge_inflight(&mut inflight);
        let txid = (0..=u16::MAX as u32).find_map(|_| {
            let c = (self.next_internal_txid.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
            (!inflight.contains_key(&c)).then_some(c)
        })?;
        inflight.insert(txid, entry);
        Some(txid)
    }

    fn take_inflight(&self, txid: u16) -> Option<InflightEntry> {
        let mut inflight = self.inflight_queries.lock().ok()?;
        purge_inflight(&mut inflight);
        inflight.remove(&txid)
    }

    fn inflight_len(&self) -> usize {
        self.inflight_queries
            .lock()
            .map(|map| map.len())
            .unwrap_or_default()
    }
}

/// UDP DNS proxy server.
/// Listens on local IPv4 and IPv6 loopback addresses and forwards DNS
/// queries to the original upstream DNS server, caching A/AAAA records
/// from responses.
pub struct DnsProxyServer {
    socket_v4: Arc<UdpSocket>,
    socket_v6: Option<Arc<UdpSocket>>,
    upstream_v4: Arc<UdpSocket>,
    upstream_v6: Option<Arc<UdpSocket>>,
    state: Arc<DnsProxyState>,
}

/// Buffer size for DNS packets (EDNS0 supports up to 4096).
const DNS_BUF_SIZE: usize = 4096;

/// Maximum time to keep pending DNS queries.
const PENDING_TTL: Duration = Duration::from_secs(10);
/// Maximum time to keep in-flight DNS queries.
const INFLIGHT_TTL: Duration = Duration::from_secs(10);
/// Warn when in-flight DNS proxy tasks exceed this count.
const DNS_INFLIGHT_WARN: usize = 128;
struct InflightEntry {
    query: PendingDnsQuery,
    child_addr: SocketAddr,
    listen_is_v6: bool,
    original_txid: u16,
    inserted_at: Instant,
}

impl DnsProxyServer {
    /// Binds the proxy on `127.0.0.1` and, when available, `[::1]` with the
    /// given port (0 for ephemeral). When `port` is 0, the IPv6 socket reuses
    /// the port assigned to the IPv4 socket so both share the same port number.
    pub async fn bind(state: Arc<DnsProxyState>, port: u16) -> Result<Self, std::io::Error> {
        let socket_v4 = UdpSocket::bind(("127.0.0.1", port)).await?;
        let v6_port = if port == 0 {
            socket_v4.local_addr()?.port()
        } else {
            port
        };
        let socket_v6 = match UdpSocket::bind(("::1", v6_port)).await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(err) => {
                warn!(
                    "failed to bind DNS proxy on [::1]:{}, falling back to IPv4 only: {}",
                    v6_port, err
                );
                None
            }
        };
        let upstream_v4 = UdpSocket::bind(("0.0.0.0", 0)).await?;
        let upstream_v6 = match UdpSocket::bind(("::", 0)).await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(err) => {
                warn!(
                    "failed to bind upstream DNS socket on [::]:0, IPv6 upstream queries will be dropped: {}",
                    err
                );
                None
            }
        };
        Ok(Self {
            socket_v4: Arc::new(socket_v4),
            socket_v6,
            upstream_v4: Arc::new(upstream_v4),
            upstream_v6,
            state,
        })
    }

    /// Returns the IPv4 local address the proxy is listening on.
    pub fn local_addr_v4(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket_v4.local_addr()
    }

    /// Returns the IPv6 local address the proxy is listening on.
    /// Falls back to an IPv4-mapped IPv6 address when IPv6 is unavailable.
    pub fn local_addr_v6(&self) -> Result<SocketAddr, std::io::Error> {
        if let Some(socket_v6) = &self.socket_v6 {
            return socket_v6.local_addr();
        }
        let v4_addr = self.socket_v4.local_addr()?;
        let v4_addr = match v4_addr {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "unexpected IPv6 address for IPv4 socket",
                ));
            }
        };
        let v4_mapped = v4_addr.ip().to_ipv6_mapped();
        let v6_addr = std::net::SocketAddrV6::new(v4_mapped, v4_addr.port(), 0, 0);
        Ok(SocketAddr::V6(v6_addr))
    }

    /// Runs the proxy on both IPv4 and IPv6 sockets concurrently.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        match (&self.socket_v6, &self.upstream_v6) {
            (Some(socket_v6), Some(upstream_v6)) => {
                tokio::try_join!(
                    self.run_socket(&self.socket_v4),
                    self.run_socket(socket_v6),
                    self.run_upstream(&self.upstream_v4),
                    self.run_upstream(upstream_v6)
                )?;
            }
            (Some(socket_v6), None) => {
                tokio::try_join!(
                    self.run_socket(&self.socket_v4),
                    self.run_socket(socket_v6),
                    self.run_upstream(&self.upstream_v4)
                )?;
            }
            (None, Some(upstream_v6)) => {
                tokio::try_join!(
                    self.run_socket(&self.socket_v4),
                    self.run_upstream(&self.upstream_v4),
                    self.run_upstream(upstream_v6)
                )?;
            }
            (None, None) => {
                tokio::try_join!(
                    self.run_socket(&self.socket_v4),
                    self.run_upstream(&self.upstream_v4)
                )?;
            }
        }
        Ok(())
    }

    async fn run_socket(&self, socket: &Arc<UdpSocket>) -> Result<(), std::io::Error> {
        let mut buf = [0u8; DNS_BUF_SIZE];

        loop {
            let (len, child_addr) = socket.recv_from(&mut buf).await?;
            let mut packet = buf[..len].to_vec();

            let txid = match extract_txid(&packet) {
                Some(txid) => txid,
                None => {
                    warn!("DNS proxy received invalid packet: missing txid");
                    continue;
                }
            };

            let pending = self.state.take_query(txid, None);
            let Some(query) = pending else {
                warn!(
                    "DNS proxy received packet with no pending query (txid={}), dropping",
                    txid
                );
                continue;
            };

            let original_server = query.original_server;
            let domain_for_log = query.domain.as_deref().unwrap_or("<unknown>");
            debug!(
                "forwarding DNS query for {} to {}",
                domain_for_log, original_server
            );

            let listen_is_v6 = child_addr.is_ipv6();
            let entry = InflightEntry {
                query,
                child_addr,
                listen_is_v6,
                original_txid: txid,
                inserted_at: Instant::now(),
            };

            let Some(internal_txid) = self.state.insert_inflight(entry) else {
                warn!(
                    "DNS proxy in-flight table full, dropping query (txid={})",
                    txid
                );
                continue;
            };

            rewrite_txid(&mut packet, internal_txid);

            let upstream = if original_server.is_ipv6() {
                if let Some(socket) = &self.upstream_v6 {
                    socket
                } else {
                    warn!(
                        "IPv6 upstream DNS socket unavailable; dropping query to {}",
                        original_server
                    );
                    self.state.take_inflight(internal_txid);
                    continue;
                }
            } else {
                &self.upstream_v4
            };

            if let Err(e) = upstream.send_to(&packet, original_server).await {
                error!("upstream DNS send error for {}: {}", original_server, e);
                self.state.take_inflight(internal_txid);
                continue;
            }

            let inflight_now = self.state.inflight_len();
            if inflight_now >= DNS_INFLIGHT_WARN && inflight_now.is_multiple_of(DNS_INFLIGHT_WARN) {
                warn!("DNS proxy in-flight tasks: {}", inflight_now);
            }
        }
    }

    async fn run_upstream(&self, socket: &Arc<UdpSocket>) -> Result<(), std::io::Error> {
        let mut buf = [0u8; DNS_BUF_SIZE];

        loop {
            let (len, _from) = socket.recv_from(&mut buf).await?;
            let mut response = buf[..len].to_vec();

            let internal_txid = match extract_txid(&response) {
                Some(txid) => txid,
                None => {
                    warn!("upstream DNS response missing txid, dropping");
                    continue;
                }
            };

            let Some(entry) = self.state.take_inflight(internal_txid) else {
                warn!(
                    "DNS proxy received response with unknown txid {}, dropping",
                    internal_txid
                );
                continue;
            };

            rewrite_txid(&mut response, entry.original_txid);

            if let Some(dns_response) = DohResponse::from_wire(&response) {
                debug!(
                    "DNS response for {}: {:?} (TTL: {})",
                    entry.query.domain.as_deref().unwrap_or("<unknown>"),
                    dns_response.addresses,
                    dns_response.ttl
                );
                if let Some(ref domain) = entry.query.domain {
                    self.state.resolution_cache.cache_resolution(
                        domain,
                        &dns_response.addresses,
                        entry.query.ports,
                    );
                }
            }

            let listen_socket = if entry.listen_is_v6 {
                if let Some(socket) = &self.socket_v6 {
                    socket
                } else {
                    warn!(
                        "IPv6 listen socket unavailable; dropping response to {}",
                        entry.child_addr
                    );
                    continue;
                }
            } else {
                &self.socket_v4
            };

            if let Err(e) = listen_socket.send_to(&response, entry.child_addr).await {
                error!("DNS proxy send_to child error: {}", e);
            }
        }
    }
}

fn purge_expired(pending: &mut HashMap<u16, VecDeque<PendingEntry>>) {
    let now = Instant::now();
    pending.retain(|_, entries| {
        entries.retain(|entry| now.duration_since(entry.inserted_at) <= PENDING_TTL);
        !entries.is_empty()
    });
}

fn purge_inflight(inflight: &mut HashMap<u16, InflightEntry>) {
    let now = Instant::now();
    inflight.retain(|_, entry| {
        let alive = now.duration_since(entry.inserted_at) <= INFLIGHT_TTL;
        if !alive {
            warn!(
                "upstream DNS timeout for {} (server: {})",
                entry.query.domain.as_deref().unwrap_or("<unknown>"),
                entry.query.original_server
            );
        }
        alive
    });
}

fn extract_txid(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

fn rewrite_txid(packet: &mut [u8], txid: u16) {
    if packet.len() < 2 {
        return;
    }
    let bytes = txid.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}
