use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::{mem::offset_of, mem::size_of};

use crate::allowlist::AllowList;
use crate::proxy::PendingDnsQuery;
use crate::seccomp::{InterceptedSyscall, NotificationHandler, ProcessMemory, SyscallNotification};

use super::dns::DnsQuery;
use super::sockaddr::{ParsedAddress, SockaddrError, SocketAddress};

use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to parse socket address: {0}")]
    Sockaddr(#[from] super::sockaddr::SockaddrError),
    #[error("failed to parse DNS query: {0}")]
    Dns(#[from] super::dns::DnsError),
    #[error("notification error: {0}")]
    Notify(#[from] crate::seccomp::notify::NotifyError),
}

/// Result of handling a syscall notification.
#[derive(Debug)]
pub enum Decision {
    /// The connection was allowed.
    Allowed { target: ConnectionTarget },
    /// The connection was denied.
    Denied { target: ConnectionTarget },
    /// Could not determine the target (e.g., non-IP socket).
    Skipped { reason: String },
}

/// Describes the target of a network connection.
#[derive(Debug, Clone)]
pub struct ConnectionTarget {
    pub ip: IpAddr,
    pub port: u16,
    /// DNS name if this was a DNS query.
    pub dns_name: Option<String>,
}

impl std::fmt::Display for ConnectionTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref name) = self.dns_name {
            write!(f, "{}:{} ({})", self.ip, self.port, name)
        } else {
            write!(f, "{}:{}", self.ip, self.port)
        }
    }
}

/// Configuration for the proxy redirect.
#[derive(Clone)]
pub struct ProxyRedirect {
    /// The local proxy address to redirect to.
    pub proxy_addr: SocketAddr,
    /// Callback to register the original destination with the proxy.
    pub register_destination: Arc<dyn Fn(SocketAddr) + Send + Sync>,
}

/// Configuration for the DNS proxy redirect.
#[derive(Clone)]
pub struct DnsRedirect {
    /// The local DNS proxy address to redirect to (IPv4).
    pub proxy_addr_v4: SocketAddr,
    /// The local DNS proxy address to redirect to (IPv6).
    pub proxy_addr_v6: Option<SocketAddr>,
    /// Callback to register a pending DNS query with the proxy.
    pub register_query: Arc<dyn Fn(PendingDnsQuery) + Send + Sync>,
}

/// Tracks connected sockets for send() handling.
/// Maps (pid, fd) -> destination address.
#[derive(Default)]
pub struct SocketTracker {
    connected: RwLock<HashMap<(u32, i32), SocketAddr>>,
}

impl SocketTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a socket's connected destination.
    pub fn track(&self, pid: u32, fd: i32, addr: SocketAddr) {
        if let Ok(mut map) = self.connected.write() {
            map.insert((pid, fd), addr);
        }
    }

    /// Gets the connected destination for a socket.
    pub fn get(&self, pid: u32, fd: i32) -> Option<SocketAddr> {
        if let Ok(map) = self.connected.read() {
            map.get(&(pid, fd)).copied()
        } else {
            None
        }
    }
}

struct DnsSendtoContext<'a> {
    mem: &'a ProcessMemory,
    notification: &'a SyscallNotification,
    target: &'a ConnectionTarget,
    original_server: SocketAddr,
    dest_addr_ptr: u64,
    addr_len: u32,
    txid: Option<u16>,
}

/// Handles network-related syscall notifications.
pub struct NetworkHandler<'a> {
    handler: &'a NotificationHandler,
    allowlist: Arc<RwLock<AllowList>>,
    /// Proxy redirect configuration (if DoH interception is enabled).
    proxy_redirect: Option<ProxyRedirect>,
    /// DNS proxy redirect configuration.
    dns_redirect: Option<DnsRedirect>,
    /// Tracks connected sockets for send() handling.
    socket_tracker: SocketTracker,
}

impl<'a> NetworkHandler<'a> {
    pub fn new(handler: &'a NotificationHandler, allowlist: Arc<RwLock<AllowList>>) -> Self {
        Self {
            handler,
            allowlist,
            proxy_redirect: None,
            dns_redirect: None,
            socket_tracker: SocketTracker::new(),
        }
    }

    /// Returns a reference to the allowlist for external access.
    pub fn allowlist(&self) -> &Arc<RwLock<AllowList>> {
        &self.allowlist
    }

    /// Sets the proxy redirect configuration for TLS interception.
    pub fn with_proxy_redirect(mut self, redirect: ProxyRedirect) -> Self {
        self.proxy_redirect = Some(redirect);
        self
    }

    /// Sets the DNS proxy redirect configuration.
    pub fn with_dns_redirect(mut self, redirect: DnsRedirect) -> Self {
        self.dns_redirect = Some(redirect);
        self
    }

    /// Handles a syscall notification and returns the decision made.
    pub fn handle(&self, notification: &SyscallNotification) -> Result<Decision, HandlerError> {
        let mem = ProcessMemory::new(notification.pid);

        match notification.syscall {
            InterceptedSyscall::Connect => self.handle_connect(&mem, notification),
            InterceptedSyscall::Sendto => self.handle_sendto(&mem, notification),
            InterceptedSyscall::Send => self.handle_send(&mem, notification),
            InterceptedSyscall::Sendmmsg => self.handle_sendmmsg(&mem, notification),
        }
    }

    /// Handles connect(fd, addr, addrlen) syscall.
    ///
    /// Args layout:
    /// - args[0]: fd
    /// - args[1]: sockaddr pointer
    /// - args[2]: addrlen
    fn handle_connect(
        &self,
        mem: &ProcessMemory,
        notification: &SyscallNotification,
    ) -> Result<Decision, HandlerError> {
        let addr_ptr = notification.args[1];
        let addr_len = notification.args[2] as u32;

        // Validate notification is still valid (TOCTOU)
        if !self.handler.is_valid(notification) {
            warn!("notification {} became invalid", notification.id);
            return Ok(Decision::Skipped {
                reason: "notification became invalid".into(),
            });
        }

        let parsed = match SocketAddress::read(mem, addr_ptr, addr_len) {
            Ok(addr) => addr,
            Err(SockaddrError::UnsupportedFamily(family)) => {
                debug!("skipping non-INET sockaddr family {}, allowing", family);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("non-INET address family: {}", family),
                });
            }
            Err(e) => {
                debug!("failed to parse sockaddr, allowing: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("could not parse address: {}", e),
                });
            }
        };

        let target = ConnectionTarget {
            ip: parsed.ip(),
            port: parsed.port(),
            dns_name: None,
        };

        // Port 0 connect is used by glibc's getaddrinfo() for RFC 6724
        // address sorting (determining source address via UDP routing probe).
        // This is harmless and must be allowed for proper DNS resolution in
        // runtimes that rely on getaddrinfo (e.g. Node.js).
        if parsed.port() == 0 {
            debug!(
                "allowing port 0 connect to {} (address sorting probe)",
                target.ip
            );
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "port 0 address sorting probe".into(),
            });
        }

        // Track DNS server connections for send() handling.
        // Record the **original** address before any rewrite.
        if parsed.port() == 53 {
            let fd = notification.args[0] as i32;
            self.socket_tracker.track(notification.pid, fd, parsed.addr);
            debug!(
                "tracking DNS socket: pid={} fd={} -> {}",
                notification.pid, fd, parsed.addr
            );
        }

        // Also track connections to our DNS proxy port.
        // This handles cases where the child (e.g., Node.js/libuv) caches the
        // redirected proxy address and reconnects directly to it.
        if let Some(ref dns_redirect) = self.dns_redirect {
            let is_proxy_port = parsed.addr == dns_redirect.proxy_addr_v4
                || dns_redirect
                    .proxy_addr_v6
                    .is_some_and(|addr| parsed.addr == addr);
            if is_proxy_port {
                let fd = notification.args[0] as i32;
                // Track as DNS proxy connection; use a well-known DNS server
                // as the "original" so send() handler processes it correctly.
                let synthetic_dns = if parsed.addr.is_ipv6() {
                    std::net::SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                        53,
                    )
                } else {
                    std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53)),
                        53,
                    )
                };
                self.socket_tracker
                    .track(notification.pid, fd, synthetic_dns);
                debug!(
                    "tracking DNS proxy socket: pid={} fd={} -> {} (synthetic: {})",
                    notification.pid, fd, parsed.addr, synthetic_dns
                );
                self.handler.allow(notification)?;
                return Ok(Decision::Allowed { target });
            }
        }

        // Redirect DNS connections to the local proxy if configured
        if parsed.port() == 53
            && let Some(ref dns_redirect) = self.dns_redirect
        {
            let proxy_addr = if target.ip.is_ipv6() {
                match dns_redirect.proxy_addr_v6 {
                    Some(addr) => addr,
                    None => {
                        warn!(
                            "DNS proxy IPv6 socket unavailable; skipping redirect for {}",
                            target
                        );
                        return self.decide_and_respond(notification, &target, &parsed);
                    }
                }
            } else {
                dns_redirect.proxy_addr_v4
            };
            if let Err(e) = SocketAddress::write(mem, addr_ptr, addr_len, proxy_addr) {
                warn!("failed to rewrite DNS sockaddr: {}", e);
            } else {
                info!(
                    "redirected DNS {}:{} to proxy {}",
                    target.ip, target.port, proxy_addr
                );
                self.handler.allow(notification)?;
                return Ok(Decision::Allowed {
                    target: ConnectionTarget {
                        ip: target.ip,
                        port: target.port,
                        dns_name: Some("redirected to DNS proxy".to_string()),
                    },
                });
            }
        }

        // Check if we should redirect to proxy (port 443 with DoH enabled)
        if let Some(ref redirect) = self.proxy_redirect
            && parsed.port() == 443
        {
            // Rewrite the destination to the local proxy
            let original_dest = parsed.addr;

            // Register the original destination with the proxy
            (redirect.register_destination)(original_dest);

            // Rewrite the sockaddr in child's memory to point to proxy
            if let Err(e) = SocketAddress::write(mem, addr_ptr, addr_len, redirect.proxy_addr) {
                warn!("failed to rewrite sockaddr: {}", e);
                // Fall through to normal handling
            } else {
                info!(
                    "redirected {}:{} to proxy {}",
                    target.ip, target.port, redirect.proxy_addr
                );
                self.handler.allow(notification)?;
                return Ok(Decision::Allowed {
                    target: ConnectionTarget {
                        ip: target.ip,
                        port: target.port,
                        dns_name: Some("redirected to proxy".to_string()),
                    },
                });
            }
        }

        self.decide_and_respond(notification, &target, &parsed)
    }

    /// Handles sendto(fd, buf, len, flags, dest_addr, addrlen) syscall.
    ///
    /// Args layout:
    /// - args[0]: fd
    /// - args[1]: buf pointer
    /// - args[2]: len
    /// - args[3]: flags
    /// - args[4]: dest_addr pointer (can be NULL)
    /// - args[5]: addrlen
    fn handle_sendto(
        &self,
        mem: &ProcessMemory,
        notification: &SyscallNotification,
    ) -> Result<Decision, HandlerError> {
        let buf_ptr = notification.args[1];
        let buf_len = notification.args[2] as usize;
        let dest_addr_ptr = notification.args[4];
        let addr_len = notification.args[5] as u32;

        // If dest_addr is NULL, it's connected UDP; handle like send().
        if dest_addr_ptr == 0 {
            let fd = notification.args[0] as i32;
            let Some(dest) = self.socket_tracker.get(notification.pid, fd) else {
                debug!("sendto with NULL dest_addr on untracked socket, allowing");
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: "connected UDP socket (untracked)".into(),
                });
            };

            if dest.port() != 53 || buf_len == 0 {
                debug!("sendto with NULL dest_addr to non-DNS {}, allowing", dest);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: "connected UDP socket (non-DNS)".into(),
                });
            }

            // Validate notification
            if !self.handler.is_valid(notification) {
                warn!("notification {} became invalid", notification.id);
                return Ok(Decision::Skipped {
                    reason: "notification became invalid".into(),
                });
            }

            let mut txid = None;
            let dns_name = match DnsQuery::parse(mem, buf_ptr, buf_len) {
                Ok(query) => {
                    txid = Some(query.txid);
                    debug!("DNS query (sendto/connected) for: {}", query.name);
                    Some(query.name)
                }
                Err(e) => {
                    debug!("failed to parse DNS query in sendto/connected: {}", e);
                    None
                }
            };
            if txid.is_none() {
                txid = DnsQuery::read_txid(mem, buf_ptr, buf_len).ok();
            }

            let target = ConnectionTarget {
                ip: dest.ip(),
                port: dest.port(),
                dns_name,
            };

            return self.decide_dns_query(notification, &target, dest, txid);
        }

        // Validate notification
        if !self.handler.is_valid(notification) {
            warn!("notification {} became invalid", notification.id);
            return Ok(Decision::Skipped {
                reason: "notification became invalid".into(),
            });
        }

        let parsed = match SocketAddress::read(mem, dest_addr_ptr, addr_len) {
            Ok(addr) => addr,
            Err(e) => {
                debug!("failed to parse sendto sockaddr, allowing: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("could not parse address: {}", e),
                });
            }
        };

        // If this is DNS (port 53), handle as a DNS query
        if parsed.is_dns && buf_len > 0 {
            let mut txid = None;
            let dns_name = match DnsQuery::parse(mem, buf_ptr, buf_len) {
                Ok(query) => {
                    txid = Some(query.txid);
                    debug!("DNS query for: {}", query.name);
                    Some(query.name)
                }
                Err(e) => {
                    debug!("failed to parse DNS query: {}", e);
                    None
                }
            };
            if txid.is_none() {
                txid = DnsQuery::read_txid(mem, buf_ptr, buf_len).ok();
            }

            let target = ConnectionTarget {
                ip: parsed.ip(),
                port: parsed.port(),
                dns_name,
            };

            return self.decide_dns_sendto(DnsSendtoContext {
                mem,
                notification,
                target: &target,
                original_server: parsed.addr,
                dest_addr_ptr,
                addr_len,
                txid,
            });
        }

        let target = ConnectionTarget {
            ip: parsed.ip(),
            port: parsed.port(),
            dns_name: None,
        };

        self.decide_and_respond(notification, &target, &parsed)
    }

    /// Decides whether to allow or deny a DNS query from sendto().
    /// If allowed and DNS proxy is configured, registers the query and
    /// rewrites the destination to the proxy.
    fn decide_dns_sendto(&self, ctx: DnsSendtoContext<'_>) -> Result<Decision, HandlerError> {
        let DnsSendtoContext {
            mem,
            notification,
            target,
            original_server,
            dest_addr_ptr,
            addr_len,
            txid,
        } = ctx;
        let allowlist = self.allowlist.read().unwrap();
        let (allowed, ports) = if let Some(ref name) = target.dns_name {
            let ports = allowlist.get_domain_ports(name);
            (allowlist.is_dns_query_allowed(name), ports)
        } else {
            (allowlist.is_ip_allowed(target.ip, target.port), Vec::new())
        };
        drop(allowlist);

        if allowed {
            // Register with DNS proxy and rewrite destination if configured
            if let Some(ref dns_redirect) = self.dns_redirect {
                if let Some(txid) = txid {
                    (dns_redirect.register_query)(PendingDnsQuery {
                        original_server,
                        domain: target.dns_name.clone(),
                        ports,
                        txid,
                    });

                    let proxy_addr = if target.ip.is_ipv6() {
                        match dns_redirect.proxy_addr_v6 {
                            Some(addr) => addr,
                            None => {
                                warn!(
                                    "DNS proxy IPv6 socket unavailable; skipping redirect for {}",
                                    target
                                );
                                info!("allowed: {} (DNS sendto, no redirect)", target);
                                self.handler.allow(notification)?;
                                return Ok(Decision::Allowed {
                                    target: target.clone(),
                                });
                            }
                        }
                    } else {
                        dns_redirect.proxy_addr_v4
                    };
                    if let Err(e) = SocketAddress::write(mem, dest_addr_ptr, addr_len, proxy_addr) {
                        warn!("failed to rewrite DNS sendto dest: {}", e);
                    } else {
                        info!("allowed: {} (DNS sendto, redirected to proxy)", target);
                        self.handler.allow(notification)?;
                        return Ok(Decision::Allowed {
                            target: target.clone(),
                        });
                    }
                } else {
                    warn!(
                        "DNS sendto allowed but missing txid; skipping proxy redirect for {}",
                        target
                    );
                }
            }

            info!("allowed: {} (DNS query)", target);
            self.handler.allow(notification)?;
            Ok(Decision::Allowed {
                target: target.clone(),
            })
        } else {
            info!("denied: {} (DNS query)", target);
            let al = self.allowlist.read().unwrap();
            if al.should_notify_block(target.ip, target.port) {
                eprintln!("[egress-filter] DNS query blocked: {}", target);
            }
            drop(al);
            self.handler.deny(notification)?;
            Ok(Decision::Denied {
                target: target.clone(),
            })
        }
    }

    /// Decides whether to allow or deny a DNS query from send()/sendmmsg().
    /// These use connected sockets already pointing to the proxy, so no
    /// destination rewrite is needed, but we still register the pending query.
    fn decide_dns_query(
        &self,
        notification: &SyscallNotification,
        target: &ConnectionTarget,
        original_server: SocketAddr,
        txid: Option<u16>,
    ) -> Result<Decision, HandlerError> {
        let allowlist = self.allowlist.read().unwrap();
        let (allowed, ports) = if let Some(ref name) = target.dns_name {
            let ports = allowlist.get_domain_ports(name);
            (allowlist.is_dns_query_allowed(name), ports)
        } else {
            (allowlist.is_ip_allowed(target.ip, target.port), Vec::new())
        };
        drop(allowlist);

        if allowed {
            // Register with DNS proxy if configured
            if let Some(ref dns_redirect) = self.dns_redirect {
                if let Some(txid) = txid {
                    (dns_redirect.register_query)(PendingDnsQuery {
                        original_server,
                        domain: target.dns_name.clone(),
                        ports,
                        txid,
                    });
                } else {
                    warn!(
                        "DNS query allowed but missing txid; skipping proxy registration for {}",
                        target
                    );
                }
            }

            info!("allowed: {} (DNS query)", target);
            self.handler.allow(notification)?;
            Ok(Decision::Allowed {
                target: target.clone(),
            })
        } else {
            info!("denied: {} (DNS query)", target);
            let al = self.allowlist.read().unwrap();
            if al.should_notify_block(target.ip, target.port) {
                eprintln!("[egress-filter] DNS query blocked: {}", target);
            }
            drop(al);
            self.handler.deny(notification)?;
            Ok(Decision::Denied {
                target: target.clone(),
            })
        }
    }

    fn decide_and_respond(
        &self,
        notification: &SyscallNotification,
        target: &ConnectionTarget,
        _parsed: &ParsedAddress,
    ) -> Result<Decision, HandlerError> {
        let allowlist = self.allowlist.read().unwrap();

        let allowed = if let Some(ref dns_name) = target.dns_name {
            allowlist.is_domain_allowed(dns_name, target.port)
        } else {
            allowlist.is_ip_allowed(target.ip, target.port)
        };

        if allowed {
            info!("allowed: {}", target);
            self.handler.allow(notification)?;
            Ok(Decision::Allowed {
                target: target.clone(),
            })
        } else {
            info!("denied: {}", target);
            // Output a message to stderr (deduplicated)
            if allowlist.should_notify_block(target.ip, target.port) {
                eprintln!("[egress-filter] Connection blocked: {}", target);
            }
            self.handler.deny(notification)?;
            Ok(Decision::Denied {
                target: target.clone(),
            })
        }
    }

    /// Handles sendmmsg(fd, msgvec, vlen, flags) syscall.
    ///
    /// Args layout:
    /// - args[0]: fd
    /// - args[1]: msgvec pointer (struct mmsghdr*)
    /// - args[2]: vlen (number of messages)
    /// - args[3]: flags
    ///
    /// This is used by modern DNS libraries (dig, host) for DNS queries.
    fn handle_sendmmsg(
        &self,
        mem: &ProcessMemory,
        notification: &SyscallNotification,
    ) -> Result<Decision, HandlerError> {
        let fd = notification.args[0] as i32;
        let msgvec_ptr = notification.args[1];
        let vlen = notification.args[2] as usize;

        if vlen == 0 {
            debug!("sendmmsg with vlen=0, allowing");
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "empty sendmmsg".into(),
            });
        }

        // Look up the connected destination from our tracking
        let Some(dest) = self.socket_tracker.get(notification.pid, fd) else {
            // Not a tracked socket (not DNS), allow
            debug!("sendmmsg on untracked socket fd={}, allowing", fd);
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "untracked socket".into(),
            });
        };

        // This is a DNS socket, parse the query from the first message
        if dest.port() != 53 {
            debug!("sendmmsg to non-DNS destination {}, allowing", dest);
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "not a DNS packet".into(),
            });
        }

        // Validate notification
        if !self.handler.is_valid(notification) {
            warn!("notification {} became invalid", notification.id);
            return Ok(Decision::Skipped {
                reason: "notification became invalid".into(),
            });
        }

        let mut first_target: Option<ConnectionTarget> = None;
        let mut queries: Vec<(Option<String>, Option<u16>)> = Vec::with_capacity(vlen);

        for idx in 0..vlen {
            let msg_offset = msgvec_ptr + (idx as u64 * size_of::<libc::mmsghdr>() as u64);
            let msg_hdr_offset = msg_offset + offset_of!(libc::mmsghdr, msg_hdr) as u64;

            let msg_iov_ptr: u64 =
                match mem.read_value(msg_hdr_offset + offset_of!(libc::msghdr, msg_iov) as u64) {
                    Ok(ptr) => ptr,
                    Err(e) => {
                        debug!("failed to read msg_iov pointer: {}", e);
                        continue;
                    }
                };

            let msg_iovlen: u64 = match mem
                .read_value(msg_hdr_offset + offset_of!(libc::msghdr, msg_iovlen) as u64)
            {
                Ok(len) => len,
                Err(e) => {
                    debug!("failed to read msg_iovlen: {}", e);
                    continue;
                }
            };

            if msg_iovlen == 0 || msg_iov_ptr == 0 {
                debug!("sendmmsg with empty iov entry, skipping");
                continue;
            }

            let iov_base: u64 =
                match mem.read_value(msg_iov_ptr + offset_of!(libc::iovec, iov_base) as u64) {
                    Ok(ptr) => ptr,
                    Err(e) => {
                        debug!("failed to read iov_base: {}", e);
                        continue;
                    }
                };

            let iov_len: u64 =
                match mem.read_value(msg_iov_ptr + offset_of!(libc::iovec, iov_len) as u64) {
                    Ok(len) => len,
                    Err(e) => {
                        debug!("failed to read iov_len: {}", e);
                        continue;
                    }
                };

            if iov_base == 0 || iov_len == 0 {
                debug!("sendmmsg with empty buffer entry, skipping");
                continue;
            }

            let mut txid = None;
            let dns_name = match DnsQuery::parse(mem, iov_base, iov_len as usize) {
                Ok(query) => {
                    txid = Some(query.txid);
                    debug!("DNS query (sendmmsg) for: {}", query.name);
                    Some(query.name)
                }
                Err(e) => {
                    debug!("failed to parse DNS query in sendmmsg: {}", e);
                    None
                }
            };
            if txid.is_none() {
                txid = DnsQuery::read_txid(mem, iov_base, iov_len as usize).ok();
            }

            if first_target.is_none() {
                first_target = Some(ConnectionTarget {
                    ip: dest.ip(),
                    port: dest.port(),
                    dns_name: dns_name.clone(),
                });
            }

            queries.push((dns_name, txid));
        }

        let Some(target) = first_target else {
            debug!("sendmmsg with no parseable DNS queries, allowing");
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "empty DNS payloads".into(),
            });
        };

        let allowlist = self.allowlist.read().unwrap();
        let denied_name = queries.iter().find_map(|(name, _)| match name {
            None => Some("<unknown>".to_string()),
            Some(name) if !allowlist.is_dns_query_allowed(name) => Some(name.clone()),
            _ => None,
        });

        if let Some(name) = denied_name {
            let denied_target = ConnectionTarget {
                ip: dest.ip(),
                port: dest.port(),
                dns_name: Some(name),
            };
            let should_notify = allowlist.should_notify_block(denied_target.ip, denied_target.port);
            drop(allowlist);
            info!("denied: {} (DNS query)", denied_target);
            if should_notify {
                eprintln!("[egress-filter] DNS query blocked: {}", denied_target);
            }
            self.handler.deny(notification)?;
            return Ok(Decision::Denied {
                target: denied_target,
            });
        }
        drop(allowlist);

        let decision = self.decide_dns_query(notification, &target, dest, queries[0].1)?;

        if let Decision::Allowed { .. } = decision
            && let Some(ref dns_redirect) = self.dns_redirect
        {
            let allowlist = self.allowlist.read().unwrap();
            for (idx, (name, txid)) in queries.iter().enumerate() {
                if idx == 0 {
                    continue;
                }
                let Some(txid) = txid else {
                    continue;
                };
                let ports = name
                    .as_ref()
                    .map(|name| allowlist.get_domain_ports(name))
                    .unwrap_or_default();
                (dns_redirect.register_query)(PendingDnsQuery {
                    original_server: dest,
                    domain: name.clone(),
                    ports,
                    txid: *txid,
                });
            }
        }

        Ok(decision)
    }

    /// Handles send(fd, buf, len, flags) syscall for connected sockets.
    ///
    /// Args layout:
    /// - args[0]: fd
    /// - args[1]: buf pointer
    /// - args[2]: len
    /// - args[3]: flags
    fn handle_send(
        &self,
        mem: &ProcessMemory,
        notification: &SyscallNotification,
    ) -> Result<Decision, HandlerError> {
        let fd = notification.args[0] as i32;
        let buf_ptr = notification.args[1];
        let buf_len = notification.args[2] as usize;

        // Look up the connected destination from our tracking
        let Some(dest) = self.socket_tracker.get(notification.pid, fd) else {
            // Not a tracked socket (not DNS), allow
            debug!("send on untracked socket fd={}, allowing", fd);
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "untracked socket".into(),
            });
        };

        // This is a DNS socket, parse the query
        if dest.port() != 53 || buf_len == 0 {
            debug!("send to non-DNS destination {}, allowing", dest);
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "not a DNS packet".into(),
            });
        }

        // Validate notification
        if !self.handler.is_valid(notification) {
            warn!("notification {} became invalid", notification.id);
            return Ok(Decision::Skipped {
                reason: "notification became invalid".into(),
            });
        }

        // Parse DNS query
        let mut txid = None;
        let dns_name = match DnsQuery::parse(mem, buf_ptr, buf_len) {
            Ok(query) => {
                txid = Some(query.txid);
                debug!("DNS query (send) for: {}", query.name);
                Some(query.name)
            }
            Err(e) => {
                debug!("failed to parse DNS query in send: {}", e);
                None
            }
        };
        if txid.is_none() {
            txid = DnsQuery::read_txid(mem, buf_ptr, buf_len).ok();
        }

        let target = ConnectionTarget {
            ip: dest.ip(),
            port: dest.port(),
            dns_name,
        };

        self.decide_dns_query(notification, &target, dest, txid)
    }
}
