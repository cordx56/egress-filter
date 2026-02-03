use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use crate::allowlist::AllowList;
use crate::seccomp::{InterceptedSyscall, NotificationHandler, ProcessMemory, SyscallNotification};

use super::dns::DnsQuery;
use super::sockaddr::{ParsedAddress, SocketAddress};

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

/// Handles network-related syscall notifications.
pub struct NetworkHandler<'a> {
    handler: &'a NotificationHandler,
    allowlist: Arc<RwLock<AllowList>>,
    /// Proxy redirect configuration (if DoH interception is enabled).
    proxy_redirect: Option<ProxyRedirect>,
    /// Tracks connected sockets for send() handling.
    socket_tracker: SocketTracker,
}

impl<'a> NetworkHandler<'a> {
    pub fn new(handler: &'a NotificationHandler, allowlist: Arc<RwLock<AllowList>>) -> Self {
        Self {
            handler,
            allowlist,
            proxy_redirect: None,
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

        // Track DNS server connections for send() handling
        if parsed.port() == 53 {
            let fd = notification.args[0] as i32;
            self.socket_tracker.track(notification.pid, fd, parsed.addr);
            debug!(
                "tracking DNS socket: pid={} fd={} -> {}",
                notification.pid, fd, parsed.addr
            );
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

        // If dest_addr is NULL, it's connected UDP; allow for now
        if dest_addr_ptr == 0 {
            debug!("sendto with NULL dest_addr, allowing");
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "connected UDP socket".into(),
            });
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
            let dns_name = match DnsQuery::parse(mem, buf_ptr, buf_len) {
                Ok(query) => {
                    debug!("DNS query for: {}", query.name);
                    Some(query.name)
                }
                Err(e) => {
                    debug!("failed to parse DNS query: {}", e);
                    None
                }
            };

            let target = ConnectionTarget {
                ip: parsed.ip(),
                port: parsed.port(),
                dns_name,
            };

            return self.decide_dns_query(notification, &target);
        }

        let target = ConnectionTarget {
            ip: parsed.ip(),
            port: parsed.port(),
            dns_name: None,
        };

        self.decide_and_respond(notification, &target, &parsed)
    }

    /// Decides whether to allow or deny a DNS query.
    /// Uses `is_dns_query_allowed` which checks domain rules without port restriction,
    /// since the target port here is the DNS server port (53), not the service port.
    fn decide_dns_query(
        &self,
        notification: &SyscallNotification,
        target: &ConnectionTarget,
    ) -> Result<Decision, HandlerError> {
        let allowlist = self.allowlist.read().unwrap();
        let allowed = if let Some(ref name) = target.dns_name {
            allowlist.is_dns_query_allowed(name)
        } else {
            // Can't parse DNS query, fall back to IP check
            allowlist.is_ip_allowed(target.ip, target.port)
        };

        if allowed {
            info!("allowed: {} (DNS query)", target);
            self.handler.allow(notification)?;
            Ok(Decision::Allowed {
                target: target.clone(),
            })
        } else {
            info!("denied: {} (DNS query)", target);
            if allowlist.should_notify_block(target.ip, target.port) {
                eprintln!("[egress-filter] DNS query blocked: {}", target);
            }
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

        // Read the first mmsghdr structure
        // struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; }
        // struct msghdr { void *msg_name; socklen_t msg_namelen; struct iovec *msg_iov; size_t msg_iovlen; ... }
        // On 64-bit: msghdr is 56 bytes, mmsghdr is 64 bytes
        // msg_iov is at offset 16 in msghdr
        // struct iovec { void *iov_base; size_t iov_len; }
        let msg_iov_ptr: u64 = match mem.read_value(msgvec_ptr + 16) {
            Ok(ptr) => ptr,
            Err(e) => {
                debug!("failed to read msg_iov pointer: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("failed to read msg_iov: {}", e),
                });
            }
        };

        let msg_iovlen: u64 = match mem.read_value(msgvec_ptr + 24) {
            Ok(len) => len,
            Err(e) => {
                debug!("failed to read msg_iovlen: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("failed to read msg_iovlen: {}", e),
                });
            }
        };

        if msg_iovlen == 0 || msg_iov_ptr == 0 {
            debug!("sendmmsg with empty iov, allowing");
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "empty iov".into(),
            });
        }

        // Read the first iovec
        let iov_base: u64 = match mem.read_value(msg_iov_ptr) {
            Ok(ptr) => ptr,
            Err(e) => {
                debug!("failed to read iov_base: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("failed to read iov_base: {}", e),
                });
            }
        };

        let iov_len: u64 = match mem.read_value(msg_iov_ptr + 8) {
            Ok(len) => len,
            Err(e) => {
                debug!("failed to read iov_len: {}", e);
                self.handler.allow(notification)?;
                return Ok(Decision::Skipped {
                    reason: format!("failed to read iov_len: {}", e),
                });
            }
        };

        if iov_base == 0 || iov_len == 0 {
            debug!("sendmmsg with empty buffer, allowing");
            self.handler.allow(notification)?;
            return Ok(Decision::Skipped {
                reason: "empty buffer".into(),
            });
        }

        // Parse DNS query from the buffer
        let dns_name = match DnsQuery::parse(mem, iov_base, iov_len as usize) {
            Ok(query) => {
                debug!("DNS query (sendmmsg) for: {}", query.name);
                Some(query.name)
            }
            Err(e) => {
                debug!("failed to parse DNS query in sendmmsg: {}", e);
                None
            }
        };

        let target = ConnectionTarget {
            ip: dest.ip(),
            port: dest.port(),
            dns_name,
        };

        self.decide_dns_query(notification, &target)
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
        let dns_name = match DnsQuery::parse(mem, buf_ptr, buf_len) {
            Ok(query) => {
                debug!("DNS query (send) for: {}", query.name);
                Some(query.name)
            }
            Err(e) => {
                debug!("failed to parse DNS query in send: {}", e);
                None
            }
        };

        let target = ConnectionTarget {
            ip: dest.ip(),
            port: dest.port(),
            dns_name,
        };

        self.decide_dns_query(notification, &target)
    }
}
