//! Egress filter using seccomp user notification.
//!
//! This crate provides tools to intercept and filter outgoing network
//! connections from a child process using Linux seccomp-bpf with user
//! notification (SECCOMP_RET_USER_NOTIF).
//!
//! # Architecture
//!
//! The supervisor process:
//! 1. Creates a socket pair for fd passing
//! 2. Forks a child process
//! 3. Child loads seccomp filter and sends notify fd to parent
//! 4. Child execs the target command
//! 5. Parent receives notify fd and handles notifications
//!
//! # DoH (DNS over HTTPS) Interception
//!
//! When DoH is enabled, the supervisor also:
//! - Spawns a TLS-terminating proxy on localhost
//! - Generates an ephemeral CA certificate
//! - Injects CA into child's environment (EGRESS_FILTER_CA_CERT, SSL_CERT_FILE, etc.)
//! - Redirects HTTPS connections (port 443) through the proxy
//! - Intercepts DoH queries and checks them against the allowlist
//! - Caches resolved IP addresses for subsequent connections
//!
//! # Example
//!
//! ```no_run
//! use egress_filter::{Supervisor, AllowListConfig};
//!
//! let config = AllowListConfig::load("allowlist.yaml").unwrap();
//! let supervisor = Supervisor::new(config);
//! supervisor.run(&["curl", "https://example.com"]).unwrap();
//! ```

mod allowlist;
pub mod ca;
mod config_watcher;
mod network;
pub mod proxy;
mod seccomp;

pub use allowlist::{AllowList, AllowListConfig, AllowListError, DnsConfig, DohConfig};
pub use network::{
    ConnectionTarget, Decision, DnsQuery, DnsRedirect, NetworkHandler, ProxyRedirect,
};
pub use seccomp::{NotificationHandler, ProcessMemory, SeccompFilter, SyscallNotification};

// Re-export InterceptedSyscall for handlers
pub use seccomp::notify::InterceptedSyscall;

use anyhow::{Context, Result};
use nix::cmsg_space;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::ffi::CString;
use std::io::{IoSlice, IoSliceMut};
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

use config_watcher::ConfigEvent;

use ca::CaState;
use proxy::{
    AllowListChecker, DnsProxyServer, DnsProxyState, PendingDnsQuery, ProxyServer, ProxyState,
    ResolutionCache,
};

/// Supervisor that runs a command under egress filtering.
pub struct Supervisor {
    allowlist: Arc<RwLock<AllowList>>,
    config: AllowListConfig,
    /// Path to the configuration file for hot-reloading.
    config_path: Option<PathBuf>,
    /// Port for the DNS proxy server (0 = ephemeral).
    dns_proxy_port: u16,
}

/// Wrapper to implement AllowListChecker for AllowList
struct AllowListWrapper(Arc<RwLock<AllowList>>);

impl AllowListChecker for AllowListWrapper {
    fn is_domain_allowed(&self, domain: &str, port: u16) -> bool {
        self.0.read().unwrap().is_domain_allowed(domain, port)
    }
}

/// Wrapper to implement ResolutionCache for AllowList
struct ResolutionCacheWrapper(Arc<RwLock<AllowList>>);

impl ResolutionCache for ResolutionCacheWrapper {
    fn cache_resolution(&self, domain: &str, addresses: &[IpAddr], ports: Vec<u16>) {
        self.0
            .read()
            .unwrap()
            .cache_doh_resolution(domain, addresses, ports);
    }
}

fn write_ca_cert_temp(ca_pem: &str) -> Result<PathBuf> {
    let base_dir = std::env::temp_dir();
    let pid = std::process::id();
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..16 {
        let path = base_dir.join(format!(
            "egress-filter-ca-{}-{}-{}.pem",
            pid, now_nanos, attempt
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(ca_pem.as_bytes())
                    .context("failed to write CA certificate to temp file")?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).context("failed to create CA certificate temp file");
            }
        }
    }

    anyhow::bail!("failed to allocate unique CA certificate temp file")
}

impl Supervisor {
    /// Creates a new supervisor with the given allowlist configuration.
    pub fn new(config: AllowListConfig) -> Self {
        Self {
            allowlist: Arc::new(RwLock::new(AllowList::new(&config))),
            config,
            config_path: None,
            dns_proxy_port: 0,
        }
    }

    /// Creates a new supervisor that watches the configuration file for changes.
    pub fn with_config_path(config: AllowListConfig, path: PathBuf) -> Self {
        Self {
            allowlist: Arc::new(RwLock::new(AllowList::new(&config))),
            config,
            config_path: Some(path),
            dns_proxy_port: 0,
        }
    }

    /// Sets the DNS proxy port (0 = ephemeral).
    pub fn with_dns_proxy_port(mut self, port: u16) -> Self {
        self.dns_proxy_port = port;
        self
    }

    /// Runs the command with egress filtering.
    ///
    /// Returns the exit code of the child process.
    pub fn run<S: AsRef<str>>(&self, args: &[S]) -> Result<i32> {
        if args.is_empty() {
            anyhow::bail!("no command specified");
        }

        let program = args[0].as_ref();
        let c_args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_ref()).unwrap())
            .collect();

        // Capture environment variables BEFORE fork to ensure they are passed to child.
        // Some container runtimes may inject env vars in ways that don't survive fork.
        let mut env: Vec<CString> = std::env::vars()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect();

        // If DoH is enabled, set up the TLS proxy and inject CA certificate
        let doh_enabled = self.config.doh.enabled;
        let proxy_state = if doh_enabled {
            info!("DoH interception enabled, generating ephemeral CA");

            // Generate ephemeral CA
            let ca = Arc::new(CaState::generate().context("failed to generate CA certificate")?);

            // Create proxy state
            let proxy_state = Arc::new(ProxyState::new(
                Arc::clone(&ca),
                Arc::new(AllowListWrapper(Arc::clone(&self.allowlist))),
                Arc::new(ResolutionCacheWrapper(Arc::clone(&self.allowlist))),
            ));

            // Inject CA certificate into environment
            let ca_pem = ca.ca_cert_pem();

            // Write CA to a unique temp file for SSL_CERT_FILE
            let ca_file_path = write_ca_cert_temp(ca_pem)?;
            let ca_file_path_str = ca_file_path.to_string_lossy();

            // Add environment variables for various TLS libraries
            env.push(CString::new(format!("EGRESS_FILTER_CA_CERT={}", ca_pem)).unwrap());
            env.push(CString::new(format!("SSL_CERT_FILE={}", ca_file_path_str)).unwrap());
            env.push(CString::new(format!("CURL_CA_BUNDLE={}", ca_file_path_str)).unwrap());
            env.push(CString::new(format!("NODE_EXTRA_CA_CERTS={}", ca_file_path_str)).unwrap());
            env.push(CString::new(format!("REQUESTS_CA_BUNDLE={}", ca_file_path_str)).unwrap());

            info!("CA certificate injected into environment");

            Some(proxy_state)
        } else {
            None
        };

        // Create socket pair for passing the notify fd from child to parent
        // Use SEQPACKET for reliable, message-based communication
        let (parent_sock, child_sock) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )
        .context("failed to create socket pair")?;

        // Block signals and create signalfd before fork.
        // This allows the parent to detect child termination and handle termination signals.
        let mut sigset = SigSet::empty();
        sigset.add(Signal::SIGCHLD);
        sigset.add(Signal::SIGTERM);
        sigset.add(Signal::SIGINT);
        sigset.thread_block().context("failed to block signals")?;
        let signal_fd = SignalFd::with_flags(&sigset, SfdFlags::SFD_NONBLOCK)
            .context("failed to create signalfd")?;

        // SAFETY: We're careful to only do async-signal-safe operations
        // in the child between fork and exec.
        match unsafe { fork() }.context("fork failed")? {
            ForkResult::Parent { child } => {
                // Close child's end of the socket
                drop(child_sock);
                self.supervisor_main(child, parent_sock, proxy_state, signal_fd)
            }
            ForkResult::Child => {
                // Close parent's end of the socket
                drop(parent_sock);
                // Close signalfd in child (not needed)
                drop(signal_fd);
                // Unblock SIGCHLD in child
                let _ = sigset.thread_unblock();

                // In child: create filter, load it, send fd, then exec
                match self.child_main(child_sock, program, &c_args, &env) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        eprintln!("egress-filter: child setup failed: {}", e);
                        std::process::exit(127);
                    }
                }
            }
        }
    }

    fn child_main(
        &self,
        sock: OwnedFd,
        program: &str,
        args: &[CString],
        env: &[CString],
    ) -> Result<()> {
        // Request SIGKILL when parent dies (safety net for orphaned child)
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }

        // Create and load the seccomp filter
        let filter = SeccompFilter::new().context("failed to create seccomp filter")?;
        let notify_fd = filter.load().context("failed to load seccomp filter")?;

        // Send the notify fd to parent via SCM_RIGHTS
        let fd = notify_fd.as_raw_fd();
        let iov = [IoSlice::new(&[0u8])]; // Need at least 1 byte of data
        let cmsg = [ControlMessage::ScmRights(&[fd])];

        sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .context("failed to send notify fd to parent")?;

        // Close our copy of the notify fd (parent has it now)
        drop(notify_fd);

        // Close the socket
        drop(sock);

        // Find program in PATH if not absolute
        let program_path = if program.contains('/') {
            Path::new(program).to_path_buf()
        } else {
            which::which(program).context("program not found in PATH")?
        };

        let c_program = CString::new(program_path.as_os_str().as_bytes())?;

        // exec with explicit environment variables to ensure they are passed
        nix::unistd::execve(&c_program, args, env).context("execve failed")?;

        unreachable!()
    }

    fn supervisor_main(
        &self,
        child: Pid,
        sock: OwnedFd,
        proxy_state: Option<Arc<ProxyState>>,
        signal_fd: SignalFd,
    ) -> Result<i32> {
        // Receive the notify fd from child via SCM_RIGHTS
        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_buf = cmsg_space!([RawFd; 1]);

        let msg = recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .context("failed to receive notify fd from child")?;

        // Extract the fd from control message
        let notify_fd = msg
            .cmsgs()
            .context("failed to get control messages")?
            .find_map(|cmsg| {
                if let ControlMessageOwned::ScmRights(fds) = cmsg {
                    fds.into_iter().next()
                } else {
                    None
                }
            })
            .context("no fd received from child")?;

        // SAFETY: We received this fd via SCM_RIGHTS
        let notify_fd = unsafe { OwnedFd::from_raw_fd(notify_fd) };

        // Close the socket
        drop(sock);

        info!("supervisor started for child {}", child);

        // Start proxy if DoH is enabled
        let proxy_redirect = if let Some(state) = proxy_state {
            // Create tokio runtime for the proxy
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("failed to create tokio runtime")?;

            // Start proxy server
            let proxy_server = rt
                .block_on(async { ProxyServer::bind(Arc::clone(&state)).await })
                .context("failed to start proxy server")?;

            let proxy_addr = proxy_server.local_addr()?;
            info!("DoH proxy listening on {}", proxy_addr);

            // Spawn proxy in background thread
            std::thread::spawn(move || {
                rt.block_on(async {
                    if let Err(e) = proxy_server.run().await {
                        error!("proxy server error: {}", e);
                    }
                });
            });

            // Create proxy redirect for network handler
            let state_for_redirect = state;
            Some(ProxyRedirect {
                proxy_addr,
                register_destination: Arc::new(move |original| {
                    // We use a blocking approach here since this is called from sync code
                    // The proxy state uses async internally, but we can use tokio::spawn
                    let state = Arc::clone(&state_for_redirect);
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        rt.block_on(async {
                            state.register_destination(original).await;
                        });
                    });
                }),
            })
        } else {
            None
        };

        // Start DNS proxy (always active, independent of DoH)
        let resolution_cache = Arc::new(ResolutionCacheWrapper(Arc::clone(&self.allowlist)));
        let dns_proxy_state = Arc::new(DnsProxyState::new(resolution_cache));

        let dns_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create DNS proxy tokio runtime")?;

        let dns_server = dns_rt
            .block_on(async {
                DnsProxyServer::bind(Arc::clone(&dns_proxy_state), self.dns_proxy_port).await
            })
            .context("failed to start DNS proxy server")?;

        let dns_proxy_addr = dns_server.local_addr()?;
        info!("DNS proxy listening on {}", dns_proxy_addr);

        std::thread::spawn(move || {
            dns_rt.block_on(async {
                if let Err(e) = dns_server.run().await {
                    error!("DNS proxy server error: {}", e);
                }
            });
        });

        let dns_state_for_redirect = dns_proxy_state;
        let dns_redirect = DnsRedirect {
            proxy_addr: dns_proxy_addr,
            register_query: Arc::new(move |query: PendingDnsQuery| {
                dns_state_for_redirect.register_query(query);
            }),
        };

        self.supervisor_loop(
            child,
            notify_fd,
            proxy_redirect,
            Some(dns_redirect),
            signal_fd,
        )
    }

    fn supervisor_loop(
        &self,
        child: Pid,
        notify_fd: OwnedFd,
        proxy_redirect: Option<ProxyRedirect>,
        dns_redirect: Option<DnsRedirect>,
        signal_fd: SignalFd,
    ) -> Result<i32> {
        let handler = NotificationHandler::new(notify_fd);
        let mut network_handler = NetworkHandler::new(&handler, Arc::clone(&self.allowlist));

        // Configure proxy redirect if enabled
        if let Some(redirect) = proxy_redirect {
            network_handler = network_handler.with_proxy_redirect(redirect);
        }

        // Configure DNS proxy redirect
        if let Some(redirect) = dns_redirect {
            network_handler = network_handler.with_dns_redirect(redirect);
        }

        // Start config watcher if a config path was provided
        let config_receiver = if let Some(ref path) = self.config_path {
            match config_watcher::spawn_config_watcher(path) {
                Ok(rx) => Some(rx),
                Err(e) => {
                    warn!("failed to start config watcher: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut notification_count = 0u64;

        // Set up poll fds for notify_fd and signal_fd
        let notify_fd_raw = handler.as_raw_fd();
        let signal_fd_raw = signal_fd.as_fd();

        loop {
            // Check for config reload events
            if let Some(ref rx) = config_receiver {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        ConfigEvent::Modified => {
                            if let Some(ref path) = self.config_path {
                                info!("configuration file changed, reloading...");
                                match AllowListConfig::load(path) {
                                    Ok(new_config) => {
                                        let new_allowlist = AllowList::new(&new_config);
                                        if let Ok(mut al) = self.allowlist.write() {
                                            *al = new_allowlist;
                                            info!("configuration reloaded successfully");
                                        }
                                    }
                                    Err(e) => {
                                        warn!("failed to reload config: {}", e);
                                    }
                                }
                            }
                        }
                        ConfigEvent::Error(e) => {
                            warn!("config watcher error: {}", e);
                        }
                    }
                }
            }

            // Periodically clean up expired DNS cache entries (every 100 notifications)
            notification_count = notification_count.wrapping_add(1);
            if notification_count.is_multiple_of(100)
                && let Ok(al) = self.allowlist.read()
            {
                al.cleanup_dns_cache();
            }

            // Use poll to wait for either:
            // - notify_fd becoming readable (new seccomp notification)
            // - signal_fd becoming readable (SIGCHLD received)
            let notify_borrow = unsafe { BorrowedFd::borrow_raw(notify_fd_raw) };
            let mut poll_fds = [
                PollFd::new(notify_borrow, PollFlags::POLLIN),
                PollFd::new(signal_fd_raw, PollFlags::POLLIN),
            ];

            match poll(&mut poll_fds, PollTimeout::NONE) {
                Ok(0) => continue, // Timeout (shouldn't happen with NONE)
                Ok(_) => {}
                Err(nix::Error::EINTR) => continue, // Interrupted, retry
                Err(e) => {
                    error!("poll error: {}", e);
                    continue;
                }
            }

            // Check if signal_fd is readable (signal received)
            if poll_fds[1]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                // Read the signal info
                if let Ok(Some(siginfo)) = signal_fd.read_signal() {
                    let signo = siginfo.ssi_signo as i32;

                    // Forward termination signals to child
                    if signo == libc::SIGTERM || signo == libc::SIGINT {
                        info!("received signal {}, forwarding to child", signo);
                        let _ = nix::sys::signal::kill(child, Signal::try_from(signo).ok());
                        // Continue to wait for child to exit
                    }
                }

                // Check child status
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) => {
                        // Child still running, continue
                    }
                    Ok(WaitStatus::Exited(_, code)) => {
                        info!("child exited with code {}", code);
                        return Ok(code);
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        info!("child killed by signal {:?}", sig);
                        return Ok(128 + sig as i32);
                    }
                    Ok(status) => {
                        debug!("child status: {:?}", status);
                    }
                    Err(nix::Error::ECHILD) => {
                        debug!("child already gone");
                        break;
                    }
                    Err(e) => {
                        warn!("waitpid error: {}", e);
                    }
                }
            }

            // Check if notify_fd is readable (new notification)
            if poll_fds[0]
                .revents()
                .is_some_and(|r| r.contains(PollFlags::POLLIN))
            {
                let notification = match handler.receive() {
                    Ok(n) => n,
                    Err(e) => {
                        let err_str = e.to_string();
                        // These errors indicate the child process has exited
                        if err_str.contains("ENOENT")
                            || err_str.contains("ESRCH")
                            || err_str.contains("EBADF")
                            || err_str.contains("system failure")
                        {
                            debug!("notification fd closed, child likely exited");
                            break;
                        }
                        error!("receive error: {}", e);
                        continue;
                    }
                };

                debug!(
                    "notification: pid={} syscall={:?}",
                    notification.pid, notification.syscall
                );

                match network_handler.handle(&notification) {
                    Ok(decision) => {
                        debug!("decision: {:?}", decision);
                    }
                    Err(e) => {
                        error!("handler error: {}", e);
                        // Try to allow on error to avoid hanging the child
                        let _ = handler.allow(&notification);
                    }
                }
            }
        }

        // Final wait for child
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => Ok(128 + sig as i32),
            Ok(_) => Ok(1),
            Err(_) => Ok(1),
        }
    }
}

/// Callback for reporting blocked connections.
pub type BlockedCallback = Box<dyn Fn(&ConnectionTarget) + Send + Sync>;
