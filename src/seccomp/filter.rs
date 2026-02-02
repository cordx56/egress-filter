use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};
use std::os::fd::{FromRawFd, OwnedFd};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("failed to create seccomp filter: {0}")]
    Creation(#[source] libseccomp::error::SeccompError),
    #[error("failed to add rule for syscall {syscall}: {source}")]
    AddRule {
        syscall: &'static str,
        #[source]
        source: libseccomp::error::SeccompError,
    },
    #[error("failed to load filter: {0}")]
    Load(#[source] libseccomp::error::SeccompError),
    #[error("failed to get notify fd: {0}")]
    NotifyFd(#[source] libseccomp::error::SeccompError),
}

/// Syscalls to intercept for egress filtering.
/// Note: sendmsg is excluded because it's used for fd passing during setup.
/// - connect: TCP connections and UDP "connected" sockets
/// - sendto: UDP packets with explicit destination
/// - send: Used by connected UDP sockets
/// - sendmmsg: Batched sendmsg, used by modern DNS libraries (dig, host)
const INTERCEPTED_SYSCALLS: &[&str] = &["connect", "sendto", "send", "sendmmsg"];

/// Seccomp filter configured to notify on network syscalls.
pub struct SeccompFilter {
    context: ScmpFilterContext,
}

impl SeccompFilter {
    /// Creates a new seccomp filter that notifies on network-related syscalls.
    /// All other syscalls are allowed by default.
    pub fn new() -> Result<Self, FilterError> {
        let mut context =
            ScmpFilterContext::new(ScmpAction::Allow).map_err(FilterError::Creation)?;

        // Add native architecture
        context
            .add_arch(ScmpArch::Native)
            .map_err(FilterError::Creation)?;

        // Add notification rules for network syscalls
        for name in INTERCEPTED_SYSCALLS {
            let syscall = ScmpSyscall::from_name(name).map_err(|e| FilterError::AddRule {
                syscall: name,
                source: e,
            })?;
            context
                .add_rule(ScmpAction::Notify, syscall)
                .map_err(|e| FilterError::AddRule {
                    syscall: name,
                    source: e,
                })?;
        }

        Ok(Self { context })
    }

    /// Loads the filter and returns the notification file descriptor.
    /// After this call, the filter is active for the current process.
    pub fn load(self) -> Result<OwnedFd, FilterError> {
        self.context.load().map_err(FilterError::Load)?;

        let raw_fd = self
            .context
            .get_notify_fd()
            .map_err(FilterError::NotifyFd)?;

        // SAFETY: get_notify_fd returns a valid fd after load() succeeds.
        // We take ownership of the fd; libseccomp docs indicate the caller
        // is responsible for closing it.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that seccomp filter creation succeeds.
    /// Note: We only test creation, not loading, because loading the filter
    /// would affect the current process and interfere with test execution.
    #[test]
    fn filter_creation_succeeds() {
        let filter = SeccompFilter::new();
        assert!(filter.is_ok());
    }
}
