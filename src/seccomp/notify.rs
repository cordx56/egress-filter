use libseccomp::{ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags, ScmpSyscall, notify_id_valid};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("failed to receive notification: {0}")]
    Receive(#[source] libseccomp::error::SeccompError),
    #[error("failed to send response: {0}")]
    Respond(#[source] libseccomp::error::SeccompError),
    #[error("notification {id} is no longer valid")]
    NotificationInvalid { id: u64 },
    #[error("unknown syscall number: {0}")]
    UnknownSyscall(i32),
}

/// Identifies the syscall that triggered a notification.
///
/// Note: `sendmsg` is intentionally excluded from interception because it's used
/// for fd passing during supervisor setup (SCM_RIGHTS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptedSyscall {
    Connect,
    Sendto,
    /// send() for connected sockets (no destination address)
    Send,
    /// sendmmsg() - batched sendmsg, used by modern DNS libraries
    Sendmmsg,
}

impl InterceptedSyscall {
    fn from_nr(nr: i32) -> Result<Self, NotifyError> {
        // Resolve syscall names to numbers at runtime
        let connect = ScmpSyscall::from_name("connect").ok().map(i32::from);
        let sendto = ScmpSyscall::from_name("sendto").ok().map(i32::from);
        let send = ScmpSyscall::from_name("send").ok().map(i32::from);
        let sendmmsg = ScmpSyscall::from_name("sendmmsg").ok().map(i32::from);

        if connect == Some(nr) {
            Ok(Self::Connect)
        } else if sendto == Some(nr) {
            Ok(Self::Sendto)
        } else if send == Some(nr) {
            Ok(Self::Send)
        } else if sendmmsg == Some(nr) {
            Ok(Self::Sendmmsg)
        } else {
            Err(NotifyError::UnknownSyscall(nr))
        }
    }
}

/// A syscall notification from the kernel.
#[derive(Debug)]
pub struct SyscallNotification {
    /// Unique notification ID for responding.
    pub id: u64,
    /// Process ID that triggered the syscall.
    pub pid: u32,
    /// Which syscall was intercepted.
    pub syscall: InterceptedSyscall,
    /// Syscall arguments (up to 6).
    pub args: [u64; 6],
}

impl SyscallNotification {
    fn from_request(req: ScmpNotifReq) -> Result<Self, NotifyError> {
        // ScmpSyscall implements Into<i32>
        let syscall_nr: i32 = req.data.syscall.into();
        let syscall = InterceptedSyscall::from_nr(syscall_nr)?;

        Ok(Self {
            id: req.id,
            pid: req.pid,
            syscall,
            args: req.data.args,
        })
    }
}

/// Handles seccomp notifications on a notify fd.
pub struct NotificationHandler {
    fd: OwnedFd,
}

impl AsRawFd for NotificationHandler {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl NotificationHandler {
    /// Creates a handler from an owned notify fd.
    pub fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Blocks until a notification is received.
    pub fn receive(&self) -> Result<SyscallNotification, NotifyError> {
        let req = ScmpNotifReq::receive(self.fd.as_raw_fd()).map_err(NotifyError::Receive)?;
        SyscallNotification::from_request(req)
    }

    /// Checks if a notification is still valid (TOCTOU mitigation).
    pub fn is_valid(&self, notification: &SyscallNotification) -> bool {
        notify_id_valid(self.fd.as_raw_fd(), notification.id).is_ok()
    }

    /// Allow the syscall to proceed normally.
    pub fn allow(&self, notification: &SyscallNotification) -> Result<(), NotifyError> {
        let resp = ScmpNotifResp::new_continue(notification.id, ScmpNotifRespFlags::CONTINUE);
        resp.respond(self.fd.as_raw_fd())
            .map_err(NotifyError::Respond)
    }

    /// Deny the syscall with EACCES.
    pub fn deny(&self, notification: &SyscallNotification) -> Result<(), NotifyError> {
        // new_error expects a negative errno value
        let resp =
            ScmpNotifResp::new_error(notification.id, -libc::EACCES, ScmpNotifRespFlags::empty());
        resp.respond(self.fd.as_raw_fd())
            .map_err(NotifyError::Respond)
    }

    /// Deny the syscall with a specific errno.
    pub fn deny_with_errno(
        &self,
        notification: &SyscallNotification,
        errno: i32,
    ) -> Result<(), NotifyError> {
        // new_error expects a negative errno value
        let resp =
            ScmpNotifResp::new_error(notification.id, -errno.abs(), ScmpNotifRespFlags::empty());
        resp.respond(self.fd.as_raw_fd())
            .map_err(NotifyError::Respond)
    }
}
