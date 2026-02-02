use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::io::{self, IoSlice, IoSliceMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("failed to read process memory at address {address:#x}: {source}")]
    ReadFailed {
        address: u64,
        #[source]
        source: nix::Error,
    },
    #[error("failed to write process memory at address {address:#x}: {source}")]
    WriteFailed {
        address: u64,
        #[source]
        source: nix::Error,
    },
    #[error("partial read: expected {expected} bytes, got {actual}")]
    PartialRead { expected: usize, actual: usize },
    #[error("partial write: expected {expected} bytes, wrote {actual}")]
    PartialWrite { expected: usize, actual: usize },
}

/// Provides access to another process's memory via process_vm_readv.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemory {
    pid: Pid,
}

impl ProcessMemory {
    pub fn new(pid: u32) -> Self {
        Self {
            pid: Pid::from_raw(pid as i32),
        }
    }

    /// Reads bytes from the target process's memory.
    pub fn read(&self, address: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        if buf.is_empty() {
            return Ok(());
        }

        let expected_len = buf.len();
        let mut local_iov = [IoSliceMut::new(buf)];
        let remote_iov = [RemoteIoVec {
            base: address as usize,
            len: expected_len,
        }];

        let bytes_read = process_vm_readv(self.pid, &mut local_iov, &remote_iov)
            .map_err(|e| MemoryError::ReadFailed { address, source: e })?;

        if bytes_read != expected_len {
            return Err(MemoryError::PartialRead {
                expected: expected_len,
                actual: bytes_read,
            });
        }

        Ok(())
    }

    /// Reads a value of type T from the target process's memory.
    ///
    /// # Safety
    ///
    /// The type T must be safe to read from arbitrary bytes (i.e., no invalid
    /// bit patterns). Use only for primitive types or `#[repr(C)]` structs.
    /// The caller is responsible for ensuring T is valid for any bit pattern.
    pub fn read_value<T: Copy>(&self, address: u64) -> Result<T, MemoryError> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        self.read(address, &mut buf)?;

        // SAFETY: We've read exactly size_of::<T>() bytes into a properly aligned buffer.
        Ok(unsafe { std::ptr::read(buf.as_ptr() as *const T) })
    }

    /// Writes bytes to the target process's memory.
    pub fn write(&self, address: u64, buf: &[u8]) -> Result<(), MemoryError> {
        if buf.is_empty() {
            return Ok(());
        }

        let expected_len = buf.len();
        let local_iov = [IoSlice::new(buf)];
        let remote_iov = [RemoteIoVec {
            base: address as usize,
            len: expected_len,
        }];

        let bytes_written = process_vm_writev(self.pid, &local_iov, &remote_iov)
            .map_err(|e| MemoryError::WriteFailed { address, source: e })?;

        if bytes_written != expected_len {
            return Err(MemoryError::PartialWrite {
                expected: expected_len,
                actual: bytes_written,
            });
        }

        Ok(())
    }

    /// Writes a value of type T to the target process's memory.
    ///
    /// # Safety
    ///
    /// The type T must have a valid memory representation.
    /// Use only for primitive types or `#[repr(C)]` structs.
    pub fn write_value<T: Copy>(&self, address: u64, value: &T) -> Result<(), MemoryError> {
        // SAFETY: We're reading size_of::<T>() bytes from a valid T reference.
        let buf = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.write(address, buf)
    }
}

impl From<MemoryError> for io::Error {
    fn from(err: MemoryError) -> Self {
        io::Error::other(err)
    }
}
