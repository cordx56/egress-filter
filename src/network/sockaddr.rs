use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

use crate::seccomp::ProcessMemory;

#[derive(Debug, Error)]
pub enum SockaddrError {
    #[error("unsupported address family: {0}")]
    UnsupportedFamily(u16),
    #[error("failed to read sockaddr from process memory: {0}")]
    MemoryRead(#[from] crate::seccomp::memory::MemoryError),
    #[error("address length too short: {len} bytes for family {family}")]
    TooShort { len: usize, family: u16 },
    #[error("address family mismatch: cannot write IPv6 to IPv4 sockaddr")]
    FamilyMismatch,
}

/// A parsed socket address with additional metadata.
#[derive(Debug, Clone)]
pub struct ParsedAddress {
    pub addr: SocketAddr,
    pub is_dns: bool,
}

impl ParsedAddress {
    pub fn new(addr: SocketAddr) -> Self {
        let is_dns = addr.port() == 53;
        Self { addr, is_dns }
    }

    pub fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

/// Raw sockaddr structures for reading from process memory.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16, // Network byte order (big-endian)
    sin_addr: [u8; 4],
    _pad: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16, // Network byte order (big-endian)
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

const AF_INET: u16 = libc::AF_INET as u16;
const AF_INET6: u16 = libc::AF_INET6 as u16;

/// Represents a socket address that can be read from process memory.
pub struct SocketAddress;

impl SocketAddress {
    /// Reads a sockaddr from the target process's memory.
    ///
    /// # Arguments
    /// * `mem` - Process memory accessor
    /// * `addr_ptr` - Pointer to sockaddr in target process
    /// * `addr_len` - Length of the sockaddr structure
    pub fn read(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: u32,
    ) -> Result<ParsedAddress, SockaddrError> {
        // First, read just the family to determine the address type
        let family: u16 = mem.read_value(addr_ptr)?;

        match family {
            AF_INET => Self::read_ipv4(mem, addr_ptr, addr_len as usize),
            AF_INET6 => Self::read_ipv6(mem, addr_ptr, addr_len as usize),
            _ => Err(SockaddrError::UnsupportedFamily(family)),
        }
    }

    fn read_ipv4(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: usize,
    ) -> Result<ParsedAddress, SockaddrError> {
        const MIN_LEN: usize = std::mem::size_of::<SockaddrIn>();
        if addr_len < MIN_LEN {
            return Err(SockaddrError::TooShort {
                len: addr_len,
                family: AF_INET,
            });
        }

        let sockaddr: SockaddrIn = mem.read_value(addr_ptr)?;
        let port = u16::from_be(sockaddr.sin_port);
        let ip = Ipv4Addr::from(sockaddr.sin_addr);

        Ok(ParsedAddress::new(SocketAddr::new(IpAddr::V4(ip), port)))
    }

    fn read_ipv6(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: usize,
    ) -> Result<ParsedAddress, SockaddrError> {
        const MIN_LEN: usize = std::mem::size_of::<SockaddrIn6>();
        if addr_len < MIN_LEN {
            return Err(SockaddrError::TooShort {
                len: addr_len,
                family: AF_INET6,
            });
        }

        let sockaddr: SockaddrIn6 = mem.read_value(addr_ptr)?;
        let port = u16::from_be(sockaddr.sin6_port);
        let ip = Ipv6Addr::from(sockaddr.sin6_addr);

        Ok(ParsedAddress::new(SocketAddr::new(IpAddr::V6(ip), port)))
    }

    /// Writes a socket address to the target process's memory.
    ///
    /// The new address must be IPv4 if the original was IPv4.
    /// IPv6 addresses can only be written to IPv6 sockaddrs.
    ///
    /// # Arguments
    /// * `mem` - Process memory accessor
    /// * `addr_ptr` - Pointer to sockaddr in target process
    /// * `addr_len` - Length of the sockaddr structure
    /// * `new_addr` - The new socket address to write
    pub fn write(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: u32,
        new_addr: SocketAddr,
    ) -> Result<(), SockaddrError> {
        // First, read the original family
        let family: u16 = mem.read_value(addr_ptr)?;

        match (family, new_addr) {
            (AF_INET, SocketAddr::V4(addr)) => {
                Self::write_ipv4(mem, addr_ptr, addr_len as usize, addr)
            }
            (AF_INET6, SocketAddr::V6(addr)) => {
                Self::write_ipv6(mem, addr_ptr, addr_len as usize, addr)
            }
            // Allow writing IPv4 to IPv6 sockaddr as IPv4-mapped IPv6
            (AF_INET6, SocketAddr::V4(addr)) => {
                let mapped = addr.ip().to_ipv6_mapped();
                let v6_addr = std::net::SocketAddrV6::new(mapped, addr.port(), 0, 0);
                Self::write_ipv6(mem, addr_ptr, addr_len as usize, v6_addr)
            }
            _ => Err(SockaddrError::FamilyMismatch),
        }
    }

    fn write_ipv4(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: usize,
        new_addr: std::net::SocketAddrV4,
    ) -> Result<(), SockaddrError> {
        const MIN_LEN: usize = std::mem::size_of::<SockaddrIn>();
        if addr_len < MIN_LEN {
            return Err(SockaddrError::TooShort {
                len: addr_len,
                family: AF_INET,
            });
        }

        let sockaddr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: new_addr.port().to_be(),
            sin_addr: new_addr.ip().octets(),
            _pad: [0u8; 8],
        };

        mem.write_value(addr_ptr, &sockaddr)?;
        Ok(())
    }

    fn write_ipv6(
        mem: &ProcessMemory,
        addr_ptr: u64,
        addr_len: usize,
        new_addr: std::net::SocketAddrV6,
    ) -> Result<(), SockaddrError> {
        const MIN_LEN: usize = std::mem::size_of::<SockaddrIn6>();
        if addr_len < MIN_LEN {
            return Err(SockaddrError::TooShort {
                len: addr_len,
                family: AF_INET6,
            });
        }

        let sockaddr = SockaddrIn6 {
            sin6_family: AF_INET6,
            sin6_port: new_addr.port().to_be(),
            sin6_flowinfo: new_addr.flowinfo(),
            sin6_addr: new_addr.ip().octets(),
            sin6_scope_id: new_addr.scope_id(),
        };

        mem.write_value(addr_ptr, &sockaddr)?;
        Ok(())
    }
}
