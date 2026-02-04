use crate::seccomp::ProcessMemory;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("failed to read DNS packet from memory: {0}")]
    MemoryRead(#[from] crate::seccomp::memory::MemoryError),
    #[error("DNS packet too short: {0} bytes")]
    TooShort(usize),
    #[error("invalid DNS label length: {0}")]
    InvalidLabel(u8),
    #[error("DNS name too long")]
    NameTooLong,
    #[error("invalid compression pointer")]
    InvalidCompression,
    #[error("no questions in DNS packet")]
    NoQuestions,
}

/// Maximum size of a DNS packet we'll read.
const MAX_DNS_PACKET_SIZE: usize = 512;

/// Maximum length of a domain name.
const MAX_DOMAIN_LEN: usize = 253;

/// Maximum compression pointer jumps to prevent infinite loops.
const MAX_COMPRESSION_JUMPS: usize = 10;

/// A parsed DNS query.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// The queried domain name.
    pub name: String,
    /// Query type (A=1, AAAA=28, etc).
    pub qtype: u16,
    /// DNS transaction ID.
    pub txid: u16,
}

/// Low-level DNS name parser that operates on byte slices.
/// This is the shared implementation used by both network/dns.rs and proxy/doh.rs.
pub struct DnsNameParser;

impl DnsNameParser {
    /// Parses a DNS name starting at the given offset.
    /// Returns the parsed name and the offset after the name (for non-compressed case).
    ///
    /// Handles DNS name compression (RFC 1035 Section 4.1.4).
    pub fn parse_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
        let mut name = String::with_capacity(64);
        let mut jumps = 0;
        let mut final_offset = None;

        loop {
            if offset >= packet.len() {
                return Err(DnsError::TooShort(packet.len()));
            }

            let len = packet[offset];

            // Check for compression pointer (top 2 bits set)
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= packet.len() {
                    return Err(DnsError::TooShort(packet.len()));
                }

                // Save the position after the pointer (only on first jump)
                if final_offset.is_none() {
                    final_offset = Some(offset + 2);
                }

                // Follow the pointer
                let ptr = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
                if ptr >= offset {
                    return Err(DnsError::InvalidCompression);
                }

                offset = ptr;
                jumps += 1;
                if jumps > MAX_COMPRESSION_JUMPS {
                    return Err(DnsError::InvalidCompression);
                }
                continue;
            }

            // End of name
            if len == 0 {
                let end = final_offset.unwrap_or(offset + 1);
                // Remove trailing dot if present
                if name.ends_with('.') {
                    name.pop();
                }
                return Ok((name, end));
            }

            // Label length
            let label_len = len as usize;
            if label_len > 63 {
                return Err(DnsError::InvalidLabel(len));
            }

            let label_end = offset + 1 + label_len;
            if label_end > packet.len() {
                return Err(DnsError::TooShort(packet.len()));
            }

            // Add label to name
            if !name.is_empty() {
                name.push('.');
            }
            if name.len() + label_len > MAX_DOMAIN_LEN {
                return Err(DnsError::NameTooLong);
            }

            // Labels should be ASCII, but we'll be lenient
            for &b in &packet[offset + 1..label_end] {
                name.push(b as char);
            }

            offset = label_end;
        }
    }

    /// Parses the first DNS query from a packet.
    /// Returns the parsed query or None if parsing fails.
    pub fn parse_query(packet: &[u8]) -> Result<DnsQuery, DnsError> {
        if packet.len() < 12 {
            return Err(DnsError::TooShort(packet.len()));
        }

        let txid = u16::from_be_bytes([packet[0], packet[1]]);
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        if qdcount == 0 {
            return Err(DnsError::NoQuestions);
        }

        // Parse the first question (starting at offset 12)
        let (name, end_offset) = Self::parse_name(packet, 12)?;

        // After the name comes QTYPE (2 bytes) and QCLASS (2 bytes)
        if end_offset + 4 > packet.len() {
            return Err(DnsError::TooShort(packet.len()));
        }

        let qtype = u16::from_be_bytes([packet[end_offset], packet[end_offset + 1]]);

        Ok(DnsQuery { name, qtype, txid })
    }
}

impl DnsQuery {
    /// Reads the DNS transaction ID from a UDP packet buffer in the target process.
    pub fn read_txid(mem: &ProcessMemory, buf_ptr: u64, buf_len: usize) -> Result<u16, DnsError> {
        if buf_len < 2 {
            return Err(DnsError::TooShort(buf_len));
        }

        let mut buf = [0u8; 2];
        mem.read(buf_ptr, &mut buf)?;

        Ok(u16::from_be_bytes(buf))
    }

    /// Parses a DNS query from a UDP packet buffer in the target process.
    ///
    /// # Arguments
    /// * `mem` - Process memory accessor
    /// * `buf_ptr` - Pointer to the UDP payload (DNS packet)
    /// * `buf_len` - Length of the packet
    pub fn parse(mem: &ProcessMemory, buf_ptr: u64, buf_len: usize) -> Result<Self, DnsError> {
        let read_len = buf_len.min(MAX_DNS_PACKET_SIZE);
        if read_len < 12 {
            return Err(DnsError::TooShort(read_len));
        }

        let mut buf = vec![0u8; read_len];
        mem.read(buf_ptr, &mut buf)?;

        DnsNameParser::parse_query(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests parsing a simple DNS query packet with a single question.
    /// Verifies that the domain name and query type (A record) are correctly extracted.
    #[test]
    fn parse_simple_query() {
        let packet = [
            // DNS Header (12 bytes)
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // End of name
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];

        let query = DnsNameParser::parse_query(&packet).unwrap();
        assert_eq!(query.name, "example.com");
        assert_eq!(query.qtype, 1);
        assert_eq!(query.txid, 0x1234);
    }

    /// Tests parsing a DNS name with compression pointer.
    /// Compression is used in DNS responses to reduce packet size.
    #[test]
    fn parse_name_with_compression() {
        // Packet with name pointer at offset 25 pointing back to offset 12
        let packet = [
            // Header
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Question: example.com (offset 12)
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            // QTYPE, QCLASS
            0x00, 0x01, 0x00, 0x01,
        ];

        let (name, _) = DnsNameParser::parse_name(&packet, 12).unwrap();
        assert_eq!(name, "example.com");
    }

    /// Tests that a packet with zero questions returns an appropriate error.
    #[test]
    fn reject_empty_query() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x00, // QDCOUNT = 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(matches!(
            DnsNameParser::parse_query(&packet),
            Err(DnsError::NoQuestions)
        ));
    }
}
