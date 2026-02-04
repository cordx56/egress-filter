//! DoH (DNS over HTTPS) detection and parsing.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Request;
use tracing::debug;

use crate::network::DnsNameParser;

/// Content type for DNS messages.
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// Common DoH endpoint paths.
const DOH_PATHS: &[&str] = &["/dns-query", "/resolve"];

/// Detects and parses DoH requests.
pub struct DohDetector;

impl DohDetector {
    /// Checks if the request path is a known DoH endpoint.
    pub fn is_doh_path(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        DOH_PATHS.iter().any(|p| path_lower.starts_with(p))
    }

    /// Checks if the content type indicates a DNS message.
    pub fn is_dns_content_type(content_type: &str) -> bool {
        content_type
            .to_lowercase()
            .contains(DNS_MESSAGE_CONTENT_TYPE)
    }

    /// Extracts a DoH request from an HTTP request.
    /// Supports both GET (with ?dns= query parameter) and POST methods.
    pub fn extract<B>(request: &Request<B>, body: Option<&[u8]>) -> Option<DohRequest> {
        let uri = request.uri();
        let path = uri.path();

        // Check if this looks like a DoH request
        if !Self::is_doh_path(path) {
            return None;
        }

        match *request.method() {
            http::Method::GET => Self::extract_from_get(request),
            http::Method::POST => Self::extract_from_post(request, body),
            _ => None,
        }
    }

    /// Extracts DoH request from GET with ?dns= query parameter.
    fn extract_from_get<B>(request: &Request<B>) -> Option<DohRequest> {
        let uri = request.uri();
        let query = uri.query()?;

        // Parse query parameters to find dns=
        for param in query.split('&') {
            let (key, value) = param.split_once('=')?;

            if key.to_lowercase() == "dns" {
                // Decode base64url-encoded DNS query
                let wire_bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
                let query = parse_dns_query(&wire_bytes)?;

                debug!(
                    "extracted DoH GET request for {} (type {})",
                    query.name, query.qtype
                );

                return Some(DohRequest {
                    method: DohMethod::Get,
                    query,
                    wire_bytes,
                });
            }
        }

        None
    }

    /// Extracts DoH request from POST with DNS message body.
    fn extract_from_post<B>(request: &Request<B>, body: Option<&[u8]>) -> Option<DohRequest> {
        // Check content type
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)?
            .to_str()
            .ok()?;

        if !Self::is_dns_content_type(content_type) {
            return None;
        }

        let body = body?;
        let query = parse_dns_query(body)?;

        debug!(
            "extracted DoH POST request for {} (type {})",
            query.name, query.qtype
        );

        Some(DohRequest {
            method: DohMethod::Post,
            query,
            wire_bytes: body.to_vec(),
        })
    }
}

/// HTTP method used for DoH request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    Get,
    Post,
}

/// A parsed DoH request.
#[derive(Debug, Clone)]
pub struct DohRequest {
    /// The HTTP method used.
    pub method: DohMethod,
    /// The parsed DNS query.
    pub query: DnsQuery,
    /// The raw wire-format DNS message.
    pub wire_bytes: Vec<u8>,
}

/// A parsed DNS query.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// The queried domain name.
    pub name: String,
    /// Query type (A=1, AAAA=28, etc).
    pub qtype: u16,
}

/// Parses a DNS query from wire format using the shared parser.
fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    DnsNameParser::parse_query_lenient(packet)
        .ok()
        .map(|q| DnsQuery {
            name: q.name,
            qtype: q.qtype,
        })
}

/// A parsed DNS response.
#[derive(Debug, Clone)]
pub struct DohResponse {
    /// Resolved IP addresses (A and AAAA records).
    pub addresses: Vec<IpAddr>,
    /// The queried domain name.
    pub name: String,
    /// TTL in seconds (minimum of all records).
    pub ttl: u32,
}

impl DohResponse {
    /// Parses a DNS response from wire format.
    pub fn from_wire(packet: &[u8]) -> Option<Self> {
        // DNS header is 12 bytes minimum
        if packet.len() < 12 {
            return None;
        }

        // Check flags for response bit (QR=1)
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if flags & 0x8000 == 0 {
            return None; // Not a response
        }

        // Check RCODE (lower 4 bits of flags)
        let rcode = flags & 0x0F;
        if rcode != 0 {
            debug!("DNS response has error code {}", rcode);
            return None;
        }

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

        if ancount == 0 {
            return None;
        }

        // Skip header
        let mut offset = 12;

        // Skip questions
        let mut queried_name = String::new();
        for i in 0..qdcount {
            let (name, new_offset) = Self::parse_name(packet, offset)?;
            if i == 0 {
                queried_name = name;
            }
            offset = new_offset + 4; // Skip QTYPE and QCLASS
        }

        // Parse answers
        let mut addresses = Vec::new();
        let mut min_ttl = u32::MAX;

        for _ in 0..ancount {
            if offset >= packet.len() {
                break;
            }

            // Skip name
            let (_, new_offset) = Self::parse_name(packet, offset)?;
            offset = new_offset;

            // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
            if offset + 10 > packet.len() {
                break;
            }

            let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let ttl = u32::from_be_bytes([
                packet[offset + 4],
                packet[offset + 5],
                packet[offset + 6],
                packet[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;

            offset += 10;

            if offset + rdlength > packet.len() {
                break;
            }

            match rtype {
                1 if rdlength == 4 => {
                    // A record
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        packet[offset],
                        packet[offset + 1],
                        packet[offset + 2],
                        packet[offset + 3],
                    ));
                    addresses.push(ip);
                    min_ttl = min_ttl.min(ttl);
                }
                28 if rdlength == 16 => {
                    // AAAA record
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[offset..offset + 16]);
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                    addresses.push(ip);
                    min_ttl = min_ttl.min(ttl);
                }
                _ => {
                    // Skip other record types
                }
            }

            offset += rdlength;
        }

        if addresses.is_empty() {
            return None;
        }

        Some(DohResponse {
            addresses,
            name: queried_name,
            ttl: min_ttl,
        })
    }

    /// Parses a DNS name and returns the name and new offset.
    /// Uses the shared DnsNameParser implementation.
    fn parse_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
        DnsNameParser::parse_name(packet, offset).ok()
    }
}

/// Creates a DNS REFUSED response for a query.
pub fn create_refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut response = query.to_vec();

    // Set QR bit (response) and RCODE=5 (REFUSED)
    // Flags are at bytes 2-3
    // QR=1, OPCODE=keep, AA=0, TC=0, RD=keep, RA=1, Z=0, RCODE=5
    let original_flags = u16::from_be_bytes([query[2], query[3]]);
    let new_flags = (original_flags & 0x7800) // Keep OPCODE and RD
        | 0x8000  // QR=1 (response)
        | 0x0080  // RA=1
        | 0x0005; // RCODE=5 (REFUSED)

    response[2] = (new_flags >> 8) as u8;
    response[3] = (new_flags & 0xFF) as u8;

    // Set ANCOUNT, NSCOUNT, ARCOUNT to 0
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;

    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a DNS query packet for testing.
    fn create_test_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        // Encode domain name as DNS wire format labels
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // End of name

        // QTYPE and QCLASS
        packet.push((qtype >> 8) as u8);
        packet.push((qtype & 0xFF) as u8);
        packet.push(0x00);
        packet.push(0x01); // IN class

        packet
    }

    /// Tests parsing a DNS query packet using the shared parser.
    #[test]
    fn test_parse_dns_query() {
        let packet = create_test_dns_query("example.com", 1);
        let query = parse_dns_query(&packet).unwrap();
        assert_eq!(query.name, "example.com");
        assert_eq!(query.qtype, 1);
    }

    /// Tests detection of standard DoH endpoint paths.
    /// Both /dns-query and /resolve are recognized, case-insensitively.
    #[test]
    fn test_doh_path_detection() {
        assert!(DohDetector::is_doh_path("/dns-query"));
        assert!(DohDetector::is_doh_path("/dns-query?dns=AAAA"));
        assert!(DohDetector::is_doh_path("/DNS-QUERY"));
        assert!(DohDetector::is_doh_path("/resolve"));
        assert!(!DohDetector::is_doh_path("/api/dns"));
        assert!(!DohDetector::is_doh_path("/"));
    }

    /// Tests extraction of DoH request from GET method with ?dns= parameter.
    /// The DNS query is base64url-encoded in the query string.
    #[test]
    fn test_extract_from_get() {
        let packet = create_test_dns_query("example.com", 1);
        let encoded = URL_SAFE_NO_PAD.encode(&packet);

        let uri: http::Uri = format!("/dns-query?dns={}", encoded).parse().unwrap();
        let request = Request::builder().method("GET").uri(uri).body(()).unwrap();

        let doh_request = DohDetector::extract(&request, None).unwrap();
        assert_eq!(doh_request.method, DohMethod::Get);
        assert_eq!(doh_request.query.name, "example.com");
    }

    /// Tests parsing a DNS response with an A record.
    /// Verifies that the IP address and TTL are correctly extracted.
    #[test]
    fn test_parse_dns_response_with_a_record() {
        // DNS response: example.com -> 93.184.216.34, TTL 3600
        let response = [
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x01, // ANCOUNT: 1
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // A
            0x00, 0x01, // IN
            // Answer: name pointer + A record
            0xc0, 0x0c, // Name pointer to question (offset 12)
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x04, // RDLENGTH: 4
            93, 184, 216, 34, // IP address
        ];

        let parsed = DohResponse::from_wire(&response).unwrap();
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.addresses.len(), 1);
        assert_eq!(
            parsed.addresses[0],
            IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(parsed.ttl, 3600);
    }

    /// Tests creation of DNS REFUSED response.
    /// When a DoH query is blocked, we return RCODE=5 (REFUSED).
    #[test]
    fn test_create_refused() {
        let query = create_test_dns_query("blocked.com", 1);
        let response = create_refused_response(&query).unwrap();

        // Verify QR bit is set (indicating response)
        assert!(response[2] & 0x80 != 0);
        // Verify RCODE is 5 (REFUSED)
        assert_eq!(response[3] & 0x0F, 5);
    }
}
