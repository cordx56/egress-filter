use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tracing::debug;

use super::config::{AllowListConfig, DefaultPolicy, DomainRule, IpRule};

/// TTL for cached DNS resolutions.
const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// TTL for blocked notification deduplication.
const BLOCKED_NOTIFY_TTL: Duration = Duration::from_secs(60); // 1 minute

/// Entry in the DNS resolution cache.
struct DnsCacheEntry {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    /// Timestamp of the most recent update. Used for TTL.
    updated_at: Instant,
}

/// Compiled allowlist for efficient matching.
pub struct AllowList {
    default_policy: DefaultPolicy,
    domains: Vec<CompiledDomainRule>,
    ip_ranges: Vec<CompiledIpRule>,
    /// Cache of resolved DNS names -> IPs.
    /// Key is the domain name, value is the resolved IPs and allowed ports.
    dns_cache: RwLock<HashMap<String, DnsCacheEntry>>,
    /// Cache of recently notified blocked targets to avoid duplicate messages.
    /// Key is "ip:port", value is when the notification expires.
    notified_blocks: RwLock<HashMap<String, Instant>>,
}

#[derive(Debug)]
struct CompiledDomainRule {
    /// The pattern components, reversed for suffix matching.
    /// e.g., "*.example.com" -> ["com", "example", "*"]
    parts: Vec<String>,
    is_wildcard: bool,
    ports: Option<Vec<u16>>,
}

#[derive(Debug)]
struct CompiledIpRule {
    network: IpNetwork,
    ports: Option<Vec<u16>>,
}

impl std::fmt::Debug for AllowList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowList")
            .field("default_policy", &self.default_policy)
            .field("domains", &self.domains)
            .field("ip_ranges", &self.ip_ranges)
            .field("dns_cache", &"<RwLock>")
            .field("notified_blocks", &"<RwLock>")
            .finish()
    }
}

impl AllowList {
    /// Creates a allowlist from a config.
    /// Non-wildcard domains are resolved immediately and cached.
    pub fn new(config: &AllowListConfig) -> Self {
        let domains: Vec<CompiledDomainRule> = config
            .domains
            .iter()
            .map(CompiledDomainRule::from)
            .collect();

        let ip_ranges = config
            .ip_ranges
            .iter()
            .filter_map(|rule| CompiledIpRule::try_from(rule).ok())
            .collect();

        let allowlist = Self {
            default_policy: config.default_policy,
            domains,
            ip_ranges,
            dns_cache: RwLock::new(HashMap::new()),
            notified_blocks: RwLock::new(HashMap::new()),
        };

        // Pre-resolve non-wildcard domains at initialization
        allowlist.pre_resolve_domains(config);

        allowlist
    }

    /// Pre-resolves non-wildcard domains and caches their IPs.
    /// This allows connect() calls to resolved IPs to be permitted
    /// even when we can't see the DNS query (e.g., via systemd-resolved).
    fn pre_resolve_domains(&self, config: &AllowListConfig) {
        for rule in &config.domains {
            // Skip wildcard patterns - can't pre-resolve "*.example.com"
            if rule.pattern.starts_with("*.") {
                continue;
            }

            let ports = rule.ports.clone().unwrap_or_default();
            debug!("pre-resolving domain: {}", rule.pattern);
            self.resolve_and_cache(&rule.pattern, ports);
        }
    }

    /// Returns the allowed ports for a domain if it matches any rule.
    /// Returns an empty Vec if no rule matches (not allowed).
    pub fn get_domain_ports(&self, domain: &str) -> Vec<u16> {
        let domain_lower = domain.to_lowercase();

        for rule in &self.domains {
            if rule.matches(&domain_lower) {
                return rule.allowed_ports();
            }
        }

        Vec::new()
    }

    /// Checks if a domain:port is allowed.
    /// If allowed, tracks the domain for future IP lookups.
    pub fn is_domain_allowed(&self, domain: &str, port: u16) -> bool {
        let domain_lower = domain.to_lowercase();

        for rule in &self.domains {
            if rule.matches(&domain_lower) && rule.port_allowed(port) {
                // Track the domain so refresh_and_check_ip can resolve it later
                self.track_domain(&domain_lower, rule.allowed_ports());
                return true;
            }
        }

        self.default_policy == DefaultPolicy::Allow
    }

    /// Checks if a DNS query for a domain should be allowed.
    /// This checks if the domain is in the allowlist, ignoring port restrictions.
    /// Used for filtering DNS queries where we don't know the target port yet.
    ///
    /// Does NOT perform synchronous DNS resolution here, because the child's
    /// DNS query hasn't actually been sent yet at this point. Resolution is
    /// deferred to connect() time via `refresh_and_check_ip`.
    pub fn is_dns_query_allowed(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        for rule in &self.domains {
            if rule.matches(&domain_lower) {
                // Track the domain so refresh_and_check_ip can resolve it later
                self.track_domain(&domain_lower, rule.allowed_ports());
                return true;
            }
        }

        self.default_policy == DefaultPolicy::Allow
    }

    /// Checks if an IP:port is allowed.
    /// Also checks the DNS cache for IPs resolved from permitted domain queries.
    /// If not found in cache, re-resolves all cached domains to handle DNS rotation.
    pub fn is_ip_allowed(&self, ip: IpAddr, port: u16) -> bool {
        // First check static IP rules
        for rule in &self.ip_ranges {
            if rule.network.contains(ip) && rule.port_allowed(port) {
                return true;
            }
        }

        // Check DNS cache for dynamically resolved IPs
        if self.is_cached_ip_allowed(ip, port) {
            return true;
        }

        // IP not found in cache - DNS might have rotated
        // Re-resolve all cached domains and check again
        if self.refresh_and_check_ip(ip, port) {
            return true;
        }

        self.default_policy == DefaultPolicy::Allow
    }

    /// Ensures a domain is tracked in the cache with its allowed ports.
    /// Creates an entry with empty IPs if one doesn't exist yet.
    /// This allows `refresh_and_check_ip` to resolve the domain later at connect() time.
    fn track_domain(&self, domain: &str, ports: Vec<u16>) {
        let Ok(mut cache) = self.dns_cache.write() else {
            return;
        };
        let domain_key = domain.to_string();
        cache.entry(domain_key).or_insert_with(|| {
            debug!("tracking allowed domain: {}", domain);
            DnsCacheEntry {
                ips: Vec::new(),
                ports,
                updated_at: Instant::now(),
            }
        });
    }

    /// Resolves a domain and merges the resulting IPs into the cache.
    /// Existing IPs are preserved to handle DNS round-robin and rotation.
    /// If resolution fails, a domain entry is still created so it can be
    /// re-resolved later.
    fn resolve_and_cache(&self, domain: &str, ports: Vec<u16>) {
        // Try to resolve the domain using the system resolver
        let addr_str = format!("{}:0", domain);
        match addr_str.to_socket_addrs() {
            Ok(addrs) => {
                let new_ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                if new_ips.is_empty() {
                    debug!("DNS resolution returned no IPs for {}", domain);
                    self.track_domain(domain, ports);
                    return;
                }

                self.merge_into_cache(domain, &new_ips, ports);
            }
            Err(e) => {
                debug!("failed to resolve {}: {}", domain, e);
                self.track_domain(domain, ports);
            }
        }
    }

    /// Merges new IPs into the cache entry for a domain.
    /// Preserves existing IPs and resets the TTL.
    fn merge_into_cache(&self, domain: &str, new_ips: &[IpAddr], ports: Vec<u16>) {
        let Ok(mut cache) = self.dns_cache.write() else {
            return;
        };

        let domain_key = domain.to_string();
        let now = Instant::now();

        if let Some(entry) = cache.get_mut(&domain_key) {
            let before = entry.ips.len();
            for ip in new_ips {
                if !entry.ips.contains(ip) {
                    entry.ips.push(*ip);
                }
            }
            entry.updated_at = now;
            // Merge port restrictions (use broader set)
            if ports.is_empty() || entry.ports.is_empty() {
                entry.ports = Vec::new(); // All ports
            } else {
                for p in &ports {
                    if !entry.ports.contains(p) {
                        entry.ports.push(*p);
                    }
                }
            }
            debug!(
                "merged IPs for {}: {} -> {} entries",
                domain,
                before,
                entry.ips.len()
            );
        } else {
            debug!(
                "caching resolved IPs for {}: {:?} (ports: {:?})",
                domain, new_ips, ports
            );
            cache.insert(
                domain_key,
                DnsCacheEntry {
                    ips: new_ips.to_vec(),
                    ports,
                    updated_at: now,
                },
            );
        }
    }

    /// Checks if an IP is in the DNS cache and allowed for the given port.
    fn is_cached_ip_allowed(&self, ip: IpAddr, port: u16) -> bool {
        let cache = match self.dns_cache.read() {
            Ok(c) => c,
            Err(_) => return false,
        };

        let now = Instant::now();
        for entry in cache.values() {
            // Skip expired entries
            if now.duration_since(entry.updated_at) > DNS_CACHE_TTL {
                continue;
            }

            if entry.ips.contains(&ip) {
                // Check port restriction
                if entry.ports.is_empty() || entry.ports.contains(&port) {
                    debug!("IP {} allowed via DNS cache (port {})", ip, port);
                    return true;
                }
            }
        }

        false
    }

    /// Re-resolves all cached domains and checks if the IP matches any of them.
    /// This handles DNS rotation where different IPs are returned on different queries.
    fn refresh_and_check_ip(&self, ip: IpAddr, port: u16) -> bool {
        // Get list of domains and their ports from cache
        let domains_to_check: Vec<(String, Vec<u16>)> = {
            let cache = match self.dns_cache.read() {
                Ok(c) => c,
                Err(_) => return false,
            };
            cache
                .iter()
                .map(|(domain, entry)| (domain.clone(), entry.ports.clone()))
                .collect()
        };

        if domains_to_check.is_empty() {
            return false;
        }

        debug!(
            "IP {} not in cache, re-resolving {} domains",
            ip,
            domains_to_check.len()
        );

        // Re-resolve each domain and check if IP matches
        for (domain, ports) in domains_to_check {
            let addr_str = format!("{}:0", domain);
            if let Ok(addrs) = addr_str.to_socket_addrs() {
                let resolved_ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();

                if resolved_ips.contains(&ip) {
                    // Check port restriction
                    if ports.is_empty() || ports.contains(&port) {
                        debug!(
                            "IP {} allowed via DNS refresh for {} (port {})",
                            ip, domain, port
                        );

                        // Update cache with new IPs
                        self.resolve_and_cache(&domain, ports);
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Cleans up expired entries from the DNS cache.
    /// Called periodically to prevent memory growth.
    pub fn cleanup_dns_cache(&self) {
        let now = Instant::now();
        if let Ok(mut cache) = self.dns_cache.write() {
            cache.retain(|domain, entry| {
                let keep = now.duration_since(entry.updated_at) <= DNS_CACHE_TTL;
                if !keep {
                    debug!("expiring DNS cache entry for {}", domain);
                }
                keep
            });
        }
        // Also clean up expired block notifications
        if let Ok(mut notified) = self.notified_blocks.write() {
            notified.retain(|_, expires_at| *expires_at > now);
        }
    }

    /// Caches DoH resolution results.
    /// This is called by the proxy when it intercepts DoH responses.
    pub fn cache_doh_resolution(&self, domain: &str, addresses: &[IpAddr], ports: Vec<u16>) {
        if addresses.is_empty() {
            return;
        }

        self.merge_into_cache(&domain.to_lowercase(), addresses, ports);
    }

    /// Checks if we should notify about a blocked target.
    /// Returns true if this is the first block for this target recently.
    /// Marks the target as notified to prevent duplicate messages.
    pub fn should_notify_block(&self, ip: IpAddr, port: u16) -> bool {
        let key = format!("{}:{}", ip, port);
        let now = Instant::now();

        // Check if already notified recently
        if let Ok(notified) = self.notified_blocks.read()
            && let Some(expires_at) = notified.get(&key)
            && *expires_at > now
        {
            return false; // Already notified recently
        }

        // Mark as notified
        if let Ok(mut notified) = self.notified_blocks.write() {
            notified.insert(key, now + BLOCKED_NOTIFY_TTL);
        }

        true
    }
}

impl From<&DomainRule> for CompiledDomainRule {
    fn from(rule: &DomainRule) -> Self {
        let is_wildcard = rule.pattern.starts_with("*.");
        let pattern = if is_wildcard {
            &rule.pattern[2..]
        } else {
            &rule.pattern
        };

        // Split and reverse for efficient suffix matching
        let parts: Vec<String> = pattern.split('.').map(|s| s.to_lowercase()).rev().collect();

        Self {
            parts,
            is_wildcard,
            ports: rule.ports.clone(),
        }
    }
}

impl CompiledDomainRule {
    fn matches(&self, domain: &str) -> bool {
        let domain_parts: Vec<&str> = domain.split('.').rev().collect();

        if self.is_wildcard {
            // Wildcard: domain must have MORE parts than pattern (subdomain required)
            if domain_parts.len() <= self.parts.len() {
                return false;
            }
        } else {
            // Exact match: must have same number of parts
            if domain_parts.len() != self.parts.len() {
                return false;
            }
        }

        // Match from the end (TLD first)
        for (i, part) in self.parts.iter().enumerate() {
            if domain_parts[i] != part {
                return false;
            }
        }

        true
    }

    fn port_allowed(&self, port: u16) -> bool {
        match &self.ports {
            Some(ports) => ports.contains(&port),
            None => true, // All ports allowed
        }
    }

    /// Returns the list of allowed ports for this rule.
    /// Empty vec means all ports are allowed.
    fn allowed_ports(&self) -> Vec<u16> {
        self.ports.clone().unwrap_or_default()
    }
}

impl TryFrom<&IpRule> for CompiledIpRule {
    type Error = ();

    fn try_from(rule: &IpRule) -> Result<Self, Self::Error> {
        let network = rule
            .cidr
            .parse::<IpNetwork>()
            .or_else(|_| {
                // Try parsing as single IP
                rule.cidr.parse::<IpAddr>().map(IpNetwork::from)
            })
            .map_err(|_| ())?;

        Ok(Self {
            network,
            ports: rule.ports.clone(),
        })
    }
}

impl CompiledIpRule {
    fn port_allowed(&self, port: u16) -> bool {
        match &self.ports {
            Some(ports) => ports.contains(&port),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Creates a test configuration with various domain and IP rules.
    fn test_config() -> AllowListConfig {
        AllowListConfig::parse(
            r#"
version: 1
default_policy: deny
domains:
  - pattern: "*.anthropic.com"
    ports: [443]
  - pattern: "api.github.com"
    ports: [443, 80]
  - pattern: "example.org"
ip_ranges:
  - cidr: "10.0.0.0/8"
  - cidr: "192.168.1.100"
    ports: [22]
"#,
        )
        .unwrap()
    }

    /// Tests wildcard domain pattern matching.
    /// Wildcard patterns (*.example.com) should match any subdomain,
    /// but NOT the exact domain itself (example.com).
    #[test]
    fn wildcard_domain_matching() {
        let allowlist = AllowList::new(&test_config());

        // Wildcard matches any subdomain
        assert!(allowlist.is_domain_allowed("api.anthropic.com", 443));
        assert!(allowlist.is_domain_allowed("www.anthropic.com", 443));
        assert!(allowlist.is_domain_allowed("deep.sub.anthropic.com", 443));

        // Wildcard does NOT match the exact base domain
        assert!(!allowlist.is_domain_allowed("anthropic.com", 443));

        // Port restriction is enforced
        assert!(!allowlist.is_domain_allowed("api.anthropic.com", 80));
    }

    /// Tests exact domain matching (non-wildcard patterns).
    /// Exact patterns should only match the specified domain,
    /// not subdomains.
    #[test]
    fn exact_domain_matching() {
        let allowlist = AllowList::new(&test_config());

        // Exact match with allowed ports
        assert!(allowlist.is_domain_allowed("api.github.com", 443));
        assert!(allowlist.is_domain_allowed("api.github.com", 80));

        // Subdomains don't match exact patterns
        assert!(!allowlist.is_domain_allowed("www.api.github.com", 443));

        // Omitted ports field means all ports are allowed
        assert!(allowlist.is_domain_allowed("example.org", 443));
        assert!(allowlist.is_domain_allowed("example.org", 8080));
    }

    /// Tests IP range matching with CIDR notation.
    /// Verifies both range matching and port restrictions.
    #[test]
    fn ip_range_matching() {
        let allowlist = AllowList::new(&test_config());

        // CIDR range matches all IPs in the range
        assert!(allowlist.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80));
        assert!(allowlist.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)), 443));

        // IPs outside the range are rejected
        assert!(!allowlist.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1)), 80));

        // Single IP with port restriction
        assert!(allowlist.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 22));
        assert!(!allowlist.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 80));
    }

    /// Tests that domain matching is case-insensitive.
    /// DNS names are case-insensitive per RFC 4343.
    #[test]
    fn case_insensitive_domain() {
        let allowlist = AllowList::new(&test_config());
        assert!(allowlist.is_domain_allowed("API.GITHUB.COM", 443));
        assert!(allowlist.is_domain_allowed("Api.GitHub.Com", 443));
    }

    /// Tests that DNS cache merges IPs instead of replacing them.
    /// When DNS returns different IPs on subsequent queries (round-robin),
    /// previously cached IPs must remain valid.
    #[test]
    fn dns_cache_merges_ips() {
        let config = AllowListConfig::parse(
            r#"
version: 1
default_policy: deny
domains:
  - pattern: "rotating.example.com"
    ports: [443]
"#,
        )
        .unwrap();
        let allowlist = AllowList::new(&config);

        let ip_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));

        // First resolution returns [A, B]
        allowlist.cache_doh_resolution("rotating.example.com", &[ip_a, ip_b], vec![443]);
        assert!(allowlist.is_cached_ip_allowed(ip_a, 443));
        assert!(allowlist.is_cached_ip_allowed(ip_b, 443));

        // Second resolution returns [B, C] - A must still be valid
        allowlist.cache_doh_resolution("rotating.example.com", &[ip_b, ip_c], vec![443]);
        assert!(
            allowlist.is_cached_ip_allowed(ip_a, 443),
            "IP A lost after merge"
        );
        assert!(allowlist.is_cached_ip_allowed(ip_b, 443));
        assert!(allowlist.is_cached_ip_allowed(ip_c, 443));
    }

    /// Tests the deferred resolution flow that occurs at startup.
    ///
    /// When a DNS query is intercepted, `is_dns_query_allowed` tracks the domain
    /// in the cache with empty IPs (no synchronous resolution). Later, when the
    /// child process calls connect() with the resolved IP, `is_ip_allowed` triggers
    /// `refresh_and_check_ip`, which re-resolves all tracked domains and finds a match.
    ///
    /// This test simulates the flow using `cache_doh_resolution` to inject IPs
    /// (as if the child's DNS query had completed), verifying that `track_domain`
    /// + later cache population allows connect() to succeed.
    #[test]
    fn track_domain_deferred_resolution() {
        let config = AllowListConfig::parse(
            r#"
version: 1
default_policy: deny
domains:
  - pattern: "deferred.example.com"
    ports: [443]
"#,
        )
        .unwrap();
        let allowlist = AllowList::new(&config);

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));

        // Step 1: DNS query intercepted — domain tracked with empty IPs
        assert!(allowlist.is_dns_query_allowed("deferred.example.com"));

        // Verify the cache entry exists but has no IPs yet
        {
            let cache = allowlist.dns_cache.read().unwrap();
            let entry = cache
                .get("deferred.example.com")
                .expect("domain should be tracked");
            assert!(entry.ips.is_empty(), "no IPs should be cached yet");
            assert_eq!(entry.ports, vec![443]);
        }

        // Step 2: Child's DNS query completes, DoH proxy caches the result
        allowlist.cache_doh_resolution("deferred.example.com", &[ip], vec![443]);

        // Step 3: Child calls connect() — IP should now be allowed via cache
        assert!(allowlist.is_ip_allowed(ip, 443));

        // Port restriction is still enforced
        assert!(!allowlist.is_ip_allowed(ip, 80));
    }

    /// Tests that port restrictions are enforced on cached DNS entries.
    #[test]
    fn dns_cache_port_restriction() {
        let config = AllowListConfig::parse(
            r#"
version: 1
default_policy: deny
domains:
  - pattern: "secure.example.com"
    ports: [443]
"#,
        )
        .unwrap();
        let allowlist = AllowList::new(&config);

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        allowlist.cache_doh_resolution("secure.example.com", &[ip], vec![443]);

        assert!(allowlist.is_cached_ip_allowed(ip, 443));
        // Port 80 should not be allowed
        assert!(!allowlist.is_cached_ip_allowed(ip, 80));
    }
}
