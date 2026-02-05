use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AllowListError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
    #[error("invalid domain pattern: {0}")]
    InvalidPattern(String),
}

/// Default policy when no rules match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    #[default]
    Deny,
    Allow,
}

/// A domain allowlist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    /// Domain pattern. Supports wildcards: "*.example.com"
    pub pattern: String,
    /// Allowed ports. If empty or None, all ports are allowed.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// Human-readable reason for this rule.
    #[serde(default)]
    pub reason: Option<String>,
}

/// An IP range allowlist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    /// CIDR notation: "10.0.0.0/8" or single IP: "192.168.1.1"
    pub cidr: String,
    /// Allowed ports. If empty or None, all ports are allowed.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// Human-readable reason for this rule.
    #[serde(default)]
    pub reason: Option<String>,
}

/// DoH (DNS over HTTPS) interception configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DohConfig {
    /// Enable DoH interception (requires TLS MitM).
    #[serde(default)]
    pub enabled: bool,
}

/// DNS proxy mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Preserve the original DNS server and forward queries to it.
    #[default]
    Preserve,
    /// Ignore the original DNS server and use the system resolver's servers.
    System,
}

/// DNS handling configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS proxy behavior.
    #[serde(default)]
    pub mode: DnsMode,
}

/// AllowList configuration file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowListConfig {
    /// Config version for future compatibility.
    #[serde(default = "default_version")]
    pub version: u32,

    /// Default policy when no rules match.
    #[serde(default)]
    pub default_policy: DefaultPolicy,

    /// Domain patterns to allow.
    #[serde(default)]
    pub domains: Vec<DomainRule>,

    /// IP ranges to allow.
    #[serde(default)]
    pub ip_ranges: Vec<IpRule>,

    /// DNS handling settings.
    #[serde(default)]
    pub dns: DnsConfig,

    /// DoH interception settings.
    #[serde(default)]
    pub doh: DohConfig,
}

fn default_version() -> u32 {
    1
}

impl AllowListConfig {
    /// Loads config from a YAML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AllowListError> {
        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parses config from a YAML string.
    pub fn parse(yaml: &str) -> Result<Self, AllowListError> {
        let config: Self = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Creates a default deny-all config.
    pub fn deny_all() -> Self {
        Self {
            version: 1,
            default_policy: DefaultPolicy::Deny,
            domains: Vec::new(),
            ip_ranges: Vec::new(),
            dns: DnsConfig::default(),
            doh: DohConfig::default(),
        }
    }

    /// Creates a default allow-all config.
    pub fn allow_all() -> Self {
        Self {
            version: 1,
            default_policy: DefaultPolicy::Allow,
            domains: Vec::new(),
            ip_ranges: Vec::new(),
            dns: DnsConfig::default(),
            doh: DohConfig::default(),
        }
    }

    fn validate(&self) -> Result<(), AllowListError> {
        // Validate domain patterns
        for rule in &self.domains {
            if rule.pattern.is_empty() {
                return Err(AllowListError::InvalidPattern("empty pattern".to_string()));
            }
            // Basic validation: pattern should not contain whitespace
            if rule.pattern.chars().any(|c| c.is_whitespace()) {
                return Err(AllowListError::InvalidPattern(rule.pattern.clone()));
            }
        }

        // Validate CIDR notations
        for rule in &self.ip_ranges {
            // Try parsing as IpNetwork
            if rule.cidr.parse::<ipnetwork::IpNetwork>().is_err() {
                // Also try as single IP
                if rule.cidr.parse::<std::net::IpAddr>().is_err() {
                    return Err(AllowListError::InvalidCidr(rule.cidr.clone()));
                }
            }
        }

        Ok(())
    }
}

impl Default for AllowListConfig {
    fn default() -> Self {
        Self::deny_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CONFIG: &str = r#"
version: 1
default_policy: deny

dns:
  mode: system

domains:
  - pattern: "*.anthropic.com"
    ports: [443]
    reason: Claude API

  - pattern: "api.github.com"
    ports: [443]
    reason: GitHub API

ip_ranges:
  - cidr: "10.0.0.0/8"
    ports: null
    reason: Internal network
"#;

    /// Tests parsing a complete YAML configuration file.
    /// Verifies that all fields (version, default_policy, domains, ip_ranges)
    /// are correctly deserialized.
    #[test]
    fn parse_example_config() {
        let config = AllowListConfig::parse(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.default_policy, DefaultPolicy::Deny);
        assert_eq!(config.dns.mode, DnsMode::System);
        assert_eq!(config.domains.len(), 2);
        assert_eq!(config.ip_ranges.len(), 1);

        assert_eq!(config.domains[0].pattern, "*.anthropic.com");
        assert_eq!(config.domains[0].ports, Some(vec![443]));
    }

    /// Tests that invalid CIDR notation is rejected during validation.
    /// This ensures malformed IP ranges don't silently pass through.
    #[test]
    fn invalid_cidr_rejected() {
        let yaml = r#"
version: 1
ip_ranges:
  - cidr: "not-a-cidr"
"#;
        assert!(AllowListConfig::parse(yaml).is_err());
    }
}
