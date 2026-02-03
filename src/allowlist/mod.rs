mod config;
mod matcher;

pub use config::{AllowListConfig, AllowListError, DohConfig};
pub use matcher::AllowList;

pub type DnsConfig = config::DnsConfig;
