//! HTTPS proxy for DoH interception.
//!
//! This module provides a TLS-terminating proxy that intercepts HTTPS connections
//! and filters DoH (DNS over HTTPS) requests based on allowlist rules.

mod doh;
mod server;
mod tls;
mod tunnel;

pub use doh::{DohDetector, DohRequest, DohResponse};
pub use server::{AllowListChecker, ProxyServer, ProxyState, ResolutionCache};
pub use tls::TlsAcceptor;
pub use tunnel::Tunnel;
