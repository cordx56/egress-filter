//! CA certificate management for TLS MitM.
//!
//! This module provides ephemeral CA generation and dynamic host certificate caching.

mod generator;

pub use generator::{CaState, CertCache};
