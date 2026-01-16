//! Configuration module for dazhbog.
//!
//! This module provides all configuration types and parsing logic:
//! - `Config` - Root configuration container
//! - `Limits` - Connection and resource limits
//! - `Engine` - Storage engine settings
//! - `Lumina` - Lumina protocol server settings
//! - `Upstream` - Upstream server configuration
//! - `Scoring` - Version selection scoring weights

mod parser;
mod types;

pub use parser::load_config;
pub use types::*;
