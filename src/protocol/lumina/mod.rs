//! IDA Pro Lumina protocol implementation.
//!
//! This module implements the Lumina protocol used by IDA Pro for function metadata exchange.
//! It supports:
//! - Protocol parsing (server-side)
//! - Response building (server-side)
//! - Client-side helpers for upstream forwarding

mod builder;
mod parser;
mod types;
mod wire;

pub use crate::common::error::LuminaError;
pub use builder::*;
pub use parser::*;
pub use types::*;
pub use wire::*;
