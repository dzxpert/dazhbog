//! Protocol implementations for dazhbog.
//!
//! This module contains all protocol-related code:
//! - `codec` - Low-level binary serialization primitives
//! - `lumina` - IDA Pro Lumina protocol implementation
//! - `rpc` - Internal RPC protocol implementation

pub mod codec;
pub mod lumina;
pub mod rpc;

// Re-export commonly used items
pub use codec::{
    frame, get_bytes_max, get_str, get_str_max, get_u128_le, put_bytes, put_str, put_u128_le,
};
pub use lumina::LuminaCaps;
pub use rpc::{HelloReq, PushCaps, PushItem};
