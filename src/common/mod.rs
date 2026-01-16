//! Common utilities shared across the codebase.
//!
//! This module provides foundational types and functions used throughout dazhbog:
//! - Error types for unified error handling
//! - Time utilities for timestamp operations
//! - Hash functions (CRC32C, wyhash)
//! - Address packing/unpacking for segment storage

pub mod addr;
pub mod error;
pub mod hash;
pub mod time;

// Re-export commonly used items for convenience
pub use addr::{addr_off, addr_seg, pack_addr};
pub use error::CodecError;
pub use hash::{crc32c, crc32c_legacy, version_id, wyhash64};
pub use time::now_ts_sec;
