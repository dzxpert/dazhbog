//! Internal RPC protocol implementation.
//!
//! This is the non-Lumina protocol variant used for internal communication.

mod decoder;
mod encoder;
mod types;

pub use decoder::*;
pub use encoder::*;
pub use types::*;

// Message type constants
pub const MSG_HELLO: u8 = 0x01;
pub const MSG_HELLO_OK: u8 = 0x02;
pub const MSG_FAIL: u8 = 0x03;
pub const MSG_OK: u8 = 0x04;
pub const MSG_PULL: u8 = 0x10;
pub const MSG_PULL_OK: u8 = 0x11;
pub const MSG_PUSH: u8 = 0x12;
pub const MSG_PUSH_OK: u8 = 0x13;
pub const MSG_DEL: u8 = 0x14;
pub const MSG_DEL_OK: u8 = 0x15;
pub const MSG_HIST: u8 = 0x16;
pub const MSG_HIST_OK: u8 = 0x17;
