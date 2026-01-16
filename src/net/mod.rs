//! Network layer for the Lumina server.
//!
//! This module contains:
//! - `budget`: Memory budget management for connection and global limits
//! - `frame`: Frame reading with budget management
//! - `protocol`: Protocol detection utilities (TLS vs cleartext)
//! - `tls`: TLS acceptor setup
//! - `handler`: Client connection handler
//! - `server`: TCP server for binary RPC

pub mod budget;
pub mod frame;
pub mod handler;
pub mod protocol;
pub mod server;
pub mod tls;

// Re-export main entry point
pub use server::serve_binary_rpc;
