//! Network layer for the Lumina server.
//!
//! This module contains:
//! - `budget`: Memory budget management for connection and global limits
//! - `frame`: Frame reading with budget management
//! - `peekable`: Peekable stream wrapper for protocol detection
//! - `protocol`: Protocol detection utilities (TLS vs cleartext, HTTP)
//! - `tls`: TLS acceptor setup
//! - `handler`: Client connection handler
//! - `server`: TCP server for binary RPC and HTTP

pub mod budget;
pub mod frame;
pub mod handler;
pub mod peekable;
pub mod protocol;
pub mod server;
pub mod tls;

// Re-export main entry point
pub use server::serve_binary_rpc;
