//! HTTP API server module.
//!
//! Provides:
//! - Web dashboard at `/`
//! - Search API at `/api/search`
//! - JSON metrics at `/api/metrics`
//! - Prometheus metrics at `/metrics`

mod handlers;
mod router;
mod templates;

pub use router::{handle_http_connection, handle_http_connection_with_protocol, serve_http};
