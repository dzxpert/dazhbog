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

pub use router::serve_http;
