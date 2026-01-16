//! API module for dazhbog.
//!
//! This module provides external interfaces:
//! - `http` - HTTP API server with web dashboard
//! - `metrics` - Prometheus metrics collection

pub mod http;
pub mod metrics;

pub use http::serve_http;
pub use metrics::METRICS;
