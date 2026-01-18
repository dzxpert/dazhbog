//! HTTP request handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, Request, Response, StatusCode};
use log::*;
use percent_encoding::percent_decode_str;
use serde::Serialize;
use std::sync::Arc;

use crate::api::metrics::METRICS;
use crate::db::Database;
use crate::engine::SearchHit;

/// Search response structure.
#[derive(Serialize)]
pub struct SearchResponse {
    query: String,
    results: Vec<SearchHit>,
}

/// Metrics snapshot for JSON API.
#[derive(Serialize)]
pub struct MetricsSnapshot {
    // Database stats
    indexed_funcs: u64,
    total_records: u64,
    storage_bytes: u64,
    search_docs: u64,
    unique_binaries: u64,
    uptime_secs: u64,
    start_time: u64,

    // Traffic counters
    pulls: u64,
    pushes: u64,
    new_funcs: u64,
    queried_funcs: u64,
    active_connections: u64,

    // Protocol counters
    lumina_v0_4: u64,
    lumina_v5p: u64,

    // Error counters
    errors: u64,
    timeouts: u64,
    index_overflows: u64,
    append_failures: u64,
    decoder_rejects: u64,

    // Upstream counters
    upstream_requests: u64,
    upstream_fetched: u64,
    upstream_errors: u64,

    // Scoring counters
    scoring_batches: u64,
    scoring_versions_considered: u64,
    scoring_fallback_latest: u64,
}

/// Get current metrics snapshot.
pub fn metrics_snapshot() -> MetricsSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    MetricsSnapshot {
        // Database stats
        indexed_funcs: METRICS.indexed_funcs.load(Relaxed),
        total_records: METRICS.total_records.load(Relaxed),
        storage_bytes: METRICS.storage_bytes.load(Relaxed),
        search_docs: METRICS.search_docs.load(Relaxed),
        unique_binaries: METRICS.unique_binaries.load(Relaxed),
        uptime_secs: METRICS.uptime_secs(),
        start_time: METRICS.start_time.load(Relaxed),

        // Traffic counters
        pulls: METRICS.pulls.load(Relaxed),
        pushes: METRICS.pushes.load(Relaxed),
        new_funcs: METRICS.new_funcs.load(Relaxed),
        queried_funcs: METRICS.queried_funcs.load(Relaxed),
        active_connections: METRICS.active_connections.load(Relaxed),

        // Protocol counters
        lumina_v0_4: METRICS.lumina_v0_4.load(Relaxed),
        lumina_v5p: METRICS.lumina_v5p.load(Relaxed),

        // Error counters
        errors: METRICS.errors.load(Relaxed),
        timeouts: METRICS.timeouts.load(Relaxed),
        index_overflows: METRICS.index_overflows.load(Relaxed),
        append_failures: METRICS.append_failures.load(Relaxed),
        decoder_rejects: METRICS.decoder_rejects.load(Relaxed),

        // Upstream counters
        upstream_requests: METRICS.upstream_requests.load(Relaxed),
        upstream_fetched: METRICS.upstream_fetched.load(Relaxed),
        upstream_errors: METRICS.upstream_errors.load(Relaxed),

        // Scoring counters
        scoring_batches: METRICS.scoring_batches.load(Relaxed),
        scoring_versions_considered: METRICS.scoring_versions_considered.load(Relaxed),
        scoring_fallback_latest: METRICS.scoring_fallback_latest.load(Relaxed),
    }
}

/// Parse a query parameter from a request.
pub fn parse_query_param(req: &Request<Incoming>, key: &str) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        if k == key {
            let raw = it.next().unwrap_or_default();
            return percent_decode_str(raw)
                .decode_utf8()
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}

/// Create a JSON response.
pub fn json_response<T: Serialize>(value: &T, status: StatusCode) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut r = Response::new(Full::new(Bytes::from(body)));
            *r.status_mut() = status;
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(e) => {
            error!("json serialize error: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from_static(
                    b"{\"error\":\"serialization\"}",
                )))
                .unwrap()
        }
    }
}

/// Handle search API request.
pub async fn handle_search(db: Arc<Database>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let Some(q) = parse_query_param(&req, "q") else {
        return json_response(
            &serde_json::json!({"error": "missing query"}),
            StatusCode::BAD_REQUEST,
        );
    };

    // Max 25 results
    const MAX_RESULTS: usize = 25;

    match db.search_functions(&q, MAX_RESULTS).await {
        Ok(results) => json_response(&SearchResponse { query: q, results }, StatusCode::OK),
        Err(e) => {
            error!("search failed: {}", e);
            json_response(
                &serde_json::json!({"error": "search failed"}),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}
