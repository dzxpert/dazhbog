//! Global metrics collection using atomic counters.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Global metrics structure.
#[derive(Default)]
pub struct Metrics {
    pub pulls: AtomicU64,
    pub pushes: AtomicU64,
    pub new_funcs: AtomicU64,
    pub queried_funcs: AtomicU64,
    pub active_connections: AtomicU64,
    pub lumina_v0_4: AtomicU64,
    pub lumina_v5p: AtomicU64,
    pub errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub shutting_down: AtomicBool,
    pub index_overflows: AtomicU64,
    pub append_failures: AtomicU64,
    pub decoder_rejects: AtomicU64,
    // Upstream metrics
    pub upstream_requests: AtomicU64,
    pub upstream_fetched: AtomicU64,
    pub upstream_errors: AtomicU64,
    // Scoring / selection metrics
    pub scoring_batches: AtomicU64,
    pub scoring_versions_considered: AtomicU64,
    pub scoring_fallback_latest: AtomicU64,
    pub scoring_time_ns: AtomicU64,
}

/// Global metrics singleton.
pub static METRICS: once_cell::sync::Lazy<&'static Metrics> =
    once_cell::sync::Lazy::new(|| Box::leak(Box::new(Metrics::default())));

impl Metrics {
    /// Render metrics in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let g = |name: &str, help: &str, val: u64| -> String {
            format!(
                "# HELP {0} {1}\n# TYPE {0} counter\n{0} {2}\n",
                name, help, val
            )
        };
        let mut s = String::with_capacity(2048);
        s.push_str(&g(
            "dazhbog_pulls_total",
            "Number of functions successfully pulled",
            self.pulls.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_pushes_total",
            "Number of functions pushed",
            self.pushes.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_new_funcs_total",
            "New unique functions inserted",
            self.new_funcs.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_queried_funcs_total",
            "Requested function keys",
            self.queried_funcs.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_active_connections",
            "Active binary RPC connections",
            self.active_connections.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_lumina_v0_4",
            "Hello protocol versions 0..4",
            self.lumina_v0_4.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_lumina_v5p",
            "Hello protocol versions >=5",
            self.lumina_v5p.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_errors_total",
            "Errors",
            self.errors.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_timeouts_total",
            "Timeouts",
            self.timeouts.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_index_overflows_total",
            "Index insertion overflows (no overwrite)",
            self.index_overflows.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_append_failures_total",
            "Database append operation failures",
            self.append_failures.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_decoder_rejects_total",
            "Protocol decoder rejections due to size limits",
            self.decoder_rejects.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_upstream_requests_total",
            "Batches requested from upstream",
            self.upstream_requests.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_upstream_fetched_total",
            "Functions fetched from upstream",
            self.upstream_fetched.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_upstream_errors_total",
            "Errors contacting upstream",
            self.upstream_errors.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_batches_total",
            "Version selection batches scored",
            self.scoring_batches.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_versions_considered_total",
            "Versions considered across batches",
            self.scoring_versions_considered.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_fallback_latest_total",
            "Batches falling back to latest semantics",
            self.scoring_fallback_latest.load(Ordering::Relaxed),
        ));
        s.push_str(&g(
            "dazhbog_scoring_time_ns_total",
            "Cumulative time spent scoring (ns)",
            self.scoring_time_ns.load(Ordering::Relaxed),
        ));
        s
    }
}
