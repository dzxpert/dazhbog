//! Thread-safe cache for tracking upstream fetch failures.
//!
//! Prevents repeated upstream queries for keys that have already failed.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const FAILURE_CACHE_TTL_SECS: u64 = 86400; // 24 hours

/// Thread-safe cache for tracking upstream fetch failures.
#[derive(Clone)]
pub struct FailureCache {
    inner: Arc<RwLock<FailureCacheInner>>,
}

struct FailureCacheInner {
    /// Maps key (symbol hash) to timestamp when failure was recorded.
    entries: HashMap<u128, u64>,
}

impl FailureCache {
    /// Create a new empty failure cache.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(FailureCacheInner {
                entries: HashMap::new(),
            })),
        }
    }

    /// Check if a key is in the failure cache and not expired.
    pub fn is_failed(&self, key: u128) -> bool {
        let now = now_ts_sec();
        if let Ok(cache) = self.inner.read() {
            if let Some(&ts) = cache.entries.get(&key) {
                // Check if entry has expired
                if now - ts < FAILURE_CACHE_TTL_SECS {
                    return true;
                }
            }
        }
        false
    }

    /// Add a key to the failure cache with current timestamp.
    pub fn insert(&self, key: u128) {
        let now = now_ts_sec();
        if let Ok(mut cache) = self.inner.write() {
            cache.entries.insert(key, now);
        }
    }

    /// Remove a key from the failure cache.
    pub fn remove(&self, key: u128) {
        if let Ok(mut cache) = self.inner.write() {
            cache.entries.remove(&key);
        }
    }
}

impl Default for FailureCache {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ts_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
