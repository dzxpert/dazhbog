//! Time utilities for timestamp operations.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
#[inline]
pub fn now_ts_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
