//! Memory budget management for connection and global limits.
//!
//! Provides atomic budget tracking to prevent memory exhaustion
//! from large frames or many concurrent connections.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Atomic counter for tracking memory usage against a limit.
pub struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    /// Create a new budget with the given limit in bytes.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    /// Try to reserve `n` bytes from the budget.
    /// Returns a guard that releases the reservation on drop.
    pub fn try_reserve(self: &Arc<Self>, n: usize) -> Option<BudgetGuard> {
        loop {
            let cur = self.used.load(Ordering::Relaxed);
            let new = cur.checked_add(n)?;
            if new > self.limit {
                return None;
            }
            if self
                .used
                .compare_exchange(cur, new, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(BudgetGuard {
                    b: Arc::clone(self),
                    n,
                });
            }
        }
    }

    /// Release `n` bytes back to the budget.
    fn release(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }
}

/// RAII guard that releases reserved bytes when dropped.
pub struct BudgetGuard {
    b: Arc<Budget>,
    n: usize,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        self.b.release(self.n);
    }
}

/// A frame buffer with associated budget guards.
/// The guards ensure the memory is released when the frame is dropped.
pub struct OwnedFrame {
    buf: Vec<u8>,
    _conn: BudgetGuard,
    _global: BudgetGuard,
}

impl OwnedFrame {
    /// Create a new owned frame with the given buffer and budget guards.
    pub fn new(buf: Vec<u8>, conn: BudgetGuard, global: BudgetGuard) -> Self {
        Self {
            buf,
            _conn: conn,
            _global: global,
        }
    }

    /// Get the frame data as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}
