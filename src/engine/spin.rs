// SAFETY: This module uses unsafe for zero-cost interior mutability.
// SpinLock provides fast, uncontended locking.
use std::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock {
    locked: AtomicBool,
}

pub struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl SpinLock {
    pub const fn new() -> Self { Self { locked: AtomicBool::new(false) } }
    pub fn lock(&self) -> SpinGuard<'_> {
        while self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            std::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}
impl<'a> Drop for SpinGuard<'a> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
