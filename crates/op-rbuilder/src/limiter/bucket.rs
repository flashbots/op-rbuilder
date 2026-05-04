use std::{
    cmp::min,
    ops::{Add, SubAssign},
};

/// A `TokenBucket` can be used to track various resources. We currently use
/// them to track gas usage and compute usage.
#[derive(Debug, Clone)]
pub(super) struct TokenBucket<T> {
    capacity: T,
    available: T,
}

impl<T: Copy + Ord + PartialEq + PartialOrd + Add<Output = T> + SubAssign> TokenBucket<T> {
    /// Create a new full bucket
    pub(super) fn new(capacity: T) -> Self {
        Self {
            capacity,
            available: capacity,
        }
    }

    pub(super) fn available(&self) -> T {
        self.available
    }

    /// Returns `true` if the bucket is at capacity
    pub(super) fn is_full(&self) -> bool {
        self.available == self.capacity
    }

    /// Attempts to deduct the specified amount from the bucket. Returns `false`
    /// if the bucket doesn't have enough.
    pub(super) fn try_consume(&mut self, requested_amount: T) -> bool {
        if requested_amount > self.available {
            return false;
        }

        self.available -= requested_amount;
        true
    }

    /// Refill the bucket with the provided amount, up to the capacity
    pub(super) fn refill(&mut self, refill_amount: T) {
        self.available = min(self.capacity, self.available + refill_amount)
    }
}
