use std::cmp::min;

/// A `TokenBucket` can be used to track various resources. We currently use
/// them to track gas usage and compute usage.
#[derive(Debug, Clone)]
pub(super) struct TokenBucket {
    capacity: u64,
    available: u64,
}

impl TokenBucket {
    /// Create a new full bucket
    pub(super) fn new(capacity: u64) -> Self {
        Self {
            capacity,
            available: capacity,
        }
    }

    pub(super) fn available(&self) -> u64 {
        self.available
    }

    /// Returns `true` if the bucket is at capacity
    pub(super) fn is_full(&self) -> bool {
        self.available == self.capacity
    }

    /// Attempts to deduct the specified amount from the bucket. Returns `false`
    /// if the bucket doesn't have enough.
    pub(super) fn try_consume(&mut self, requested_amount: u64) -> bool {
        if requested_amount > self.available {
            return false;
        }

        self.available -= requested_amount;
        true
    }

    /// Refill the bucket with the provided amount, up to the capacity
    pub(super) fn refill(&mut self, refill_amount: u64) {
        self.available = min(self.capacity, self.available + refill_amount)
    }
}
