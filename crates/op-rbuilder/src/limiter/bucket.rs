use std::{
    cmp::min,
    ops::{Add, SubAssign},
    sync::Arc,
};

use alloy_primitives::Address;
use dashmap::DashMap;

pub(super) trait Token: Copy + Ord + Add<Output = Self> + SubAssign {}
impl<T: Copy + Ord + Add<Output = T> + SubAssign> Token for T {}

// We don't need an Arc<Mutex<_>> here, we can get away with RefCell, but
// the reth PayloadBuilder trait needs this to be Send + Sync
#[derive(Debug, Clone)]
pub(super) struct AddressBuckets<T>(Arc<DashMap<Address, TokenBucket<T>>>);

impl<T: Token> AddressBuckets<T> {
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn refill(&self, refill_amount: T) {
        self.0.iter_mut().for_each(|mut bucket| {
            bucket.refill(refill_amount);
        });
    }

    pub(super) fn discard_stale_buckets(&self) {
        self.0.retain(|_, bucket| !bucket.is_full());
    }

    pub(super) fn try_consume(
        &self,
        address: Address,
        requested: T,
        default_capacity: T,
    ) -> Result<bool, T> {
        let mut created_new_bucket = false;
        let mut bucket = self.0.entry(address).or_insert_with(|| {
            created_new_bucket = true;
            TokenBucket::new(default_capacity)
        });

        if !bucket.try_consume(requested) {
            return Err(bucket.available()); // caller gets `available` to build its own error
        }

        Ok(created_new_bucket)
    }
}

impl<T> Default for AddressBuckets<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// A `TokenBucket` can be used to track various resources. We currently use
/// them to track gas usage and compute usage.
#[derive(Debug, Clone)]
struct TokenBucket<T> {
    capacity: T,
    available: T,
}

impl<T: Token> TokenBucket<T> {
    /// Create a new full bucket
    fn new(capacity: T) -> Self {
        Self {
            capacity,
            available: capacity,
        }
    }

    fn available(&self) -> T {
        self.available
    }

    /// Returns `true` if the bucket is at capacity
    fn is_full(&self) -> bool {
        self.available == self.capacity
    }

    /// Attempts to deduct the specified amount from the bucket. Returns `false`
    /// if the bucket doesn't have enough.
    fn try_consume(&mut self, requested_amount: T) -> bool {
        if requested_amount > self.available {
            return false;
        }

        self.available -= requested_amount;
        true
    }

    /// Refill the bucket with the provided amount, up to the capacity
    fn refill(&mut self, refill_amount: T) {
        self.available = min(self.capacity, self.available + refill_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_cleanup() {
        let capacity = 1000;
        let refill_rate = 1000;

        let addr1 = Address::from([0x1; 20]);
        let addr2 = Address::from([0x2; 20]);

        let buckets = AddressBuckets::<u64>::default();

        // Create buckets for both addresses
        assert!(buckets.try_consume(addr1, 100, capacity).is_ok());
        assert!(buckets.try_consume(addr2, 100, capacity).is_ok());
        assert_eq!(buckets.len(), 2);

        // Refill for several rounds - addr1 goes unused while addr2 stays active
        for block in 1..=10 {
            buckets.refill(refill_rate);

            if block > 1 {
                assert!(buckets.try_consume(addr2, 100, capacity).is_ok());
            }
        }

        // addr1 is full (unused), addr2 is not — cleanup should remove only addr1
        buckets.discard_stale_buckets();

        assert_eq!(
            buckets.len(),
            1,
            "Unused bucket (addr1) should have been cleaned up"
        );
        assert!(buckets.0.contains_key(&addr2));
        assert!(!buckets.0.contains_key(&addr1));
    }
}
