use std::{
    cmp::min,
    ops::{Add, AddAssign, Sub, SubAssign},
    sync::Arc,
};

use alloy_primitives::Address;
use dashmap::DashMap;

pub(super) trait Token:
    Copy + Ord + Default + Add<Output = Self> + AddAssign + Sub<Output = Self> + SubAssign
{
}
impl<T: Copy + Ord + Default + Add<Output = T> + AddAssign + Sub<Output = Self> + SubAssign> Token
    for T
{
}

// We don't need an Arc<Mutex<_>> here, we can get away with RefCell, but
// the reth PayloadBuilder trait needs this to be Send + Sync
#[derive(Debug, Clone)]
pub(super) struct AddressBuckets<T>(Arc<DashMap<Address, TokenBucket<T>>>);

impl<T: Token> AddressBuckets<T> {
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the address has no debt (or has no bucket yet).
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.0.get(address).is_none_or(|bucket| bucket.debt_free())
    }

    pub(super) fn refill(&self, refill_amount: T) {
        self.0.iter_mut().for_each(|mut bucket| {
            bucket.refill(refill_amount);
        });
    }

    pub(super) fn discard_stale_buckets(&self) {
        self.0.retain(|_, bucket| !bucket.is_full());
    }

    /// Consume the given amount for an address. Always succeeds — excess
    /// is tracked as debt. Returns `true` if a new bucket was created.
    pub(super) fn consume(&self, address: Address, amount: T, default_capacity: T) -> bool {
        let mut created_new_bucket = false;
        let mut bucket = self.0.entry(address).or_insert_with(|| {
            created_new_bucket = true;
            TokenBucket::new(default_capacity)
        });

        bucket.consume(amount);
        created_new_bucket
    }
}

impl<T> Default for AddressBuckets<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// A `TokenBucket` can be used to track various resources. We currently use
/// them to track gas usage and compute usage.
///
/// Buckets can go into debt — `consume` always succeeds, but the bucket
/// tracks how much was overdrawn.
#[derive(Debug, Clone)]
struct TokenBucket<T> {
    capacity: T,
    available: T,
    debt: T,
}

impl<T: Token> TokenBucket<T> {
    /// Create a new full bucket
    fn new(capacity: T) -> Self {
        Self {
            capacity,
            available: capacity,
            debt: T::default(),
        }
    }

    /// Returns `true` if the bucket has no debt
    fn debt_free(&self) -> bool {
        self.debt == T::default()
    }

    /// Returns `true` if the bucket is at capacity with no debt
    fn is_full(&self) -> bool {
        self.debt_free() && self.available == self.capacity
    }

    /// Deduct the specified amount from the bucket. If the amount exceeds
    /// what's available, the excess is tracked as debt.
    fn consume(&mut self, amount: T) {
        if amount <= self.available {
            self.available -= amount;
        } else {
            // amount > available, so (amount - available) overflows into debt.
            self.debt += amount - self.available;
            self.available = T::default();
        }
    }

    /// Refill the bucket with the provided amount. Pays down debt first,
    /// then adds to available up to capacity.
    fn refill(&mut self, refill_amount: T) {
        if self.debt >= refill_amount {
            self.debt -= refill_amount;
        } else {
            // refill_amount > debt, so surplus goes to available
            let surplus = refill_amount - self.debt;
            self.debt = T::default();
            self.available = min(self.capacity, self.available + surplus);
        }
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
        buckets.consume(addr1, 100, capacity);
        buckets.consume(addr2, 100, capacity);
        assert_eq!(buckets.len(), 2);

        // Refill for several rounds - addr1 goes unused while addr2 stays active
        for block in 1..=10 {
            buckets.refill(refill_rate);

            if block > 1 {
                buckets.consume(addr2, 100, capacity);
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
