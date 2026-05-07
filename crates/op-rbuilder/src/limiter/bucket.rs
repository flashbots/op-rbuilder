use std::{
    cmp::min,
    collections::{HashMap, hash_map},
    ops::{Add, AddAssign, Sub, SubAssign},
    sync::{Arc, Mutex},
};

use alloy_primitives::Address;
use metrics::Gauge;

pub(super) trait Token:
    Copy + Ord + Default + Add<Output = Self> + AddAssign + Sub<Output = Self> + SubAssign
{
}
impl<T: Copy + Ord + Default + Add<Output = T> + AddAssign + Sub<Output = Self> + SubAssign> Token
    for T
{
}

/// Batch of pending per-address bucket updates produced by a [`BucketLimiterGuard`]. Hands the deltas back to [`BucketLimiter::commit`].
#[derive(Debug, Clone)]
pub(super) struct PendingDeltas<T>(HashMap<Address, TokenBucket<T>>);

impl<T> PendingDeltas<T> {
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Canonical token-bucket store.
///
/// Holds the persistent `Arc<HashMap>` of buckets; only mutates on
/// [`AddressBuckets::refill_buckets`] (per-block refill + GC) and
/// [`AddressBuckets::commit`] (applying a guard's pending deltas).
/// Beginning a guard is an O(1) `Arc` bump on the immutable base.
#[derive(Debug, Clone)]
struct AddressBuckets<T> {
    base: Arc<HashMap<Address, TokenBucket<T>>>,
}

impl<T: Token> AddressBuckets<T> {
    fn new() -> Self {
        Self {
            base: Arc::new(HashMap::new()),
        }
    }

    fn len(&self) -> usize {
        self.base.len()
    }

    /// Begin a guard sharing this canonical's base. O(1).
    fn begin(&self) -> AddressBucketsGuard<T> {
        AddressBucketsGuard {
            base: Arc::clone(&self.base),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Per-block bucket refill + (optional) cleanup. Returns the count of
    /// buckets removed by cleanup.
    fn refill_buckets(&mut self, refill_amount: T, cleanup: bool) -> usize {
        let mut new_base = HashMap::with_capacity(self.base.len());
        for (addr, bucket) in self.base.iter() {
            let mut refilled = bucket.clone();
            refilled.refill(refill_amount);
            if cleanup && refilled.is_full() {
                continue;
            }
            new_base.insert(*addr, refilled);
        }
        let removed = self.base.len().saturating_sub(new_base.len());
        self.base = Arc::new(new_base);
        removed
    }

    /// Apply a guard's accumulated deltas. Caller must already have validated
    /// the guard's epoch. Returns the number of addresses that were newly
    /// added to the canonical (i.e. not present before the commit).
    fn commit(&mut self, deltas: HashMap<Address, TokenBucket<T>>) -> usize {
        if deltas.is_empty() {
            return 0;
        }
        let mut new_base = (*self.base).clone();
        let mut newly_inserted = 0;
        for (addr, bucket) in deltas {
            if new_base.insert(addr, bucket).is_none() {
                newly_inserted += 1;
            }
        }
        self.base = Arc::new(new_base);
        newly_inserted
    }
}

impl<T: Token> Default for AddressBuckets<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// In-flight working copy. Begun from an [`AddressBuckets`]; mutations
/// accumulate in a private pending map until committed back.
///
/// Reads (pending-then-base) are O(1); the internal `Mutex` only serializes
/// concurrent access from within a single guard (typically uncontended: each
/// guard is owned by a single build task).
#[derive(Debug)]
struct AddressBucketsGuard<T> {
    /// Immutable view of the canonical's base at the time the guard began.
    base: Arc<HashMap<Address, TokenBucket<T>>>,
    /// Local mutations layered on top of `base`. An address only appears here
    /// once it's been touched.
    pending: Mutex<HashMap<Address, TokenBucket<T>>>,
}

impl<T: Token> AddressBucketsGuard<T> {
    /// Returns `true` if the address has no debt (or has no bucket yet).
    /// Reads through the pending map first, then the base.
    fn is_debt_free(&self, address: &Address) -> bool {
        let guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = guard.get(address) {
            return b.debt_free();
        }
        drop(guard);
        self.base.get(address).is_none_or(|b| b.debt_free())
    }

    /// Consume the given amount for an address. Always succeeds — excess is
    /// tracked as debt. Reads through to base on first touch, then mutates
    /// the pending map. Returns `true` if a brand-new bucket was created
    /// (i.e. the address was not present in the base view either).
    fn consume(&self, address: Address, amount: T, default_capacity: T) -> bool {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let mut created_new = false;
        let bucket = match guard.entry(address) {
            hash_map::Entry::Occupied(e) => e.into_mut(),
            hash_map::Entry::Vacant(e) => {
                let b = match self.base.get(&address) {
                    Some(b) => b.clone(),
                    None => {
                        created_new = true;
                        TokenBucket::new(default_capacity)
                    }
                };
                e.insert(b)
            }
        };
        bucket.consume(amount);
        created_new
    }

    /// Consume self, returning the accumulated pending map.
    fn into_pending(self) -> HashMap<Address, TokenBucket<T>> {
        self.pending.into_inner().unwrap_or_else(|p| p.into_inner())
    }

    /// Clone the current pending map without consuming the guard. Used by the
    /// continuous candidate loop to checkpoint pending state across candidate
    /// iterations.
    fn clone_pending(&self) -> HashMap<Address, TokenBucket<T>> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replace the pending map. Used by the continuous candidate loop to
    /// rewind to a saved checkpoint before evaluating the next candidate.
    fn set_pending(&self, pending: HashMap<Address, TokenBucket<T>>) {
        *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = pending;
    }
}

/// Configuration for a [`BucketLimiter`].
#[derive(Debug, Clone)]
pub(super) struct BucketLimiterConfig<T> {
    /// Per-address bucket capacity (the steady-state allowance).
    pub default_capacity: T,
    /// Amount refilled per block.
    pub refill_amount: T,
    /// Cleanup full buckets every N blocks.
    pub cleanup_interval: u64,
}

/// Canonical per-address rate limiter, generic over the resource type.
/// Wraps [`AddressBuckets`] with config and metric handle.
#[derive(Debug, Clone)]
pub(super) struct BucketLimiter<T> {
    buckets: AddressBuckets<T>,
    config: BucketLimiterConfig<T>,
    active_count: Gauge,
}

impl<T: Token> BucketLimiter<T> {
    pub(super) fn new(config: BucketLimiterConfig<T>, active_count: Gauge) -> Self {
        Self {
            buckets: AddressBuckets::new(),
            config,
            active_count,
        }
    }

    /// Begin a per-build guard sharing the canonical state.
    pub(super) fn begin(&self) -> BucketLimiterGuard<T> {
        BucketLimiterGuard {
            buckets: self.buckets.begin(),
            default_capacity: self.config.default_capacity,
        }
    }

    /// Per-block refill (and periodic cleanup).
    pub(super) fn refill_buckets(&mut self, block_number: u64) {
        let do_cleanup = block_number.is_multiple_of(self.config.cleanup_interval);
        self.buckets
            .refill_buckets(self.config.refill_amount, do_cleanup);
        self.active_count.set(self.buckets.len() as f64);
    }

    /// Apply a guard's accumulated deltas back into the canonical.
    pub(super) fn commit(&mut self, deltas: PendingDeltas<T>) {
        self.buckets.commit(deltas.0);
        self.active_count.set(self.buckets.len() as f64);
    }
}

/// In-flight guard begun from a [`BucketLimiter`]. Reads/consumes go through
/// here with `&self`; on commit the accumulated deltas are applied back into
/// the canonical.
#[derive(Debug)]
pub(super) struct BucketLimiterGuard<T> {
    buckets: AddressBucketsGuard<T>,
    default_capacity: T,
}

impl<T: Token> BucketLimiterGuard<T> {
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.buckets.is_debt_free(address)
    }

    pub(super) fn consume(&self, address: Address, amount: T) {
        self.buckets.consume(address, amount, self.default_capacity);
    }

    pub(super) fn into_pending(self) -> PendingDeltas<T> {
        PendingDeltas(self.buckets.into_pending())
    }

    /// Snapshot the current pending deltas without consuming the guard.
    /// Continuous candidate evaluation uses this to checkpoint between
    /// candidate iterations.
    pub(super) fn snapshot_pending(&self) -> PendingDeltas<T> {
        PendingDeltas(self.buckets.clone_pending())
    }

    /// Replace pending deltas with a previous snapshot. Continuous candidate
    /// evaluation uses this to rewind to a checkpoint before trying the next
    /// candidate.
    pub(super) fn restore_pending(&self, snapshot: PendingDeltas<T>) {
        self.buckets.set_pending(snapshot.0);
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
    fn new(capacity: T) -> Self {
        Self {
            capacity,
            available: capacity,
            debt: T::default(),
        }
    }

    fn debt_free(&self) -> bool {
        self.debt == T::default()
    }

    fn is_full(&self) -> bool {
        self.debt_free() && self.available == self.capacity
    }

    /// Deduct the specified amount from the bucket. If the amount exceeds
    /// what's available, the excess is tracked as debt.
    fn consume(&mut self, amount: T) {
        if amount <= self.available {
            self.available -= amount;
        } else {
            self.debt += amount - self.available;
            self.available = T::default();
        }
    }

    /// Refill the bucket. Pays down debt first, then adds to available up to
    /// capacity.
    fn refill(&mut self, refill_amount: T) {
        if self.debt >= refill_amount {
            self.debt -= refill_amount;
        } else {
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
        let capacity = 1000u64;
        let refill_rate = 1000u64;

        let addr1 = Address::from([0x1; 20]);
        let addr2 = Address::from([0x2; 20]);

        let mut buckets = AddressBuckets::<u64>::new();

        // Seed both addresses via guard→commit so they land in the canonical.
        let guard = buckets.begin();
        guard.consume(addr1, 100, capacity);
        guard.consume(addr2, 100, capacity);
        buckets.commit(guard.into_pending());
        assert_eq!(buckets.len(), 2);

        // addr1 stays unused; addr2 keeps consuming.
        for block in 1..=10u64 {
            let _removed = buckets.refill_buckets(refill_rate, block.is_multiple_of(5));
            if block > 1 {
                let guard = buckets.begin();
                guard.consume(addr2, 100, capacity);
                buckets.commit(guard.into_pending());
            }
        }

        // After cleanup, addr1 (at capacity, debt-free) should be gone.
        assert_eq!(buckets.len(), 1, "addr1 should have been cleaned up");
        assert!(buckets.base.contains_key(&addr2));
        assert!(!buckets.base.contains_key(&addr1));
    }
}
