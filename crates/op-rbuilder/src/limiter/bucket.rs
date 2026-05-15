use std::{
    cmp::min,
    collections::{HashMap, hash_map},
    ops::{Add, AddAssign, Sub, SubAssign},
    sync::{Arc, Mutex},
};

use alloy_primitives::Address;

pub(super) trait Token:
    Copy + Ord + Default + Add<Output = Self> + AddAssign + Sub<Output = Self> + SubAssign
{
}
impl<T: Copy + Ord + Default + Add<Output = T> + AddAssign + Sub<Output = Self> + SubAssign> Token
    for T
{
}

/// Canonical token-bucket store.
///
/// Holds the persistent `Arc<HashMap>` of buckets; only mutates on
/// [`AddressBuckets::refresh`] (per-block refill + GC) and
/// [`AddressBuckets::fold_overlay`] (folding an overlay's deltas back).
/// Forking an overlay is an O(1) `Arc` bump on the immutable base.
#[derive(Debug, Clone)]
pub(super) struct AddressBuckets<T> {
    base: Arc<HashMap<Address, TokenBucket<T>>>,
}

impl<T: Token> AddressBuckets<T> {
    pub(super) fn new() -> Self {
        Self {
            base: Arc::new(HashMap::new()),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.base.len()
    }

    /// Fork an overlay sharing this canonical's base. O(1).
    pub(super) fn fork(&self) -> AddressBucketsOverlay<T> {
        AddressBucketsOverlay {
            base: Arc::clone(&self.base),
            overlay: Mutex::new(HashMap::new()),
        }
    }

    /// Per-block bucket refill + (optional) cleanup. Returns the count of
    /// buckets removed by cleanup.
    pub(super) fn refresh(&mut self, refill_amount: T, cleanup: bool) -> usize {
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

    /// Apply an overlay's accumulated deltas. Caller must already have
    /// validated the overlay's epoch. Returns the number of addresses that
    /// were newly added to the canonical (i.e. not present before the fold).
    pub(super) fn fold_overlay(&mut self, overlay_map: HashMap<Address, TokenBucket<T>>) -> usize {
        if overlay_map.is_empty() {
            return 0;
        }
        let mut new_base = (*self.base).clone();
        let mut newly_inserted = 0;
        for (addr, bucket) in overlay_map {
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

/// In-flight working copy. Forked from an [`AddressBuckets`]; mutations
/// accumulate in a private overlay map until folded back.
///
/// Reads (overlay-then-base) are O(1); the internal `Mutex` only serializes
/// concurrent access from within a single overlay (typically uncontended:
/// each overlay is owned by a single build task).
#[derive(Debug)]
pub(super) struct AddressBucketsOverlay<T> {
    /// Immutable view of the canonical's base at fork time.
    base: Arc<HashMap<Address, TokenBucket<T>>>,
    /// Local mutations layered on top of `base`. An address only appears here
    /// once it's been touched.
    overlay: Mutex<HashMap<Address, TokenBucket<T>>>,
}

impl<T: Token> AddressBucketsOverlay<T> {
    /// Returns `true` if the address has no debt (or has no bucket yet).
    /// Reads through the overlay first, then the base.
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        let guard = self.overlay.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = guard.get(address) {
            return b.debt_free();
        }
        drop(guard);
        self.base.get(address).is_none_or(|b| b.debt_free())
    }

    /// Consume the given amount for an address. Always succeeds — excess is
    /// tracked as debt. Reads through to base on first touch, then mutates
    /// the overlay. Returns `true` if a brand-new bucket was created (i.e.
    /// the address was not present in the base view either).
    pub(super) fn consume(&self, address: Address, amount: T, default_capacity: T) -> bool {
        let mut guard = self.overlay.lock().unwrap_or_else(|p| p.into_inner());
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

    /// Capture the overlay's current state. O(K) where K is the number of
    /// addresses touched since the fork.
    pub(super) fn checkpoint(&self) -> OverlayCheckpoint<T> {
        let guard = self.overlay.lock().unwrap_or_else(|p| p.into_inner());
        OverlayCheckpoint(guard.clone())
    }

    /// Restore the overlay to a previously captured checkpoint. Base is not
    /// touched.
    pub(super) fn restore(&self, cp: &OverlayCheckpoint<T>) {
        let mut guard = self.overlay.lock().unwrap_or_else(|p| p.into_inner());
        *guard = cp.0.clone();
    }

    /// Consume self, returning the accumulated overlay map.
    pub(super) fn into_overlay_map(self) -> HashMap<Address, TokenBucket<T>> {
        self.overlay.into_inner().unwrap_or_else(|p| p.into_inner())
    }
}

/// Opaque overlay-only snapshot.
#[derive(Debug, Clone)]
pub(super) struct OverlayCheckpoint<T>(HashMap<Address, TokenBucket<T>>);

impl<T> Default for OverlayCheckpoint<T> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

/// A `TokenBucket` can be used to track various resources. We currently use
/// them to track gas usage and compute usage.
///
/// Buckets can go into debt — `consume` always succeeds, but the bucket
/// tracks how much was overdrawn.
#[derive(Debug, Clone)]
pub(super) struct TokenBucket<T> {
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

        // Seed both addresses via overlay→fold so they land in the canonical.
        let ov = buckets.fork();
        ov.consume(addr1, 100, capacity);
        ov.consume(addr2, 100, capacity);
        buckets.fold_overlay(ov.into_overlay_map());
        assert_eq!(buckets.len(), 2);

        // addr1 stays unused; addr2 keeps consuming.
        for block in 1..=10u64 {
            let _removed = buckets.refresh(refill_rate, block.is_multiple_of(5));
            if block > 1 {
                let ov = buckets.fork();
                ov.consume(addr2, 100, capacity);
                buckets.fold_overlay(ov.into_overlay_map());
            }
        }

        // After cleanup, addr1 (at capacity, debt-free) should be gone.
        assert_eq!(buckets.len(), 1, "addr1 should have been cleaned up");
        assert!(buckets.base.contains_key(&addr2));
        assert!(!buckets.base.contains_key(&addr1));
    }
}
