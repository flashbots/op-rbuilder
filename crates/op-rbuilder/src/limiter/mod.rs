use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy_primitives::Address;

use crate::limiter::{
    args::{ComputeLimiterArgs, GasLimiterArgs},
    bucket::{BucketLimiter, BucketLimiterConfig, BucketLimiterGuard, PendingDeltas},
    metrics::LimiterMetrics,
};

pub use error::CommitError;

pub mod args;
mod bucket;
mod error;
mod metrics;

/// Canonical address-rate-limiter. Owns the persistent gas + compute buckets
/// behind an internal `Arc<Mutex<…>>`, so clones share state cheaply and the
/// public API is `&self` throughout.
///
/// Per-build code should call [`AddressLimiter::begin`] to obtain an
/// [`AddressLimiterGuard`], use that guard for all consume/check operations,
/// and let it auto-commit on drop (or call [`AddressLimiterGuard::commit`]
/// explicitly).
#[derive(Debug, Clone)]
pub struct AddressLimiter {
    inner: Arc<Mutex<AddressLimiterInner>>,
    metrics: LimiterMetrics,
}

#[derive(Debug)]
struct AddressLimiterInner {
    gas_limiter: Option<BucketLimiter<u64>>,
    compute_limiter: Option<BucketLimiter<Duration>>,
    /// Bumped on each `refill_buckets` and each successful guard commit. Used
    /// to detect stale guards.
    epoch: u64,
}

impl AddressLimiter {
    pub fn new(gas_config: GasLimiterArgs, compute_config: ComputeLimiterArgs) -> Self {
        let metrics = LimiterMetrics::default();
        let gas_limiter = gas_config.gas_limiter_enabled.then(|| {
            BucketLimiter::new(
                BucketLimiterConfig {
                    default_capacity: gas_config.max_gas_per_address,
                    refill_amount: gas_config.refill_rate_per_block,
                    cleanup_interval: gas_config.cleanup_interval,
                },
                metrics.gas_limiter_active_address_count.clone(),
            )
        });
        let compute_limiter = compute_config.compute_limiter_enabled.then(|| {
            BucketLimiter::new(
                BucketLimiterConfig {
                    default_capacity: Duration::from_micros(compute_config.max_time_us_per_address),
                    refill_amount: Duration::from_micros(
                        compute_config.compute_refill_rate_per_block,
                    ),
                    cleanup_interval: compute_config.compute_cleanup_interval,
                },
                metrics.compute_limiter_active_address_count.clone(),
            )
        });
        Self {
            inner: Arc::new(Mutex::new(AddressLimiterInner {
                gas_limiter,
                compute_limiter,
                epoch: 0,
            })),
            metrics,
        }
    }

    /// Begin a per-build guard. The returned guard carries an `Arc` clone of
    /// this canonical's state, so it can auto-commit on drop.
    pub fn begin(&self) -> AddressLimiterGuard {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let gas = inner.gas_limiter.as_ref().map(|l| l.begin());
        let compute = inner.compute_limiter.as_ref().map(|l| l.begin());
        let epoch = inner.epoch;
        drop(inner);
        AddressLimiterGuard {
            canonical: self.clone(),
            gas,
            compute,
            epoch,
            armed: true,
            metrics: self.metrics.clone(),
        }
    }

    /// Should be called once per new block. Refills buckets and (periodically)
    /// garbage-collects full ones. Bumps the epoch so any in-flight guards
    /// become stale.
    pub fn refill_buckets(&self, block_number: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(l) = inner.gas_limiter.as_mut() {
            l.refill_buckets(block_number);
        }
        if let Some(l) = inner.compute_limiter.as_mut() {
            l.refill_buckets(block_number);
        }
        inner.epoch = inner.epoch.wrapping_add(1);
    }

    /// Apply a guard's deltas back into this canonical. Returns
    /// [`CommitError::StaleEpoch`] if the canonical advanced since the guard
    /// began. On success the epoch is bumped, so any other in-flight guards
    /// from the same generation become stale.
    fn commit_deltas(
        &self,
        guard_epoch: u64,
        gas_deltas: Option<PendingDeltas<u64>>,
        compute_deltas: Option<PendingDeltas<Duration>>,
    ) -> Result<(), CommitError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.epoch != guard_epoch {
            return Err(CommitError::StaleEpoch {
                guard_epoch,
                canonical_epoch: inner.epoch,
            });
        }
        let gas_empty = gas_deltas.as_ref().is_none_or(|d| d.is_empty());
        let compute_empty = compute_deltas.as_ref().is_none_or(|d| d.is_empty());
        if gas_empty && compute_empty {
            // No-op commit: don't bump the epoch so sibling guards remain valid.
            return Ok(());
        }
        if let (Some(deltas), Some(l)) = (gas_deltas, inner.gas_limiter.as_mut()) {
            l.commit(deltas);
        }
        if let (Some(deltas), Some(l)) = (compute_deltas, inner.compute_limiter.as_mut()) {
            l.commit(deltas);
        }
        inner.epoch = inner.epoch.wrapping_add(1);
        Ok(())
    }
}

/// In-flight working copy. Held for the duration of a single build; reads
/// (`is_debt_free`) and consume calls go through here first and only land in
/// the canonical when the guard is committed (explicitly or on drop).
#[derive(Debug)]
pub struct AddressLimiterGuard {
    canonical: AddressLimiter,
    gas: Option<BucketLimiterGuard<u64>>,
    compute: Option<BucketLimiterGuard<Duration>>,
    /// Snapshot of the canonical's epoch at the time the guard began.
    /// Required to match at commit time.
    epoch: u64,
    /// `true` while the guard still owns its deltas; flipped to `false` by an
    /// explicit `commit` or the Drop impl to prevent double-commits.
    armed: bool,
    metrics: LimiterMetrics,
}

impl AddressLimiterGuard {
    /// Returns `true` if the address is debt-free in all enabled limiters.
    /// Increments the rejection counter for the first failing reason only.
    pub fn is_debt_free(&self, address: &Address) -> bool {
        if self.gas.as_ref().is_some_and(|l| !l.is_debt_free(address)) {
            self.metrics.gas_limiter_rejections.increment(1);
            return false;
        }

        if self
            .compute
            .as_ref()
            .is_some_and(|l| !l.is_debt_free(address))
        {
            self.metrics.compute_limiter_rejections.increment(1);
            return false;
        }

        true
    }

    /// Record gas consumed by an address. Excess goes into debt.
    pub fn consume_gas(&self, address: Address, gas_used: u64) {
        if let Some(l) = self.gas.as_ref() {
            l.consume(address, gas_used);
        }
    }

    /// Record compute time consumed by an address. Excess goes into debt.
    pub fn consume_compute(&self, address: Address, time_used: Duration) {
        if let Some(l) = self.compute.as_ref() {
            l.consume(address, time_used);
        }
    }

    /// Explicitly commit accumulated deltas. Disarms the Drop auto-commit so
    /// the guard is consumed without firing it again.
    pub fn commit(mut self) -> Result<(), CommitError> {
        self.do_commit()
    }

    fn do_commit(&mut self) -> Result<(), CommitError> {
        self.armed = false;
        let gas_deltas = self.gas.take().map(|l| l.into_pending());
        let compute_deltas = self.compute.take().map(|l| l.into_pending());
        self.canonical
            .commit_deltas(self.epoch, gas_deltas, compute_deltas)
    }
}

impl Drop for AddressLimiterGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort auto-commit; a stale-epoch error means the canonical
        // moved on (refill or sibling commit) and the deltas are no longer
        // applicable, which is the correct outcome anyway.
        let _ = self.do_commit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use std::assert_matches;

    fn create_test_config(max_gas: u64, refill_rate: u64, cleanup_interval: u64) -> GasLimiterArgs {
        GasLimiterArgs {
            gas_limiter_enabled: true,
            max_gas_per_address: max_gas,
            refill_rate_per_block: refill_rate,
            cleanup_interval,
        }
    }

    fn test_address() -> Address {
        Address::from([1u8; 20])
    }

    fn consume_via_guard(limiter: &AddressLimiter, address: Address, gas: u64) {
        let guard = limiter.begin();
        guard.consume_gas(address, gas);
        guard.commit().expect("fresh guard should commit cleanly");
    }

    fn is_debt_free_via_guard(limiter: &AddressLimiter, address: &Address) -> bool {
        let guard = limiter.begin();

        // Drop without consuming → empty guard; auto-commit is a no-op.
        guard.is_debt_free(address)
    }

    #[test]
    fn test_basic_debt_and_refill() {
        let config = create_test_config(1000, 200, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        consume_via_guard(&limiter, test_address(), 1000);
        assert!(
            is_debt_free_via_guard(&limiter, &test_address()),
            "no debt yet, just empty"
        );

        consume_via_guard(&limiter, test_address(), 1);
        assert!(
            !is_debt_free_via_guard(&limiter, &test_address()),
            "should be in debt"
        );

        limiter.refill_buckets(1);
        assert!(
            is_debt_free_via_guard(&limiter, &test_address()),
            "debt should be paid off"
        );
    }

    #[test]
    fn test_over_capacity_goes_into_debt() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        consume_via_guard(&limiter, test_address(), 1500);
        assert!(!is_debt_free_via_guard(&limiter, &test_address()));

        for i in 1..=4 {
            limiter.refill_buckets(i);
            assert!(
                !is_debt_free_via_guard(&limiter, &test_address()),
                "still in debt at block {i}"
            );
        }
        limiter.refill_buckets(5);
        assert!(
            is_debt_free_via_guard(&limiter, &test_address()),
            "debt cleared at block 5"
        );
    }

    #[test]
    fn test_multiple_users_independent() {
        let config = create_test_config(10_000_000, 1_000_000, 100);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let searcher = Address::from([0x1; 20]);
        let attacker = Address::from([0x3; 20]);

        consume_via_guard(&limiter, attacker, 15_000_000);
        assert!(!is_debt_free_via_guard(&limiter, &attacker));

        assert!(is_debt_free_via_guard(&limiter, &searcher));
        consume_via_guard(&limiter, searcher, 500_000);
        assert!(is_debt_free_via_guard(&limiter, &searcher));
    }

    #[test]
    fn test_guard_isolated_until_commit() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let guard = limiter.begin();
        guard.consume_gas(test_address(), 2000);
        assert!(!guard.is_debt_free(&test_address()), "guard sees debt");

        // The canonical, observed by a sibling guard, is unaffected.
        let sibling = limiter.begin();
        assert!(
            sibling.is_debt_free(&test_address()),
            "canonical not yet touched"
        );
        drop(sibling); // empty guard → no-op commit

        guard.commit().expect("commit must succeed");

        // Now a new guard sees the debt.
        assert!(!is_debt_free_via_guard(&limiter, &test_address()));
    }

    #[test]
    fn test_stale_epoch_after_refill() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let guard = limiter.begin();
        guard.consume_gas(test_address(), 500);

        // Canonical advances → guard's epoch is now stale.
        limiter.refill_buckets(1);

        let err = guard.commit().expect_err("must reject stale commit");
        assert_matches!(err, CommitError::StaleEpoch { .. });
    }

    #[test]
    fn test_auto_commit_on_drop() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        {
            let guard = limiter.begin();
            guard.consume_gas(test_address(), 2000);
            // Dropped without explicit commit → auto-commits.
        }

        assert!(
            !is_debt_free_via_guard(&limiter, &test_address()),
            "auto-commit should have landed the debt"
        );
    }
}
