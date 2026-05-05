use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy_primitives::Address;

use crate::limiter::{
    args::{ComputeLimiterArgs, GasLimiterArgs},
    compute::{ComputeLimiter, ComputeLimiterOverlay, ComputeOverlayMap},
    gas::{GasLimiter, GasLimiterOverlay, GasOverlayMap},
    metrics::LimiterMetrics,
};

pub use error::CommitError;

pub mod args;
mod bucket;
mod compute;
mod error;
mod gas;
mod metrics;

/// Canonical address-rate-limiter. Owns the persistent gas + compute buckets
/// behind an internal `Arc<Mutex<…>>`, so clones share state cheaply and the
/// public API is `&self` throughout.
///
/// Per-build code should call [`AddressLimiter::fork`] to obtain an
/// [`AddressLimiterOverlay`], use that overlay for all consume/check
/// operations, and let it auto-commit on drop (or call
/// [`AddressLimiterOverlay::commit`] explicitly).
#[derive(Debug, Clone)]
pub struct AddressLimiter {
    inner: Arc<Mutex<AddressLimiterInner>>,
    metrics: LimiterMetrics,
}

#[derive(Debug)]
struct AddressLimiterInner {
    gas_limiter: Option<GasLimiter>,
    compute_limiter: Option<ComputeLimiter>,
    /// Bumped on each refresh and each successful overlay commit. Used to
    /// detect stale overlays.
    epoch: u64,
}

impl AddressLimiter {
    pub fn new(gas_config: GasLimiterArgs, compute_config: ComputeLimiterArgs) -> Self {
        let metrics = LimiterMetrics::default();
        let gas_limiter = GasLimiter::try_new(gas_config, metrics.clone());
        let compute_limiter = ComputeLimiter::try_new(compute_config, metrics.clone());
        Self {
            inner: Arc::new(Mutex::new(AddressLimiterInner {
                gas_limiter,
                compute_limiter,
                epoch: 0,
            })),
            metrics,
        }
    }

    /// Fork a per-build overlay. The returned overlay carries an `Arc` clone
    /// of this canonical's state, so it can auto-commit on drop.
    pub fn fork(&self) -> AddressLimiterOverlay {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let gas_overlay = inner.gas_limiter.as_ref().map(|l| l.fork());
        let compute_overlay = inner.compute_limiter.as_ref().map(|l| l.fork());
        let epoch = inner.epoch;
        drop(inner);
        AddressLimiterOverlay {
            canonical: self.clone(),
            gas_overlay,
            compute_overlay,
            epoch,
            armed: true,
            metrics: self.metrics.clone(),
        }
    }

    /// Should be called once per new block. Refills buckets and (periodically)
    /// garbage-collects full ones. Bumps the epoch so any in-flight overlays
    /// become stale.
    pub fn refresh(&self, block_number: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(l) = inner.gas_limiter.as_mut() {
            l.refresh(block_number);
        }
        if let Some(l) = inner.compute_limiter.as_mut() {
            l.refresh(block_number);
        }
        inner.epoch = inner.epoch.wrapping_add(1);
    }

    /// Fold an overlay's deltas back into this canonical. Returns
    /// [`CommitError::StaleEpoch`] if the canonical advanced since the overlay
    /// was forked. On success the epoch is bumped, so any other in-flight
    /// overlays forked from the same generation become stale.
    fn commit_overlay(
        &self,
        overlay_epoch: u64,
        gas_overlay_map: Option<GasOverlayMap>,
        compute_overlay_map: Option<ComputeOverlayMap>,
    ) -> Result<(), CommitError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.epoch != overlay_epoch {
            return Err(CommitError::StaleEpoch {
                overlay_epoch,
                canonical_epoch: inner.epoch,
            });
        }
        let gas_empty = gas_overlay_map.as_ref().is_none_or(|m| m.is_empty());
        let compute_empty = compute_overlay_map.as_ref().is_none_or(|m| m.is_empty());
        if gas_empty && compute_empty {
            // No-op commit: don't bump the epoch so sibling overlays remain valid.
            return Ok(());
        }
        if let (Some(map), Some(l)) = (gas_overlay_map, inner.gas_limiter.as_mut()) {
            l.fold_overlay(map);
        }
        if let (Some(map), Some(l)) = (compute_overlay_map, inner.compute_limiter.as_mut()) {
            l.fold_overlay(map);
        }
        inner.epoch = inner.epoch.wrapping_add(1);
        Ok(())
    }
}

/// In-flight working copy. Held for the duration of a single build; reads
/// (`is_debt_free`) and consume calls go through here first and only land in
/// the canonical when the overlay is committed (explicitly or on drop).
#[derive(Debug)]
pub struct AddressLimiterOverlay {
    canonical: AddressLimiter,
    gas_overlay: Option<GasLimiterOverlay>,
    compute_overlay: Option<ComputeLimiterOverlay>,
    /// Snapshot of the canonical's epoch at fork time. Required to match
    /// at commit time.
    epoch: u64,
    /// `true` while the overlay still owns its deltas; flipped to `false`
    /// by an explicit `commit` or the Drop impl to prevent double-commits.
    armed: bool,
    metrics: LimiterMetrics,
}

/// Snapshot of the in-flight overlay state. Captured per-tx-attempt so a
/// failed transaction can roll its consumption back without disturbing the
/// canonical or earlier overlay state.
#[derive(Debug, Default)]
pub struct AddressLimiterCheckpoint {
    gas: Option<bucket::OverlayCheckpoint<u64>>,
    compute: Option<bucket::OverlayCheckpoint<Duration>>,
}

impl AddressLimiterOverlay {
    /// Returns `true` if the address is debt-free in all enabled limiters.
    /// Increments the rejection counter for the first failing reason only.
    pub fn is_debt_free(&self, address: &Address) -> bool {
        if self
            .gas_overlay
            .as_ref()
            .is_some_and(|l| !l.is_debt_free(address))
        {
            self.metrics.gas_limiter_rejections.increment(1);
            return false;
        }

        if self
            .compute_overlay
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
        if let Some(l) = self.gas_overlay.as_ref() {
            l.consume_gas(address, gas_used);
        }
    }

    /// Record compute time consumed by an address. Excess goes into debt.
    pub fn consume_compute(&self, address: Address, time_used: Duration) {
        if let Some(l) = self.compute_overlay.as_ref() {
            l.consume_compute(address, time_used);
        }
    }

    /// Snapshot the current overlay state for later [`Self::restore`].
    pub fn checkpoint(&self) -> AddressLimiterCheckpoint {
        AddressLimiterCheckpoint {
            gas: self.gas_overlay.as_ref().map(|l| l.checkpoint()),
            compute: self.compute_overlay.as_ref().map(|l| l.checkpoint()),
        }
    }

    /// Restore the overlay to a previously captured checkpoint.
    pub fn restore(&self, cp: &AddressLimiterCheckpoint) {
        if let (Some(l), Some(snap)) = (self.gas_overlay.as_ref(), cp.gas.as_ref()) {
            l.restore(snap);
        }
        if let (Some(l), Some(snap)) = (self.compute_overlay.as_ref(), cp.compute.as_ref()) {
            l.restore(snap);
        }
    }

    /// Explicitly commit accumulated deltas. Disarms the Drop auto-commit so
    /// the overlay is consumed without firing it again.
    pub fn commit(mut self) -> Result<(), CommitError> {
        self.do_commit()
    }

    fn do_commit(&mut self) -> Result<(), CommitError> {
        self.armed = false;
        let gas_map = self.gas_overlay.take().map(|l| l.into_overlay_map());
        let compute_map = self.compute_overlay.take().map(|l| l.into_overlay_map());
        self.canonical
            .commit_overlay(self.epoch, gas_map, compute_map)
    }
}

impl Drop for AddressLimiterOverlay {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort auto-commit; a stale-epoch error means the canonical
        // moved on (refresh or sibling commit) and the deltas are no longer
        // applicable, which is the correct outcome anyway.
        let _ = self.do_commit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

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

    fn consume_via_overlay(limiter: &AddressLimiter, address: Address, gas: u64) {
        let overlay = limiter.fork();
        overlay.consume_gas(address, gas);
        overlay
            .commit()
            .expect("fresh overlay should commit cleanly");
    }

    fn is_debt_free_via_overlay(limiter: &AddressLimiter, address: &Address) -> bool {
        let overlay = limiter.fork();
        let result = overlay.is_debt_free(address);
        // Drop without consuming → empty overlay; auto-commit is a no-op.
        result
    }

    #[test]
    fn test_basic_debt_and_refill() {
        let config = create_test_config(1000, 200, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        consume_via_overlay(&limiter, test_address(), 1000);
        assert!(
            is_debt_free_via_overlay(&limiter, &test_address()),
            "no debt yet, just empty"
        );

        consume_via_overlay(&limiter, test_address(), 1);
        assert!(
            !is_debt_free_via_overlay(&limiter, &test_address()),
            "should be in debt"
        );

        limiter.refresh(1);
        assert!(
            is_debt_free_via_overlay(&limiter, &test_address()),
            "debt should be paid off"
        );
    }

    #[test]
    fn test_over_capacity_goes_into_debt() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        consume_via_overlay(&limiter, test_address(), 1500);
        assert!(!is_debt_free_via_overlay(&limiter, &test_address()));

        for i in 1..=4 {
            limiter.refresh(i);
            assert!(
                !is_debt_free_via_overlay(&limiter, &test_address()),
                "still in debt at block {i}"
            );
        }
        limiter.refresh(5);
        assert!(
            is_debt_free_via_overlay(&limiter, &test_address()),
            "debt cleared at block 5"
        );
    }

    #[test]
    fn test_multiple_users_independent() {
        let config = create_test_config(10_000_000, 1_000_000, 100);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let searcher = Address::from([0x1; 20]);
        let attacker = Address::from([0x3; 20]);

        consume_via_overlay(&limiter, attacker, 15_000_000);
        assert!(!is_debt_free_via_overlay(&limiter, &attacker));

        assert!(is_debt_free_via_overlay(&limiter, &searcher));
        consume_via_overlay(&limiter, searcher, 500_000);
        assert!(is_debt_free_via_overlay(&limiter, &searcher));
    }

    #[test]
    fn test_overlay_isolated_until_commit() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let overlay = limiter.fork();
        overlay.consume_gas(test_address(), 2000);
        assert!(!overlay.is_debt_free(&test_address()), "overlay sees debt");

        // The canonical, observed by a sibling overlay, is unaffected.
        let sibling = limiter.fork();
        assert!(
            sibling.is_debt_free(&test_address()),
            "canonical not yet touched"
        );
        drop(sibling); // empty overlay → no-op commit

        overlay.commit().expect("commit must succeed");

        // Now a new overlay sees the debt.
        assert!(!is_debt_free_via_overlay(&limiter, &test_address()));
    }

    #[test]
    fn test_stale_epoch_after_refresh() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let overlay = limiter.fork();
        overlay.consume_gas(test_address(), 500);

        // Canonical advances → overlay's epoch is now stale.
        limiter.refresh(1);

        let err = overlay.commit().expect_err("must reject stale commit");
        assert!(matches!(err, CommitError::StaleEpoch { .. }));
    }

    #[test]
    fn test_checkpoint_restore() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let overlay = limiter.fork();
        overlay.consume_gas(test_address(), 400);
        let cp = overlay.checkpoint();
        overlay.consume_gas(test_address(), 700);
        assert!(!overlay.is_debt_free(&test_address()), "overdrawn");

        overlay.restore(&cp);
        assert!(
            overlay.is_debt_free(&test_address()),
            "rolled back, debt-free"
        );
    }

    #[test]
    fn test_auto_commit_on_drop() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        {
            let overlay = limiter.fork();
            overlay.consume_gas(test_address(), 2000);
            // Dropped without explicit commit → auto-commits.
        }

        assert!(
            !is_debt_free_via_overlay(&limiter, &test_address()),
            "auto-commit should have landed the debt"
        );
    }
}
