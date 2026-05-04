use std::{cmp::min, sync::Arc, time::Instant};

use alloy_primitives::Address;
use dashmap::DashMap;

use crate::gas_limiter::{args::GasLimiterArgs, error::GasLimitError, metrics::GasLimiterMetrics};

pub mod args;
pub mod error;
mod metrics;

#[derive(Debug, Clone)]
pub struct AddressGasLimiter {
    max_gas_per_address: u64,
    refill_rate_per_block: u64,
    cleanup_interval: u64,
    // We don't need an Arc<Mutex<_>> here, we can get away with RefCell, but
    // the reth PayloadBuilder trait needs this to be Send + Sync
    address_buckets: Arc<DashMap<Address, TokenBucket>>,
    metrics: GasLimiterMetrics,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: u64,
    available: u64,
}

impl AddressGasLimiter {
    pub fn new(
        max_gas_per_address: u64,
        refill_rate_per_block: u64,
        cleanup_interval: u64,
    ) -> Self {
        Self {
            max_gas_per_address,
            refill_rate_per_block,
            cleanup_interval,
            address_buckets: Default::default(),
            metrics: Default::default(),
        }
    }

    /// Check if there's enough gas for this address and consume it. Returns
    /// `Ok(())` if there's enough, otherwise an error.
    pub fn consume_gas(&self, address: Address, gas_requested: u64) -> Result<(), GasLimitError> {
        let start = Instant::now();
        let result = self.consume_gas_inner(address, gas_requested);

        self.metrics.record_gas_check(&result, start.elapsed());

        result.map(|_| ())
    }

    /// Should be called upon each new block. Refills buckets and runs
    /// periodic garbage collection.
    pub fn refresh(&self, block_number: u64) {
        let start = Instant::now();
        let removed_addresses = self.refresh_inner(block_number);

        self.metrics
            .record_refresh(removed_addresses, start.elapsed());
    }

    fn consume_gas_inner(
        &self,
        address: Address,
        gas_requested: u64,
    ) -> Result<bool, GasLimitError> {
        let mut created_new_bucket = false;
        let mut bucket = self.address_buckets.entry(address).or_insert_with(|| {
            created_new_bucket = true;
            TokenBucket::new(self.max_gas_per_address)
        });

        if gas_requested > bucket.available {
            return Err(GasLimitError::AddressLimitExceeded {
                address,
                requested: gas_requested,
                available: bucket.available,
            });
        }

        bucket.available -= gas_requested;

        Ok(created_new_bucket)
    }

    fn refresh_inner(&self, block_number: u64) -> usize {
        let active_addresses = self.address_buckets.len();

        self.address_buckets.iter_mut().for_each(|mut bucket| {
            bucket.available = min(
                bucket.capacity,
                bucket.available + self.refill_rate_per_block,
            )
        });

        // Only clean up stale buckets every `cleanup_interval` blocks
        if block_number.is_multiple_of(self.cleanup_interval) {
            self.address_buckets
                .retain(|_, bucket| bucket.available < bucket.capacity);
        }

        active_addresses - self.address_buckets.len()
    }
}

impl TokenBucket {
    fn new(capacity: u64) -> Self {
        Self {
            capacity,
            available: capacity,
        }
    }
}

/// Holds one [`AddressGasLimiter`] per tx source. The two pools are always
/// configured together — callers represent the disabled state with
/// `Option<GasLimiters>` rather than per-field optionality.
#[derive(Debug, Clone)]
pub struct GasLimiters {
    /// Limiter applied to public-mempool txs.
    pub mempool: AddressGasLimiter,
    /// Limiter applied to bundle txs (including backruns).
    pub bundle: AddressGasLimiter,
}

impl GasLimiters {
    /// Build per-source limiters from the flat `GasLimiterArgs`. Returns
    /// `None` when the limiter is disabled. When enabled, both pools are
    /// constructed with their respective capacity/refill settings.
    pub fn from_args(args: &GasLimiterArgs) -> Option<Self> {
        if !args.gas_limiter_enabled {
            return None;
        }

        Some(Self {
            mempool: AddressGasLimiter::new(
                args.max_gas_per_address,
                args.refill_rate_per_block,
                args.cleanup_interval,
            ),
            bundle: AddressGasLimiter::new(
                args.bundle_max_gas_per_address,
                args.bundle_refill_rate_per_block,
                args.cleanup_interval,
            ),
        })
    }

    /// Refresh both limiters. Call once per new block.
    pub fn refresh(&self, block_number: u64) {
        self.mempool.refresh(block_number);
        self.bundle.refresh(block_number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    fn enabled_args(max_gas: u64, refill_rate: u64, cleanup_interval: u64) -> GasLimiterArgs {
        GasLimiterArgs {
            gas_limiter_enabled: true,
            max_gas_per_address: max_gas,
            refill_rate_per_block: refill_rate,
            cleanup_interval,
            bundle_max_gas_per_address: max_gas,
            bundle_refill_rate_per_block: refill_rate,
        }
    }

    fn test_address() -> Address {
        Address::from([1u8; 20])
    }

    #[test]
    fn test_basic_refill() {
        let limiter = AddressGasLimiter::new(1000, 200, 10);

        // Consume all gas
        assert!(limiter.consume_gas(test_address(), 1000).is_ok());
        assert!(limiter.consume_gas(test_address(), 1).is_err());

        // Refill and check available gas increased
        limiter.refresh(1);
        assert!(limiter.consume_gas(test_address(), 200).is_ok());
        assert!(limiter.consume_gas(test_address(), 1).is_err());
    }

    #[test]
    fn test_over_capacity_request() {
        let limiter = AddressGasLimiter::new(1000, 100, 10);

        // Request more than capacity should fail
        let result = limiter.consume_gas(test_address(), 1500);
        assert!(result.is_err());

        if let Err(GasLimitError::AddressLimitExceeded { available, .. }) = result {
            assert_eq!(available, 1000);
        }

        // Bucket should still be full after failed request
        assert!(limiter.consume_gas(test_address(), 1000).is_ok());
    }

    #[test]
    fn test_multiple_users() {
        // Simulate more realistic scenario
        let limiter = AddressGasLimiter::new(10_000_000, 1_000_000, 100); // 10M max, 1M refill

        let searcher1 = Address::from([0x1; 20]);
        let searcher2 = Address::from([0x2; 20]);
        let attacker = Address::from([0x3; 20]);

        // Normal searchers use reasonable amounts
        assert!(limiter.consume_gas(searcher1, 500_000).is_ok());
        assert!(limiter.consume_gas(searcher2, 750_000).is_ok());

        // Attacker tries to consume massive amounts
        assert!(limiter.consume_gas(attacker, 15_000_000).is_err()); // Should fail - over capacity
        assert!(limiter.consume_gas(attacker, 5_000_000).is_ok()); // Should succeed - within capacity

        // Attacker tries to consume more
        assert!(limiter.consume_gas(attacker, 6_000_000).is_err()); // Should fail - would exceed remaining

        // New block - refill
        limiter.refresh(1);

        // Everyone should get some gas back
        assert!(limiter.consume_gas(searcher1, 1_000_000).is_ok()); // Had 9.5M + 1M refill, now 9.5M
        assert!(limiter.consume_gas(searcher2, 1_000_000).is_ok()); // Had 9.25M + 1M refill, now 9.25M
        assert!(limiter.consume_gas(attacker, 1_000_000).is_ok()); // Had 5M + 1M refill, now 5M
    }

    #[test]
    fn test_bucket_cleanup() {
        // Test that unused buckets get cleaned up properly
        let limiter = AddressGasLimiter::new(1000, 1000, 10);

        let addr1 = Address::from([0x1; 20]);
        let addr2 = Address::from([0x2; 20]);

        // Create buckets for both
        assert!(limiter.consume_gas(addr1, 100).is_ok());
        assert!(limiter.consume_gas(addr2, 100).is_ok());

        assert_eq!(limiter.address_buckets.len(), 2);

        // Refill for several blocks - addr1 stays at full capacity (unused)
        // but addr2 continues to be used
        for block in 1..=10 {
            limiter.refresh(block);

            if block > 1 {
                // addr1 is now full and unused
                // addr2 continues to use gas
                assert!(limiter.consume_gas(addr2, 100).is_ok());
            }
        }

        // After cleanup at block 10 (multiple of cleanup_interval), addr1
        // should be removed because it's at full capacity (unused), while
        // addr2 remains.
        assert_eq!(
            limiter.address_buckets.len(),
            1,
            "Unused bucket (addr1) should have been cleaned up"
        );
        assert!(limiter.address_buckets.contains_key(&addr2));
        assert!(!limiter.address_buckets.contains_key(&addr1));
    }

    #[test]
    fn test_gas_limiters_separate_bundle_and_mempool_pools() {
        // Tight bundle limit, generous mempool limit.
        let args = GasLimiterArgs {
            bundle_max_gas_per_address: 500,
            bundle_refill_rate_per_block: 100,
            ..enabled_args(10_000_000, 1_000_000, 10)
        };
        let limiters = GasLimiters::from_args(&args).expect("limiter enabled");
        let addr = test_address();

        // Bundle pool: 500 capacity. Drain it.
        assert!(limiters.bundle.consume_gas(addr, 500).is_ok());
        assert!(limiters.bundle.consume_gas(addr, 1).is_err());

        // Mempool pool: 10M capacity, untouched by the bundle activity.
        assert!(limiters.mempool.consume_gas(addr, 5_000_000).is_ok());
        assert!(limiters.mempool.consume_gas(addr, 5_000_000).is_ok());
        assert!(limiters.mempool.consume_gas(addr, 1).is_err());

        // Refresh both pools at once.
        limiters.refresh(1);
        assert!(limiters.bundle.consume_gas(addr, 100).is_ok());
        assert!(limiters.bundle.consume_gas(addr, 1).is_err());
        assert!(limiters.mempool.consume_gas(addr, 1_000_000).is_ok());
    }

    #[test]
    fn test_gas_limiters_disabled() {
        let args = GasLimiterArgs::default(); // gas_limiter_enabled = false
        assert!(GasLimiters::from_args(&args).is_none());
    }
}
