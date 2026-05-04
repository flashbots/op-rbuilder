use std::{sync::Arc, time::Instant};

use alloy_primitives::Address;
use dashmap::DashMap;

use crate::limiter::{
    GasLimiterMetrics, args::GasLimiterArgs, bucket::TokenBucket, error::GasLimitError,
};

#[derive(Debug, Clone)]
pub(super) struct GasLimiter {
    config: GasLimiterArgs,
    // We don't need an Arc<Mutex<_>> here, we can get away with RefCell, but
    // the reth PayloadBuilder trait needs this to be Send + Sync
    address_buckets: Arc<DashMap<Address, TokenBucket>>,
    metrics: GasLimiterMetrics,
}

impl GasLimiter {
    pub(super) fn try_new(config: GasLimiterArgs) -> Option<Self> {
        if !config.gas_limiter_enabled {
            return None;
        }

        Some(Self {
            config,
            address_buckets: Default::default(),
            metrics: Default::default(),
        })
    }

    fn consume_gas_inner(
        &self,
        address: Address,
        gas_requested: u64,
    ) -> Result<bool, GasLimitError> {
        let mut created_new_bucket = false;
        let mut bucket = self
            .address_buckets
            .entry(address)
            // if we don't find a bucket we need to initialize a new one
            .or_insert_with(|| {
                created_new_bucket = true;
                TokenBucket::new(self.config.max_gas_per_address)
            });

        if !bucket.try_consume(gas_requested) {
            return Err(GasLimitError::AddressLimitExceeded {
                address,
                requested: gas_requested,
                available: bucket.available(),
            });
        }

        Ok(created_new_bucket)
    }

    pub(super) fn consume_gas(
        &self,
        address: Address,
        gas_requested: u64,
    ) -> Result<(), GasLimitError> {
        let start = Instant::now();
        let result = self.consume_gas_inner(address, gas_requested);

        self.metrics.record_gas_check(&result, start.elapsed());

        result.map(|_| ())
    }

    fn refresh_inner(&self, block_number: u64) -> usize {
        let active_addresses = self.address_buckets.len();

        self.address_buckets.iter_mut().for_each(|mut bucket| {
            bucket.refill(self.config.refill_rate_per_block);
        });

        // Only clean up stale buckets every `cleanup_interval` blocks
        if block_number.is_multiple_of(self.config.cleanup_interval) {
            self.address_buckets.retain(|_, bucket| !bucket.is_full());
        }

        active_addresses - self.address_buckets.len()
    }

    pub(super) fn refresh(&self, block_number: u64) {
        let start = Instant::now();
        let removed_addresses = self.refresh_inner(block_number);

        self.metrics
            .record_refresh(removed_addresses, start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_cleanup() {
        // Test that unused buckets get cleaned up properly
        let config = GasLimiterArgs {
            gas_limiter_enabled: true,
            max_gas_per_address: 1000,
            refill_rate_per_block: 1000,
            cleanup_interval: 10,
        };
        let limiter = GasLimiter::try_new(config).unwrap();

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
                // addr1 is now full and unusedlimiter
                // addr2 continues to use gas
                assert!(limiter.consume_gas(addr2, 100).is_ok());
            }
        }

        // After cleanup at block 10 (multiple of 5), addr1 should be removed
        // because it's at full capacity (unused), while addr2 remains
        assert_eq!(
            limiter.address_buckets.len(),
            1,
            "Unused bucket (addr1) should have been cleaned up"
        );
        assert!(limiter.address_buckets.contains_key(&addr2));
        assert!(!limiter.address_buckets.contains_key(&addr1));
    }
}
