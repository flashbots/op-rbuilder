use std::time::Duration;

use alloy_primitives::Address;

use crate::limiter::{args::ComputeLimiterArgs, bucket::AddressBuckets, error::ComputeLimitError};

type ComputeBuckets = AddressBuckets<Duration>;

#[derive(Debug, Clone)]
pub(super) struct ComputeLimiter {
    config: ComputeLimiterArgs,
    compute_buckets: ComputeBuckets,
}

impl ComputeLimiter {
    pub(super) fn try_new(config: ComputeLimiterArgs) -> Option<Self> {
        if !config.compute_limiter_enabled {
            return None;
        }

        Some(Self {
            config,
            compute_buckets: Default::default(),
        })
    }

    pub(super) fn consume_compute(
        &self,
        address: Address,
        time_requested: Duration,
    ) -> Result<(), ComputeLimitError> {
        self.compute_buckets
            .try_consume(
                address,
                time_requested,
                Duration::from_micros(self.config.max_time_us_per_address),
            )
            .map_err(|available| ComputeLimitError::AddressLimitExceeded {
                address,
                requested: time_requested,
                available,
            })?;

        Ok(())
    }

    fn refresh_inner(&self, block_number: u64) -> usize {
        let active_addresses = self.compute_buckets.len();

        self.compute_buckets
            .refill(Duration::from_micros(self.config.refill_rate_per_block));

        if block_number.is_multiple_of(self.config.cleanup_interval) {
            self.compute_buckets.discard_stale_buckets();
        }

        active_addresses - self.compute_buckets.len()
    }

    pub(super) fn refresh(&self, block_number: u64) {
        self.refresh_inner(block_number);
    }
}
