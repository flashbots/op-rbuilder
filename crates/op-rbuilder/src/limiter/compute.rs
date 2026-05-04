use std::time::Duration;

use alloy_primitives::Address;

use crate::limiter::{args::ComputeLimiterArgs, bucket::AddressBuckets, metrics::LimiterMetrics};

type ComputeBuckets = AddressBuckets<Duration>;

#[derive(Debug, Clone)]
pub(super) struct ComputeLimiter {
    config: ComputeLimiterArgs,
    compute_buckets: ComputeBuckets,
    metrics: LimiterMetrics,
}

impl ComputeLimiter {
    pub(super) fn try_new(config: ComputeLimiterArgs) -> Option<Self> {
        if !config.compute_limiter_enabled {
            return None;
        }

        Some(Self {
            config,
            compute_buckets: Default::default(),
            metrics: Default::default(),
        })
    }

    /// Returns `true` if the address has no debt and can submit work.
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.compute_buckets.is_debt_free(address)
    }

    /// Record compute time consumed by an address. Always succeeds — excess
    /// is tracked as debt.
    pub(super) fn consume_compute(&self, address: Address, time_used: Duration) {
        let created_new = self.compute_buckets.consume(
            address,
            time_used,
            Duration::from_micros(self.config.max_time_us_per_address),
        );

        if created_new {
            self.metrics
                .compute_limiter_active_address_count
                .increment(1);
        }
    }

    pub(super) fn refresh(&self, block_number: u64) {
        let active_before = self.compute_buckets.len();

        self.compute_buckets.refill(Duration::from_micros(
            self.config.compute_refill_rate_per_block,
        ));

        if block_number.is_multiple_of(self.config.compute_cleanup_interval) {
            self.compute_buckets.discard_stale_buckets();
        }

        let removed = active_before - self.compute_buckets.len();
        self.metrics
            .compute_limiter_active_address_count
            .decrement(removed as f64);
    }
}
