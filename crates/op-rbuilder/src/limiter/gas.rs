use std::time::Instant;

use alloy_primitives::Address;

use crate::limiter::{
    GasLimiterMetrics, args::GasLimiterArgs, bucket::AddressBuckets, error::GasLimitError,
};

type GasBuckets = AddressBuckets<u64>;

#[derive(Debug, Clone)]
pub(super) struct GasLimiter {
    config: GasLimiterArgs,
    // We don't need an Arc<Mutex<_>> here, we can get away with RefCell, but
    // the reth PayloadBuilder trait needs this to be Send + Sync
    gas_buckets: GasBuckets,
    metrics: GasLimiterMetrics,
}

impl GasLimiter {
    pub(super) fn try_new(config: GasLimiterArgs) -> Option<Self> {
        if !config.gas_limiter_enabled {
            return None;
        }

        Some(Self {
            config,
            gas_buckets: Default::default(),
            metrics: Default::default(),
        })
    }

    pub(super) fn consume_gas(
        &self,
        address: Address,
        gas_requested: u64,
    ) -> Result<(), GasLimitError> {
        let start = Instant::now();
        let result = self
            .gas_buckets
            .try_consume(address, gas_requested, self.config.max_gas_per_address)
            .map_err(|available| GasLimitError::AddressLimitExceeded {
                address,
                requested: gas_requested,
                available: available,
            });

        self.metrics.record_gas_check(&result, start.elapsed());

        result.map(|_| ())
    }

    fn refresh_inner(&self, block_number: u64) -> usize {
        let active_addresses = self.gas_buckets.len();

        self.gas_buckets.refill(self.config.refill_rate_per_block);

        // Only clean up stale buckets every `cleanup_interval` blocks
        if block_number.is_multiple_of(self.config.cleanup_interval) {
            self.gas_buckets.discard_stale_buckets();
        }

        active_addresses - self.gas_buckets.len()
    }

    pub(super) fn refresh(&self, block_number: u64) {
        let start = Instant::now();
        let removed_addresses = self.refresh_inner(block_number);

        self.metrics
            .record_refresh(removed_addresses, start.elapsed());
    }
}
