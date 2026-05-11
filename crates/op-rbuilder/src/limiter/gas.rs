use alloy_primitives::Address;

use crate::limiter::{args::GasLimiterArgs, bucket::AddressBuckets, metrics::LimiterMetrics};

type GasBuckets = AddressBuckets<u64>;

#[derive(Debug, Clone)]
pub(super) struct GasLimiter {
    config: GasLimiterArgs,
    gas_buckets: GasBuckets,
    metrics: LimiterMetrics,
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

    /// Returns `true` if the address has no debt and can submit txs.
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.gas_buckets.is_debt_free(address)
    }

    /// Record gas consumed by an address. Always succeeds — excess is
    /// tracked as debt.
    pub(super) fn consume_gas(&self, address: Address, gas_used: u64) {
        let created_new =
            self.gas_buckets
                .consume(address, gas_used, self.config.max_gas_per_address);

        if created_new {
            self.metrics.gas_limiter_active_address_count.increment(1);
        }
    }

    pub(super) fn refresh(&self, block_number: u64) {
        let active_before = self.gas_buckets.len();

        self.gas_buckets.refill(self.config.refill_rate_per_block);

        if block_number.is_multiple_of(self.config.cleanup_interval) {
            self.gas_buckets.discard_stale_buckets();
        }

        let removed = active_before - self.gas_buckets.len();
        self.metrics
            .gas_limiter_active_address_count
            .decrement(removed as f64);
    }
}
