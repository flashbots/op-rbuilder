use std::time::Duration;

use alloy_primitives::Address;

use crate::limiter::{
    args::{ComputeLimiterArgs, GasLimiterArgs},
    compute::ComputeLimiter,
    gas::GasLimiter,
    metrics::LimiterMetrics,
};

pub mod args;
mod bucket;
mod compute;
mod gas;
mod metrics;

#[derive(Debug, Clone)]
pub struct AddressLimiter {
    gas_limiter: Option<GasLimiter>,
    compute_limiter: Option<ComputeLimiter>,
    metrics: LimiterMetrics,
}

impl AddressLimiter {
    pub fn new(gas_config: GasLimiterArgs, compute_config: ComputeLimiterArgs) -> Self {
        Self {
            gas_limiter: GasLimiter::try_new(gas_config),
            compute_limiter: ComputeLimiter::try_new(compute_config),
            metrics: Default::default(),
        }
    }

    /// Returns `true` if the address is debt-free in all enabled limiters.
    /// Checks gas first, then compute. Increments the rejection counter for the
    /// first failing reason only.
    pub fn is_debt_free(&self, address: &Address) -> bool {
        if self
            .gas_limiter
            .as_ref()
            .is_some_and(|l| !l.is_debt_free(address))
        {
            self.metrics.gas_limiter_rejections.increment(1);
            return false;
        }

        if self
            .compute_limiter
            .as_ref()
            .is_some_and(|l| !l.is_debt_free(address))
        {
            self.metrics.compute_limiter_rejections.increment(1);
            return false;
        }

        true
    }

    /// Record gas consumed by an address. The bucket may go negative (into debt).
    pub fn consume_gas(&self, address: Address, gas_used: u64) {
        if let Some(inner) = &self.gas_limiter {
            inner.consume_gas(address, gas_used);
        }
    }

    /// Record compute time consumed by an address. The bucket may go negative (into debt).
    pub fn consume_compute(&self, address: Address, time_used: Duration) {
        if let Some(inner) = &self.compute_limiter {
            inner.consume_compute(address, time_used);
        }
    }

    /// Should be called upon each new block. Refills buckets/Garbage collection
    pub fn refresh(&self, block_number: u64) {
        if let Some(inner) = self.gas_limiter.as_ref() {
            inner.refresh(block_number)
        }
        if let Some(inner) = self.compute_limiter.as_ref() {
            inner.refresh(block_number)
        }
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

    #[test]
    fn test_basic_debt_and_refill() {
        let config = create_test_config(1000, 200, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        // Consume all gas
        limiter.consume_gas(test_address(), 1000);
        assert!(
            limiter.is_debt_free(&test_address()),
            "no debt yet, just empty"
        );

        // Go into debt
        limiter.consume_gas(test_address(), 1);
        assert!(!limiter.is_debt_free(&test_address()), "should be in debt");

        // Refill 200 — pays down 1 debt, 199 goes to available
        limiter.refresh(1);
        assert!(
            limiter.is_debt_free(&test_address()),
            "debt should be paid off"
        );
    }

    #[test]
    fn test_over_capacity_goes_into_debt() {
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        // Consume more than capacity — goes into debt
        limiter.consume_gas(test_address(), 1500);
        assert!(!limiter.is_debt_free(&test_address()));

        // Refill 100 per block, need 5 blocks to clear 500 debt
        for i in 1..=4 {
            limiter.refresh(i);
            assert!(
                !limiter.is_debt_free(&test_address()),
                "still in debt at block {i}"
            );
        }
        limiter.refresh(5);
        assert!(
            limiter.is_debt_free(&test_address()),
            "debt cleared at block 5"
        );
    }

    #[test]
    fn test_multiple_users_independent() {
        let config = create_test_config(10_000_000, 1_000_000, 100);
        let limiter = AddressLimiter::new(config, ComputeLimiterArgs::default());

        let searcher = Address::from([0x1; 20]);
        let attacker = Address::from([0x3; 20]);

        // Attacker goes deep into debt
        limiter.consume_gas(attacker, 15_000_000);
        assert!(!limiter.is_debt_free(&attacker));

        // Searcher is unaffected
        assert!(limiter.is_debt_free(&searcher));
        limiter.consume_gas(searcher, 500_000);
        assert!(limiter.is_debt_free(&searcher));
    }
}
