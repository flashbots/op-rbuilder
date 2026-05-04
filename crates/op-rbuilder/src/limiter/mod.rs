use alloy_primitives::Address;

use crate::limiter::{
    args::GasLimiterArgs, error::GasLimitError, gas::GasLimiter, metrics::GasLimiterMetrics,
};

pub mod args;
mod bucket;
pub mod error;
mod gas;
mod metrics;

#[derive(Debug, Clone)]
pub struct AddressLimiter {
    gas_limiter: Option<GasLimiter>,
}

impl AddressLimiter {
    pub fn new(config: GasLimiterArgs) -> Self {
        Self {
            gas_limiter: GasLimiter::try_new(config),
        }
    }

    /// Check if there's enough gas for this address and consume it. Returns
    /// Ok(()) if there's enough otherwise returns an error.
    pub fn consume_gas(&self, address: Address, gas_requested: u64) -> Result<(), GasLimitError> {
        if let Some(inner) = &self.gas_limiter {
            inner.consume_gas(address, gas_requested)
        } else {
            Ok(())
        }
    }

    /// Should be called upon each new block. Refills buckets/Garbage collection
    pub fn refresh(&self, block_number: u64) {
        if let Some(inner) = self.gas_limiter.as_ref() {
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
    fn test_basic_refill() {
        let config = create_test_config(1000, 200, 10);
        let limiter = AddressLimiter::new(config);

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
        let config = create_test_config(1000, 100, 10);
        let limiter = AddressLimiter::new(config);

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
        let config = create_test_config(10_000_000, 1_000_000, 100); // 10M max, 1M refill
        let limiter = AddressLimiter::new(config);

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
}
