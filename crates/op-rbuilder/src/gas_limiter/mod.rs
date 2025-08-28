use std::{sync::Arc, time::Instant};

use alloy_primitives::Address;
use dashmap::DashMap;

use crate::gas_limiter::{args::GasLimiterArgs, error::GasLimitError, metrics::GasLimiterMetrics};

pub mod args;
pub mod error;
mod metrics;

#[derive(Debug, Clone)]
pub struct AddressGasLimiter {
    config: GasLimiterArgs,
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
    pub fn try_new(config: GasLimiterArgs) -> Option<Self> {
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

    /// Check if there's enough gas for this address and consume it. Returns
    /// Ok(()) if there's enough otherwise returns an error.
    pub fn consume_gas(&self, address: Address, gas_requested: u64) -> Result<(), GasLimitError> {
        let start = Instant::now();
        let result = self.consume_gas_inner(address, gas_requested);

        self.metrics.record_gas_check(&result, start.elapsed());

        result.map(|_| ())
    }

    /// Should be called upon each new block. Refills buckets/Garbage collection
    fn refresh_inner(&self) -> usize {
        let active_addresses = self.address_buckets.len();

        self.address_buckets.iter_mut().for_each(|mut bucket| {
            bucket.available += self.config.refill_rate_per_block;
        });
        self.address_buckets
            .retain(|_, bucket| bucket.available <= bucket.capacity);

        active_addresses - self.address_buckets.len()
    }

    pub fn refresh(&self) {
        let start = Instant::now();
        let removed_addresses = self.refresh_inner();

        self.metrics
            .record_refresh(removed_addresses, start.elapsed());
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
