use std::{collections::HashMap, time::Duration};

use alloy_primitives::Address;

use crate::limiter::{
    args::ComputeLimiterArgs,
    bucket::{AddressBuckets, AddressBucketsOverlay, OverlayCheckpoint, TokenBucket},
    metrics::LimiterMetrics,
};

pub(super) type ComputeOverlayMap = HashMap<Address, TokenBucket<Duration>>;

/// Canonical compute-time limiter. Mirrors [`GasLimiter`] but tracks
/// [`Duration`] per address.
///
/// [`GasLimiter`]: super::gas::GasLimiter
#[derive(Debug, Clone)]
pub(super) struct ComputeLimiter {
    config: ComputeLimiterArgs,
    compute_buckets: AddressBuckets<Duration>,
    metrics: LimiterMetrics,
}

impl ComputeLimiter {
    pub(super) fn try_new(config: ComputeLimiterArgs, metrics: LimiterMetrics) -> Option<Self> {
        if !config.compute_limiter_enabled {
            return None;
        }
        Some(Self {
            config,
            compute_buckets: AddressBuckets::new(),
            metrics,
        })
    }

    pub(super) fn fork(&self) -> ComputeLimiterOverlay {
        ComputeLimiterOverlay {
            buckets_overlay: self.compute_buckets.fork(),
            default_capacity: Duration::from_micros(self.config.max_time_us_per_address),
        }
    }

    pub(super) fn refresh(&mut self, block_number: u64) {
        let do_cleanup = block_number.is_multiple_of(self.config.compute_cleanup_interval);
        self.compute_buckets.refresh(
            Duration::from_micros(self.config.compute_refill_rate_per_block),
            do_cleanup,
        );
        self.metrics
            .compute_limiter_active_address_count
            .set(self.compute_buckets.len() as f64);
    }

    pub(super) fn fold_overlay(&mut self, overlay_map: ComputeOverlayMap) {
        self.compute_buckets.fold_overlay(overlay_map);
        self.metrics
            .compute_limiter_active_address_count
            .set(self.compute_buckets.len() as f64);
    }
}

#[derive(Debug)]
pub(super) struct ComputeLimiterOverlay {
    buckets_overlay: AddressBucketsOverlay<Duration>,
    default_capacity: Duration,
}

impl ComputeLimiterOverlay {
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.buckets_overlay.is_debt_free(address)
    }

    pub(super) fn consume_compute(&self, address: Address, time_used: Duration) {
        self.buckets_overlay
            .consume(address, time_used, self.default_capacity);
    }

    pub(super) fn checkpoint(&self) -> OverlayCheckpoint<Duration> {
        self.buckets_overlay.checkpoint()
    }

    pub(super) fn restore(&self, cp: &OverlayCheckpoint<Duration>) {
        self.buckets_overlay.restore(cp);
    }

    pub(super) fn into_overlay_map(self) -> ComputeOverlayMap {
        self.buckets_overlay.into_overlay_map()
    }
}
