use std::collections::HashMap;

use alloy_primitives::Address;

use crate::limiter::{
    args::GasLimiterArgs,
    bucket::{AddressBuckets, AddressBucketsOverlay, OverlayCheckpoint, TokenBucket},
    metrics::LimiterMetrics,
};

pub(super) type GasOverlayMap = HashMap<Address, TokenBucket<u64>>;

/// Canonical gas limiter. Holds the persistent per-address bucket state;
/// mutates only on [`GasLimiter::refresh`] and [`GasLimiter::fold_overlay`].
#[derive(Debug, Clone)]
pub(super) struct GasLimiter {
    config: GasLimiterArgs,
    gas_buckets: AddressBuckets<u64>,
    metrics: LimiterMetrics,
}

impl GasLimiter {
    pub(super) fn try_new(config: GasLimiterArgs, metrics: LimiterMetrics) -> Option<Self> {
        if !config.gas_limiter_enabled {
            return None;
        }
        Some(Self {
            config,
            gas_buckets: AddressBuckets::new(),
            metrics,
        })
    }

    /// Fork a per-build overlay sharing the current canonical state. O(1).
    pub(super) fn fork(&self) -> GasLimiterOverlay {
        GasLimiterOverlay {
            buckets_overlay: self.gas_buckets.fork(),
            default_capacity: self.config.max_gas_per_address,
        }
    }

    /// Per-block refill (and periodic cleanup of full buckets).
    pub(super) fn refresh(&mut self, block_number: u64) {
        let do_cleanup = block_number.is_multiple_of(self.config.cleanup_interval);
        self.gas_buckets
            .refresh(self.config.refill_rate_per_block, do_cleanup);
        self.metrics
            .gas_limiter_active_address_count
            .set(self.gas_buckets.len() as f64);
    }

    /// Apply an overlay's accumulated deltas back into the canonical.
    pub(super) fn fold_overlay(&mut self, overlay_map: GasOverlayMap) {
        self.gas_buckets.fold_overlay(overlay_map);
        self.metrics
            .gas_limiter_active_address_count
            .set(self.gas_buckets.len() as f64);
    }
}

/// In-flight overlay. Reads/consumes go through here with `&self`; on
/// commit the accumulated deltas are folded back into the canonical.
#[derive(Debug)]
pub(super) struct GasLimiterOverlay {
    buckets_overlay: AddressBucketsOverlay<u64>,
    default_capacity: u64,
}

impl GasLimiterOverlay {
    pub(super) fn is_debt_free(&self, address: &Address) -> bool {
        self.buckets_overlay.is_debt_free(address)
    }

    pub(super) fn consume_gas(&self, address: Address, gas_used: u64) {
        self.buckets_overlay
            .consume(address, gas_used, self.default_capacity);
    }

    pub(super) fn checkpoint(&self) -> OverlayCheckpoint<u64> {
        self.buckets_overlay.checkpoint()
    }

    pub(super) fn restore(&self, cp: &OverlayCheckpoint<u64>) {
        self.buckets_overlay.restore(cp);
    }

    pub(super) fn into_overlay_map(self) -> GasOverlayMap {
        self.buckets_overlay.into_overlay_map()
    }
}
