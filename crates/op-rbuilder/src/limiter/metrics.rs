use std::time::Duration;

use metrics::{Counter, Gauge, Histogram};
use reth_metrics::Metrics;

use crate::limiter::error::{ComputeLimitError, GasLimitError};

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.gas_limiter")]
pub(super) struct GasLimiterMetrics {
    /// Transactions rejected by gas limits Labeled by reason: "per_address",
    /// "global", "burst"
    pub rejections: Counter,

    /// Time spent in rate limiting logic
    pub check_time: Histogram,

    /// Number of addresses with active budgets
    pub active_address_count: Gauge,

    /// Time to refill buckets
    pub refresh_duration: Histogram,
}

impl GasLimiterMetrics {
    pub(super) fn record_gas_check(
        &self,
        check_result: &Result<bool, GasLimitError>,
        duration: Duration,
    ) {
        if let Ok(created_new_bucket) = check_result {
            if *created_new_bucket {
                self.active_address_count.increment(1);
            }
        } else {
            self.rejections.increment(1);
        }

        self.check_time.record(duration);
    }

    pub(super) fn record_refresh(&self, removed_addresses: usize, duration: Duration) {
        self.active_address_count
            .decrement(removed_addresses as f64);
        self.refresh_duration.record(duration);
    }
}

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.compute_limiter")]
pub(super) struct ComputeLimiterMetrics {
    /// Transactions rejected by compute limits
    pub rejections: Counter,

    /// Number of addresses with active budgets
    pub active_address_count: Gauge,
}

impl ComputeLimiterMetrics {
    pub(super) fn record_compute_check(
        &self,
        check_result: &Result<bool, ComputeLimitError>,
    ) {
        if let Ok(created_new_bucket) = check_result {
            if *created_new_bucket {
                self.active_address_count.increment(1);
            }
        } else {
            self.rejections.increment(1);
        }
    }

    pub(super) fn record_refresh(&self, removed_addresses: usize) {
        self.active_address_count
            .decrement(removed_addresses as f64);
    }
}
