use metrics::{Counter, Gauge, Histogram, counter};
use reth_metrics::Metrics;

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.pool")]
pub(super) struct PoolMetrics {
    /// Histogram of bundle pre-simulation duration
    pub presim_duration: Histogram,
    /// Number of updates to the tip state for the top of block simulator
    pub presim_tip_state_updates: Counter,
    /// Number of pending txs evicted due to failing top of block simulation
    pub presim_pending_evictions: Counter,
    /// Number of presim tasks waiting for a concurrency permit.
    pub presim_waiting: Gauge,
    /// Number of presim tasks currently executing.
    pub presim_in_flight: Gauge,
    /// Histogram of time spent waiting for a presim concurrency permit.
    pub presim_wait_duration: Histogram,
    /// Configured maximum number of concurrent presim tasks.
    pub presim_concurrency_limit: Gauge,
}

pub(super) fn increment_presim_count(sim_result: &eyre::Result<bool>) {
    let label = match sim_result {
        Ok(true) => "passed",
        Ok(false) => "reverted",
        Err(_) => "failed",
    };
    counter!("op_rbuilder.pool.presim_count", "result" => label).increment(1);
}
