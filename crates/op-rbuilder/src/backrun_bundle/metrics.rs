use metrics::{Counter, Gauge, Histogram};
use reth_metrics::Metrics;

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.backrun_pool")]
pub(super) struct BackrunPoolMetrics {
    /// Current number of bundles in the backrun pool
    pub backrun_bundle_count: Gauge,
    /// Total bundles added to the pool
    pub backrun_bundles_added: Counter,
    /// Total bundles removed from the pool (expiry and replacement)
    pub backrun_bundles_removed: Counter,
    /// Number of backruns per transaction (recorded during pool cleanup)
    pub backruns_per_tx: Histogram,
}
