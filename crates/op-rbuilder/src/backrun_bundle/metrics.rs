use metrics::{Gauge, Histogram};
use reth_metrics::Metrics;

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.backrun_pool")]
pub(super) struct BackrunPoolMetrics {
    /// Current number of bundles in the backrun pool
    pub bundle_count: Gauge,
    /// Number of backruns per target transaction (recorded during pool cleanup)
    pub backruns_per_tx: Histogram,
}
