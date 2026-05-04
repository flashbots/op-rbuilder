use metrics::{Counter, Gauge};
use reth_metrics::Metrics;

#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder")]
pub(super) struct LimiterMetrics {
    /// Number of addresses with active gas budgets
    pub gas_limiter_active_address_count: Gauge,

    /// Number of addresses with active compute budgets
    pub compute_limiter_active_address_count: Gauge,

    /// Transactions rejected due to gas debt
    pub gas_limiter_rejections: Counter,

    /// Transactions rejected due to compute debt
    pub compute_limiter_rejections: Counter,
}
