use crate::{
    builder::hooks::post_seal::{PostSealHook, SealedCandidate, SealedCtx},
    metrics::OpRBuilderMetrics,
};
use std::sync::Arc;

/// Records per-flashblock metrics that aren't tied to publication:
/// build duration and transaction-count histogram.
#[derive(Debug)]
pub(in crate::builder) struct MetricsHook {
    metrics: Arc<OpRBuilderMetrics>,
}

impl MetricsHook {
    pub(in crate::builder) fn new(metrics: Arc<OpRBuilderMetrics>) -> Self {
        Self { metrics }
    }
}

impl PostSealHook for MetricsHook {
    fn on_sealed(&self, _candidate: &SealedCandidate, ctx: &SealedCtx) {
        if let Some(duration) = ctx.flashblock_build_duration {
            self.metrics.flashblock_build_duration.record(duration);
        }
        self.metrics
            .flashblock_num_tx_histogram
            .record(ctx.executed_tx_count as f64);
    }
}
