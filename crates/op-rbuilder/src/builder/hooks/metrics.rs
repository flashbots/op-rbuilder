use crate::{
    builder::hooks::post_seal::{PostSealHook, SealedCandidate, SlotMeta},
    metrics::OpRBuilderMetrics,
};
use std::sync::Arc;

/// Records per-flashblock metrics that aren't tied to publication:
/// build duration and transaction-count histogram.
#[derive(Debug)]
pub(crate) struct MetricsHook {
    metrics: Arc<OpRBuilderMetrics>,
}

impl MetricsHook {
    pub(crate) fn new(metrics: Arc<OpRBuilderMetrics>) -> Self {
        Self { metrics }
    }
}

impl PostSealHook for MetricsHook {
    fn on_sealed(&self, candidate: &SealedCandidate, _slot: &SlotMeta) {
        if let Some(duration) = candidate.build_duration {
            self.metrics.flashblock_build_duration.record(duration);
        }
        self.metrics
            .flashblock_num_tx_histogram
            .record(candidate.payload.block().body().transactions.len() as f64);
    }
}
