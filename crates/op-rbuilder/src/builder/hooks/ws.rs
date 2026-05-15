use crate::{
    builder::{
        hooks::post_seal::{PostSealHook, SealedCandidate, SealedCtx},
        timing::compute_slot_offset_ms,
        wspub::WebSocketPublisher,
    },
    metrics::{OpRBuilderMetrics, record_flashblock_publish_timing},
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Publishes the flashblock payload to WebSocket subscribers, record metrics.
///
/// Suppressed when `SealedCtx::no_tx_pool` is true
pub(in crate::builder) struct WsHook {
    ws_pub: Arc<WebSocketPublisher>,
    metrics: Arc<OpRBuilderMetrics>,
}

impl std::fmt::Debug for WsHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsHook").finish_non_exhaustive()
    }
}

impl WsHook {
    pub(in crate::builder) fn new(
        ws_pub: Arc<WebSocketPublisher>,
        metrics: Arc<OpRBuilderMetrics>,
    ) -> Self {
        Self { ws_pub, metrics }
    }
}

impl PostSealHook for WsHook {
    fn on_sealed(&self, candidate: &SealedCandidate, ctx: &SealedCtx) {
        if ctx.no_tx_pool {
            return;
        }

        let byte_size = match self.ws_pub.publish(&candidate.fb_payload) {
            Ok(size) => size,
            Err(e) => {
                warn!(
                    target: "payload_builder",
                    error = %e,
                    flashblock_index = ctx.flashblock_index,
                    "Failed to publish flashblock via websocket"
                );
                return;
            }
        };

        let slot_offset_ms = compute_slot_offset_ms(ctx.slot_timestamp_secs, ctx.block_time);
        record_flashblock_publish_timing(candidate.fb_payload.index, slot_offset_ms);
        self.metrics
            .flashblock_byte_size_histogram
            .record(byte_size as f64);

        if ctx.enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                payload_id = %ctx.payload_id,
                block_number = ctx.block_number,
                flashblock_index = candidate.fb_payload.index,
                byte_size,
                total_txs = ctx.executed_tx_count,
                slot_offset_ms,
                stage = "fb_published"
            );
        }
    }
}
