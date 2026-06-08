use crate::{
    builder::{
        hooks::post_seal::{PostSealHook, SealedCandidate, SlotMeta},
        timing::compute_slot_offset_ms,
        wspub::WebSocketPublisher,
    },
    metrics::{OpRBuilderMetrics, record_flashblock_publish_timing},
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Publishes the flashblock payload to WebSocket subscribers, record metrics.
///
/// Suppressed when `SlotMeta::no_tx_pool` is true.
pub(crate) struct WsHook {
    ws_pub: Arc<WebSocketPublisher>,
    metrics: Arc<OpRBuilderMetrics>,
    enable_tx_tracking_debug_logs: bool,
}

impl std::fmt::Debug for WsHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsHook").finish_non_exhaustive()
    }
}

impl WsHook {
    pub(crate) fn new(
        ws_pub: Arc<WebSocketPublisher>,
        metrics: Arc<OpRBuilderMetrics>,
        enable_tx_tracking_debug_logs: bool,
    ) -> Self {
        Self {
            ws_pub,
            metrics,
            enable_tx_tracking_debug_logs,
        }
    }
}

impl PostSealHook for WsHook {
    fn on_sealed(&self, candidate: &SealedCandidate, slot: &SlotMeta) {
        if slot.no_tx_pool {
            return;
        }

        let byte_size = match self.ws_pub.publish(&candidate.fb_payload) {
            Ok(size) => size,
            Err(e) => {
                warn!(
                    target: "payload_builder",
                    error = %e,
                    flashblock_index = candidate.fb_payload.index,
                    "Failed to publish flashblock via websocket"
                );
                return;
            }
        };

        let slot_offset_ms = compute_slot_offset_ms(slot.slot_timestamp_secs, slot.block_time);
        record_flashblock_publish_timing(candidate.fb_payload.index, slot_offset_ms);
        self.metrics
            .flashblock_byte_size_histogram
            .record(byte_size as f64);

        if self.enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                payload_id = %slot.payload_id,
                block_number = candidate.payload.block().header().number,
                flashblock_index = candidate.fb_payload.index,
                byte_size,
                total_txs = candidate.payload.block().body().transactions.len(),
                slot_offset_ms,
                stage = "fb_published"
            );
        }
    }
}
