use core::time::Duration;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_optimism_node::OpBuiltPayload;
use reth_payload_builder::PayloadId;

/// A flashblock candidate that has been sealed and is ready for publication
/// and downstream propagation.
///
/// `payload` is the full built payload for engine/p2p delivery; `fb_payload`
/// is the slim, serialisable view streamed to flashblocks subscribers.
/// `build_duration` is the wall-clock time spent building this flashblock,
/// or `None` for the fallback candidate (no incremental build step).
#[derive(Debug, Clone)]
pub(crate) struct SealedCandidate {
    pub payload: OpBuiltPayload,
    pub fb_payload: OpFlashblockPayload,
    pub build_duration: Option<Duration>,
}

/// Slot-level metadata for a given building slot.
#[derive(Debug, Clone)]
pub(crate) struct SlotMeta {
    pub payload_id: PayloadId,
    /// True when the FCU specified `no_tx_pool`.
    pub no_tx_pool: bool,
    /// Slot start timestamp from the payload attributes.
    pub slot_timestamp_secs: u64,
    pub block_time: Duration,
}

/// Hook invoked after a flashblock or fallback candidate has been sealed.
///
/// Implementations should be cheap and non-blocking: dispatch happens on the
/// builder's hot path. Errors are intentionally swallowed at the dispatch site;
/// hooks that want to surface failures should do so via metrics or logs.
pub(crate) trait PostSealHook: Send + Sync + std::fmt::Debug {
    fn on_sealed(&self, candidate: &SealedCandidate, slot: &SlotMeta);
}
