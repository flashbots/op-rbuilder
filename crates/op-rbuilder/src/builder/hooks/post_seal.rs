use core::time::Duration;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_optimism_node::OpBuiltPayload;
use reth_payload_builder::PayloadId;

/// A flashblock candidate that has been sealed and is ready for publication
/// and downstream propagation.
///
/// `payload` is the full built payload for engine/p2p delivery; `fb_payload`
/// is the slim, serialisable view streamed to flashblocks subscribers.
#[derive(Debug, Clone)]
pub(in crate::builder) struct SealedCandidate {
    pub payload: OpBuiltPayload,
    pub fb_payload: OpFlashblockPayload,
}

/// Context describing the slot a sealed candidate belongs to.
///
/// The fields are intentionally limited to data downstream hooks need.
#[derive(Debug, Clone)]
pub(in crate::builder) struct SealedCtx {
    pub payload_id: PayloadId,
    pub block_number: u64,
    pub flashblock_index: u64,
    /// True when the FCU specified `no_tx_pool`.
    pub no_tx_pool: bool,
    pub executed_tx_count: usize,
    /// Slot start timestamp from the payload attributes.
    pub slot_timestamp_secs: u64,
    pub block_time: Duration,
    /// Wall-clock time spent building this flashblock.
    /// `None` for the fallback candidate.
    pub flashblock_build_duration: Option<Duration>,
    pub enable_tx_tracking_debug_logs: bool,
}

/// Hook invoked after a flashblock or fallback candidate has been sealed.
///
/// Implementations should be cheap and non-blocking: dispatch happens on the
/// builder's hot path. Errors are intentionally swallowed at the dispatch site;
/// hooks that want to surface failures should do so via metrics or logs.
pub(in crate::builder) trait PostSealHook:
    Send + Sync + std::fmt::Debug
{
    fn on_sealed(&self, candidate: &SealedCandidate, ctx: &SealedCtx);
}
