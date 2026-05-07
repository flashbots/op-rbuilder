use super::shared_best::SharedBest;
use crate::{
    builder::{
        best_txs::FlashblockTxTracker, cancellation::PayloadJobCancellation,
        context::OpPayloadJobCtx, payload::FlashblocksState,
    },
    gas_limiter::GasLimiterSnapshot,
    primitives::reth::ExecutionInfo,
};
use alloy_primitives::U256;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_node_api::PayloadBuilderError;
use reth_optimism_node::OpBuiltPayload;
use reth_revm::db::{CacheState, TransitionState};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};

pub(crate) struct BuildState {
    pub(crate) ctx: OpPayloadJobCtx,
    pub(crate) info: ExecutionInfo,
    pub(crate) cache: CacheState,
    pub(crate) transition: Option<TransitionState>,
    pub(crate) tx_tracker: FlashblockTxTracker,
    pub(crate) fb_state: FlashblocksState,
}

/// References borrowed by the continuous build job for the duration of a single
/// payload.
pub(crate) struct JobDeps<'a> {
    pub(crate) span: &'a tracing::Span,
    pub(crate) best_payload_tx: &'a watch::Sender<Option<OpBuiltPayload>>,
    pub(crate) payload_cancel: &'a PayloadJobCancellation,
}

/// Result of a continuous candidate loop within a single flashblock interval.
/// Contains the best sealed candidate and statistics.
pub(super) struct CandidateLoopResult {
    pub(super) best: Option<BestCandidate>,
    pub(super) candidates_evaluated: u64,
    pub(super) candidates_improved: u64,
}

/// Output from a continuous build candidate loop.
/// Each iteration clones state, executes txs, seals, and keeps the best candidate.
/// When fb_cancel fires, the pre-sealed candidate is ready for instant publish.
pub(super) struct BuildOutput {
    pub(super) base_state: BuildState,
    pub(super) candidate_result: CandidateLoopResult,
}

pub(super) type BuildReceiver = oneshot::Receiver<Result<BuildOutput, PayloadBuilderError>>;

/// Best sealed candidate found so far within a flashblock interval.
/// Groups all the state that must be updated in lockstep when a new best is found.
#[derive(Clone)]
pub(super) struct BestCandidate {
    /// The flashblock state + sealed payload + flashblock delta for next flashblock
    pub(super) result: (FlashblocksState, OpBuiltPayload, OpFlashblockPayload),
    /// Total priority fees accumulated by this candidate (comparison key).
    pub(super) total_fees: U256,
    /// EVM cache.
    pub(super) cache: CacheState,
    /// EVM transition.
    pub(super) transition: Option<TransitionState>,
    /// EVM execution info.
    pub(super) info: ExecutionInfo,
    /// Flashblock state.
    pub(super) fb_state: FlashblocksState,
    /// Committed txs from the winning build.
    pub(super) tx_tracker: FlashblockTxTracker,
    /// Gas limiter snapshot.
    pub(super) gas_limiter_snapshot: GasLimiterSnapshot,
    /// Wall time spent building this single candidate.
    pub(super) build_duration: Duration,
    /// Number of candidates evaluated when this candidate became best.
    pub(super) candidates_evaluated: u64,
    /// Number of times the interval best improved including this candidate.
    pub(super) candidates_improved: u64,
}

/// Per-flashblock-interval state owned by the main loop. Replaced as a unit
/// when advancing to the next interval; in particular `candidate_slot` is a
/// fresh `Arc<Mutex<_>>` per interval so a cancelled-but-not-yet-stopped
/// build task cannot overwrite the new task's slot.
pub(super) struct FlashblockInterval {
    pub(super) fb_span: tracing::Span,
    pub(super) build_rx: BuildReceiver,
    pub(super) candidate_slot: SharedBest,
    pub(super) build_start: Instant,
    pub(super) base_ctx: OpPayloadJobCtx,
    pub(super) base_fb_state: FlashblocksState,
    pub(super) base_info: ExecutionInfo,
}
