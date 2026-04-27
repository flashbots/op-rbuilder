use crate::{
    builder::{
        best_txs::{FlashblockPoolTxCursor, FlashblockTxCache},
        builder_tx::{BuilderTransactions, reserve_builder_tx_budget},
        cancellation::PayloadJobCancellation,
        context::OpPayloadBuilderCtx,
        payload::{FlashblocksState, OpPayloadBuilder, build_block},
    },
    gas_limiter::GasLimiterSnapshot,
    primitives::reth::ExecutionInfo,
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::{B256, U256};
use eyre::WrapErr as _;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_node_api::PayloadBuilderError;
use reth_optimism_node::OpBuiltPayload;
use reth_payload_util::BestPayloadTransactions;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::{
    State,
    database::StateProviderDatabase,
    db::{CacheState, TransitionState},
};
use revm::Database;
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, metadata::Level, span, warn};

struct ContinuousBuildState<Cache, Transition> {
    ctx: OpPayloadBuilderCtx,
    info: ExecutionInfo,
    cache: Cache,
    transition: Transition,
    tx_cache: FlashblockTxCache,
    fb_state: FlashblocksState,
}

/// Result of a continuous candidate loop within a single flashblock interval.
/// Contains the best sealed candidate and statistics.
struct CandidateLoopResult {
    best: Option<BestCandidate>,
    candidates_evaluated: u64,
    candidates_improved: u64,
}

/// Output from a continuous build candidate loop.
/// Each iteration clones state, executes txs, seals, and keeps the best candidate.
/// When fb_cancel fires, the pre-sealed candidate is ready for instant publish.
struct ContinuousBuildOutput<Cache, Transition> {
    state: ContinuousBuildState<Cache, Transition>,
    candidate_result: CandidateLoopResult,
}

type BuildReceiver = oneshot::Receiver<
    Result<ContinuousBuildOutput<CacheState, Option<TransitionState>>, PayloadBuilderError>,
>;

/// Slot that holds the latest sealed candidate from the build task.
/// Task writes on each improvement; main loop takes on trigger to publish
/// without awaiting task completion.
type SharedBest = Arc<std::sync::Mutex<Option<BestCandidate>>>;

/// Returned by `publish_and_spawn_next` to tell the caller whether to continue or exit.
enum FlashblockAction {
    /// Published successfully: continue with updated loop state
    Continue {
        fb_span: tracing::Span,
        build_rx: BuildReceiver,
        shared_best: SharedBest,
        build_start: Instant,
    },
    /// Cancelled or no candidate: caller should return Ok(())
    Exit,
}

/// Best sealed candidate found so far within a flashblock interval.
/// Groups all the state that must be updated in lockstep when a new best is found.
#[derive(Clone)]
struct BestCandidate {
    /// The flashblock state + sealed payload + flashblock delta for next flashblock
    result: (FlashblocksState, OpBuiltPayload, OpFlashblockPayload),
    /// Total priority fees accumulated by this candidate (comparison key).
    total_fees: U256,
    /// EVM cache.
    cache: CacheState,
    /// EVM transition.
    transition: Option<TransitionState>,
    /// EVM execution info.
    info: ExecutionInfo,
    /// Flashblock state.
    fb_state: FlashblocksState,
    /// Committed txs from the winning build.
    tx_cache: FlashblockTxCache,
    /// Gas limiter snapshot.
    gas_limiter_snapshot: GasLimiterSnapshot,
    /// When this candidate was sealed (for staleness metric).
    sealed_at: Instant,
    /// Wall time spent building this single candidate.
    build_duration: Duration,
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn run_continuous_flashblocks(
        &self,
        span: &tracing::Span,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        payload_cancel: &PayloadJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
        mut rx: mpsc::Receiver<CancellationToken>,
        ctx: OpPayloadBuilderCtx,
        info: ExecutionInfo,
        cache: CacheState,
        transition: Option<TransitionState>,
        tx_cache: FlashblockTxCache,
        fb_state: FlashblocksState,
    ) -> Result<(), PayloadBuilderError> {
        let state = ContinuousBuildState {
            ctx,
            info,
            cache,
            transition,
            tx_cache,
            fb_state,
        };

        info!(
            target: "payload_builder",
            "Continuous build mode enabled"
        );

        let mut fb_span = if span.is_none() {
            tracing::Span::none()
        } else {
            span!(
                parent: span,
                Level::INFO,
                "build_flashblock",
                flashblock_index = state.fb_state.flashblock_index(),
                block_number = state.ctx.block_number(),
                tx_count = tracing::field::Empty,
                gas_used = tracing::field::Empty,
                candidates_evaluated = tracing::field::Empty,
                candidates_improved = tracing::field::Empty,
                staleness_ms = tracing::field::Empty,
            )
        };

        let mut shared_best: SharedBest = Arc::new(std::sync::Mutex::new(None));
        let mut build_rx = self.spawn_continuous_build_task(
            parent_hash,
            payload_cancel,
            state,
            fb_span.clone(),
            shared_best.clone(),
        );
        let mut build_start = Instant::now();

        loop {
            tokio::select! {
                biased;
                _ = payload_cancel.cancelled() => {
                    Self::record_cancellation_reason(self.metrics(), payload_cancel, span);
                    return Ok(());
                }
                trigger = rx.recv() => match trigger {
                    Some(new_fb_cancel) => {
                        // Fast path: take latest best from shared slot without
                        // awaiting the task. Publish happens immediately; the
                        // old task will drop its work on cancel.
                        let pretaken = shared_best.lock().unwrap().take();
                        match self.publish_and_spawn_next(
                            build_rx, pretaken, new_fb_cancel, fb_span, build_start,
                            span, best_payload_tx, payload_cancel,
                            target_flashblocks, parent_hash,
                        ).await? {
                            FlashblockAction::Continue {
                                fb_span: new_fb_span,
                                build_rx: new_build_rx,
                                shared_best: new_shared_best,
                                build_start: new_build_start,
                            } => {
                                fb_span = new_fb_span;
                                build_rx = new_build_rx;
                                shared_best = new_shared_best;
                                build_start = new_build_start;
                            }
                            FlashblockAction::Exit => return Ok(()),
                        }
                    }
                    None => {
                        // Channel closed (scheduler finished or dropped). Drain
                        // the task for metrics then exit.
                        let output = build_rx.await
                            .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?
                            ?;
                        Self::record_cancellation_reason(self.metrics(), payload_cancel, span);
                        self.record_flashblocks_metrics(
                            &output.state.ctx,
                            &output.state.fb_state,
                            &output.state.info,
                            target_flashblocks,
                            span,
                        );
                        return Ok(());
                    }
                },
            }
        }
    }

    /// Publish a candidate flashblock immediately. Does NOT need ctx, so can
    /// run before awaiting the build task. Returns the serialized byte size.
    fn publish_candidate(
        &self,
        candidate: &BestCandidate,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        fb_span: &tracing::Span,
    ) -> Result<usize, PayloadBuilderError> {
        let _publish_span = if fb_span.is_none() {
            tracing::Span::none()
        } else {
            span!(parent: fb_span, Level::INFO, "publish_flashblock",)
        }
        .entered();

        let (_, ref new_payload, ref fb_payload_delta) = candidate.result;
        let flashblock_byte_size = self
            .ws_pub()
            .publish(fb_payload_delta)
            .map_err(PayloadBuilderError::other)?;
        self.built_fb_payload_tx()
            .try_send(new_payload.clone())
            .map_err(PayloadBuilderError::other)?;
        if let Err(e) = self.built_payload_tx().try_send(new_payload.clone()) {
            warn!(
                target: "payload_builder",
                error = %e,
                "Failed to send updated payload"
            );
        }
        best_payload_tx.send_replace(Some(new_payload.clone()));
        Ok(flashblock_byte_size)
    }

    #[expect(clippy::too_many_arguments)]
    async fn publish_and_spawn_next(
        &self,
        build_rx: BuildReceiver,
        pretaken: Option<BestCandidate>,
        new_fb_cancel: CancellationToken,
        fb_span: tracing::Span,
        build_start: Instant,
        span: &tracing::Span,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        payload_cancel: &PayloadJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
    ) -> Result<FlashblockAction, PayloadBuilderError> {
        self.metrics()
            .continuous_build_duration
            .record(build_start.elapsed());

        // Fast path: publish pretaken BEFORE awaiting the build task.
        // This is the whole point of shared_best — minimize trigger→publish latency.
        let (pretaken, pretaken_byte_size) = match pretaken {
            Some(candidate) => {
                if payload_cancel.is_resolved() || payload_cancel.is_new_fcu() {
                    // Suppress publish if job was cancelled between trigger and here.
                    if payload_cancel.is_resolved() {
                        self.metrics()
                            .flashblock_publish_suppressed_total
                            .increment(1);
                    }
                    (Some(candidate), None)
                } else {
                    let bytes = self.publish_candidate(&candidate, best_payload_tx, &fb_span)?;
                    (Some(candidate), Some(bytes))
                }
            }
            None => (None, None),
        };

        // Await the build task for ctx handoff. With fast-cancel (task #4), this
        // completes in ~1-2ms after we took pretaken.
        let output = build_rx
            .await
            .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))??;

        let ContinuousBuildOutput {
            mut state,
            candidate_result:
                CandidateLoopResult {
                    best: task_best,
                    candidates_evaluated,
                    candidates_improved,
                },
        } = output;

        // If we haven't published yet (no pretaken was available), fall back to
        // task_best now.
        let (best, byte_size) = match (pretaken, pretaken_byte_size, task_best) {
            (Some(p), Some(b), _) => (Some(p), Some(b)),
            (Some(p), None, _) => (Some(p), None),
            (None, _, Some(t)) => {
                let bytes = if payload_cancel.is_resolved() || payload_cancel.is_new_fcu() {
                    if payload_cancel.is_resolved() {
                        state
                            .ctx
                            .metrics
                            .flashblock_publish_suppressed_total
                            .increment(1);
                    }
                    None
                } else {
                    Some(self.publish_candidate(&t, best_payload_tx, &fb_span)?)
                };
                (Some(t), bytes)
            }
            (None, _, None) => (None, None),
        };

        let staleness = best.as_ref().map(|b| b.sealed_at.elapsed());
        let staleness_ms = staleness.map(|d| d.as_millis() as u64);
        self.metrics()
            .continuous_candidates_evaluated
            .record(candidates_evaluated as f64);
        self.metrics()
            .continuous_candidates_improved
            .record(candidates_improved as f64);
        if let Some(d) = staleness {
            self.metrics().candidate_staleness.record(d);
        }

        fb_span.record("candidates_evaluated", candidates_evaluated);
        fb_span.record("candidates_improved", candidates_improved);
        if let Some(ms) = staleness_ms {
            fb_span.record("staleness_ms", ms);
        }

        {
            let _enter = fb_span.enter();
            info!(
                target: "payload_builder",
                candidates_evaluated,
                candidates_improved,
                staleness_ms = staleness_ms.unwrap_or(0),
                "Scheduler trigger fired, publishing best candidate"
            );
        }

        if payload_cancel.is_resolved() || payload_cancel.is_new_fcu() {
            Self::record_cancellation_reason(self.metrics(), payload_cancel, span);
            self.record_flashblocks_metrics(
                &state.ctx,
                &state.fb_state,
                &state.info,
                target_flashblocks,
                span,
            );
            return Ok(FlashblockAction::Exit);
        }

        match best {
            Some(candidate) => {
                let (next_fb_state, _new_payload, _fb_payload_delta) = candidate.result;
                // Commit fully to the published candidate. The build task may
                // have produced a newer candidate after we took pretaken; its
                // cache/transition/tx_cache would be present in `state` from
                // the task's return, but the payload we published is this
                // candidate's, so seed the next interval from this candidate
                // only. `address_gas_limiter` lives on ctx (not a field we
                // move) and is similarly restored so its baseline matches.
                state.cache = candidate.cache;
                state.transition = candidate.transition;
                state.info = candidate.info;
                state.fb_state = candidate.fb_state;
                state.tx_cache = candidate.tx_cache;
                state
                    .ctx
                    .address_gas_limiter
                    .restore(&candidate.gas_limiter_snapshot);

                if self.config().enable_tx_tracking_debug_logs
                    && let Some(size) = byte_size
                {
                    debug!(
                        target: "tx_trace",
                        payload_id = %state.ctx.payload_id(),
                        block_number = state.ctx.block_number(),
                        flashblock_index = state.fb_state.flashblock_index(),
                        byte_size = size,
                        total_txs = state.info.executed_transactions.len(),
                        stage = "fb_published"
                    );
                }

                if let Some(size) = byte_size {
                    state
                        .ctx
                        .metrics
                        .flashblock_byte_size_histogram
                        .record(size as f64);
                }
                state
                    .ctx
                    .metrics
                    .flashblock_num_tx_histogram
                    .record(state.info.executed_transactions.len() as f64);
                // Record only the winning candidate's single-build time, so
                // this stays comparable with the non-continuous path. The
                // full trigger-to-trigger interval is in
                // `continuous_build_duration`.
                state
                    .ctx
                    .metrics
                    .flashblock_build_duration
                    .record(candidate.build_duration);

                fb_span.record("tx_count", state.info.executed_transactions.len() as u64);
                fb_span.record("gas_used", state.info.cumulative_gas_used);

                info!(
                    target: "payload_builder",
                    event = "flashblock_built",
                    id = %state.ctx.payload_id(),
                    flashblock_index = state.fb_state.flashblock_index(),
                    current_gas = state.info.cumulative_gas_used,
                    current_da = state.info.cumulative_da_bytes_used,
                    target_flashblocks = state.fb_state.target_flashblock_count(),
                    candidates_evaluated,
                    candidates_improved,
                    "Continuous flashblock built"
                );

                state.fb_state = next_fb_state;
            }
            None => {
                Self::record_cancellation_reason(self.metrics(), payload_cancel, span);
                self.record_flashblocks_metrics(
                    &state.ctx,
                    &state.fb_state,
                    &state.info,
                    target_flashblocks,
                    span,
                );
                return Ok(FlashblockAction::Exit);
            }
        }

        let fb_span = if span.is_none() {
            tracing::Span::none()
        } else {
            span!(
                parent: span,
                Level::INFO,
                "build_flashblock",
                flashblock_index = state.fb_state.flashblock_index(),
                block_number = state.ctx.block_number(),
                tx_count = tracing::field::Empty,
                gas_used = tracing::field::Empty,
                candidates_evaluated = tracing::field::Empty,
                candidates_improved = tracing::field::Empty,
                staleness_ms = tracing::field::Empty,
            )
        };

        state.ctx = state.ctx.with_cancel(new_fb_cancel);
        let build_start = Instant::now();
        let new_shared_best: SharedBest = Arc::new(std::sync::Mutex::new(None));
        let build_rx = self.spawn_continuous_build_task(
            parent_hash,
            payload_cancel,
            state,
            fb_span.clone(),
            new_shared_best.clone(),
        );

        Ok(FlashblockAction::Continue {
            fb_span,
            build_rx,
            shared_best: new_shared_best,
            build_start,
        })
    }

    fn spawn_continuous_build_task(
        &self,
        parent_hash: B256,
        payload_cancel: &PayloadJobCancellation,
        state: ContinuousBuildState<CacheState, Option<TransitionState>>,
        fb_span: tracing::Span,
        shared_best: SharedBest,
    ) -> oneshot::Receiver<
        Result<ContinuousBuildOutput<CacheState, Option<TransitionState>>, PayloadBuilderError>,
    > {
        let (build_tx, build_rx) = oneshot::channel();
        self.executor().spawn_blocking_task(Box::pin({
            let builder = self.clone();
            let block_cancel = payload_cancel.token();
            async move {
                let _ = build_tx.send((|| -> Result<_, PayloadBuilderError> {
                    let _enter = fb_span.enter();
                    let state_provider = builder.client().state_by_block_hash(parent_hash)?;
                    let mut state_db = State::builder()
                        .with_database(StateProviderDatabase::new(&state_provider))
                        .with_cached_prestate(state.cache)
                        .with_bundle_update()
                        .build();
                    state_db.transition_state = state.transition;

                    let mut tx_cache = state.tx_cache;
                    let mut info = state.info;
                    let mut fb_state = state.fb_state;

                    let candidate_result = builder
                        .build_continuous_flashblock(
                            &state.ctx,
                            &mut fb_state,
                            &mut info,
                            &mut state_db,
                            &state_provider,
                            &mut tx_cache,
                            &block_cancel,
                            &shared_best,
                        )
                        .map_err(|e| PayloadBuilderError::Other(e.into()))?;

                    let cache = std::mem::take(&mut state_db.cache);
                    let transition_state = state_db.transition_state.take();

                    Ok(ContinuousBuildOutput {
                        state: ContinuousBuildState {
                            ctx: state.ctx,
                            info,
                            cache,
                            transition: transition_state,
                            tx_cache,
                            fb_state,
                        },
                        candidate_result,
                    })
                })());
            }
        }));
        build_rx
    }

    fn build_empty_flashblock_candidate<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadBuilderCtx,
        fb_state: &mut FlashblocksState,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        state_provider: impl reth::providers::StateProvider + Clone,
    ) -> eyre::Result<(FlashblocksState, OpBuiltPayload, OpFlashblockPayload)> {
        if let Err(e) = self.builder_tx().add_builder_txs(
            &state_provider,
            info,
            ctx,
            state,
            false,
            fb_state.is_first_flashblock(),
            fb_state.is_last_flashblock(),
        ) {
            error!(
                target: "payload_builder",
                "Error adding bottom builder txs to empty flashblock candidate: {}",
                e
            );
        }

        let (new_payload, mut fb_payload) = build_block(
            state,
            ctx,
            Some(fb_state),
            info,
            !ctx.disable_state_root || ctx.attributes().no_tx_pool,
            self.config().enable_tx_tracking_debug_logs,
        )
        .wrap_err("failed to build empty flashblock candidate")?;

        fb_payload.index = fb_state.flashblock_index();
        fb_payload.base = None;

        let next_target_da = fb_state.target_da_for_batch();
        let next_target_da_footprint = fb_state.target_da_footprint_for_batch();
        Ok((
            fb_state.next_after_seal(next_target_da, next_target_da_footprint),
            new_payload,
            fb_payload,
        ))
    }

    #[expect(clippy::too_many_arguments)]
    fn build_continuous_flashblock<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadBuilderCtx,
        fb_state: &mut FlashblocksState,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        state_provider: impl reth::providers::StateProvider + Clone,
        tx_cache: &mut FlashblockTxCache,
        block_cancel: &CancellationToken,
        shared_best: &SharedBest,
    ) -> eyre::Result<CandidateLoopResult> {
        let flashblock_index = fb_state.flashblock_index();
        let mut target_gas_for_batch = fb_state.target_gas_for_batch();
        let mut target_da_for_batch = fb_state.target_da_for_batch();
        let mut target_da_footprint_for_batch = fb_state.target_da_footprint_for_batch();
        let enable_tx_tracking_debug_logs = self.config().enable_tx_tracking_debug_logs;

        info!(
            target: "payload_builder",
            block_number = ctx.block_number(),
            flashblock_index,
            target_gas = target_gas_for_batch,
            gas_used = info.cumulative_gas_used,
            target_da = target_da_for_batch,
            da_used = info.cumulative_da_bytes_used,
            block_gas_used = ctx.block_gas_limit(),
            target_da_footprint = target_da_footprint_for_batch,
            "Continuous build+seal: starting candidate loop",
        );

        let builder_txs = self
            .builder_tx()
            .add_builder_txs(
                &state_provider,
                info,
                ctx,
                state,
                true,
                fb_state.is_first_flashblock(),
                fb_state.is_last_flashblock(),
            )
            .inspect_err(
                |e| error!(target: "payload_builder", "Error simulating builder txs: {}", e),
            )
            .unwrap_or_default();

        let max_uncompressed_block_size = reserve_builder_tx_budget(
            &builder_txs,
            &mut target_gas_for_batch,
            &mut target_da_for_batch,
            &mut target_da_footprint_for_batch,
            info.da_footprint_scalar,
            ctx.max_uncompressed_block_size,
            info.cumulative_uncompressed_bytes,
        );

        // Each candidate must start with the same gas budget.
        let gas_limiter_snapshot = ctx.address_gas_limiter.snapshot();

        let base_cache = state.cache.clone();
        let base_transition = state.transition_state.clone();
        let base_info = info.clone();
        let base_fb_state = fb_state.clone();
        let base_tx_cache = tx_cache.clone();

        let mut best: Option<BestCandidate> = None;
        let mut candidates_evaluated: u64 = 0;
        let mut candidates_improved: u64 = 0;
        // rebuilds when the tx pool hasn't changed since our last candidate AND we already have a best.
        let mut last_seen_pool_change_epoch = self.pool_change_epoch().load(Ordering::Relaxed);
        let mut idle_backoff = Duration::from_millis(1);
        let max_idle_backoff = Duration::from_millis(25);

        ctx.address_gas_limiter.restore(&gas_limiter_snapshot);
        let mut empty_candidate_info = base_info.clone();
        let mut empty_candidate_fb_state = base_fb_state.clone();
        let empty_build_start = Instant::now();
        let empty_candidate = self.build_empty_flashblock_candidate(
            ctx,
            &mut empty_candidate_fb_state,
            &mut empty_candidate_info,
            state,
            &state_provider,
        );
        let empty_build_duration = empty_build_start.elapsed();
        candidates_evaluated += 1;

        // Baseline fees for the fee-improvement metric: whatever the first
        // successful candidate produced. Subsequent candidates measure their
        // gain against this.
        let mut first_candidate_fees: Option<U256> = None;

        match empty_candidate {
            Ok((next_flashblock_state, new_payload, fb_payload)) => {
                let empty_fees = empty_candidate_info.total_fees;
                let candidate = BestCandidate {
                    total_fees: empty_fees,
                    cache: state.cache.clone(),
                    transition: state.transition_state.clone(),
                    info: empty_candidate_info,
                    fb_state: empty_candidate_fb_state,
                    tx_cache: base_tx_cache.clone(),
                    sealed_at: Instant::now(),
                    result: (next_flashblock_state, new_payload, fb_payload),
                    build_duration: empty_build_duration,
                    gas_limiter_snapshot: ctx.address_gas_limiter.snapshot(),
                };
                *shared_best.lock().unwrap() = Some(candidate.clone());
                best = Some(candidate);
                first_candidate_fees = Some(empty_fees);
                candidates_improved += 1;
            }
            Err(err) => {
                ctx.metrics.invalid_built_blocks_count.increment(1);
                warn!(
                    target: "payload_builder",
                    ?err,
                    "Empty flashblock candidate seal failed, continuing"
                );
            }
        }

        loop {
            if ctx.cancel.is_cancelled() || block_cancel.is_cancelled() {
                break;
            }

            // Pool-change gating: if the pool hasn't changed since our last
            // candidate AND we already have a best, back off to avoid burning
            // CPU cloning and re-simulating identical state. The fresh load
            // after the sleep catches any pool activity that arrived during
            // the backoff and lets us react on the next iteration.
            let current_epoch = self.pool_change_epoch().load(Ordering::Relaxed);
            if best.is_some() && current_epoch == last_seen_pool_change_epoch {
                std::thread::sleep(idle_backoff);
                idle_backoff = (idle_backoff * 2).min(max_idle_backoff);
                continue;
            }
            last_seen_pool_change_epoch = current_epoch;
            idle_backoff = Duration::from_millis(1);

            // Yield CPU briefly to avoid starving the tokio runtime
            // (RPC handling, WS delivery, pool processing).
            std::thread::sleep(Duration::from_millis(1));

            let candidate_span = span!(
                Level::INFO,
                "candidate",
                candidate_index = candidates_evaluated,
                gas_used = tracing::field::Empty,
                total_fees_wei = tracing::field::Empty,
                is_best = tracing::field::Empty,
            );
            let _candidate_guard = candidate_span.enter();

            // Per-candidate build timing so a winning candidate can carry its
            // own single-build duration. This is what gets recorded on
            // `flashblock_build_duration` at publish time, keeping that
            // metric comparable with the non-continuous path.
            let candidate_build_start = Instant::now();

            state.cache = base_cache.clone();
            state.transition_state = base_transition.clone();
            ctx.address_gas_limiter.restore(&gas_limiter_snapshot);
            let mut sim_info = base_info.clone();
            let mut sim_fb_state = base_fb_state.clone();
            let mut sim_tx_cache = base_tx_cache.clone();

            let mut best_txs = FlashblockPoolTxCursor::new(&mut sim_tx_cache);
            let best_txs_start_time = Instant::now();
            best_txs.refresh_iterator(
                BestPayloadTransactions::new(
                    self.pool()
                        .best_transactions_with_attributes(ctx.best_transaction_attributes()),
                ),
                flashblock_index,
            );
            let transaction_pool_fetch_time = best_txs_start_time.elapsed();
            ctx.metrics
                .transaction_pool_fetch_duration
                .record(transaction_pool_fetch_time);
            ctx.metrics
                .transaction_pool_fetch_gauge
                .set(transaction_pool_fetch_time);

            let exec_cancelled = ctx
                .execute_best_transactions(
                    &mut sim_info,
                    state,
                    &mut best_txs,
                    target_gas_for_batch.min(ctx.block_gas_limit()),
                    target_da_for_batch,
                    target_da_footprint_for_batch,
                    max_uncompressed_block_size,
                    sim_fb_state.flashblock_index(),
                )
                .wrap_err("failed to execute best transactions")?
                .is_some();

            let new_transactions: Vec<_> = sim_fb_state
                .slice_new_transactions(&sim_info.executed_transactions)
                .iter()
                .map(|tx| tx.tx_hash())
                .collect::<Vec<_>>();
            best_txs.mark_committed(new_transactions);
            drop(best_txs);

            if exec_cancelled || ctx.cancel.is_cancelled() || block_cancel.is_cancelled() {
                break;
            }

            if let Err(e) = self.builder_tx().add_builder_txs(
                &state_provider,
                &mut sim_info,
                ctx,
                state,
                false,
                sim_fb_state.is_first_flashblock(),
                sim_fb_state.is_last_flashblock(),
            ) {
                error!(target: "payload_builder", "Error adding bottom builder txs: {}", e);
            }

            if ctx.cancel.is_cancelled() || block_cancel.is_cancelled() {
                break;
            }

            let total_block_built_start = Instant::now();
            let build_result = build_block(
                state,
                ctx,
                Some(&mut sim_fb_state),
                &mut sim_info,
                !ctx.disable_state_root || ctx.attributes().no_tx_pool,
                enable_tx_tracking_debug_logs,
            );
            let total_block_built_duration = total_block_built_start.elapsed();
            ctx.metrics
                .total_block_built_duration
                .record(total_block_built_duration);
            ctx.metrics
                .total_block_built_gauge
                .set(total_block_built_duration);

            candidates_evaluated += 1;

            match build_result {
                Ok((new_payload, mut fb_payload)) => {
                    fb_payload.index = flashblock_index;
                    fb_payload.base = None;

                    let best_total_fees = best.as_ref().map_or(U256::ZERO, |b| b.total_fees);
                    let is_new_best = sim_info.total_fees > best_total_fees || best.is_none();
                    candidate_span.record("gas_used", sim_info.cumulative_gas_used);
                    candidate_span.record("total_fees_wei", sim_info.total_fees.to_string());
                    candidate_span.record("is_best", is_new_best);

                    // Record the first successfully-built candidate's fees as
                    // the improvement baseline (in case the empty-candidate
                    // path failed or didn't run).
                    if first_candidate_fees.is_none() {
                        first_candidate_fees = Some(sim_info.total_fees);
                    }

                    if is_new_best {
                        let next_flashblock_state = sim_fb_state
                            .next_after_seal(target_da_for_batch, target_da_footprint_for_batch);
                        let candidate = BestCandidate {
                            total_fees: sim_info.total_fees,
                            cache: state.cache.clone(),
                            transition: state.transition_state.clone(),
                            info: sim_info,
                            fb_state: sim_fb_state,
                            tx_cache: sim_tx_cache,
                            sealed_at: Instant::now(),
                            build_duration: candidate_build_start.elapsed(),
                            result: (next_flashblock_state, new_payload, fb_payload),
                            gas_limiter_snapshot: ctx.address_gas_limiter.snapshot(),
                        };
                        // Publish to shared slot so the main loop can take it
                        // on trigger without awaiting this task.
                        *shared_best.lock().unwrap() = Some(candidate.clone());
                        best = Some(candidate);
                        candidates_improved += 1;
                    } else if let Some(ref mut b) = best {
                        // Tie or worse: just update the timestamp so staleness
                        // stays low without expensive state clones.
                        b.sealed_at = Instant::now();
                    }
                }
                Err(err) => {
                    ctx.metrics.invalid_built_blocks_count.increment(1);
                    warn!(target: "payload_builder", ?err, "Candidate seal failed, continuing");
                }
            }

            drop(_candidate_guard);

            if ctx.cancel.is_cancelled() {
                break;
            }

            if block_cancel.is_cancelled() {
                break;
            }
        }

        // Record priority-fee improvement over the flashblock interval: how
        // much more fee the best candidate captured vs. the first successful
        // candidate (empty or otherwise). 0 when no improvement or no
        // baseline.
        let improvement_wei = match (best.as_ref(), first_candidate_fees) {
            (Some(b), Some(first)) => b.total_fees.saturating_sub(first),
            _ => U256::ZERO,
        };
        let improvement_f64 = u128::try_from(improvement_wei).unwrap_or(u128::MAX) as f64;
        ctx.metrics
            .continuous_fee_improvement
            .record(improvement_f64);

        if let Some(ref b) = best {
            state.cache = b.cache.clone();
            state.transition_state = b.transition.clone();
            *info = b.info.clone();
            *fb_state = b.fb_state.clone();
            *tx_cache = b.tx_cache.clone();
        } else if block_cancel.is_cancelled() {
            state.cache = base_cache;
            state.transition_state = base_transition;
            return Ok(CandidateLoopResult {
                best: None,
                candidates_evaluated,
                candidates_improved,
            });
        }

        Ok(CandidateLoopResult {
            best,
            candidates_evaluated,
            candidates_improved,
        })
    }
}
