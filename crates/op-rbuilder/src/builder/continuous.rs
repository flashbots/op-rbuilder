use super::*;
use crate::builder::cancellation::PayloadJobCancellation;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, metadata::Level, span, warn};

pub(super) struct ContinuousBuildState<Cache, Transition> {
    pub(super) ctx: OpPayloadBuilderCtx,
    pub(super) info: ExecutionInfo,
    pub(super) cache: Cache,
    pub(super) transition: Transition,
    pub(super) tx_cache: FlashblockTxCache,
    pub(super) fb_state: FlashblocksState,
}

/// Result of a continuous candidate loop within a single flashblock interval.
/// Contains the best sealed candidate (if any) and loop statistics.
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

/// Returned by `publish_and_spawn_next` to tell the caller whether to continue or exit.
enum FlashblockAction {
    /// Published successfully: continue with updated loop state
    Continue {
        fb_span: tracing::Span,
        build_rx: BuildReceiver,
        build_start: Instant,
    },
    /// Cancelled or no candidate: caller should return Ok(())
    Exit,
}

/// Best sealed candidate found so far within a flashblock interval.
/// Groups all the state that must be updated in lockstep when a new best is found.
struct BestCandidate {
    /// The sealed payload + flashblock delta + next flashblock state.
    result: (FlashblocksState, OpBuiltPayload, OpFlashblockPayload),
    /// Gas used by this candidate (comparison key).
    gas_used: u64,
    /// EVM cache from the winning build (restored for next interval).
    cache: CacheState,
    /// EVM transition state from the winning build.
    transition: Option<TransitionState>,
    /// ExecutionInfo from the winning build.
    info: ExecutionInfo,
    /// FlashblocksState from the winning build (pre-next_after_seal).
    fb_state: FlashblocksState,
    /// Committed txs from the winning build.
    tx_cache: FlashblockTxCache,
    /// When this candidate was sealed (for staleness metric).
    sealed_at: Instant,
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    pub(super) async fn run_continuous_flashblocks(
        &self,
        span: &tracing::Span,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        payload_cancel: &PayloadJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
        mut rx: mpsc::Receiver<CancellationToken>,
        state: ContinuousBuildState<CacheState, Option<TransitionState>>,
    ) -> Result<(), PayloadBuilderError> {
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

        let mut build_rx =
            self.spawn_continuous_build_task(parent_hash, payload_cancel, state, fb_span.clone());
        let mut pending_output: Option<ContinuousBuildOutput<_, _>> = None;
        let mut build_start = Instant::now();

        loop {
            if let Some(output) = pending_output.take() {
                // Build completed before trigger: wait for trigger only.
                tokio::select! {
                    biased;
                    _ = payload_cancel.cancelled() => {
                        Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
                        self.record_flashblocks_metrics(
                            &output.state.ctx,
                            &output.state.fb_state,
                            &output.state.info,
                            target_flashblocks,
                            span,
                        );
                        return Ok(());
                    }
                    trigger = rx.recv() => match trigger {
                        Some(new_fb_cancel) => {
                            match self.publish_and_spawn_next(
                                output, new_fb_cancel, fb_span, build_start,
                                span, best_payload_tx, payload_cancel,
                                target_flashblocks, parent_hash,
                            )? {
                                FlashblockAction::Continue { fb_span: new_fb_span, build_rx: new_build_rx, build_start: new_build_start } => {
                                    fb_span = new_fb_span;
                                    build_rx = new_build_rx;
                                    build_start = new_build_start;
                                }
                                FlashblockAction::Exit => return Ok(()),
                            }
                        }
                        None => {
                            Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
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
            } else {
                // Build still running: wait for trigger or early completion.
                tokio::select! {
                    biased;
                    _ = payload_cancel.cancelled() => {
                        Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
                        return Ok(());
                    }
                    trigger = rx.recv() => match trigger {
                        Some(new_fb_cancel) => {
                            let output = build_rx.await
                                .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?
                                ?;
                            match self.publish_and_spawn_next(
                                output, new_fb_cancel, fb_span, build_start,
                                span, best_payload_tx, payload_cancel,
                                target_flashblocks, parent_hash,
                            )? {
                                FlashblockAction::Continue { fb_span: new_fb_span, build_rx: new_build_rx, build_start: new_build_start } => {
                                    fb_span = new_fb_span;
                                    build_rx = new_build_rx;
                                    build_start = new_build_start;
                                }
                                FlashblockAction::Exit => return Ok(()),
                            }
                        }
                        None => {
                            let output = build_rx.await
                                .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?
                                ?;
                            Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
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
                    result = &mut build_rx => {
                        let output = result
                            .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?
                            ?;
                        pending_output = Some(output);
                    }
                }
            }
        }
    }

    /// Publish the best candidate from a completed build, then spawn the next build task.
    /// Returns `Continue` with updated loop state, or `Exit` if cancelled/no candidate.
    #[expect(clippy::too_many_arguments)]
    fn publish_and_spawn_next(
        &self,
        output: ContinuousBuildOutput<CacheState, Option<TransitionState>>,
        new_fb_cancel: CancellationToken,
        fb_span: tracing::Span,
        build_start: Instant,
        span: &tracing::Span,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        payload_cancel: &PayloadJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
    ) -> Result<FlashblockAction, PayloadBuilderError> {
        self.metrics
            .continuous_build_duration
            .record(build_start.elapsed());

        let ContinuousBuildOutput {
            mut state,
            candidate_result:
                CandidateLoopResult {
                    best,
                    candidates_evaluated,
                    candidates_improved,
                },
        } = output;

        let staleness = best.as_ref().map(|b| b.sealed_at.elapsed());
        let staleness_ms = staleness.map(|d| d.as_millis() as u64);
        self.metrics
            .continuous_candidates_evaluated
            .record(candidates_evaluated as f64);
        self.metrics
            .continuous_candidates_improved
            .record(candidates_improved as f64);
        if let Some(d) = staleness {
            self.metrics.candidate_staleness.record(d);
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
            if payload_cancel.is_resolved() {
                state
                    .ctx
                    .metrics
                    .flashblock_publish_suppressed_total
                    .increment(1);
            }
            Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
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
                let (next_fb_state, new_payload, fb_payload_delta) = candidate.result;
                state.info = candidate.info;
                state.fb_state = candidate.fb_state;

                // Defensive: re-check between candidate unwrap and publish (no .await in between).
                if payload_cancel.is_resolved() || payload_cancel.is_new_fcu() {
                    if payload_cancel.is_resolved() {
                        state
                            .ctx
                            .metrics
                            .flashblock_publish_suppressed_total
                            .increment(1);
                    }
                    Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
                    self.record_flashblocks_metrics(
                        &state.ctx,
                        &state.fb_state,
                        &state.info,
                        target_flashblocks,
                        span,
                    );
                    return Ok(FlashblockAction::Exit);
                }

                let _publish_span = if fb_span.is_none() {
                    tracing::Span::none()
                } else {
                    span!(parent: &fb_span, Level::INFO, "publish_flashblock",)
                }
                .entered();

                let flashblock_byte_size = self
                    .ws_pub
                    .publish(&fb_payload_delta)
                    .map_err(PayloadBuilderError::other)?;
                self.built_fb_payload_tx
                    .try_send(new_payload.clone())
                    .map_err(PayloadBuilderError::other)?;
                if let Err(e) = self.built_payload_tx.try_send(new_payload.clone()) {
                    warn!(
                        target: "payload_builder",
                        error = %e,
                        "Failed to send updated payload"
                    );
                }
                best_payload_tx.send_replace(Some(new_payload));

                if self.config.enable_tx_tracking_debug_logs {
                    debug!(
                        target: "tx_trace",
                        payload_id = %state.ctx.payload_id(),
                        block_number = state.ctx.block_number(),
                        flashblock_index = state.fb_state.flashblock_index(),
                        byte_size = flashblock_byte_size,
                        total_txs = state.info.executed_transactions.len(),
                        stage = "fb_published"
                    );
                }

                drop(_publish_span);

                state
                    .ctx
                    .metrics
                    .flashblock_byte_size_histogram
                    .record(flashblock_byte_size as f64);
                state
                    .ctx
                    .metrics
                    .flashblock_num_tx_histogram
                    .record(state.info.executed_transactions.len() as f64);
                state
                    .ctx
                    .metrics
                    .flashblock_build_duration
                    .record(build_start.elapsed());

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
                Self::record_cancellation_reason(&self.metrics, payload_cancel, span);
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
        let build_rx =
            self.spawn_continuous_build_task(parent_hash, payload_cancel, state, fb_span.clone());

        Ok(FlashblockAction::Continue {
            fb_span,
            build_rx,
            build_start,
        })
    }

    fn spawn_continuous_build_task(
        &self,
        parent_hash: B256,
        payload_cancel: &PayloadJobCancellation,
        state: ContinuousBuildState<CacheState, Option<TransitionState>>,
        fb_span: tracing::Span,
    ) -> oneshot::Receiver<
        Result<ContinuousBuildOutput<CacheState, Option<TransitionState>>, PayloadBuilderError>,
    > {
        let (build_tx, build_rx) = oneshot::channel();
        self.executor.spawn_blocking_task(Box::pin({
            let builder = self.clone();
            let block_cancel = payload_cancel.token();
            async move {
                let _ = build_tx.send((|| -> Result<_, PayloadBuilderError> {
                    let _enter = fb_span.enter();
                    let state_provider = builder.client.state_by_block_hash(parent_hash)?;
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
        if let Err(e) = self.builder_tx.add_builder_txs(
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
            self.config.enable_tx_tracking_debug_logs,
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
    ) -> eyre::Result<CandidateLoopResult> {
        let flashblock_index = fb_state.flashblock_index();
        let mut target_gas_for_batch = fb_state.target_gas_for_batch();
        let mut target_da_for_batch = fb_state.target_da_for_batch();
        let mut target_da_footprint_for_batch = fb_state.target_da_footprint_for_batch();
        let enable_tx_tracking_debug_logs = self.config.enable_tx_tracking_debug_logs;

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
            .builder_tx
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
        let mut last_seen_pool_change_epoch = self.pool_change_epoch.load(Ordering::Relaxed);
        let mut force_candidate = true;
        let mut idle_backoff = Duration::from_millis(1);
        let max_idle_backoff = Duration::from_millis(25);

        ctx.address_gas_limiter.restore(&gas_limiter_snapshot);
        let mut empty_candidate_info = base_info.clone();
        let mut empty_candidate_fb_state = base_fb_state.clone();
        let empty_candidate = self.build_empty_flashblock_candidate(
            ctx,
            &mut empty_candidate_fb_state,
            &mut empty_candidate_info,
            state,
            &state_provider,
        );
        candidates_evaluated += 1;

        match empty_candidate {
            Ok((next_flashblock_state, new_payload, fb_payload)) => {
                best = Some(BestCandidate {
                    gas_used: empty_candidate_info.cumulative_gas_used,
                    cache: state.cache.clone(),
                    transition: state.transition_state.clone(),
                    info: empty_candidate_info,
                    fb_state: empty_candidate_fb_state,
                    tx_cache: base_tx_cache.clone(),
                    sealed_at: Instant::now(),
                    result: (next_flashblock_state, new_payload, fb_payload),
                });
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
            let current_pool_change_epoch = self.pool_change_epoch.load(Ordering::Relaxed);
            if !force_candidate && current_pool_change_epoch == last_seen_pool_change_epoch {
                if ctx.cancel.is_cancelled() || block_cancel.is_cancelled() {
                    break;
                }
                std::thread::sleep(idle_backoff);
                idle_backoff = (idle_backoff * 2).min(max_idle_backoff);
                continue;
            }
            force_candidate = false;
            idle_backoff = Duration::from_millis(1);
            last_seen_pool_change_epoch = current_pool_change_epoch;

            let candidate_span = span!(
                Level::INFO,
                "candidate",
                candidate_index = candidates_evaluated,
                gas_used = tracing::field::Empty,
                is_best = tracing::field::Empty,
            );
            let _candidate_guard = candidate_span.enter();

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
                    self.pool
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

            ctx.execute_best_transactions(
                &mut sim_info,
                state,
                &mut best_txs,
                target_gas_for_batch.min(ctx.block_gas_limit()),
                target_da_for_batch,
                target_da_footprint_for_batch,
                max_uncompressed_block_size,
                sim_fb_state.flashblock_index,
            )
            .wrap_err("failed to execute best transactions")?;

            let new_transactions: Vec<_> = sim_fb_state
                .slice_new_transactions(&sim_info.executed_transactions)
                .iter()
                .map(|tx| tx.tx_hash())
                .collect::<Vec<_>>();
            best_txs.mark_committed(new_transactions);
            drop(best_txs);

            if block_cancel.is_cancelled() {
                break;
            }

            if let Err(e) = self.builder_tx.add_builder_txs(
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

                    let best_gas_used = best.as_ref().map_or(0, |b| b.gas_used);
                    let is_new_best =
                        sim_info.cumulative_gas_used > best_gas_used || best.is_none();
                    candidate_span.record("gas_used", sim_info.cumulative_gas_used);
                    candidate_span.record("is_best", is_new_best);

                    if is_new_best {
                        let next_flashblock_state = sim_fb_state
                            .next_after_seal(target_da_for_batch, target_da_footprint_for_batch);
                        best = Some(BestCandidate {
                            gas_used: sim_info.cumulative_gas_used,
                            cache: state.cache.clone(),
                            transition: state.transition_state.clone(),
                            info: sim_info,
                            fb_state: sim_fb_state,
                            tx_cache: sim_tx_cache,
                            sealed_at: Instant::now(),
                            result: (next_flashblock_state, new_payload, fb_payload),
                        });
                        candidates_improved += 1;
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
