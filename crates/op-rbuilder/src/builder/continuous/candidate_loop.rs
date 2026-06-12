use super::{
    shared_best::SharedBest,
    types::{BestCandidate, CandidateLoopResult},
};
use crate::{
    builder::{
        best_txs::{FlashblockPoolTxCursor, FlashblockTxTracker},
        builder_tx::{BuilderTransactions, reserve_builder_tx_budget},
        context::OpPayloadJobCtx,
        payload::{FlashblocksState, OpPayloadBuilder},
        state_root::StateRootCalculator,
    },
    primitives::reth::ExecutionInfo,
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::U256;
use eyre::WrapErr as _;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_optimism_node::OpBuiltPayload;
use reth_payload_util::BestPayloadTransactions;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::State;
use revm::Database;
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, field, info, metadata::Level, span, warn};

// === Build / candidate loop internals =======================
//
// Runs inside the spawned blocking task. The candidate loop repeatedly
// clones state, executes txs, seals a flashblock, and writes the new
// best into [`SharedBest`] until its per-interval cancel fires.

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    #[expect(clippy::too_many_arguments)]
    fn build_empty_flashblock_candidate<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadJobCtx,
        fb_state: &mut FlashblocksState,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        state_provider: impl reth::providers::StateProvider + Clone,
        state_root_calc: &mut StateRootCalculator,
        // Builder-tx-reduced DA budgets: must be passed in from the caller after
        // `reserve_builder_tx_budget` has been applied, so the next flashblock's
        // DA window is computed from the residual that actually reaches pool txs
        // (matching the legacy per-trigger path in `build_next_flashblock`).
        target_da_for_batch: Option<u64>,
        target_da_footprint_for_batch: Option<u64>,
    ) -> eyre::Result<(FlashblocksState, OpBuiltPayload, OpFlashblockPayload)> {
        if let Err(e) = self.builder_tx().add_builder_txs(
            &state_provider,
            info,
            &ctx.builder_tx_env(),
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

        let (new_payload, mut fb_payload) = ctx
            .block_assembly_input()
            .wrap_err("failed to construct block assembly input")?
            .assemble(
                state,
                Some(fb_state),
                info,
                state_root_calc,
                ctx.metrics.clone(),
                ctx.enable_tx_tracking_debug_logs,
            )
            .wrap_err("failed to build empty flashblock candidate")?;

        fb_payload.index = fb_state.flashblock_index();
        fb_payload.base = None;

        Ok((
            fb_state.next_after_seal(target_da_for_batch, target_da_footprint_for_batch),
            new_payload,
            fb_payload,
        ))
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn build_continuous_flashblock<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadJobCtx,
        fb_state: &mut FlashblocksState,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        state_provider: impl reth::providers::StateProvider + Clone,
        tx_tracker: &mut FlashblockTxTracker,
        state_root_calc: &mut StateRootCalculator,
        block_cancel: &CancellationToken,
        shared_best: &SharedBest,
    ) -> eyre::Result<CandidateLoopResult> {
        let flashblock_index = fb_state.flashblock_index();
        let mut target_gas_for_batch = fb_state.target_gas_for_batch();
        let mut target_da_for_batch = fb_state.target_da_for_batch();
        let mut target_da_footprint_for_batch = fb_state.target_da_footprint_for_batch();

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
            "continuous: starting candidate loop",
        );

        let builder_txs = self
            .builder_tx()
            .add_builder_txs(
                &state_provider,
                info,
                &ctx.builder_tx_env(),
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

        // Each candidate must start with the same base state.
        let base_cache = state.cache.clone();
        let base_transition = state.transition_state.clone();
        let base_info = info.clone();
        let base_fb_state = fb_state.clone();
        let base_tx_tracker = tx_tracker.clone();
        let base_limiter_snapshot = ctx.address_limiter().snapshot_pending();
        let base_state_root_calc = state_root_calc.clone();

        let mut best: Option<BestCandidate> = None;
        let mut candidates_evaluated: u64 = 0;
        let mut candidates_improved: u64 = 0;
        // Force one pool-backed candidate after the empty baseline so txs
        // already pending at interval start are considered without waiting for
        // a fresh pool event.
        let mut last_seen_pool_change_epoch = self
            .pool_change_epoch()
            .load(Ordering::Relaxed)
            .wrapping_sub(1);
        let mut idle_backoff = Duration::from_millis(1);
        let max_idle_backoff = Duration::from_millis(25);

        ctx.address_limiter()
            .restore_pending(&base_limiter_snapshot);
        let mut empty_candidate_info = base_info.clone();
        let mut empty_candidate_fb_state = base_fb_state.clone();
        let mut empty_candidate_state_root_calc = base_state_root_calc.clone();
        let empty_build_start = Instant::now();
        let empty_candidate = self.build_empty_flashblock_candidate(
            ctx,
            &mut empty_candidate_fb_state,
            &mut empty_candidate_info,
            state,
            &state_provider,
            &mut empty_candidate_state_root_calc,
            target_da_for_batch,
            target_da_footprint_for_batch,
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
                    tx_tracker: base_tx_tracker.clone(),
                    result: (next_flashblock_state, new_payload, fb_payload),
                    build_duration: empty_build_duration,
                    limiter_snapshot: ctx.address_limiter().snapshot_pending(),
                    candidates_evaluated,
                    candidates_improved: candidates_improved + 1,
                    state_root_calc: empty_candidate_state_root_calc,
                };
                shared_best.store(candidate.clone());
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
            if ctx.cancel().is_cancelled() || block_cancel.is_cancelled() {
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

            let candidate_span = span!(
                Level::INFO,
                "candidate",
                candidate_index = candidates_evaluated,
                gas_used = field::Empty,
                total_fees_wei = field::Empty,
                is_best = field::Empty,
            );
            let _candidate_guard = candidate_span.enter();

            // Per-candidate build timing so a winning candidate can carry its
            // own single-build duration. This is what gets recorded on
            // `flashblock_build_duration` at publish time, keeping that
            // metric comparable with the non-continuous path.
            let candidate_build_start = Instant::now();

            state.cache = base_cache.clone();
            state.transition_state = base_transition.clone();
            ctx.address_limiter()
                .restore_pending(&base_limiter_snapshot);
            let mut sim_info = base_info.clone();
            let mut sim_fb_state = base_fb_state.clone();
            let mut sim_tx_tracker = base_tx_tracker.clone();
            let mut sim_state_root_calc = base_state_root_calc.clone();

            let mut best_txs = FlashblockPoolTxCursor::new(&mut sim_tx_tracker);
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

            if exec_cancelled || ctx.cancel().is_cancelled() || block_cancel.is_cancelled() {
                break;
            }

            if let Err(e) = self.builder_tx().add_builder_txs(
                &state_provider,
                &mut sim_info,
                &ctx.builder_tx_env(),
                state,
                false,
                sim_fb_state.is_first_flashblock(),
                sim_fb_state.is_last_flashblock(),
            ) {
                error!(target: "payload_builder", "Error adding bottom builder txs: {}", e);
            }

            if ctx.cancel().is_cancelled() || block_cancel.is_cancelled() {
                break;
            }

            let total_block_built_start = Instant::now();
            let build_result = ctx
                .block_assembly_input()
                .map_err(|e| eyre::eyre!("failed to construct block assembly input: {e}"))
                .and_then(|input| {
                    input
                        .assemble(
                            state,
                            Some(&mut sim_fb_state),
                            &mut sim_info,
                            &mut sim_state_root_calc,
                            ctx.metrics.clone(),
                            ctx.enable_tx_tracking_debug_logs,
                        )
                        .map_err(|e| eyre::eyre!("failed to assemble candidate: {e}"))
                });
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
                            tx_tracker: sim_tx_tracker,
                            build_duration: candidate_build_start.elapsed(),
                            result: (next_flashblock_state, new_payload, fb_payload),
                            limiter_snapshot: ctx.address_limiter().snapshot_pending(),
                            candidates_evaluated,
                            candidates_improved: candidates_improved + 1,
                            state_root_calc: sim_state_root_calc,
                        };
                        // Publish to shared slot so the main loop can take it
                        // on trigger without awaiting this task.
                        shared_best.store(candidate.clone());
                        best = Some(candidate);
                        candidates_improved += 1;
                    } else if let Some(ref mut b) = best {
                        // Tie or worse: keep the winning candidate state, but
                        // update the counters exposed to the main loop.
                        b.candidates_evaluated = candidates_evaluated;
                        b.candidates_improved = candidates_improved;
                        shared_best.refresh_metrics(candidates_evaluated, candidates_improved);
                    }
                }
                Err(err) => {
                    ctx.metrics.invalid_built_blocks_count.increment(1);
                    warn!(target: "payload_builder", ?err, "Candidate seal failed, continuing");
                    if best.is_some() {
                        shared_best.refresh_metrics(candidates_evaluated, candidates_improved);
                    }
                }
            }

            drop(_candidate_guard);

            if ctx.cancel().is_cancelled() {
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
            *tx_tracker = b.tx_tracker.clone();
            *state_root_calc = b.state_root_calc.clone();
            // Re-apply the winning candidate's pending limiter deltas so the
            // per-build guard reflects the chosen candidate's gas/compute
            // charges. Losing candidates' charges are discarded.
            ctx.address_limiter().restore_pending(&b.limiter_snapshot);
        } else if block_cancel.is_cancelled() {
            state.cache = base_cache;
            state.transition_state = base_transition;
            ctx.address_limiter()
                .restore_pending(&base_limiter_snapshot);
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
