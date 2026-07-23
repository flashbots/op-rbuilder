use super::{
    shared_best::SharedBest,
    types::{BestCandidate, CandidateLoopResult},
};
use crate::{
    builder::{
        best_txs::FlashblockTxTracker,
        builder_tx::BuilderTransactions,
        candidate::{BuiltCandidate, CandidateKind, CandidateOutcome, InterruptPolicy},
        context::OpPayloadJobCtx,
        payload::{FlashblocksState, OpPayloadBuilder},
        state_root::StateRootCalculator,
    },
    primitives::reth::ExecutionInfo,
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::U256;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::State;
use revm::Database;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing::{field, info, metadata::Level, span, warn};

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
        info!(
            target: "payload_builder",
            block_number = ctx.block_number(),
            flashblock_index,
            target_gas = fb_state.target_gas_for_batch(),
            gas_used = info.cumulative_gas_used,
            target_da = fb_state.target_da_for_batch(),
            da_used = info.cumulative_da_bytes_used,
            block_gas_used = ctx.block_gas_limit(),
            target_da_footprint = fb_state.target_da_footprint_for_batch(),
            "continuous: starting candidate loop",
        );

        let budget_targets =
            self.prepare_candidate_budget(ctx, &state_provider, state, info, fb_state);

        // Each candidate must start with the same prepared base state.
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
        state.cache = base_cache.clone();
        state.transition_state = base_transition.clone();
        let empty_candidate = self
            .build_candidate(
                CandidateKind::Empty,
                budget_targets,
                ctx,
                &state_provider,
                state,
                base_info.clone(),
                base_fb_state.clone(),
                base_tx_tracker.clone(),
                base_state_root_calc.clone(),
                block_cancel,
                InterruptPolicy::JobAndFlashblock,
            )
            .expect("empty candidates report sealing failures as outcomes");
        candidates_evaluated += 1;

        // Baseline fees for the fee-improvement metric: whatever the first
        // successful candidate produced. Subsequent candidates measure their
        // gain against this.
        let mut first_candidate_fees: Option<U256> = None;

        match empty_candidate {
            CandidateOutcome::Built(BuiltCandidate {
                new_payload,
                fb_payload,
                next_fb_state,
                carried,
                timings,
            }) => {
                let empty_fees = carried.info.total_fees;
                let candidate = BestCandidate {
                    total_fees: empty_fees,
                    cache: carried.cache,
                    transition: carried.transition,
                    info: carried.info,
                    fb_state: carried.fb_state,
                    tx_tracker: carried.tx_tracker,
                    result: (next_fb_state, new_payload, Arc::new(fb_payload)),
                    build_duration: timings.total,
                    // no pool fetch
                    transaction_pool_fetch_duration: None,
                    // not measured for empty candidate
                    total_block_built_duration: None,
                    limiter_snapshot: ctx.address_limiter().snapshot_pending(),
                    candidates_evaluated,
                    candidates_improved: candidates_improved + 1,
                    state_root_calc: carried.state_root_calc,
                };
                shared_best.store(candidate.clone());
                best = Some(candidate);
                first_candidate_fees = Some(empty_fees);
                candidates_improved += 1;
            }
            CandidateOutcome::Cancelled(cancelled) => {
                cancelled
                    .carried
                    .restore(state, info, fb_state, tx_tracker, state_root_calc);
            }
            CandidateOutcome::SealFailed(failure) => {
                ctx.metrics.invalid_built_blocks_count.increment(1);
                let err = failure.into_continuous_error();
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

            // Include clone/reset work to stay comparable with the naive builder.
            let candidate_build_start = std::time::Instant::now();
            state.cache = base_cache.clone();
            state.transition_state = base_transition.clone();
            ctx.address_limiter()
                .restore_pending(&base_limiter_snapshot);
            let outcome = self.build_candidate(
                CandidateKind::PoolBacked,
                budget_targets,
                ctx,
                &state_provider,
                state,
                base_info.clone(),
                base_fb_state.clone(),
                base_tx_tracker.clone(),
                base_state_root_calc.clone(),
                block_cancel,
                InterruptPolicy::JobAndFlashblock,
            )?;

            match outcome {
                CandidateOutcome::Built(BuiltCandidate {
                    new_payload,
                    fb_payload,
                    next_fb_state,
                    carried,
                    timings,
                }) => {
                    candidates_evaluated += 1;
                    let best_total_fees = best.as_ref().map_or(U256::ZERO, |b| b.total_fees);
                    let is_new_best = carried.info.total_fees > best_total_fees || best.is_none();
                    candidate_span.record("gas_used", carried.info.cumulative_gas_used);
                    candidate_span.record("total_fees_wei", carried.info.total_fees.to_string());
                    candidate_span.record("is_best", is_new_best);

                    // Record the first successfully-built candidate's fees as
                    // the improvement baseline (in case the empty-candidate
                    // path failed or didn't run).
                    if first_candidate_fees.is_none() {
                        first_candidate_fees = Some(carried.info.total_fees);
                    }

                    if is_new_best {
                        let candidate = BestCandidate {
                            total_fees: carried.info.total_fees,
                            cache: carried.cache,
                            transition: carried.transition,
                            info: carried.info,
                            fb_state: carried.fb_state,
                            tx_tracker: carried.tx_tracker,
                            build_duration: candidate_build_start.elapsed(),
                            transaction_pool_fetch_duration: timings.pool_fetch,
                            total_block_built_duration: Some(timings.assemble),
                            result: (next_fb_state, new_payload, Arc::new(fb_payload)),
                            limiter_snapshot: ctx.address_limiter().snapshot_pending(),
                            candidates_evaluated,
                            candidates_improved: candidates_improved + 1,
                            state_root_calc: carried.state_root_calc,
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
                CandidateOutcome::Cancelled(cancelled) => {
                    cancelled
                        .carried
                        .restore(state, info, fb_state, tx_tracker, state_root_calc);
                    break;
                }
                CandidateOutcome::SealFailed(failure) => {
                    candidates_evaluated += 1;
                    ctx.metrics.invalid_built_blocks_count.increment(1);
                    let err = failure.into_continuous_error();
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
