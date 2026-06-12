use super::{
    shared_best::SharedBest,
    types::{BuildOutput, BuildReceiver, BuildState, FlashblockInterval, JobDeps},
};
use crate::{
    builder::{
        builder_tx::BuilderTransactions,
        cancellation::{FlashblockJobCancellation, PayloadJobCancellation},
        payload::{OpPayloadBuilder, PayloadBuildStats},
    },
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::B256;
use reth_node_api::PayloadBuilderError;
use reth_revm::{State, database::StateProviderDatabase};
use std::{ops::ControlFlow, time::Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, field, metadata::Level, span};

// === Top-level loop =========================================
//
// One `tokio::select!` over the payload-cancel and the per-interval
// trigger channel. On each trigger it advances one interval; on cancel
// or end-of-block it returns `Ok(())`.

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    /// Entrypoint to build a single payload in continuous mode, it should be called soon after FCU.
    /// It handles the top-level loop: sets up state then iterates flashblock intervals.
    ///
    /// `base_state` is the seed for the next flashblock build. At entry it is the
    /// post-fallback-block state (sealed by `build_fallback_block`, which already
    /// applied deposits and the first builder tx); after each published flashblock
    /// it advances to the top-of-last-flashblock state.
    pub(crate) async fn run_continuous_flashblocks(
        &self,
        deps: JobDeps<'_>,
        target_flashblocks: u64,
        parent_hash: B256,
        mut fb_trigger_rx: mpsc::Receiver<FlashblockJobCancellation>,
        base_state: BuildState,
    ) -> Result<PayloadBuildStats, PayloadBuilderError> {
        debug!(
            target: "payload_builder",
            "Continuous build mode enabled"
        );

        let mut interval =
            self.start_flashblock_interval(parent_hash, deps.payload_cancel, deps.span, base_state);

        loop {
            tokio::select! {
                biased;
                _ = deps.payload_cancel.wait_for_cancellation() => break,
                trigger = fb_trigger_rx.recv() => match trigger {
                    Some(new_fb_cancel) => {
                        // Fast path: take the current best from the candidate slot
                        // without awaiting the task.
                        // Publish happens immediately; the old task will drop its work on cancel.
                        let pretaken = interval.candidate_slot.take();
                        match self.publish_and_spawn_next(
                            &deps, interval, pretaken, new_fb_cancel,
                            target_flashblocks, parent_hash,
                        ).await? {
                            ControlFlow::Continue(next) => interval = next,
                            // Terminal interval: last flashblock, payload cancelled
                            // mid-flight, or fallback produced no candidate.
                            ControlFlow::Break(stats) => return Ok(stats),
                        }
                    }
                    None => {
                        // Channel closed (scheduler finished or dropped). Cancel
                        // the orphan build task and drop the receiver; metrics
                        // are recorded once after the loop from the snapshot
                        // captured when we spawned the build task.
                        interval.base_ctx.cancel().cancel_current_flashblock();
                        drop(interval.build_rx);
                        break;
                    }
                },
            }
        }

        // Record the wall time of the final in-flight interval.
        self.metrics()
            .continuous_build_duration
            .record(interval.build_start.elapsed());

        Ok(PayloadBuildStats::new(
            deps.payload_cancel.clone(),
            deps.span.clone(),
            interval.base_fb_state.flashblock_index(),
            interval.base_info.executed_transactions.len(),
            interval.base_info.cumulative_uncompressed_bytes,
            target_flashblocks,
        ))
    }

    /// Spawn the build task for a new flashblock interval and bundle the
    /// per-interval state (span, build receiver, candidate slot, build start).
    /// Used at payload entry and after each publish to advance to the next
    /// interval, so both call sites share the same setup.
    pub(super) fn start_flashblock_interval(
        &self,
        parent_hash: B256,
        payload_cancel: &PayloadJobCancellation,
        parent_span: &tracing::Span,
        base_state: BuildState,
    ) -> FlashblockInterval {
        let fb_span = if parent_span.is_none() {
            tracing::Span::none()
        } else {
            span!(
                parent: parent_span,
                Level::INFO,
                "build_flashblock",
                flashblock_index = base_state.fb_state.flashblock_index(),
                block_number = base_state.ctx.block_number(),
                tx_count = field::Empty,
                gas_used = field::Empty,
                candidates_evaluated = field::Empty,
                candidates_improved = field::Empty,
            )
        };

        let candidate_slot = SharedBest::new();
        let base_ctx = base_state.ctx.clone();
        let base_fb_state = base_state.fb_state.clone();
        let base_info = base_state.info.clone();
        let build_rx = self.spawn_continuous_build_task(
            parent_hash,
            payload_cancel,
            base_state,
            fb_span.clone(),
            candidate_slot.clone(),
        );
        FlashblockInterval {
            fb_span,
            build_rx,
            candidate_slot,
            build_start: Instant::now(),
            base_ctx,
            base_fb_state,
            base_info,
        }
    }

    fn spawn_continuous_build_task(
        &self,
        parent_hash: B256,
        payload_cancel: &PayloadJobCancellation,
        base_state: BuildState,
        fb_span: tracing::Span,
        shared_best: SharedBest,
    ) -> BuildReceiver {
        let (build_tx, build_rx) = oneshot::channel();
        self.executor().spawn_blocking_task(Box::pin({
            let builder = self.clone();
            let block_cancel = payload_cancel.token();
            async move {
                let _ = build_tx.send((|| -> Result<_, PayloadBuilderError> {
                    let _enter = fb_span.enter();
                    let base_state = base_state;

                    let state_provider = builder.client().state_by_block_hash(parent_hash)?;
                    let mut state_db = State::builder()
                        .with_database(StateProviderDatabase::new(&state_provider))
                        .with_cached_prestate(base_state.cache)
                        .with_bundle_update()
                        .build();
                    state_db.transition_state = base_state.transition;

                    let mut tx_tracker = base_state.tx_tracker;
                    let mut info = base_state.info;
                    let mut fb_state = base_state.fb_state;
                    let mut state_root_calc = base_state.state_root_calc;

                    let candidate_result = builder
                        .build_continuous_flashblock(
                            &base_state.ctx,
                            &mut fb_state,
                            &mut info,
                            &mut state_db,
                            &state_provider,
                            &mut tx_tracker,
                            &mut state_root_calc,
                            &block_cancel,
                            &shared_best,
                        )
                        .map_err(|e| PayloadBuilderError::Other(e.into()))?;

                    let cache = std::mem::take(&mut state_db.cache);
                    let transition_state = state_db.transition_state.take();

                    Ok(BuildOutput {
                        base_state: BuildState {
                            ctx: base_state.ctx,
                            info,
                            cache,
                            transition: transition_state,
                            tx_tracker,
                            fb_state,
                            state_root_calc,
                        },
                        candidate_result,
                    })
                })());
            }
        }));
        build_rx
    }
}
