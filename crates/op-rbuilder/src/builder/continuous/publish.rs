use super::{
    transition::{
        StopMetricsSource, TriggerOutcome, fallback_no_candidate_metrics_source,
        plan_with_candidate,
    },
    types::{
        BestCandidate, BuildOutput, BuildReceiver, BuildState, CandidateLoopResult,
        FlashblockInterval, JobDeps,
    },
};
use crate::{
    builder::{
        builder_tx::BuilderTransactions,
        cancellation::FlashblockJobCancellation,
        context::OpPayloadJobCtx,
        payload::{FlashblocksState, OpPayloadBuilder, PayloadBuildStats},
        timing::compute_slot_offset_ms,
    },
    metrics::record_flashblock_publish_timing,
    primitives::reth::ExecutionInfo,
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::B256;
use reth_node_api::PayloadBuilderError;
use reth_optimism_node::OpBuiltPayload;
use std::{ops::ControlFlow, time::Instant};
use tokio::sync::watch;
use tracing::{debug, info, metadata::Level, span, warn};

// === Per-interval publishing and advancement =================
//
// On each scheduler trigger: publish the pretaken candidate without awaiting
// the task, then advance from the published candidate. If no candidate is
// ready, await the task output as a fallback.
//
// Transitions:
// TriggerArrived
// ├─ Ready(candidate) → plan_with_candidate → execute_outcome → Advance | Stop
// └─ AwaitFallback    → wait
//                        ├─ Some(candidate) → plan_with_candidate → execute_outcome → Advance | Stop
//                        └─ None            → PayloadBuildStats::new → Stop

enum TriggerCandidate {
    Ready {
        candidate: Box<BestCandidate>,
        stale_build_rx: BuildReceiver,
    },
    AwaitFallback(BuildReceiver),
}

impl TriggerCandidate {
    fn from_parts(pretaken: Option<BestCandidate>, build_rx: BuildReceiver) -> Self {
        match pretaken {
            Some(candidate) => Self::Ready {
                candidate: Box::new(candidate),
                stale_build_rx: build_rx,
            },
            None => Self::AwaitFallback(build_rx),
        }
    }
}

/// Where the candidate came from.
#[derive(Clone, Copy)]
enum CandidateOrigin {
    Ready,
    Fallback,
}

impl CandidateOrigin {
    fn published_log_event(self) -> CandidateLogEvent {
        match self {
            Self::Ready => CandidateLogEvent::ReadyCandidatePublished,
            Self::Fallback => CandidateLogEvent::FallbackCandidatePublished,
        }
    }
}

#[derive(Clone, Copy)]
enum CandidateLogEvent {
    ReadyCandidatePublished,
    FallbackCandidatePublished,
    CandidatePublishSuppressed,
    FallbackNoCandidate,
}

impl CandidateLogEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadyCandidatePublished => "ready_candidate_published",
            Self::FallbackCandidatePublished => "fallback_candidate_published",
            Self::CandidatePublishSuppressed => "candidate_publish_suppressed",
            Self::FallbackNoCandidate => "fallback_no_candidate",
        }
    }
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    /// Publish a candidate flashblock immediately. The context is only used for
    /// publish timing metadata, so this can run before awaiting the build task.
    /// Returns the serialized byte size.
    fn publish_candidate(
        &self,
        candidate: &BestCandidate,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        fb_span: &tracing::Span,
        ctx: &OpPayloadJobCtx,
    ) -> Result<usize, PayloadBuilderError> {
        let _publish_span = if fb_span.is_none() {
            tracing::Span::none()
        } else {
            span!(parent: fb_span, Level::INFO, "publish_flashblock")
        }
        .entered();

        let (_, ref new_payload, ref fb_payload_delta) = candidate.result;
        let flashblock_byte_size = self
            .ws_pub()
            .publish(fb_payload_delta)
            .map_err(PayloadBuilderError::other)?;
        let slot_offset_ms =
            compute_slot_offset_ms(ctx.attributes().timestamp(), self.config().block_time);
        record_flashblock_publish_timing(candidate.fb_state.flashblock_index(), slot_offset_ms);
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

    pub(super) async fn publish_and_spawn_next(
        &self,
        deps: &JobDeps<'_>,
        interval: FlashblockInterval,
        pretaken: Option<BestCandidate>,
        new_fb_cancel: FlashblockJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
    ) -> Result<ControlFlow<PayloadBuildStats, FlashblockInterval>, PayloadBuilderError> {
        // The consumed `candidate_slot` Arc clone is dropped here; the build
        // task still holds its own clone until it observes cancel.
        let FlashblockInterval {
            fb_span,
            build_rx,
            candidate_slot: _,
            build_start,
            base_ctx,
            base_fb_state,
            base_info,
        } = interval;

        self.metrics()
            .continuous_build_duration
            .record(build_start.elapsed());

        match TriggerCandidate::from_parts(pretaken, build_rx) {
            // Fast path: publish pretaken BEFORE awaiting the build task, then
            // advance directly from the published candidate. The old task has
            // a stale per-interval slot and a detached gas limiter, so its
            // eventual result is intentionally ignored.
            TriggerCandidate::Ready {
                candidate,
                stale_build_rx,
            } => {
                self.metrics().continuous_trigger_ready_total.increment(1);
                let candidates_evaluated = candidate.candidates_evaluated;
                let candidates_improved = candidate.candidates_improved;
                let is_last_flashblock = candidate.fb_state.is_last_flashblock();
                let outcome = plan_with_candidate(
                    deps.payload_cancel.is_cancelled(),
                    deps.payload_cancel.is_resolved(),
                    is_last_flashblock,
                );
                drop(stale_build_rx);
                self.execute_outcome(
                    deps,
                    &fb_span,
                    base_ctx,
                    &base_fb_state,
                    &base_info,
                    *candidate,
                    outcome,
                    CandidateOrigin::Ready,
                    candidates_evaluated,
                    candidates_improved,
                    new_fb_cancel,
                    target_flashblocks,
                    parent_hash,
                )
            }

            // No sealed candidate was available in the slot. Fall back to
            // waiting for the task output so we can either publish its best
            // candidate or terminate cleanly if it never produced one.
            TriggerCandidate::AwaitFallback(build_rx) => {
                self.metrics().continuous_trigger_miss_total.increment(1);
                let fallback_wait_start = Instant::now();
                let output = build_rx
                    .await
                    .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?;
                self.metrics()
                    .continuous_trigger_fallback_wait_duration
                    .record(fallback_wait_start.elapsed());
                let output = output?;

                let BuildOutput {
                    base_state,
                    candidate_result:
                        CandidateLoopResult {
                            best,
                            candidates_evaluated,
                            candidates_improved,
                        },
                } = output;

                match best {
                    Some(candidate) => {
                        let is_last_flashblock = candidate.fb_state.is_last_flashblock();
                        let outcome = plan_with_candidate(
                            deps.payload_cancel.is_cancelled(),
                            deps.payload_cancel.is_resolved(),
                            is_last_flashblock,
                        );
                        self.execute_outcome(
                            deps,
                            &fb_span,
                            base_state.ctx,
                            &base_fb_state,
                            &base_info,
                            candidate,
                            outcome,
                            CandidateOrigin::Fallback,
                            candidates_evaluated,
                            candidates_improved,
                            new_fb_cancel,
                            target_flashblocks,
                            parent_hash,
                        )
                    }
                    None => {
                        self.record_continuous_candidate_metrics(
                            &fb_span,
                            candidates_evaluated,
                            candidates_improved,
                            CandidateLogEvent::FallbackNoCandidate,
                        );
                        debug_assert_eq!(
                            fallback_no_candidate_metrics_source(),
                            StopMetricsSource::IntervalBase,
                        );
                        Ok(ControlFlow::Break(PayloadBuildStats::new(
                            deps.payload_cancel.clone(),
                            deps.span.clone(),
                            base_fb_state.flashblock_index(),
                            base_info.executed_transactions.len(),
                            base_info.cumulative_uncompressed_bytes,
                            target_flashblocks,
                        )))
                    }
                }
            }
        }
    }

    /// Execute the planned outcome for a trigger that has a candidate.
    ///
    /// `candidate_ctx` is the context the candidate was built against
    /// (`base_ctx` on the Ready path, `base_state.ctx` on the Fallback path).
    #[expect(clippy::too_many_arguments)]
    fn execute_outcome(
        &self,
        deps: &JobDeps<'_>,
        fb_span: &tracing::Span,
        candidate_ctx: OpPayloadJobCtx,
        base_fb_state: &FlashblocksState,
        base_info: &ExecutionInfo,
        candidate: BestCandidate,
        outcome: TriggerOutcome,
        origin: CandidateOrigin,
        candidates_evaluated: u64,
        candidates_improved: u64,
        new_fb_cancel: FlashblockJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
    ) -> Result<ControlFlow<PayloadBuildStats, FlashblockInterval>, PayloadBuilderError> {
        match outcome {
            TriggerOutcome::PublishAndAdvance | TriggerOutcome::PublishAndStop => {
                let byte_size = self.publish_candidate(
                    &candidate,
                    deps.best_payload_tx,
                    fb_span,
                    &candidate_ctx,
                )?;
                self.record_continuous_candidate_metrics(
                    fb_span,
                    candidates_evaluated,
                    candidates_improved,
                    origin.published_log_event(),
                );
                let stop = matches!(outcome, TriggerOutcome::PublishAndStop);
                self.advance_or_stop_published(
                    deps,
                    fb_span,
                    candidate_ctx,
                    candidate,
                    byte_size,
                    candidates_evaluated,
                    candidates_improved,
                    new_fb_cancel,
                    target_flashblocks,
                    parent_hash,
                    stop,
                )
            }
            TriggerOutcome::SuppressAndStop {
                count_suppressed,
                metrics_source,
            } => {
                if count_suppressed {
                    debug_assert_eq!(metrics_source, StopMetricsSource::IntervalBase);
                    candidate_ctx
                        .metrics
                        .flashblock_publish_suppressed_total
                        .increment(1);
                }
                self.record_continuous_candidate_metrics(
                    fb_span,
                    candidates_evaluated,
                    candidates_improved,
                    CandidateLogEvent::CandidatePublishSuppressed,
                );
                Ok(ControlFlow::Break(PayloadBuildStats::new(
                    deps.payload_cancel.clone(),
                    deps.span.clone(),
                    base_fb_state.flashblock_index(),
                    base_info.executed_transactions.len(),
                    base_info.cumulative_uncompressed_bytes,
                    target_flashblocks,
                )))
            }
        }
    }

    fn record_continuous_candidate_metrics(
        &self,
        fb_span: &tracing::Span,
        candidates_evaluated: u64,
        candidates_improved: u64,
        event: CandidateLogEvent,
    ) {
        self.metrics()
            .continuous_candidates_evaluated
            .record(candidates_evaluated as f64);
        self.metrics()
            .continuous_candidates_improved
            .record(candidates_improved as f64);

        fb_span.record("candidates_evaluated", candidates_evaluated);
        fb_span.record("candidates_improved", candidates_improved);

        info!(
            target: "payload_builder",
            parent: fb_span,
            event = event.as_str(),
            candidates_evaluated,
            candidates_improved,
            "Continuous trigger handled"
        );
    }

    /// Record publish-side metrics for the just-published candidate, then
    /// either advance to the next flashblock interval or stop, per `stop`
    /// (decided up-front by `plan_with_candidate`).
    #[expect(clippy::too_many_arguments)]
    fn advance_or_stop_published(
        &self,
        deps: &JobDeps<'_>,
        fb_span: &tracing::Span,
        ctx: OpPayloadJobCtx,
        candidate: BestCandidate,
        byte_size: usize,
        candidates_evaluated: u64,
        candidates_improved: u64,
        new_fb_cancel: FlashblockJobCancellation,
        target_flashblocks: u64,
        parent_hash: B256,
        stop: bool,
    ) -> Result<ControlFlow<PayloadBuildStats, FlashblockInterval>, PayloadBuilderError> {
        let BestCandidate {
            result: (next_fb_state, _new_payload, _fb_payload_delta),
            cache,
            transition,
            info,
            fb_state,
            tx_tracker,
            limiter_snapshot,
            build_duration,
            state_root_calc,
            ..
        } = candidate;

        let mut base_state = BuildState {
            ctx,
            info,
            cache,
            transition,
            tx_tracker,
            fb_state,
            state_root_calc,
        };
        base_state
            .ctx
            .address_limiter()
            .restore_pending(&limiter_snapshot);

        if self.config().enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                payload_id = %base_state.ctx.payload_id(),
                block_number = base_state.ctx.block_number(),
                flashblock_index = base_state.fb_state.flashblock_index(),
                byte_size,
                total_txs = base_state.info.executed_transactions.len(),
                stage = "fb_published"
            );
        }

        base_state
            .ctx
            .metrics
            .flashblock_byte_size_histogram
            .record(byte_size as f64);
        base_state
            .ctx
            .metrics
            .flashblock_num_tx_histogram
            .record(base_state.info.executed_transactions.len() as f64);
        // Record only the winning candidate's single-build time, so this stays
        // comparable with the non-continuous path. The full trigger-to-trigger
        // interval is in `continuous_build_duration`.
        base_state
            .ctx
            .metrics
            .flashblock_build_duration
            .record(build_duration);

        fb_span.record(
            "tx_count",
            base_state.info.executed_transactions.len() as u64,
        );
        fb_span.record("gas_used", base_state.info.cumulative_gas_used);

        info!(
            target: "payload_builder",
            event = "flashblock_built",
            id = %base_state.ctx.payload_id(),
            flashblock_index = base_state.fb_state.flashblock_index(),
            current_gas = base_state.info.cumulative_gas_used,
            current_da = base_state.info.cumulative_da_bytes_used,
            target_flashblocks = base_state.fb_state.target_flashblock_count(),
            candidates_evaluated,
            candidates_improved,
            "Continuous flashblock built"
        );

        base_state.fb_state = next_fb_state;

        if stop {
            return Ok(ControlFlow::Break(PayloadBuildStats::new(
                deps.payload_cancel.clone(),
                deps.span.clone(),
                base_state.fb_state.flashblock_index(),
                base_state.info.executed_transactions.len(),
                base_state.info.cumulative_uncompressed_bytes,
                target_flashblocks,
            )));
        }

        base_state.ctx = base_state.ctx.with_cancel(new_fb_cancel);
        Ok(ControlFlow::Continue(self.start_flashblock_interval(
            parent_hash,
            deps.payload_cancel,
            deps.span,
            base_state,
        )))
    }
}
