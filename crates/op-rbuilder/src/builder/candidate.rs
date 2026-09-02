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
use eyre::WrapErr as _;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_optimism_node::OpBuiltPayload;
use reth_payload_util::BestPayloadTransactions;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::{
    State,
    db::{CacheState, TransitionState},
};
use revm::Database;
use std::{
    mem,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateKind {
    Empty,
    PoolBacked,
}

/// Preserves the distinct cancellation contracts of the naive and continuous builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterruptPolicy {
    JobOnly,
    JobAndFlashblock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateCheckpoint {
    AfterExecution,
    BeforeAssembly,
    AfterAssembly,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateBudgetTargets {
    gas: u64,
    da: Option<u64>,
    da_footprint: Option<u64>,
    max_uncompressed_block_size: Option<u64>,
}

impl CandidateBudgetTargets {
    pub(crate) fn from_fb_state(fb_state: &FlashblocksState) -> Self {
        Self {
            gas: fb_state.target_gas_for_batch(),
            da: fb_state.target_da_for_batch(),
            da_footprint: fb_state.target_da_footprint_for_batch(),
            max_uncompressed_block_size: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct CandidateTimings {
    pub(crate) pool_fetch: Option<Duration>,
    pub(crate) execution: Option<Duration>,
    pub(crate) assemble: Duration,
    pub(crate) total: Duration,
}

pub(crate) struct CarriedCandidate {
    pub(crate) cache: CacheState,
    pub(crate) transition: Option<TransitionState>,
    pub(crate) info: ExecutionInfo,
    pub(crate) fb_state: FlashblocksState,
    pub(crate) tx_tracker: FlashblockTxTracker,
    pub(crate) state_root_calc: StateRootCalculator,
}

impl CarriedCandidate {
    pub(crate) fn restore<DB>(
        self,
        state: &mut State<DB>,
        info: &mut ExecutionInfo,
        fb_state: &mut FlashblocksState,
        tx_tracker: &mut FlashblockTxTracker,
        state_root_calc: &mut StateRootCalculator,
    ) {
        state.cache = self.cache;
        state.transition_state = self.transition;
        *info = self.info;
        *fb_state = self.fb_state;
        *tx_tracker = self.tx_tracker;
        *state_root_calc = self.state_root_calc;
    }
}

pub(crate) struct BuiltCandidate {
    pub(crate) new_payload: OpBuiltPayload,
    pub(crate) fb_payload: OpFlashblockPayload,
    pub(crate) next_fb_state: FlashblocksState,
    pub(crate) carried: CarriedCandidate,
    pub(crate) timings: CandidateTimings,
}

pub(crate) struct CancelledCandidate {
    pub(crate) carried: CarriedCandidate,
    pub(crate) timings: CandidateTimings,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum CandidateOutcome {
    Built(BuiltCandidate),
    Cancelled(CancelledCandidate),
    SealFailed(CandidateSealFailure),
}

pub(crate) enum CandidateSealFailure {
    Input(eyre::Report),
    Assemble(eyre::Report),
}

impl CandidateSealFailure {
    pub(crate) fn into_continuous_error(self) -> eyre::Report {
        match self {
            Self::Input(err) => err.wrap_err("failed to construct block assembly input"),
            Self::Assemble(err) => err.wrap_err("failed to assemble candidate"),
        }
    }
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    pub(crate) fn prepare_candidate_budget<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadJobCtx,
        state_provider: impl reth::providers::StateProvider + Clone,
        state: &mut State<DB>,
        info: &mut ExecutionInfo,
        fb_state: &FlashblocksState,
    ) -> CandidateBudgetTargets {
        let mut targets = CandidateBudgetTargets::from_fb_state(fb_state);

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
                |err| error!(target: "payload_builder", %err, "Error simulating builder txs"),
            )
            .unwrap_or_default();

        targets.max_uncompressed_block_size = reserve_builder_tx_budget(
            &builder_txs,
            &mut targets.gas,
            &mut targets.da,
            &mut targets.da_footprint,
            info.da_footprint_scalar,
            ctx.max_uncompressed_block_size,
            info.cumulative_uncompressed_bytes,
        );
        targets
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn build_candidate<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        kind: CandidateKind,
        budget_targets: CandidateBudgetTargets,
        ctx: &OpPayloadJobCtx,
        state_provider: impl reth::providers::StateProvider + Clone,
        state: &mut State<DB>,
        mut info: ExecutionInfo,
        mut fb_state: FlashblocksState,
        mut tx_tracker: FlashblockTxTracker,
        mut state_root_calc: StateRootCalculator,
        cancellation: &CancellationToken,
        interrupt_policy: InterruptPolicy,
    ) -> eyre::Result<CandidateOutcome> {
        let total_start = Instant::now();
        let flashblock_index = fb_state.flashblock_index();
        let target_gas_for_batch = budget_targets.gas;
        let target_da_for_batch = budget_targets.da;
        let target_da_footprint_for_batch = budget_targets.da_footprint;

        let mut pool_fetch = None;
        let mut execution = None;
        if kind.uses_pool() {
            let pool_fetch_start = Instant::now();
            let mut best_txs = FlashblockPoolTxCursor::new(&mut tx_tracker);
            best_txs.refresh_iterator(
                BestPayloadTransactions::new(
                    self.pool()
                        .best_transactions_with_attributes(ctx.best_transaction_attributes()),
                ),
                flashblock_index,
            );
            pool_fetch = Some(pool_fetch_start.elapsed());

            let execution_start = Instant::now();
            let execution_cancelled = ctx
                .execute_best_transactions(
                    &mut info,
                    state,
                    &mut best_txs,
                    target_gas_for_batch.min(ctx.block_gas_limit()),
                    target_da_for_batch,
                    // The executor's Jovian footprint check is bounded by block gas, so never
                    // expose it to a caller budget above that consensus limit.
                    target_da_footprint_for_batch.map(|target| target.min(ctx.block_gas_limit())),
                    budget_targets.max_uncompressed_block_size,
                    flashblock_index,
                )
                .wrap_err("failed to execute best transactions")?
                .is_some();

            let new_transactions = fb_state
                .slice_new_transactions(&info.executed_transactions)
                .iter()
                .map(|tx| tx.tx_hash())
                .collect::<Vec<_>>();
            best_txs.mark_committed(new_transactions);
            drop(best_txs);

            if !info.reverted_bundle_tx_hashes.is_empty() {
                self.pool()
                    .remove_transactions(mem::take(&mut info.reverted_bundle_tx_hashes));
            }
            if interrupt_policy.should_interrupt(
                kind,
                CandidateCheckpoint::AfterExecution,
                cancellation.is_cancelled(),
                ctx.cancel().is_cancelled(),
                execution_cancelled,
            ) {
                return Ok(CandidateOutcome::Cancelled(CancelledCandidate {
                    carried: take_carried(state, info, fb_state, tx_tracker, state_root_calc),
                    timings: CandidateTimings {
                        pool_fetch,
                        total: total_start.elapsed(),
                        ..Default::default()
                    },
                }));
            }
            execution = Some(execution_start.elapsed());
        }

        if let Err(err) = self.builder_tx().add_builder_txs(
            &state_provider,
            &mut info,
            &ctx.builder_tx_env(),
            state,
            false,
            fb_state.is_first_flashblock(),
            fb_state.is_last_flashblock(),
        ) {
            error!(target: "payload_builder", %err, "Error adding bottom builder txs");
        }

        if interrupt_policy.should_interrupt(
            kind,
            CandidateCheckpoint::BeforeAssembly,
            cancellation.is_cancelled(),
            ctx.cancel().is_cancelled(),
            false,
        ) {
            return Ok(cancellation_before_assemble(
                state,
                info,
                fb_state,
                tx_tracker,
                state_root_calc,
                CandidateTimings {
                    pool_fetch,
                    execution,
                    total: total_start.elapsed(),
                    ..Default::default()
                },
            ));
        }

        let assemble_start = Instant::now();
        let input = match ctx.block_assembly_input() {
            Ok(input) => input,
            Err(err) => {
                return Ok(CandidateOutcome::SealFailed(CandidateSealFailure::Input(
                    err.into(),
                )));
            }
        };
        let build_result = input.assemble(
            state,
            Some(&mut fb_state),
            &mut info,
            &mut state_root_calc,
            ctx.metrics.clone(),
            ctx.enable_tx_tracking_debug_logs,
        );
        let assemble = assemble_start.elapsed();
        let (new_payload, mut fb_payload) = match build_result {
            Ok(output) => output,
            Err(err) => {
                return Ok(CandidateOutcome::SealFailed(
                    CandidateSealFailure::Assemble(err.into()),
                ));
            }
        };

        fb_payload.index = flashblock_index;
        fb_payload.base = None;

        debug_assert!(!interrupt_policy.should_interrupt(
            kind,
            CandidateCheckpoint::AfterAssembly,
            cancellation.is_cancelled(),
            ctx.cancel().is_cancelled(),
            false,
        ));

        let next_fb_state =
            fb_state.next_after_seal(target_da_for_batch, target_da_footprint_for_batch);
        let carried = take_carried(state, info, fb_state, tx_tracker, state_root_calc);
        Ok(completed_candidate(BuiltCandidate {
            new_payload,
            fb_payload,
            next_fb_state,
            carried,
            timings: CandidateTimings {
                pool_fetch,
                execution,
                assemble,
                total: total_start.elapsed(),
            },
        }))
    }
}

impl CandidateKind {
    fn uses_pool(self) -> bool {
        self == Self::PoolBacked
    }
}

impl InterruptPolicy {
    fn should_interrupt(
        self,
        kind: CandidateKind,
        checkpoint: CandidateCheckpoint,
        job_cancelled: bool,
        flashblock_cancelled: bool,
        execution_cancelled: bool,
    ) -> bool {
        if kind == CandidateKind::Empty || checkpoint == CandidateCheckpoint::AfterAssembly {
            return false;
        }
        match self {
            Self::JobOnly => checkpoint == CandidateCheckpoint::AfterExecution && job_cancelled,
            Self::JobAndFlashblock => {
                job_cancelled
                    || flashblock_cancelled
                    || (checkpoint == CandidateCheckpoint::AfterExecution && execution_cancelled)
            }
        }
    }
}

fn cancellation_before_assemble<DB>(
    state: &mut State<DB>,
    info: ExecutionInfo,
    fb_state: FlashblocksState,
    tx_tracker: FlashblockTxTracker,
    state_root_calc: StateRootCalculator,
    timings: CandidateTimings,
) -> CandidateOutcome {
    CandidateOutcome::Cancelled(CancelledCandidate {
        carried: take_carried(state, info, fb_state, tx_tracker, state_root_calc),
        timings,
    })
}

fn take_carried<DB>(
    state: &mut State<DB>,
    info: ExecutionInfo,
    fb_state: FlashblocksState,
    tx_tracker: FlashblockTxTracker,
    state_root_calc: StateRootCalculator,
) -> CarriedCandidate {
    CarriedCandidate {
        cache: mem::take(&mut state.cache),
        transition: state.transition_state.take(),
        info,
        fb_state,
        tx_tracker,
        state_root_calc,
    }
}

fn completed_candidate(candidate: BuiltCandidate) -> CandidateOutcome {
    CandidateOutcome::Built(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockBody, Header};
    use alloy_primitives::U256;
    use reth_optimism_primitives::OpBlock;
    use reth_payload_builder::PayloadId;
    use reth_primitives_traits::Block as _;
    use revm::database::EmptyDB;
    use std::sync::Arc;

    fn budget_state() -> FlashblocksState {
        FlashblocksState::new(5).with_batch_limits(
            100_000,
            Some(1_000),
            Some(500),
            100_000,
            Some(1_000),
            Some(500),
        )
    }

    #[test]
    fn empty_candidate_skips_only_pool_segment() {
        assert!(!CandidateKind::Empty.uses_pool());
        assert!(CandidateKind::PoolBacked.uses_pool());
    }

    #[test]
    fn budget_carry_advances_across_two_candidates() {
        let first = budget_state().next_after_seal(Some(700), Some(400));
        assert_eq!(first.flashblock_index(), 1);
        assert_eq!(first.target_gas_for_batch(), 200_000);
        assert_eq!(first.target_da_for_batch(), Some(1_700));
        assert_eq!(first.target_da_footprint_for_batch(), Some(900));

        let second = first.next_after_seal(Some(1_200), Some(650));
        assert_eq!(second.flashblock_index(), 2);
        assert_eq!(second.target_gas_for_batch(), 300_000);
        assert_eq!(second.target_da_for_batch(), Some(2_200));
        assert_eq!(second.target_da_footprint_for_batch(), Some(1_150));
    }

    #[test]
    fn cancellation_before_assemble_returns_carried_state_without_output() {
        let mut state = State::builder()
            .with_database(EmptyDB::default())
            .with_bundle_update()
            .build();
        let fb_state = budget_state();
        let outcome = cancellation_before_assemble(
            &mut state,
            ExecutionInfo::default(),
            fb_state,
            FlashblockTxTracker::default(),
            StateRootCalculator::new(true, false),
            CandidateTimings::default(),
        );

        let CandidateOutcome::Cancelled(cancelled) = outcome else {
            panic!("cancellation must not publish candidate outputs");
        };
        assert_eq!(cancelled.carried.fb_state.flashblock_index(), 0);
        assert!(state.transition_state.is_none());
    }

    #[test]
    fn job_only_ignores_flashblock_and_execution_cancellation() {
        let job = CancellationToken::new();
        let flashblock = CancellationToken::new();
        flashblock.cancel();

        assert!(!InterruptPolicy::JobOnly.should_interrupt(
            CandidateKind::PoolBacked,
            CandidateCheckpoint::AfterExecution,
            job.is_cancelled(),
            flashblock.is_cancelled(),
            true,
        ));
    }

    #[test]
    fn empty_candidate_ignores_all_cancellation() {
        let job = CancellationToken::new();
        let flashblock = CancellationToken::new();
        job.cancel();
        flashblock.cancel();

        assert!(!InterruptPolicy::JobAndFlashblock.should_interrupt(
            CandidateKind::Empty,
            CandidateCheckpoint::AfterExecution,
            job.is_cancelled(),
            flashblock.is_cancelled(),
            true,
        ));
    }

    #[test]
    fn cancelled_candidate_carried_state_is_restorable() {
        let mut state = State::builder()
            .with_database(EmptyDB::default())
            .with_bundle_update()
            .build();
        state.transition_state = Some(TransitionState::default());
        let mut restored_info = ExecutionInfo::default();
        let mut restored_fb_state = FlashblocksState::default();
        let mut restored_tracker = FlashblockTxTracker::default();
        let mut restored_root_calc = StateRootCalculator::new(false, false);
        let mut carried_info = ExecutionInfo::default();
        let expected_fees = alloy_primitives::U256::from_limbs([42, 0, 0, 0]);
        carried_info.total_fees = expected_fees;
        let carried_fb_state = budget_state().next_after_seal(Some(700), Some(400));
        let cancelled = cancellation_before_assemble(
            &mut state,
            carried_info,
            carried_fb_state,
            FlashblockTxTracker::default(),
            StateRootCalculator::new(true, false),
            CandidateTimings::default(),
        );
        let CandidateOutcome::Cancelled(cancelled) = cancelled else {
            panic!("expected cancelled candidate");
        };

        cancelled.carried.restore(
            &mut state,
            &mut restored_info,
            &mut restored_fb_state,
            &mut restored_tracker,
            &mut restored_root_calc,
        );

        assert!(state.transition_state.is_some());
        assert_eq!(restored_info.total_fees, expected_fees);
        assert_eq!(restored_fb_state.flashblock_index(), 1);
    }

    #[test]
    fn assembled_candidate_is_not_discarded_by_primitive_policy() {
        let job = CancellationToken::new();
        let flashblock = CancellationToken::new();
        job.cancel();
        flashblock.cancel();

        // The last primitive checkpoint is before assembly; callers decide
        // whether a successfully assembled candidate may be published.
        assert!(!InterruptPolicy::JobAndFlashblock.should_interrupt(
            CandidateKind::PoolBacked,
            CandidateCheckpoint::AfterAssembly,
            job.is_cancelled(),
            flashblock.is_cancelled(),
            false,
        ));

        let carried = CarriedCandidate {
            cache: CacheState::default(),
            transition: None,
            info: ExecutionInfo::default(),
            fb_state: budget_state(),
            tx_tracker: FlashblockTxTracker::default(),
            state_root_calc: StateRootCalculator::new(true, false),
        };
        let outcome = completed_candidate(BuiltCandidate {
            new_payload: OpBuiltPayload::new(
                PayloadId::new([0; 8]),
                Arc::new(OpBlock::new(Header::default(), BlockBody::default()).seal_slow()),
                U256::ZERO,
                None,
            ),
            fb_payload: OpFlashblockPayload::default(),
            next_fb_state: budget_state(),
            carried,
            timings: CandidateTimings::default(),
        });

        assert!(matches!(outcome, CandidateOutcome::Built(_)));
    }
}
