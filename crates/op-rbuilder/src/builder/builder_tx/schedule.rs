use alloy_eips::Encodable2718;
use alloy_evm::Database;
use alloy_primitives::map::HashSet;
use reth_evm::{Evm, EvmError, InvalidTxError};
use reth_provider::StateProvider;
use reth_revm::State;
use revm::context::result::ResultAndState;
use std::sync::Arc;
use tracing::{error, trace, warn};

use crate::{builder::builder_tx::sim::commit_tx, primitives::reth::ExecutionInfo};

use super::{
    env::BuilderTxEnv,
    producer::{BuilderTxError, BuilderTxProducer, SimulatedBuilderTx},
    sim::new_simulation_state,
};

/// Where in the block build sequence a builder transaction runs.
///
/// Each variant corresponds to a distinct dispatch point. The block builder
/// calls the matching [`BuilderTxSchedule`] method at each point without
/// passing any position flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderTxPosition {
    /// After sequencer transactions and before user transactions.
    TopOfBlock,
    /// Before user transactions in each flashblock.
    TopOfFlashblock,
    /// After user transactions in the last flashblock.
    BottomOfBlock,
}

/// Schedule entry pairing a producer with its dispatch position.
#[derive(derive_more::Constructor)]
pub struct ScheduledBuilderTx {
    source: Arc<dyn BuilderTxProducer>,
    position: BuilderTxPosition,
}

impl std::fmt::Debug for ScheduledBuilderTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledBuilderTx")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

/// The set of builder-transaction producers, each scheduled at a named point
/// in the block build sequence.
///
/// Each method corresponds to a dispatch point. The block builder calls the
/// right method at the right moment without passing position flags.
#[derive(Debug, Default)]
pub struct BuilderTxSchedule {
    scheduled: Vec<ScheduledBuilderTx>,
}

impl BuilderTxSchedule {
    pub fn new(scheduled: Vec<ScheduledBuilderTx>) -> Self {
        Self { scheduled }
    }

    pub fn commit_top_of_block(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &mut ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        db: &mut State<impl Database>,
    ) -> Result<(), BuilderTxError> {
        commit_builder_txs(
            &self.scheduled,
            state_provider,
            info,
            env,
            db,
            BuilderTxPosition::TopOfBlock,
        )
    }

    pub fn commit_top_of_flashblock(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &mut ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        db: &mut State<impl Database>,
    ) -> Result<(), BuilderTxError> {
        commit_builder_txs(
            &self.scheduled,
            state_provider,
            info,
            env,
            db,
            BuilderTxPosition::TopOfFlashblock,
        )
    }

    pub fn estimate_bottom_of_block(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        db: &State<impl Database>,
    ) -> Vec<SimulatedBuilderTx> {
        simulate_scheduled(
            &self.scheduled,
            state_provider,
            info,
            env,
            db,
            BuilderTxPosition::BottomOfBlock,
        )
    }

    pub fn commit_bottom_of_block(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &mut ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        db: &mut State<impl Database>,
    ) -> Result<(), BuilderTxError> {
        commit_builder_txs(
            &self.scheduled,
            state_provider,
            info,
            env,
            db,
            BuilderTxPosition::BottomOfBlock,
        )
    }
}

/// Simulate the scheduled builder transactions matching `position` without
/// committing to any real state.
///
/// Iterates `scheduled` in order with a shared simulation state (a throwaway
/// copy of `db`'s cache), committing each entry's txs to it so later entries
/// see correct nonces. The returned txs carry gas and DA estimates suitable
/// for `reserve_builder_tx_budget`.
pub(crate) fn simulate_scheduled(
    scheduled: &[ScheduledBuilderTx],
    state_provider: Arc<dyn StateProvider + Send>,
    info: &ExecutionInfo,
    env: &BuilderTxEnv<'_>,
    db: &State<impl Database>,
    position: BuilderTxPosition,
) -> Vec<SimulatedBuilderTx> {
    let mut sim_state = new_simulation_state(state_provider.clone(), db);

    scheduled
        .iter()
        .filter(|scheduled| scheduled.position == position)
        .flat_map(|scheduled| {
            let txs = scheduled
                .source
                .simulate_builder_txs(state_provider.clone(), info, env, &mut sim_state)
                .inspect_err(|e| {
                    error!(
                        target: "payload_builder",
                        error = %e,
                        position = ?position,
                        "Error simulating builder txs"
                    );
                })
                .unwrap_or_default();

            txs.iter().for_each(|tx| {
                if let Err(e) = commit_tx(tx.signed_tx.clone(), env, &mut sim_state) {
                    warn!(
                        target: "payload_builder",
                        error = %e,
                        "failed to commit builder txs to simulation state"
                    );
                }
            });

            txs
        })
        .collect()
}

/// Simulate builder transactions and commit the returned ones to the real `db`.
pub(crate) fn commit_builder_txs(
    scheduled: &[ScheduledBuilderTx],
    state_provider: Arc<dyn StateProvider + Send>,
    info: &mut ExecutionInfo,
    env: &BuilderTxEnv<'_>,
    db: &mut State<impl Database>,
    position: BuilderTxPosition,
) -> Result<(), BuilderTxError> {
    let builder_txs = simulate_scheduled(scheduled, state_provider, info, env, db, position);

    let mut evm = env.evm_factory.evm(&mut *db);

    let mut invalid = HashSet::new();

    for builder_tx in builder_txs.iter() {
        if invalid.contains(&builder_tx.signed_tx.signer()) {
            warn!(
                target: "payload_builder",
                tx_hash = %builder_tx.signed_tx.tx_hash(),
                "builder signer invalid as previous builder tx reverted"
            );
            continue;
        }

        let ResultAndState { result, state } = match evm.transact(&builder_tx.signed_tx) {
            Ok(res) => res,
            Err(err) => {
                if let Some(err) = err.as_invalid_tx_err() {
                    if err.is_nonce_too_low() {
                        trace!(
                            target: "payload_builder",
                            error = %err,
                            tx_hash = %builder_tx.signed_tx.tx_hash(),
                            "skipping nonce too low builder transaction"
                        );
                    } else {
                        trace!(
                            target: "payload_builder",
                            error = %err,
                            tx_hash = %builder_tx.signed_tx.tx_hash(),
                            "skipping invalid builder transaction and its descendants"
                        );
                        invalid.insert(builder_tx.signed_tx.signer());
                    }
                    continue;
                }
                return Err(BuilderTxError::EvmExecutionError(Box::new(err)));
            }
        };

        if !result.is_success() {
            warn!(
                target: "payload_builder",
                tx_hash = %builder_tx.signed_tx.tx_hash(),
                result = ?result,
                "builder tx reverted"
            );
            invalid.insert(builder_tx.signed_tx.signer());
            continue;
        }

        let tx_uncompressed_size = builder_tx.signed_tx.inner().encode_2718_len() as u64;

        if let Some(limit) = env.max_uncompressed_block_size
            && info.cumulative_uncompressed_bytes + tx_uncompressed_size > limit
        {
            warn!(
                target: "payload_builder",
                tx_hash = %builder_tx.signed_tx.tx_hash(),
                cumulative_uncompressed = info.cumulative_uncompressed_bytes,
                tx_uncompressed_size,
                limit,
                "skipping builder tx: would exceed max uncompressed block size"
            );
            continue;
        }

        info.commit_tx(
            &builder_tx.signed_tx,
            result,
            state,
            builder_tx.da_size,
            None,
            None,
            env.evm_factory,
            env.hardforks,
            &mut evm,
        );
    }

    Ok(())
}

/// Adjust batch gas/DA/uncompressed limits to reserve capacity for the provided builder txs.
/// `builder_txs` should be the bottom-of-block txs that have not yet been committed.
/// Returns the adjusted `max_uncompressed_block_size`.
pub(crate) fn reserve_builder_tx_budget(
    builder_txs: &[SimulatedBuilderTx],
    target_gas: &mut u64,
    target_da: &mut Option<u64>,
    target_da_footprint: &mut Option<u64>,
    da_footprint_scalar: Option<u16>,
    env_max_uncompressed: Option<u64>,
    cumulative_uncompressed: u64,
) -> Option<u64> {
    let mut builder_tx_gas: u64 = 0;
    let mut builder_tx_da_size: u64 = 0;
    let mut builder_tx_uncompressed_size: u64 = 0;
    for tx in builder_txs {
        builder_tx_gas += tx.gas_used;
        builder_tx_da_size += tx.da_size;
        builder_tx_uncompressed_size += tx.signed_tx.inner().encode_2718_len() as u64;
    }

    *target_gas = target_gas.saturating_sub(builder_tx_gas);

    if let Some(da_limit) = target_da.as_mut() {
        *da_limit = da_limit.saturating_sub(builder_tx_da_size);
    }

    if let (Some(footprint), Some(scalar)) = (target_da_footprint.as_mut(), da_footprint_scalar) {
        *footprint = footprint.saturating_sub(builder_tx_da_size.saturating_mul(u64::from(scalar)));
    }

    let max_uncompressed =
        env_max_uncompressed.map(|limit| limit.saturating_sub(builder_tx_uncompressed_size));
    if let Some(limit) = env_max_uncompressed
        && cumulative_uncompressed >= limit.saturating_sub(builder_tx_uncompressed_size)
    {
        error!(
            target: "payload_builder",
            current_uncompressed = cumulative_uncompressed,
            reserved_builder_tx_uncompressed = builder_tx_uncompressed_size,
            limit,
            "Builder tx uncompressed size subtraction caused max_uncompressed_block_size to be 0. \
             No transaction would be included."
        );
    }

    max_uncompressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_signer::Signer;
    use op_alloy_consensus::OpTypedTransaction;

    fn mock_builder_tx(gas_used: u64, da_size: u64) -> SimulatedBuilderTx {
        let signer = Signer::random();
        let signed = signer
            .sign_tx(OpTypedTransaction::Legacy(Default::default()))
            .unwrap();
        SimulatedBuilderTx {
            gas_used,
            da_size,
            signed_tx: signed,
        }
    }

    #[test]
    fn test_reserve_budget_empty_txs() {
        let mut gas = 1_000_000;
        let mut da = Some(10_000u64);
        let mut footprint = Some(50_000u64);

        let result = reserve_builder_tx_budget(
            &[],
            &mut gas,
            &mut da,
            &mut footprint,
            Some(1),
            Some(100_000),
            0,
        );

        assert_eq!(gas, 1_000_000, "gas unchanged");
        assert_eq!(da, Some(10_000), "da unchanged");
        assert_eq!(footprint, Some(50_000), "footprint unchanged");
        assert_eq!(result, Some(100_000), "uncompressed unchanged");
    }

    #[test]
    fn test_reserve_budget_bottom_txs_counted() {
        let txs = vec![mock_builder_tx(50_000, 200)];
        let mut gas = 1_000_000;
        let mut da = Some(10_000u64);
        let mut footprint = None;

        reserve_builder_tx_budget(&txs, &mut gas, &mut da, &mut footprint, None, None, 0);

        assert_eq!(gas, 950_000, "bottom tx gas subtracted");
        assert_eq!(da, Some(9_800), "bottom tx da subtracted");
    }

    #[test]
    fn test_reserve_budget_saturating_sub() {
        let txs = vec![mock_builder_tx(2_000_000, 50_000)];
        let mut gas = 1_000_000;
        let mut da = Some(10_000u64);
        let mut footprint = Some(100u64);

        reserve_builder_tx_budget(&txs, &mut gas, &mut da, &mut footprint, Some(1), None, 0);

        assert_eq!(gas, 0, "gas saturates at 0");
        assert_eq!(da, Some(0), "da saturates at 0");
        assert_eq!(footprint, Some(0), "footprint saturates at 0");
    }

    #[test]
    fn test_reserve_budget_da_none_untouched() {
        let txs = vec![mock_builder_tx(100, 200)];
        let mut gas = 1_000;
        let mut da: Option<u64> = None;
        let mut footprint: Option<u64> = None;

        reserve_builder_tx_budget(&txs, &mut gas, &mut da, &mut footprint, None, None, 0);

        assert_eq!(gas, 900);
        assert_eq!(da, None, "None da stays None");
        assert_eq!(footprint, None, "None footprint stays None");
    }

    #[test]
    fn test_reserve_budget_uncompressed_limit_reduction() {
        let txs = vec![mock_builder_tx(0, 0)];
        let mut gas = 1_000_000;

        let result = reserve_builder_tx_budget(
            &txs,
            &mut gas,
            &mut None,
            &mut None,
            None,
            Some(1_000_000),
            0,
        );

        assert!(result.is_some());
        assert!(
            result.unwrap() < 1_000_000,
            "uncompressed limit reduced by tx encoded size"
        );
    }
}
