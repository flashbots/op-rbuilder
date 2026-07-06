use alloy_consensus::TxEip1559;
use alloy_evm::{Database, rpc::TryIntoTxEnv};
use alloy_op_evm::{OpEvm, OpTx};
use alloy_primitives::{Address, B256, Bytes, TxKind, map::HashSet};
use alloy_sol_types::{ContractError, Revert, SolCall, SolError, SolInterface};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use op_alloy_rpc_types::OpTransactionRequest;
use op_revm::OpTransactionError;
use reth_evm::{Evm, EvmError, InvalidTxError, precompiles::PrecompilesMap};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::Recovered;
use reth_provider::{ProviderError, StateProvider};
use reth_revm::{State, database::StateProviderDatabase};
use reth_rpc_api::eth::EthTxEnvError;
use revm::{
    DatabaseCommit, DatabaseRef,
    context::result::{EVMError, ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
};
use std::sync::Arc;
use tracing::trace;

use crate::tx_signer::Signer;

use super::{
    env::BuilderTxEnv,
    producer::{BuilderTxError, InvalidContractDataError},
};

#[derive(Debug, Default)]
pub struct SimulationSuccessResult<T: SolCall> {
    pub gas_used: u64,
    pub output: T::Return,
    pub state_changes: revm::state::EvmState,
}

/// The concrete state type used for simulating builder transactions.
pub type SimulationState = State<StateProviderDatabase<Arc<dyn StateProvider + Send>>>;

/// Creates a copy of the state backed by `state_provider` to simulate against.
pub(super) fn new_simulation_state(
    state_provider: Arc<dyn StateProvider + Send>,
    db: &State<impl Database>,
) -> SimulationState {
    let state = StateProviderDatabase::new(state_provider);

    State::builder()
        .with_database(state)
        .with_cached_prestate(db.cache.clone())
        .with_bundle_update()
        .build()
}

pub fn sign_tx(
    to: Address,
    from: Signer,
    gas_used: u64,
    calldata: Bytes,
    env: &BuilderTxEnv<'_>,
    db: impl DatabaseRef,
) -> Result<Recovered<OpTransactionSigned>, BuilderTxError> {
    let nonce = get_nonce(db, from.address)?;
    let tx = OpTypedTransaction::Eip1559(TxEip1559 {
        chain_id: env.chain_id(),
        nonce,
        // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
        gas_limit: gas_used * 64 / 63,
        max_fee_per_gas: env.base_fee.into(),
        to: TxKind::Call(to),
        input: calldata,
        ..Default::default()
    });
    Ok(from.sign_tx(tx)?)
}

/// Commit a signed transaction to the state.
///
/// Transactions whose nonce is too low are skipped rather than treated as
/// errors: an implementor of [`super::producer::BuilderTxProducer`] may commit
/// its own txs' state during simulation (e.g. to chain nonces between its own
/// txs), so re-executing those here is expected to no-op.
pub(super) fn commit_tx(
    signed_tx: Recovered<OpTransactionSigned>,
    env: &BuilderTxEnv<'_>,
    db: &mut State<impl Database>,
) -> Result<(), BuilderTxError> {
    let mut evm = env.evm_factory.evm(&mut *db);

    let ResultAndState { state, .. } = match evm.transact(&signed_tx) {
        Ok(res) => res,
        Err(err) => {
            if let Some(invalid) = err.as_invalid_tx_err()
                && invalid.is_nonce_too_low()
            {
                trace!(
                    target: "payload_builder",
                    tx_hash = %signed_tx.tx_hash(),
                    "skipping already-committed builder transaction"
                );
                return Ok(());
            } else {
                return Err(BuilderTxError::EvmExecutionError(Box::new(err)));
            }
        }
    };
    evm.db_mut().commit(state);

    Ok(())
}

pub fn simulate_call<T: SolCall, E: SolInterface + Debug>(
    tx: OpTransactionRequest,
    expected_logs: Vec<B256>,
    evm: &mut OpEvm<impl Database, NoOpInspector, PrecompilesMap>,
) -> Result<SimulationSuccessResult<T>, BuilderTxError> {
    let evm_env = alloy_evm::EvmEnv::new(evm.cfg_env().clone(), evm.block().clone());
    let tx_env: revm::context::TxEnv = tx.as_ref().clone().try_into_tx_env(&evm_env)?;
    let to = tx_env.kind.into_to().unwrap_or_default();
    let op_tx = OpTx(op_revm::OpTransaction {
        base: tx_env,
        enveloped_tx: Some(Bytes::new()),
        deposit: Default::default(),
    });

    let ResultAndState { result, state } = match evm.transact(op_tx) {
        Ok(res) => res,
        Err(err) => {
            if err.is_invalid_tx_err() {
                return Err(BuilderTxError::InvalidTransactionError(Box::new(err)));
            } else {
                return Err(BuilderTxError::EvmExecutionError(Box::new(err)));
            }
        }
    };
    let gas_used = result.tx_gas_used();

    match result {
        ExecutionResult::Success { output, logs, .. } => {
            let topics: HashSet<B256> = logs
                .into_iter()
                .flat_map(|log| log.topics().to_vec())
                .collect();
            if !expected_logs
                .iter()
                .all(|expected_topic| topics.contains(expected_topic))
            {
                return Err(BuilderTxError::InvalidContract(
                    to,
                    InvalidContractDataError::InvalidLogs(
                        expected_logs,
                        topics.into_iter().collect(),
                    ),
                ));
            }
            let return_output = T::abi_decode_returns(&output.into_data()).map_err(|_| {
                BuilderTxError::InvalidContract(to, InvalidContractDataError::OutputAbiDecodeError)
            })?;
            Ok(SimulationSuccessResult::<T> {
                gas_used,
                output: return_output,
                state_changes: state,
            })
        }
        ExecutionResult::Revert { output, .. } => {
            let revert = ContractError::<E>::abi_decode(&output)
                .map(|reason| Revert::from(format!("{reason:?}")))
                .or_else(|_| Revert::abi_decode(&output))
                .unwrap_or_else(|_| {
                    Revert::from(format!("unknown revert: {}", hex::encode(&output)))
                });
            Err(BuilderTxError::TransactionReverted(to, revert))
        }
        ExecutionResult::Halt { reason, .. } => Err(BuilderTxError::TransactionHalted(to, reason)),
    }
}

pub fn get_nonce(db: impl DatabaseRef, address: Address) -> Result<u64, BuilderTxError> {
    db.basic_ref(address)
        .map(|acc| acc.unwrap_or_default().nonce)
        .map_err(|_| BuilderTxError::AccountLoadFailed(address))
}

impl From<EVMError<ProviderError, OpTransactionError>> for BuilderTxError {
    fn from(error: EVMError<ProviderError, OpTransactionError>) -> Self {
        BuilderTxError::EvmExecutionError(Box::new(error))
    }
}

impl From<EthTxEnvError> for BuilderTxError {
    fn from(error: EthTxEnvError) -> Self {
        BuilderTxError::EvmExecutionError(Box::new(error))
    }
}
