use alloy_primitives::{Address, B256};
use alloy_sol_types::Revert;
use op_revm::OpHaltReason;
use reth_node_api::PayloadBuilderError;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::Recovered;
use reth_provider::StateProvider;
use std::sync::Arc;

use crate::primitives::reth::ExecutionInfo;

use super::{env::BuilderTxEnv, sim::SimulationState};

#[derive(Debug, Clone)]
pub struct SimulatedBuilderTx {
    pub gas_used: u64,
    pub da_size: u64,
    pub signed_tx: Recovered<OpTransactionSigned>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidContractDataError {
    #[error("did not find expected logs expected {0:?} but got {1:?}")]
    InvalidLogs(Vec<B256>, Vec<B256>),
    #[error("could not decode output from contract call")]
    OutputAbiDecodeError,
}

/// Possible error variants during construction of builder txs.
#[derive(Debug, thiserror::Error)]
pub enum BuilderTxError {
    #[error("failed to load account {0}")]
    AccountLoadFailed(Address),
    #[error("failed to sign transaction: {0}")]
    SigningError(secp256k1::Error),
    #[error("contract {0} may be incorrect, invalid contract data: {1}")]
    InvalidContract(Address, InvalidContractDataError),
    #[error("transaction to {0} halted {1:?}")]
    TransactionHalted(Address, OpHaltReason),
    #[error("transaction to {0} reverted {1}")]
    TransactionReverted(Address, Revert),
    #[error("invalid transaction error {0}")]
    InvalidTransactionError(Box<dyn core::error::Error + Send + Sync>),
    #[error("evm execution error {0}")]
    EvmExecutionError(Box<dyn core::error::Error + Send + Sync>),
    #[error(transparent)]
    Other(Box<dyn core::error::Error + Send + Sync>),
}

impl From<secp256k1::Error> for BuilderTxError {
    fn from(error: secp256k1::Error) -> Self {
        BuilderTxError::SigningError(error)
    }
}

impl From<BuilderTxError> for PayloadBuilderError {
    fn from(error: BuilderTxError) -> Self {
        match error {
            BuilderTxError::EvmExecutionError(e) => PayloadBuilderError::EvmExecutionError(e),
            _ => PayloadBuilderError::other(error),
        }
    }
}

impl BuilderTxError {
    pub fn other(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        BuilderTxError::Other(Box::new(error))
    }

    pub fn msg(msg: impl core::fmt::Display) -> Self {
        Self::Other(msg.to_string().into())
    }
}

pub trait BuilderTxProducer: Send + Sync {
    /// Simulates and returns the signed builder transactions.
    ///
    /// The simulation commits changes to `sim_state`, which is a copy of the
    /// real block state. The caller is responsible for creating `sim_state` via
    /// [`super::sim::new_simulation_state`] and then re-executing the returned
    /// transactions against the real database.
    ///
    /// Positioning is declared at scheduling time via
    /// [`super::schedule::ScheduledBuilderTx`] and is not passed here.
    fn simulate_builder_txs(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        sim_state: &mut SimulationState,
    ) -> Result<Vec<SimulatedBuilderTx>, BuilderTxError>;
}
