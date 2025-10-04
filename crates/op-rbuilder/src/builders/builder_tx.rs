use alloy_consensus::{Transaction, TxEip1559};
use alloy_eips::{Encodable2718, eip7623::TOTAL_COST_FLOOR_PER_TOKEN};
use alloy_evm::Database;
use alloy_op_evm::OpEvm;
use alloy_primitives::{
    Address, B256, Bytes, TxKind, U256,
    map::foldhash::{HashMap, HashSet, HashSetExt},
};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use op_revm::{OpHaltReason, OpTransactionError};
use reth_evm::{
    ConfigureEvm, Evm, EvmError, eth::receipt_builder::ReceiptBuilderCtx,
    precompiles::PrecompilesMap,
};
use reth_node_api::PayloadBuilderError;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use reth_provider::{ProviderError, StateProvider};
use reth_revm::{State, database::StateProviderDatabase};
use revm::{
    DatabaseCommit,
    context::result::{EVMError, ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
    state::Account,
};
use tracing::warn;

use crate::{
    builders::context::OpPayloadBuilderCtx, primitives::reth::ExecutionInfo, tx_signer::Signer,
};

#[derive(Debug, Default)]
pub struct SimulationSuccessResult {
    pub gas_used: u64,
    pub output: Bytes,
    pub state_changes: HashMap<Address, Account>,
}

#[derive(Debug, Clone)]
pub struct BuilderTransactionCtx {
    pub gas_used: u64,
    pub da_size: u64,
    pub signed_tx: Recovered<OpTransactionSigned>,
    // whether the transaction should be a top of block or
    // bottom of block transaction
    pub is_top_of_block: bool,
}

impl BuilderTransactionCtx {
    pub fn set_top_of_block(mut self) -> Self {
        self.is_top_of_block = true;
        self
    }

    pub fn set_bottom_of_block(mut self) -> Self {
        self.is_top_of_block = false;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidContractDataError {
    #[error("did not find expected log {0:?} in emitted logs")]
    InvalidLogs(B256),
    #[error("could not decode output from contract call")]
    OutputAbiDecodeError,
}

/// Possible error variants during construction of builder txs.
#[derive(Debug, thiserror::Error)]
pub enum BuilderTransactionError {
    /// Builder account load fails to get builder nonce
    #[error("failed to load account {0}")]
    AccountLoadFailed(Address),
    /// Signature signing fails
    #[error("failed to sign transaction: {0}")]
    SigningError(secp256k1::Error),
    /// Invalid contract errors indicating the contract is incorrect
    #[error("contract {0} may be incorrect, invalid contract data: {1}")]
    InvalidContract(Address, InvalidContractDataError),
    /// Transaction halted execution
    #[error("transaction halted {0:?}")]
    TransactionHalted(OpHaltReason),
    /// Transaction reverted
    #[error("transaction reverted {0}")]
    TransactionReverted(Box<dyn core::error::Error + Send + Sync>),
    /// Invalid tx errors during evm execution.
    #[error("invalid transaction error {0}")]
    InvalidTransactionError(Box<dyn core::error::Error + Send + Sync>),
    /// Unrecoverable error during evm execution.
    #[error("evm execution error {0}")]
    EvmExecutionError(Box<dyn core::error::Error + Send + Sync>),
    /// Any other builder transaction errors.
    #[error(transparent)]
    Other(Box<dyn core::error::Error + Send + Sync>),
}

impl From<secp256k1::Error> for BuilderTransactionError {
    fn from(error: secp256k1::Error) -> Self {
        BuilderTransactionError::SigningError(error)
    }
}

impl From<EVMError<ProviderError, OpTransactionError>> for BuilderTransactionError {
    fn from(error: EVMError<ProviderError, OpTransactionError>) -> Self {
        BuilderTransactionError::EvmExecutionError(Box::new(error))
    }
}

impl From<BuilderTransactionError> for PayloadBuilderError {
    fn from(error: BuilderTransactionError) -> Self {
        match error {
            BuilderTransactionError::EvmExecutionError(e) => {
                PayloadBuilderError::EvmExecutionError(e)
            }
            _ => PayloadBuilderError::Other(Box::new(error)),
        }
    }
}

impl BuilderTransactionError {
    pub fn other(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        BuilderTransactionError::Other(Box::new(error))
    }

    pub fn msg(msg: impl core::fmt::Display) -> Self {
        Self::Other(msg.to_string().into())
    }
}

pub trait BuilderTransactions<ExtraCtx: Debug + Default = (), Extra: Debug + Default = ()> {
    fn simulate_builder_txs(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
        top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError>;

    fn add_builder_txs(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        builder_ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
        top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        {
            let mut evm = builder_ctx
                .evm_config
                .evm_with_env(&mut *db, builder_ctx.evm_env.clone());

            let mut invalid: HashSet<Address> = HashSet::new();

            let builder_txs = self.simulate_builder_txs(
                state_provider,
                info,
                builder_ctx,
                evm.db_mut(),
                top_of_block,
            )?;
            for builder_tx in builder_txs.iter() {
                if builder_tx.is_top_of_block != top_of_block {
                    // don't commit tx if the buidler tx is not being added in the intended
                    // position in the block
                    continue;
                }
                if invalid.contains(&builder_tx.signed_tx.signer()) {
                    warn!(target: "payload_builder", tx_hash = ?builder_tx.signed_tx.tx_hash(), "builder signer invalid as previous builder tx reverted");
                    continue;
                }

                let ResultAndState { result, state } = evm
                    .transact(&builder_tx.signed_tx)
                    .map_err(|err| BuilderTransactionError::EvmExecutionError(Box::new(err)))?;

                if !result.is_success() {
                    warn!(target: "payload_builder", tx_hash = ?builder_tx.signed_tx.tx_hash(), result = ?result, "builder tx reverted");
                    invalid.insert(builder_tx.signed_tx.signer());
                    continue;
                }

                // Add gas used by the transaction to cumulative gas used, before creating the receipt
                let gas_used = result.gas_used();
                info.cumulative_gas_used += gas_used;

                let ctx = ReceiptBuilderCtx {
                    tx: builder_tx.signed_tx.inner(),
                    evm: &evm,
                    result,
                    state: &state,
                    cumulative_gas_used: info.cumulative_gas_used,
                };
                info.receipts.push(builder_ctx.build_receipt(ctx, None));

                // Commit changes
                evm.db_mut().commit(state);

                // Append sender and transaction to the respective lists
                info.executed_senders.push(builder_tx.signed_tx.signer());
                info.executed_transactions
                    .push(builder_tx.signed_tx.clone().into_inner());
            }

            // Release the db reference by dropping evm
            drop(evm);

            Ok(builder_txs)
        }
    }

    fn simulate_builder_txs_state(
        &self,
        state_provider: impl StateProvider + Clone,
        builder_txs: Vec<&BuilderTransactionCtx>,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
    ) -> Result<State<StateProviderDatabase<impl StateProvider>>, BuilderTransactionError> {
        let state = StateProviderDatabase::new(state_provider.clone());
        let mut simulation_state = State::builder()
            .with_database(state)
            .with_cached_prestate(db.cache.clone())
            .with_bundle_update()
            .build();
        let mut evm = ctx
            .evm_config
            .evm_with_env(&mut simulation_state, ctx.evm_env.clone());

        for builder_tx in builder_txs {
            let ResultAndState { state, .. } = evm
                .transact(&builder_tx.signed_tx)
                .map_err(|err| BuilderTransactionError::EvmExecutionError(Box::new(err)))?;

            evm.db_mut().commit(state);
        }

        Ok(simulation_state)
    }

    fn sign_tx(
        &self,
        to: Address,
        from: Signer,
        gas_used: Option<u64>,
        calldata: Bytes,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
    ) -> Result<Recovered<OpTransactionSigned>, BuilderTransactionError> {
        let nonce = get_nonce(db, from.address)?;
        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            nonce,
            // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
            gas_limit: gas_used
                .map(|gas| gas * 64 / 63)
                .unwrap_or(ctx.block_gas_limit()),
            max_fee_per_gas: ctx.base_fee().into(),
            to: TxKind::Call(to),
            input: calldata,
            ..Default::default()
        });
        Ok(from.sign_tx(tx)?)
    }

    fn simulate_call(
        &self,
        signed_tx: Recovered<OpTransactionSigned>,
        expected_topic: Option<B256>,
        revert_handler: impl FnOnce(Bytes) -> BuilderTransactionError,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<SimulationSuccessResult, BuilderTransactionError> {
        let ResultAndState { result, state } = match evm.transact(&signed_tx) {
            Ok(res) => res,
            Err(err) => {
                if err.is_invalid_tx_err() {
                    return Err(BuilderTransactionError::InvalidTransactionError(Box::new(
                        err,
                    )));
                } else {
                    return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
                }
            }
        };

        match result {
            ExecutionResult::Success {
                logs,
                gas_used,
                output,
                ..
            } => {
                if let Some(topic) = expected_topic
                    && !logs.iter().any(|log| log.topics().first() == Some(&topic))
                {
                    return Err(BuilderTransactionError::InvalidContract(
                        signed_tx.to().unwrap_or_default(),
                        InvalidContractDataError::InvalidLogs(topic),
                    ));
                }
                Ok(SimulationSuccessResult {
                    gas_used,
                    output: output.into_data(),
                    state_changes: state,
                })
            }
            ExecutionResult::Revert { output, .. } => Err(revert_handler(output)),
            ExecutionResult::Halt { reason, .. } => Err(BuilderTransactionError::other(
                BuilderTransactionError::TransactionHalted(reason),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct BuilderTxBase<ExtraCtx = ()> {
    pub signer: Option<Signer>,
    _marker: std::marker::PhantomData<ExtraCtx>,
}

impl<ExtraCtx: Debug + Default> BuilderTxBase<ExtraCtx> {
    pub(super) fn new(signer: Option<Signer>) -> Self {
        Self {
            signer,
            _marker: std::marker::PhantomData,
        }
    }

    pub(super) fn simulate_builder_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
    ) -> Result<Option<BuilderTransactionCtx>, BuilderTransactionError> {
        match self.signer {
            Some(signer) => {
                let message: Vec<u8> = format!("Block Number: {}", ctx.block_number()).into_bytes();
                let gas_used = self.estimate_builder_tx_gas(&message);
                let signed_tx = self.signed_builder_tx(ctx, db, signer, gas_used, message)?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    signed_tx.encoded_2718().as_slice(),
                );
                Ok(Some(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx,
                    is_top_of_block: false,
                }))
            }
            None => Ok(None),
        }
    }

    fn estimate_builder_tx_gas(&self, input: &[u8]) -> u64 {
        // Count zero and non-zero bytes
        let (zero_bytes, nonzero_bytes) = input.iter().fold((0, 0), |(zeros, nonzeros), &byte| {
            if byte == 0 {
                (zeros + 1, nonzeros)
            } else {
                (zeros, nonzeros + 1)
            }
        });

        // Calculate gas cost (4 gas per zero byte, 16 gas per non-zero byte)
        let zero_cost = zero_bytes * 4;
        let nonzero_cost = nonzero_bytes * 16;

        // Tx gas should be not less than floor gas https://eips.ethereum.org/EIPS/eip-7623
        let tokens_in_calldata = zero_bytes + nonzero_bytes * 4;
        let floor_gas = 21_000 + tokens_in_calldata * TOTAL_COST_FLOOR_PER_TOKEN;

        std::cmp::max(zero_cost + nonzero_cost + 21_000, floor_gas)
    }

    fn signed_builder_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
        signer: Signer,
        gas_used: u64,
        message: Vec<u8>,
    ) -> Result<Recovered<OpTransactionSigned>, BuilderTransactionError> {
        let nonce = db
            .load_cache_account(signer.address)
            .map(|acc| acc.account_info().unwrap_or_default().nonce)
            .map_err(|_| BuilderTransactionError::AccountLoadFailed(signer.address))?;

        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            nonce,
            gas_limit: gas_used,
            max_fee_per_gas: ctx.base_fee().into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            // Include the message as part of the transaction data
            input: message.into(),
            ..Default::default()
        });
        // Sign the transaction
        let builder_tx = signer
            .sign_tx(tx)
            .map_err(BuilderTransactionError::SigningError)?;

        Ok(builder_tx)
    }
}

pub fn get_nonce(
    db: &mut State<impl Database>,
    address: Address,
) -> Result<u64, BuilderTransactionError> {
    db.load_cache_account(address)
        .map(|acc| acc.account_info().unwrap_or_default().nonce)
        .map_err(|_| BuilderTransactionError::AccountLoadFailed(address))
}

pub fn get_balance(
    db: &mut State<impl Database>,
    address: Address,
) -> Result<U256, BuilderTransactionError> {
    db.load_cache_account(address)
        .map(|acc| acc.account_info().unwrap_or_default().balance)
        .map_err(|_| BuilderTransactionError::AccountLoadFailed(address))
}
