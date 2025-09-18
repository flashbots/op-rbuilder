use alloy_consensus::TxEip1559;
use alloy_eips::{Encodable2718, eip7623::TOTAL_COST_FLOOR_PER_TOKEN};
use alloy_evm::{Database, Evm};
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::{SolCall, SolError, sol};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use op_revm::OpHaltReason;
use reth_evm::{ConfigureEvm, precompiles::PrecompilesMap};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use revm::{
    context::result::{ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
};

use crate::{
    builders::{
        BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions, builder_tx::get_nonce,
        context::OpPayloadBuilderCtx, flashblocks::payload::FlashblocksExtraCtx,
    },
    flashtestations::service::FlashtestationsBuilderTx,
    primitives::reth::ExecutionInfo,
    tx_signer::Signer,
};

sol!(
    #[sol(rpc, abi)]
    interface IFlashblockNumber {
        function incrementFlashblockNumber() external;
    }

    /**
    * @notice Emitted when flashblock index is incremented
    * @param newFlashblockIndex The new flashblock index (0-indexed within each L2 block)
    */
    event FlashblockIncremented(uint256 newFlashblockIndex);

    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------
    error NonBuilderAddress(address addr);
    error MismatchedFlashblockNumber(uint256 expectedFlashblockNumber, uint256 actualFlashblockNumber);
);

#[derive(Debug, thiserror::Error)]
pub(super) enum FlashblockNumberError {
    #[error("non builder address: {0}")]
    NonBuilderAddress(Address),
    #[error("mismatched flashblock number: expected {0}, actual {1}")]
    MismatchedFlashblockNumber(U256, U256),
    #[error("unknown revert: {0}")]
    Unknown(String),
    #[error("halt: {0:?}")]
    Halt(OpHaltReason),
}

impl From<Bytes> for FlashblockNumberError {
    fn from(value: Bytes) -> Self {
        // Empty revert
        if value.is_empty() {
            return FlashblockNumberError::Unknown(
                "Transaction reverted without reason".to_string(),
            );
        }

        // Try to decode each custom error type
        if let Ok(NonBuilderAddress { addr }) = NonBuilderAddress::abi_decode(&value) {
            return FlashblockNumberError::NonBuilderAddress(addr);
        }

        if let Ok(MismatchedFlashblockNumber {
            expectedFlashblockNumber,
            actualFlashblockNumber,
        }) = MismatchedFlashblockNumber::abi_decode(&value)
        {
            return FlashblockNumberError::MismatchedFlashblockNumber(
                expectedFlashblockNumber,
                actualFlashblockNumber,
            );
        }

        FlashblockNumberError::Unknown(hex::encode(value))
    }
}

// This will be the end of block transaction of a regular block
#[derive(Debug, Clone)]
pub(super) struct FlashblocksBuilderTx {
    pub signer: Option<Signer>,
    pub flashtestations_builder_tx: Option<FlashtestationsBuilderTx>,
}

impl FlashblocksBuilderTx {
    pub(super) fn new(
        signer: Option<Signer>,
        flashtestations_builder_tx: Option<FlashtestationsBuilderTx>,
    ) -> Self {
        Self {
            signer,
            flashtestations_builder_tx,
        }
    }

    pub(super) fn simulate_builder_tx<ExtraCtx: Debug + Default>(
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
                    signed_tx: Some(signed_tx),
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

    fn signed_builder_tx<ExtraCtx: Debug + Default>(
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

impl BuilderTransactions<FlashblocksExtraCtx> for FlashblocksBuilderTx {
    fn simulate_builder_txs<Extra: Debug + Default>(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        db: &mut State<impl Database>,
        top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();

        if ctx.is_first_flashblock() {
            let flashblocks_builder_tx = self.simulate_builder_tx(ctx, db)?;
            builder_txs.extend(flashblocks_builder_tx.clone());
        }

        if ctx.is_last_flashblock() {
            let flashblocks_builder_tx = self.simulate_builder_tx(ctx, db)?;
            builder_txs.extend(flashblocks_builder_tx.clone());
            if let Some(flashtestations_builder_tx) = &self.flashtestations_builder_tx {
                // We only include flashtestations txs in the last flashblock

                let mut simulation_state = self.simulate_builder_txs_state::<FlashblocksExtraCtx>(
                    state_provider.clone(),
                    flashblocks_builder_tx.iter().collect(),
                    ctx,
                    db,
                )?;
                let flashtestations_builder_txs = flashtestations_builder_tx.simulate_builder_txs(
                    state_provider,
                    info,
                    ctx,
                    &mut simulation_state,
                    top_of_block,
                )?;
                builder_txs.extend(flashtestations_builder_txs);
            }
        }
        Ok(builder_txs)
    }
}

// This will be the end of block transaction of a regular block
#[derive(Debug, Clone)]
pub(super) struct FlashblocksNumberBuilderTx {
    pub signer: Option<Signer>,
    pub flashblock_number_address: Address,
    pub flashtestations_builder_tx: Option<FlashtestationsBuilderTx>,
}

impl FlashblocksNumberBuilderTx {
    pub(super) fn new(
        signer: Option<Signer>,
        flashblock_number_address: Address,
        flashtestations_builder_tx: Option<FlashtestationsBuilderTx>,
    ) -> Self {
        Self {
            signer,
            flashblock_number_address,
            flashtestations_builder_tx,
        }
    }

    fn estimate_flashblock_number_tx_gas(
        &self,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            State<StateProviderDatabase<impl StateProvider + Clone>>,
            NoOpInspector,
            PrecompilesMap,
        >,
        signer: &Signer,
        nonce: u64,
    ) -> Result<u64, BuilderTransactionError> {
        let tx = self.signed_flashblock_number_tx(ctx, ctx.block_gas_limit(), nonce, signer)?;
        let ResultAndState { result, .. } = match evm.transact(&tx) {
            Ok(res) => res,
            Err(err) => {
                return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
            }
        };

        match result {
            ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Revert { output, .. } => Err(BuilderTransactionError::Other(
                Box::new(FlashblockNumberError::from(output)),
            )),
            ExecutionResult::Halt { reason, .. } => Err(BuilderTransactionError::Other(Box::new(
                FlashblockNumberError::Halt(reason),
            ))),
        }
    }

    fn signed_flashblock_number_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        gas_limit: u64,
        nonce: u64,
        signer: &Signer,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        let calldata = IFlashblockNumber::incrementFlashblockNumberCall {}.abi_encode();
        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            nonce,
            gas_limit,
            max_fee_per_gas: ctx.base_fee().into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(self.flashblock_number_address),
            input: calldata.into(),
            ..Default::default()
        });
        signer.sign_tx(tx)
    }
}

impl BuilderTransactions<FlashblocksExtraCtx> for FlashblocksNumberBuilderTx {
    fn simulate_builder_txs<Extra: Debug + Default>(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        db: &mut State<impl Database>,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();
        let state = StateProviderDatabase::new(state_provider.clone());
        let mut simulation_state = State::builder()
            .with_database(state)
            .with_cached_prestate(db.cache.clone())
            .with_bundle_update()
            .build();

        if ctx.is_last_flashblock() {
            if let Some(flashtestations_builder_tx) = &self.flashtestations_builder_tx {
                // We only include flashtestations txs in the last flashblock
                let flashtestations_builder_txs = flashtestations_builder_tx.simulate_builder_txs(
                    state_provider,
                    info,
                    ctx,
                    &mut simulation_state,
                )?;
                builder_txs.extend(flashtestations_builder_txs);
            }
        } else {
            // we increment the flashblock number for the next flashblock so we don't increment in the last flashblock
            if let Some(signer) = &self.signer {
                let mut evm = ctx
                    .evm_config
                    .evm_with_env(simulation_state, ctx.evm_env.clone());
                evm.modify_cfg(|cfg| {
                    cfg.disable_balance_check = true;
                });

                let nonce = get_nonce(evm.db_mut(), signer.address)?;

                let gas_used =
                    self.estimate_flashblock_number_tx_gas(ctx, &mut evm, signer, nonce)?;
                // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
                let tx =
                    self.signed_flashblock_number_tx(ctx, gas_used * 64 / 63, nonce, signer)?;
                let da_size =
                    op_alloy_flz::tx_estimated_size_fjord_bytes(tx.encoded_2718().as_slice());
                builder_txs.push(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx: tx,
                });
            }
        }

        Ok(builder_txs)
    }
}
