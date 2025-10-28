use alloy_eips::Encodable2718;
use alloy_evm::{Database, Evm};
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, B256, Bytes, Signature, U256};
use alloy_sol_types::{SolCall, SolEvent, SolInterface, SolValue, sol};
use core::fmt::Debug;
use reth_evm::{ConfigureEvm, precompiles::PrecompilesMap};
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use revm::inspector::NoOpInspector;
use tracing::warn;

use crate::{
    builders::{
        BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions,
        InvalidContractDataError, SimulationSuccessResult,
        builder_tx::BuilderTxBase,
        context::OpPayloadBuilderCtx,
        flashblocks::payload::{FlashblocksExecutionInfo, FlashblocksExtraCtx},
    },
    flashtestations::builder_tx::FlashtestationsBuilderTx,
    primitives::reth::ExecutionInfo,
    tx_signer::Signer,
};

sol!(
    // From https://github.com/Uniswap/flashblocks_number_contract/blob/main/src/FlashblockNumber.sol
    #[sol(rpc, abi)]
    #[derive(Debug)]
    interface IFlashblockNumber {
        uint256 public flashblockNumber;

        function incrementFlashblockNumber() external;

        function permitIncrementFlashblockNumber(uint256 currentFlashblockNumber, bytes memory signature) external;

        function computeStructHash(uint256 currentFlashblockNumber) external pure returns (bytes32);

        function hashTypedDataV4(bytes32 structHash) external view returns (bytes32);


        // @notice Emitted when flashblock index is incremented
        // @param newFlashblockIndex The new flashblock index (0-indexed within each L2 block)
        event FlashblockIncremented(uint256 newFlashblockIndex);

        /// -----------------------------------------------------------------------
        /// Errors
        /// -----------------------------------------------------------------------
        error NonBuilderAddress(address addr);
        error MismatchedFlashblockNumber(uint256 expectedFlashblockNumber, uint256 actualFlashblockNumber);
    }
);

#[derive(Debug, thiserror::Error)]
pub(super) enum FlashblockNumberError {
    #[error("flashblocks number contract tx reverted: {0:?}")]
    Revert(IFlashblockNumber::IFlashblockNumberErrors),
    #[error("unknown revert: {0}")]
    Unknown(String),
}

// This will be the end of block transaction of a regular block
#[derive(Debug, Clone)]
pub(super) struct FlashblocksBuilderTx {
    pub base_builder_tx: BuilderTxBase<FlashblocksExtraCtx>,
    pub flashtestations_builder_tx:
        Option<FlashtestationsBuilderTx<FlashblocksExtraCtx, FlashblocksExecutionInfo>>,
}

impl FlashblocksBuilderTx {
    pub(super) fn new(
        signer: Option<Signer>,
        flashtestations_builder_tx: Option<
            FlashtestationsBuilderTx<FlashblocksExtraCtx, FlashblocksExecutionInfo>,
        >,
    ) -> Self {
        let base_builder_tx = BuilderTxBase::new(signer);
        Self {
            base_builder_tx,
            flashtestations_builder_tx,
        }
    }
}

impl BuilderTransactions<FlashblocksExtraCtx, FlashblocksExecutionInfo> for FlashblocksBuilderTx {
    fn simulate_builder_txs(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<FlashblocksExecutionInfo>,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        db: &mut State<impl Database + DatabaseRef>,
        top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();

        if ctx.is_first_flashblock() {
            let flashblocks_builder_tx = self.base_builder_tx.simulate_builder_tx(ctx, &mut *db)?;
            builder_txs.extend(flashblocks_builder_tx.clone());
        }

        if ctx.is_last_flashblock() {
            let base_tx = self.base_builder_tx.simulate_builder_tx(ctx, &mut *db)?;
            builder_txs.extend(base_tx.clone());

            if let Some(flashtestations_builder_tx) = &self.flashtestations_builder_tx {
                // Commit state that is included to get the correct nonce
                if let Some(builder_tx) = base_tx {
                    self.commit_txs(vec![builder_tx.signed_tx], ctx, &mut *db)?;
                }
                // We only include flashtestations txs in the last flashblock
                match flashtestations_builder_tx.simulate_builder_txs(
                    state_provider,
                    info,
                    ctx,
                    db,
                    top_of_block,
                ) {
                    Ok(flashtestations_builder_txs) => {
                        builder_txs.extend(flashtestations_builder_txs)
                    }
                    Err(e) => {
                        warn!(target: "flashtestations", error = ?e, "failed to add flashtestations builder tx")
                    }
                }
            }
        }
        Ok(builder_txs)
    }
}

// This will be the end of block transaction of a regular block
#[derive(Debug, Clone)]
pub(super) struct FlashblocksNumberBuilderTx {
    pub signer: Signer,
    pub flashblock_number_address: Address,
    pub use_permit: bool,
    pub base_builder_tx: BuilderTxBase<FlashblocksExtraCtx>,
    pub flashtestations_builder_tx:
        Option<FlashtestationsBuilderTx<FlashblocksExtraCtx, FlashblocksExecutionInfo>>,
}

impl FlashblocksNumberBuilderTx {
    pub(super) fn new(
        signer: Signer,
        flashblock_number_address: Address,
        use_permit: bool,
        flashtestations_builder_tx: Option<
            FlashtestationsBuilderTx<FlashblocksExtraCtx, FlashblocksExecutionInfo>,
        >,
    ) -> Self {
        let base_builder_tx = BuilderTxBase::new(Some(signer));
        Self {
            signer,
            flashblock_number_address,
            use_permit,
            base_builder_tx,
            flashtestations_builder_tx,
        }
    }

    // TODO: remove and clean up in favour of simulate_call()
    fn estimate_flashblock_number_tx_gas(
        &self,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<impl Database, NoOpInspector, PrecompilesMap>,
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
            ExecutionResult::Success { gas_used, logs, .. } => {
                if logs.iter().any(|log| {
                    log.topics().first()
                        == Some(&IFlashblockNumber::FlashblockIncremented::SIGNATURE_HASH)
                }) {
                    Ok(gas_used)
                } else {
                    Err(BuilderTransactionError::InvalidContract(
                        self.flashblock_number_address,
                        InvalidContractDataError::InvalidLogs(
                            vec![IFlashblockNumber::FlashblockIncremented::SIGNATURE_HASH],
                            vec![],
                        ),
                    ))
                }
            }
            ExecutionResult::Revert { output, .. } => Err(BuilderTransactionError::other(
                IFlashblockNumber::IFlashblockNumberErrors::abi_decode(&output)
                    .map(FlashblockNumberError::Revert)
                    .unwrap_or_else(|e| FlashblockNumberError::Unknown(hex::encode(output), e)),
            )),
            ExecutionResult::Halt { reason, .. } => Err(BuilderTransactionError::other(
                FlashblockNumberError::Halt(reason),
            )),
        }
    }
    
    fn current_flashblock_number(
        &self,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<U256, BuilderTransactionError> {
        let current_flashblock_calldata = IFlashblockNumber::flashblockNumberCall {}.abi_encode();
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_call(current_flashblock_calldata, None, ctx, evm)?;
        IFlashblockNumber::flashblockNumberCall::abi_decode_returns(&output).map_err(|_| {
            BuilderTransactionError::InvalidContract(
                self.flashblock_number_address,
                InvalidContractDataError::OutputAbiDecodeError,
            )
        })
    }

    fn signed_increment_flashblocks_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<BuilderTransactionCtx, BuilderTransactionError> {
        let calldata = IFlashblockNumber::incrementFlashblockNumberCall {}.abi_encode();
        let SimulationSuccessResult { gas_used, .. } = self.simulate_flashblocks_call(
            calldata.clone(),
            Some(IFlashblockNumber::FlashblockIncremented::SIGNATURE_HASH),
            ctx,
            evm,
        )?;
        let signed_tx = self.sign_tx(
            self.flashblock_number_address,
            self.signer,
            Some(gas_used),
            calldata.into(),
            ctx,
            evm.db_mut(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(BuilderTransactionCtx {
            signed_tx,
            gas_used,
            da_size,
            is_top_of_block: true,
        })
    }

    fn increment_flashblocks_permit_signature(
        &self,
        flashtestations_signer: &Signer,
        current_flashblock_number: U256,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Signature, BuilderTransactionError> {
        let struct_hash_calldata = IFlashblockNumber::computeStructHashCall {
            currentFlashblockNumber: current_flashblock_number,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_call(struct_hash_calldata, None, ctx, evm)?;
        let struct_hash = B256::abi_decode(&output).map_err(|_| {
            BuilderTransactionError::InvalidContract(
                self.flashblock_number_address,
                InvalidContractDataError::OutputAbiDecodeError,
            )
        })?;
        let typed_data_hash_calldata = IFlashblockNumber::hashTypedDataV4Call {
            structHash: struct_hash,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_call(typed_data_hash_calldata, None, ctx, evm)?;
        let typed_data_hash = B256::abi_decode(&output).map_err(|_| {
            BuilderTransactionError::InvalidContract(
                self.flashblock_number_address,
                InvalidContractDataError::OutputAbiDecodeError,
            )
        })?;
        let signature = flashtestations_signer.sign_message(typed_data_hash)?;
        Ok(signature)
    }

    fn signed_increment_flashblocks_permit_tx(
        &self,
        flashtestations_signer: &Signer,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<BuilderTransactionCtx, BuilderTransactionError> {
        let current_flashblock_number = self.current_flashblock_number(ctx, evm)?;
        let signature = self.increment_flashblocks_permit_signature(
            flashtestations_signer,
            current_flashblock_number,
            ctx,
            evm,
        )?;
        let calldata = IFlashblockNumber::permitIncrementFlashblockNumberCall {
            currentFlashblockNumber: current_flashblock_number,
            signature: signature.as_bytes().into(),
        }
        .abi_encode();
        let SimulationSuccessResult { gas_used, .. } = self.simulate_flashblocks_call(
            calldata.clone(),
            Some(IFlashblockNumber::FlashblockIncremented::SIGNATURE_HASH),
            ctx,
            evm,
        )?;
        let signed_tx = self.sign_tx(
            self.flashblock_number_address,
            self.signer,
            Some(gas_used),
            calldata.into(),
            ctx,
            evm.db_mut(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(BuilderTransactionCtx {
            signed_tx,
            gas_used,
            da_size,
            is_top_of_block: true,
        })
    }

    fn simulate_flashblocks_call(
        &self,
        calldata: Vec<u8>,
        expected_topic: Option<B256>,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<SimulationSuccessResult, BuilderTransactionError> {
        let signed_tx = self.sign_tx(
            self.flashblock_number_address,
            self.signer,
            None,
            calldata.into(),
            ctx,
            evm.db_mut(),
        )?;
        self.simulate_call(signed_tx, expected_topic, Self::handle_revert, evm)
    }

    fn handle_revert(revert_output: Bytes) -> BuilderTransactionError {
        let revert_reason = IFlashblockNumber::IFlashblockNumberErrors::abi_decode(&revert_output)
            .map(FlashblockNumberError::Revert)
            .unwrap_or_else(|_| FlashblockNumberError::Unknown(hex::encode(revert_output)));
        BuilderTransactionError::TransactionReverted(Box::new(revert_reason))
    }
}

impl BuilderTransactions<FlashblocksExtraCtx, FlashblocksExecutionInfo>
    for FlashblocksNumberBuilderTx
{
    fn simulate_builder_txs(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<FlashblocksExecutionInfo>,
        ctx: &OpPayloadBuilderCtx<FlashblocksExtraCtx>,
        db: &mut State<impl Database + DatabaseRef>,
        top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();

        if ctx.is_first_flashblock() {
            // fallback block builder tx
            builder_txs.extend(self.base_builder_tx.simulate_builder_tx(ctx, &mut *db)?);
        } else {
            // we increment the flashblock number for the next flashblock so we don't increment in the last flashblock
            let mut evm = ctx
                .evm_config
                .evm_with_env(&mut simulation_state, ctx.evm_env.clone());
            evm.modify_cfg(|cfg| {
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
            });

            let flashblocks_num_tx = if let Some(flashtestations) = &self.flashtestations_builder_tx
                && self.use_permit
            {
                self.signed_increment_flashblocks_permit_tx(
                    flashtestations.tee_signer(),
                    ctx,
                    &mut evm,
                )
            } else {
                self.signed_increment_flashblocks_tx(ctx, &mut evm)
            };

            let tx = match flashblocks_num_tx {
                Ok(tx) => Some(tx),
                Err(e) => {
                    warn!(target: "builder_tx", error = ?e, "flashblocks number contract tx simulation failed, defaulting to fallback builder tx");
                    self.base_builder_tx
                        .simulate_builder_tx(ctx, db)?
                        .map(|tx| tx.set_top_of_block())
                }
            };

            builder_txs.extend(tx);
        }

        if ctx.is_last_flashblock() {
            if let Some(flashtestations_builder_tx) = &self.flashtestations_builder_tx {
                // Commit state that should be included to compute the correct nonce
                let flashblocks_builder_txs = builder_txs
                    .iter()
                    .filter(|tx| tx.is_top_of_block == top_of_block)
                    .map(|tx| tx.signed_tx.clone())
                    .collect();
                self.commit_txs(flashblocks_builder_txs, ctx, &mut *db)?;

                // We only include flashtestations txs in the last flashblock
                match flashtestations_builder_tx.simulate_builder_txs(
                    state_provider,
                    info,
                    ctx,
                    db,
                    top_of_block,
                ) {
                    Ok(flashtestations_builder_txs) => {
                        builder_txs.extend(flashtestations_builder_txs)
                    }
                    Err(e) => {
                        warn!(target: "flashtestations", error = ?e, "failed to add flashtestations builder tx")
                    }
                }
            }
        }

        Ok(builder_txs)
    }
}
