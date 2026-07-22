use alloy_eips::Encodable2718;
use alloy_evm::{Database, Evm};
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, B256, Signature, U256};
use alloy_rpc_types_eth::TransactionInput;
use alloy_sol_types::{SolCall, SolEvent, sol};
use core::fmt::Debug;
use op_alloy_rpc_types::OpTransactionRequest;
use reth_evm::precompiles::PrecompilesMap;
use reth_provider::StateProvider;
use revm::{DatabaseRef, context_interface::Cfg as _, inspector::NoOpInspector};
use std::sync::Arc;
use tracing::warn;

use crate::{
    builder::builder_tx::{
        BuilderTxEnv, BuilderTxError, BuilderTxProducer, ClaimBuilderTx, SimulatedBuilderTx,
        SimulationState, SimulationSuccessResult, get_nonce, sign_tx, simulate_call,
    },
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

/// Builder transaction that increments the on-chain flashblock number contract.
/// Scheduled for non-first flashblocks via
/// [`crate::builder::builder_tx::ScheduledBuilderTx`]; the block claim tx is a
/// separate schedule entry for the first flashblock.
#[derive(Debug, Clone)]
pub(crate) struct FlashblockNumberBuilderTx {
    pub signer: Signer,
    pub flashblock_number_address: Address,
    pub use_permit: bool,
    /// TEE signer used only when `use_permit` is true to co-sign the permit.
    pub tee_signer: Option<Signer>,
}

impl FlashblockNumberBuilderTx {
    pub(crate) fn new(
        signer: Signer,
        flashblock_number_address: Address,
        use_permit: bool,
        tee_signer: Option<Signer>,
    ) -> Self {
        Self {
            signer,
            flashblock_number_address,
            use_permit,
            tee_signer,
        }
    }

    fn signed_increment_flashblocks_tx(
        &self,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulatedBuilderTx, BuilderTxError> {
        let calldata = IFlashblockNumber::incrementFlashblockNumberCall {};
        self.increment_flashblocks_tx(calldata, env, evm)
    }

    fn increment_flashblocks_permit_signature(
        &self,
        flashtestations_signer: &Signer,
        current_flashblock_number: U256,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<Signature, BuilderTxError> {
        let struct_hash_calldata = IFlashblockNumber::computeStructHashCall {
            currentFlashblockNumber: current_flashblock_number,
        };
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_readonly_call(struct_hash_calldata, env, evm)?;
        let typed_data_hash_calldata =
            IFlashblockNumber::hashTypedDataV4Call { structHash: output };
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_readonly_call(typed_data_hash_calldata, env, evm)?;
        let signature = flashtestations_signer.sign_message(output)?;
        Ok(signature)
    }

    fn signed_increment_flashblocks_permit_tx(
        &self,
        flashtestations_signer: &Signer,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulatedBuilderTx, BuilderTxError> {
        let current_flashblock_calldata = IFlashblockNumber::flashblockNumberCall {};
        let SimulationSuccessResult { output, .. } =
            self.simulate_flashblocks_readonly_call(current_flashblock_calldata, env, evm)?;
        let signature =
            self.increment_flashblocks_permit_signature(flashtestations_signer, output, env, evm)?;
        let calldata = IFlashblockNumber::permitIncrementFlashblockNumberCall {
            currentFlashblockNumber: output,
            signature: signature.as_bytes().into(),
        };
        self.increment_flashblocks_tx(calldata, env, evm)
    }

    fn increment_flashblocks_tx<T: SolCall + Clone>(
        &self,
        calldata: T,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulatedBuilderTx, BuilderTxError> {
        let SimulationSuccessResult { gas_used, .. } = self.simulate_flashblocks_call(
            calldata.clone(),
            vec![IFlashblockNumber::FlashblockIncremented::SIGNATURE_HASH],
            env,
            evm,
        )?;
        let signed_tx = sign_tx(
            self.flashblock_number_address,
            self.signer,
            gas_used,
            calldata.abi_encode().into(),
            env,
            evm.db_mut(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(SimulatedBuilderTx {
            signed_tx,
            gas_used,
            da_size,
        })
    }

    fn simulate_flashblocks_readonly_call<T: SolCall>(
        &self,
        calldata: T,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulationSuccessResult<T>, BuilderTxError> {
        self.simulate_flashblocks_call(calldata, vec![], env, evm)
    }

    fn simulate_flashblocks_call<T: SolCall>(
        &self,
        calldata: T,
        expected_logs: Vec<B256>,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulationSuccessResult<T>, BuilderTxError> {
        let simulation_gas_limit = env.block_gas_limit.min(evm.cfg_env().tx_gas_limit_cap());
        let tx_req = OpTransactionRequest::default()
            .gas_limit(simulation_gas_limit)
            .max_fee_per_gas(env.base_fee.into())
            .to(self.flashblock_number_address)
            .from(self.signer.address)
            .nonce(get_nonce(evm.db(), self.signer.address)?)
            .input(TransactionInput::new(calldata.abi_encode().into()));
        simulate_call::<T, IFlashblockNumber::IFlashblockNumberErrors>(tx_req, expected_logs, evm)
    }
}

impl BuilderTxProducer for FlashblockNumberBuilderTx {
    fn simulate_builder_txs(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        sim_state: &mut SimulationState,
    ) -> Result<Vec<SimulatedBuilderTx>, BuilderTxError> {
        let flashblock_number_tx = {
            let mut evm = env.evm_factory.evm(&mut *sim_state);
            evm.modify_cfg(|cfg| {
                cfg.disable_balance_check = true;
                cfg.disable_block_gas_limit = true;
            });

            if let Some(tee_signer) = &self.tee_signer
                && self.use_permit
            {
                self.signed_increment_flashblocks_permit_tx(tee_signer, env, &mut evm)
            } else {
                self.signed_increment_flashblocks_tx(env, &mut evm)
            }
        };

        match flashblock_number_tx {
            Ok(tx) => Ok(vec![tx]),
            Err(e) => {
                warn!(
                    target: "builder_tx",
                    error = %e,
                    "flashblocks number contract tx simulation failed, falling back to claim tx"
                );
                ClaimBuilderTx::new(Some(self.signer)).simulate_builder_txs(
                    state_provider,
                    info,
                    env,
                    sim_state,
                )
            }
        }
    }
}
