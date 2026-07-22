use alloy_consensus::TxEip1559;
use alloy_eips::{Encodable2718, eip7623::TOTAL_COST_FLOOR_PER_TOKEN};
use alloy_primitives::{Address, TxKind};
use op_alloy_consensus::OpTypedTransaction;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::Recovered;
use reth_provider::StateProvider;
use revm::DatabaseRef;
use std::sync::Arc;

use crate::{
    builder::builder_tx::{
        BuilderTxEnv, BuilderTxError, BuilderTxProducer, SimulatedBuilderTx, SimulationState,
        get_nonce,
    },
    primitives::reth::ExecutionInfo,
    tx_signer::Signer,
};

/// Builder transaction producer for the block claim: a tx from the builder's
/// address carrying a "Block Number: {}" message, publicly indicating we built
/// the block.
#[derive(Debug, Clone, derive_more::Constructor)]
pub(crate) struct ClaimBuilderTx {
    pub signer: Option<Signer>,
}

impl BuilderTxProducer for ClaimBuilderTx {
    fn simulate_builder_txs(
        &self,
        _state_provider: Arc<dyn StateProvider + Send>,
        _info: &ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        sim_state: &mut SimulationState,
    ) -> Result<Vec<SimulatedBuilderTx>, BuilderTxError> {
        Ok(self
            .simulate_builder_tx(env, &mut *sim_state)?
            .into_iter()
            .collect())
    }
}

impl ClaimBuilderTx {
    fn simulate_builder_tx(
        &self,
        env: &BuilderTxEnv<'_>,
        db: impl DatabaseRef,
    ) -> Result<Option<SimulatedBuilderTx>, BuilderTxError> {
        let Some(signer) = self.signer else {
            return Ok(None);
        };

        let message: Vec<u8> = format!("Block Number: {}", env.block_number).into_bytes();
        let gas_used = self.estimate_builder_tx_gas(&message);
        let signed_tx = self.signed_builder_tx(env, db, signer, gas_used, message)?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());

        Ok(Some(SimulatedBuilderTx {
            gas_used,
            da_size,
            signed_tx,
        }))
    }

    fn estimate_builder_tx_gas(&self, input: &[u8]) -> u64 {
        let (zero_bytes, nonzero_bytes) = input.iter().fold((0, 0), |(zeros, nonzeros), &byte| {
            if byte == 0 {
                (zeros + 1, nonzeros)
            } else {
                (zeros, nonzeros + 1)
            }
        });

        let zero_cost = zero_bytes * 4;
        let nonzero_cost = nonzero_bytes * 16;

        let tokens_in_calldata = zero_bytes + nonzero_bytes * 4;
        let floor_gas = 21_000 + tokens_in_calldata * TOTAL_COST_FLOOR_PER_TOKEN;

        std::cmp::max(zero_cost + nonzero_cost + 21_000, floor_gas)
    }

    fn signed_builder_tx(
        &self,
        env: &BuilderTxEnv<'_>,
        db: impl DatabaseRef,
        signer: Signer,
        gas_used: u64,
        message: Vec<u8>,
    ) -> Result<Recovered<OpTransactionSigned>, BuilderTxError> {
        let nonce = get_nonce(db, signer.address)?;

        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: env.chain_id(),
            nonce,
            gas_limit: gas_used,
            max_fee_per_gas: env.base_fee.into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            input: message.into(),
            ..Default::default()
        });
        let builder_tx = signer.sign_tx(tx).map_err(BuilderTxError::SigningError)?;

        Ok(builder_tx)
    }
}
