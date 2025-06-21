use alloy_consensus::TxEip1559;
use alloy_eips::{eip7623::TOTAL_COST_FLOOR_PER_TOKEN, Encodable2718};
use alloy_primitives::{Address, TxKind};
use op_alloy_consensus::OpTypedTransaction;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use reth_provider::ProviderError;
use reth_revm::State;
use revm::Database;

use crate::{builders::context::OpPayloadBuilderCtx, tx_signer::Signer};

pub struct BuilderTransactionCtx {
    pub gas_used: u64,
    pub da_size: u64,
    pub signed_tx: Recovered<OpTransactionSigned>,
}

/// Possible error variants during construction of builder txs.
#[derive(Debug, thiserror::Error)]
pub enum BuilderTransactionError {
    /// Thrown when builder account load fails to get builder nonce
    #[error("failed to load account {0}")]
    AccountLoadFailed(Address),
    /// Thrown when signature signing fails
    #[error("failed to sign transaction: {0}")]
    SigningError(secp256k1::Error),
    /// Unrecoverable error during evm execution.
    #[error("evm execution error {0}")]
    EvmExecutionError(Box<dyn core::error::Error + Send + Sync>),
    /// Any other builder transaction errors.
    #[error(transparent)]
    Other(Box<dyn core::error::Error + Send + Sync>),
}

pub trait BuilderTransactions {
    fn get_builder_txs<DB>(
        &self,
        ctx: OpPayloadBuilderCtx,
        db: &mut State<DB>,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError>
    where
        DB: Database<Error = ProviderError>;
}

// This will be the regular end of block transaction without the TEE key
#[derive(Clone)]
pub struct StandardBuilderTx {
    pub signer: Option<Signer>,
}

impl StandardBuilderTx {
    fn estimate_builder_tx_gas(&self, input: &Vec<u8>) -> u64 {
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

    /// Creates signed builder tx to Address::ZERO and specified message as input
    fn signed_builder_tx<DB>(
        &self,
        db: &mut State<DB>,
        signer: Signer,
        gas_used: u64,
        message: Vec<u8>,
        ctx: &OpPayloadBuilderCtx,
    ) -> Result<Recovered<OpTransactionSigned>, BuilderTransactionError>
    where
        DB: Database<Error = ProviderError>,
    {
        // Create message with block number for the builder to sign
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

impl BuilderTransactions for StandardBuilderTx {
    fn get_builder_txs<DB>(
        &self,
        ctx: OpPayloadBuilderCtx,
        db: &mut State<DB>,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError>
    where
        DB: Database<Error = ProviderError>,
    {
        match self.signer {
            Some(signer) => {
                let message: Vec<u8> = format!("Block Number: {}", ctx.block_number()).into_bytes();
                let gas_used = self.estimate_builder_tx_gas(&message);
                let signed_tx = self.signed_builder_tx(db, signer, gas_used, message, &ctx)?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    signed_tx.encoded_2718().as_slice(),
                );
                Ok(vec![BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx,
                }])
            }
            None => Ok(vec![]),
        }
    }
}
