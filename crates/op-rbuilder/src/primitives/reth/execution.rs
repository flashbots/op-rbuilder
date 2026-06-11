//! Heavily influenced by [reth](https://github.com/paradigmxyz/reth/blob/1e965caf5fa176f244a31c0d2662ba1b590938db/crates/optimism/payload/src/builder.rs#L570)
use alloy_consensus::Eip658Value;
use alloy_eips::Encodable2718;
use alloy_evm::Evm;
use alloy_op_evm::block::receipt_builder::OpReceiptBuilder;
use alloy_primitives::{Address, TxHash, U256};
use core::fmt::Debug;
use derive_more::Display;
use op_alloy_consensus::{OpDepositReceipt, OpReceipt, OpTxType};
use reth_evm::{ConfigureEvm, eth::receipt_builder::ReceiptBuilderCtx};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::Recovered;
use revm::{DatabaseCommit, context::result::ExecutionResult, state::EvmState};

use crate::{evm::OpBlockEvmFactory, hardforks::ActiveHardforks};

#[derive(Debug, Display)]
pub enum TxnExecutionResult {
    TransactionDALimitExceeded,
    #[display("BlockDALimitExceeded: total_da_used={_0} tx_da_size={_1} block_da_limit={_2}")]
    BlockDALimitExceeded(u64, u64, u64),
    #[display("TransactionGasLimitExceeded: total_gas_used={_0} tx_gas_limit={_1}")]
    TransactionGasLimitExceeded(u64, u64, u64),
    SequencerTransaction,
    NonceTooLow,
    #[display("InternalError({_0})")]
    InternalError(String),
    EvmError,
    Success,
    Reverted,
    RevertedAndExcluded,
    SenderBudgetExhausted,
    MaxGasUsageExceeded,
    #[display(
        "BlockUncompressedSizeExceeded: total_uncompressed={_0} tx_uncompressed_size={_1} block_limit={_2}"
    )]
    BlockUncompressedSizeExceeded(u64, u64, u64),
    ConditionalCheckFailed,
    BackrunPriorityFeeInvalid,
    CoinbaseProfitTooLow,
}

#[derive(Default, Debug, Clone)]
pub struct ExecutionInfo {
    /// All executed transactions (unrecovered).
    pub executed_transactions: Vec<OpTransactionSigned>,
    /// The recovered senders for the executed transactions.
    pub executed_senders: Vec<Address>,
    /// The transaction receipts
    pub receipts: Vec<OpReceipt>,
    /// All gas used so far
    pub cumulative_gas_used: u64,
    /// Estimated DA size
    pub cumulative_da_bytes_used: u64,
    /// Cumulative uncompressed (EIP-2718 encoded) bytes used in the block
    pub cumulative_uncompressed_bytes: u64,
    /// Tracks fees from executed mempool transactions
    pub total_fees: U256,
    /// DA Footprint Scalar for Jovian
    pub da_footprint_scalar: Option<u16>,
    /// Optional blob fields for payload validation
    pub optional_blob_fields: Option<(Option<u64>, Option<u64>)>,
    /// Reverted bundle tx hashes to remove from the pool after each flashblock.
    pub reverted_bundle_tx_hashes: Vec<TxHash>,
}

impl ExecutionInfo {
    /// Create a new instance with allocated slots.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            executed_transactions: Vec::with_capacity(capacity),
            executed_senders: Vec::with_capacity(capacity),
            receipts: Vec::with_capacity(capacity),
            cumulative_gas_used: 0,
            cumulative_da_bytes_used: 0,
            cumulative_uncompressed_bytes: 0,
            total_fees: U256::ZERO,
            da_footprint_scalar: None,
            optional_blob_fields: None,
            reverted_bundle_tx_hashes: Vec::new(),
        }
    }

    /// Returns true if the transaction would exceed the block limits:
    /// - block gas limit: ensures the transaction still fits into the block.
    /// - tx DA limit: if configured, ensures the tx does not exceed the maximum allowed DA limit
    ///   per tx.
    /// - block DA limit: if configured, ensures the transaction's DA size does not exceed the
    ///   maximum allowed DA limit per block.
    #[expect(clippy::too_many_arguments)]
    pub fn is_tx_over_limits(
        &self,
        tx_da_size: u64,
        block_gas_limit: u64,
        tx_data_limit: Option<u64>,
        block_data_limit: Option<u64>,
        tx_gas_limit: u64,
        block_da_footprint_limit: Option<u64>,
        tx_uncompressed_size: u64,
        max_uncompressed_block_size: Option<u64>,
    ) -> Result<(), TxnExecutionResult> {
        if tx_data_limit.is_some_and(|da_limit| tx_da_size > da_limit) {
            return Err(TxnExecutionResult::TransactionDALimitExceeded);
        }
        let total_da_bytes_used = self.cumulative_da_bytes_used.saturating_add(tx_da_size);
        if block_data_limit.is_some_and(|da_limit| total_da_bytes_used > da_limit) {
            return Err(TxnExecutionResult::BlockDALimitExceeded(
                self.cumulative_da_bytes_used,
                tx_da_size,
                block_data_limit.unwrap_or_default(),
            ));
        }

        // Post Jovian: the tx DA footprint must be less than the block gas limit
        if let Some(da_footprint_gas_scalar) = self.da_footprint_scalar {
            let tx_da_footprint =
                total_da_bytes_used.saturating_mul(da_footprint_gas_scalar as u64);
            if tx_da_footprint > block_da_footprint_limit.unwrap_or(block_gas_limit) {
                return Err(TxnExecutionResult::BlockDALimitExceeded(
                    total_da_bytes_used,
                    tx_da_size,
                    tx_da_footprint,
                ));
            }
        }

        if self.cumulative_gas_used + tx_gas_limit > block_gas_limit {
            return Err(TxnExecutionResult::TransactionGasLimitExceeded(
                self.cumulative_gas_used,
                tx_gas_limit,
                block_gas_limit,
            ));
        }

        // Check block uncompressed size limit
        if let Some(limit) = max_uncompressed_block_size {
            let total = self
                .cumulative_uncompressed_bytes
                .saturating_add(tx_uncompressed_size);
            if total > limit {
                return Err(TxnExecutionResult::BlockUncompressedSizeExceeded(
                    self.cumulative_uncompressed_bytes,
                    tx_uncompressed_size,
                    limit,
                ));
            }
        }

        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub fn commit_tx<E: Evm<DB: revm::DatabaseCommit>>(
        &mut self,
        tx: &Recovered<OpTransactionSigned>,
        execution_result: ExecutionResult<E::HaltReason>,
        state_changes: EvmState,
        tx_da_size: u64,
        miner_fee: Option<u128>,
        deposit_nonce: Option<u64>,
        evm_factory: &OpBlockEvmFactory,
        hardforks: &ActiveHardforks,
        evm: &mut E,
    ) {
        let gas_used = execution_result.tx_gas_used();
        self.cumulative_gas_used += gas_used;
        self.cumulative_da_bytes_used += tx_da_size;
        self.cumulative_uncompressed_bytes += tx.inner().encode_2718_len() as u64;

        let receipt_ctx = ReceiptBuilderCtx {
            tx_type: tx.inner().tx_type(),
            evm: &*evm,
            result: execution_result,
            state: &state_changes,
            cumulative_gas_used: self.cumulative_gas_used,
        };
        self.receipts.push(build_receipt(
            evm_factory,
            hardforks,
            receipt_ctx,
            deposit_nonce,
        ));

        // Commit changes
        evm.db_mut().commit(state_changes);

        // update add to total fees
        if let Some(miner_fee) = miner_fee {
            self.total_fees += U256::from(miner_fee) * U256::from(gas_used);
        }

        // Append sender and transaction to the respective lists
        self.executed_senders.push(tx.signer());
        self.executed_transactions.push(tx.clone().into_inner());
    }
}

fn build_receipt<E: Evm>(
    evm_factory: &OpBlockEvmFactory,
    hardforks: &ActiveHardforks,
    receipt_ctx: ReceiptBuilderCtx<'_, OpTxType, E>,
    deposit_nonce: Option<u64>,
) -> OpReceipt {
    let receipt_builder = evm_factory
        .evm_config()
        .block_executor_factory()
        .receipt_builder();

    receipt_builder
        .build_receipt(receipt_ctx)
        .unwrap_or_else(|receipt_ctx| {
            let receipt = alloy_consensus::Receipt {
                // Success flag was added in `EIP-658: Embedding transaction
                // status code in receipts`.
                status: Eip658Value::Eip658(receipt_ctx.result.is_success()),
                cumulative_gas_used: receipt_ctx.cumulative_gas_used,
                logs: receipt_ctx.result.into_logs(),
            };

            receipt_builder.build_deposit_receipt(OpDepositReceipt {
                inner: receipt,
                deposit_nonce,
                // The deposit receipt version was introduced in Canyon to
                // indicate an update to how receipt hashes should be computed
                // when set. The state transition process ensures this is only
                // set for post-Canyon deposit transactions.
                deposit_receipt_version: hardforks.is_canyon_active().then_some(1),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{ExecutionInfo, TxnExecutionResult};
    use std::assert_matches;

    #[test]
    fn tx_limit_rejects_when_uncompressed_size_exceeds_limit() {
        let info = ExecutionInfo {
            cumulative_uncompressed_bytes: 100,
            ..Default::default()
        };

        let result = info.is_tx_over_limits(0, 30_000_000, None, None, 21_000, None, 50, Some(149));

        assert_matches!(
            result,
            Err(TxnExecutionResult::BlockUncompressedSizeExceeded(
                100, 50, 149
            ))
        );
    }

    #[test]
    fn tx_limit_allows_exact_uncompressed_size_fit() {
        let info = ExecutionInfo {
            cumulative_uncompressed_bytes: 100,
            ..Default::default()
        };

        let result = info.is_tx_over_limits(0, 30_000_000, None, None, 21_000, None, 50, Some(150));

        assert!(result.is_ok());
    }
}
