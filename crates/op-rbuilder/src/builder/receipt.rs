use alloy_consensus::Eip658Value;
use alloy_evm::Evm;
use alloy_op_evm::block::receipt_builder::OpReceiptBuilder;
use op_alloy_consensus::{OpDepositReceipt, OpReceipt, OpTxType};
use reth_evm::{ConfigureEvm, eth::receipt_builder::ReceiptBuilderCtx};

use crate::{evm::OpBlockEvmFactory, hardforks::ActiveHardforks};

pub(super) fn build_receipt<E: Evm>(
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
