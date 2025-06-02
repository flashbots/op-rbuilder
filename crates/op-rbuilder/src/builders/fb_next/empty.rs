use super::job::JobContext;
use crate::{primitives::reth::ExecutionInfo, traits::ClientBounds};
use alloy_consensus::{Eip658Value, Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::{merge::BEACON_NONCE, Typed2718};
use alloy_op_evm::block::receipt_builder::OpReceiptBuilder;
use alloy_primitives::U256;
use op_alloy_consensus::OpDepositReceipt;
use reth_chain_state::{ExecutedBlock, ExecutedBlockWithTrieUpdates};
use reth_evm::{
    eth::receipt_builder::ReceiptBuilderCtx, execute::BlockBuilder, ConfigureEvm, Evm, EvmError,
};
use reth_node_api::PayloadBuilderError;
use reth_optimism_consensus::calculate_receipt_root_no_memo_optimism;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpBuiltPayload;
use reth_optimism_payload_builder::error::OpPayloadBuilderError;
use reth_optimism_primitives::{OpPrimitives, OpTransactionSigned};
use reth_primitives::RecoveredBlock;
use reth_primitives_traits::SignedTransaction;
use reth_provider::ExecutionOutcome;
use reth_revm::db::states::bundle_state::BundleRetention;
use revm::{context::result::ResultAndState, DatabaseCommit};
use std::sync::Arc;
use tracing::{debug, trace};

pub struct EmptyBlockPayload(OpBuiltPayload);

impl EmptyBlockPayload {
    pub fn new<Client: ClientBounds>(
        job_ctx: &JobContext<Client>,
    ) -> Result<Self, PayloadBuilderError> {
        let state = &mut job_ctx.state_at_parent()?;
        let parent_header = job_ctx.parent_header()?;
        let evm_env = job_ctx.next_evm_environment()?;

        job_ctx
            .builder_context()
            .evm_config()
            .builder_for_next_block(
                state,
                &job_ctx.parent_header()?,
                job_ctx.next_block_env_attributes(),
            )
            .map_err(PayloadBuilderError::other)?
            .apply_pre_execution_changes()?;

        // execute sequencer transactions
        let mut evm = job_ctx
            .builder_context()
            .evm_config()
            .evm_with_env(&mut *state, evm_env.clone());

        let mut exec_info =
            ExecutionInfo::<()>::with_capacity(job_ctx.sequencer_transactions().len());

        for sequencer_tx in job_ctx.sequencer_transactions() {
            // A sequencer's block should never contain blob transactions.
            if sequencer_tx.value().is_eip4844() {
                return Err(PayloadBuilderError::other(
                    OpPayloadBuilderError::BlobTransactionRejected,
                ));
            }

            // Convert the transaction to a [Recovered<TransactionSigned>]. This is
            // purely for the purposes of utilizing the `evm_config.tx_env`` function.
            // Deposit transactions do not have signatures, so if the tx is a deposit, this
            // will just pull in its `from` address.
            let sequencer_tx = sequencer_tx
                .value()
                .try_clone_into_recovered()
                .map_err(|_| {
                    PayloadBuilderError::other(OpPayloadBuilderError::TransactionEcRecoverFailed)
                })?;

            let deposit_nonce = job_ctx.deposit_nonce(&sequencer_tx, evm.db_mut())?;

            let ResultAndState { result, state } = match evm.transact(&sequencer_tx) {
                Ok(res) => res,
                Err(err) => {
                    if err.is_invalid_tx_err() {
                        trace!(target: "payload_builder", %err, ?sequencer_tx, "Error in sequencer transaction, skipping.");
                        continue;
                    }
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(err.into()));
                }
            };

            // add gas used by the transaction to cumulative
            // gas used, before creating the receipt
            exec_info.cumulative_gas_used += result.gas_used();
            let receipt_ctx = ReceiptBuilderCtx {
                tx: sequencer_tx.inner(),
                evm: &evm,
                result,
                state: &state,
                cumulative_gas_used: exec_info.cumulative_gas_used,
            };

            let receipt_builder = job_ctx
                .builder_context()
                .evm_config()
                .block_executor_factory()
                .receipt_builder();

            let receipts =
                receipt_builder
                    .build_receipt(receipt_ctx)
                    .unwrap_or_else(|receipt_ctx| {
                        let receipt = alloy_consensus::Receipt {
                            // Success flag was added in `EIP-658: Embedding transaction status code
                            // in receipts`.
                            status: Eip658Value::Eip658(receipt_ctx.result.is_success()),
                            cumulative_gas_used: receipt_ctx.cumulative_gas_used,
                            logs: receipt_ctx.result.into_logs(),
                        };

                        receipt_builder.build_deposit_receipt(OpDepositReceipt {
                            inner: receipt,
                            deposit_nonce,
                            // The deposit receipt version was introduced in Canyon to indicate an
                            // update to how receipt hashes should be computed
                            // when set. The state transition process ensures
                            // this is only set for post-Canyon deposit
                            // transactions.
                            deposit_receipt_version: job_ctx
                                .builder_context()
                                .chain_spec()
                                .is_canyon_active_at_timestamp(parent_header.timestamp)
                                .then_some(1),
                        })
                    });

            exec_info.receipts.push(receipts);

            // commit the state changes to the database
            evm.db_mut().commit(state);

            // append sender and transaction to the respective lists
            exec_info.executed_senders.push(sequencer_tx.signer());
            exec_info
                .executed_transactions
                .push(sequencer_tx.into_inner());
        }

        // TODO: We must run this only once per block, but we are running it on every flashblock
        // merge all transitions into bundle state, this would apply the withdrawal balance changes
        // and 4788 contract call
        state.merge_transitions(BundleRetention::Reverts);
        let block_number = job_ctx.parent_header()?.number.saturating_add(1);
        let transactions_root = exec_info.transactions_root();
        let extra_data = job_ctx.extra_data();
        let execution_outcome = ExecutionOutcome::new(
            state.take_bundle(),
            vec![exec_info.receipts],
            block_number,
            vec![],
        );

        let receipts_root = execution_outcome
            .generic_receipts_root_slow(block_number, |receipts| {
                calculate_receipt_root_no_memo_optimism(
                    receipts,
                    job_ctx.builder_context().chain_spec(),
                    job_ctx.attributes().timestamp,
                )
            })
            .expect("number is in range");

        let logs_bloom = execution_outcome
            .block_logs_bloom(block_number)
            .expect("number is in range");

        let (state_root, trie_output, hashed_state) =
            job_ctx.state_root_with_updates(&*state.database, execution_outcome.state())?;

        let (withdrawals_root, requests_hash) = job_ctx
            .withdrawals_and_requests_root(execution_outcome.state(), state.database.as_ref())?;
        let (excess_blob_gas, blob_gas_used) = job_ctx.blob_gas_used();

        let header = Header {
            parent_hash: job_ctx.parent(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: evm_env.block_env.beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp: job_ctx.attributes().timestamp,
            mix_hash: job_ctx.attributes().prev_randao,
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(evm_env.block_env.basefee),
            number: block_number,
            gas_limit: job_ctx.gas_limit().unwrap_or(parent_header.gas_limit),
            difficulty: U256::ZERO,
            gas_used: exec_info.cumulative_gas_used,
            extra_data,
            parent_beacon_block_root: job_ctx.attributes().parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
            requests_hash,
        };

        let sealed_block = job_ctx.seal_block(header, exec_info.executed_transactions);
        debug!(target: "experimental_payload_builder", "sealed built block: {sealed_block:#?}");

        // create the executed block data
        let executed: ExecutedBlockWithTrieUpdates<OpPrimitives> = ExecutedBlockWithTrieUpdates {
            block: ExecutedBlock {
                recovered_block: Arc::new(RecoveredBlock::<
                    alloy_consensus::Block<OpTransactionSigned>,
                >::new_sealed(
                    sealed_block.clone(), exec_info.executed_senders
                )),
                execution_output: Arc::new(execution_outcome),
                hashed_state: Arc::new(hashed_state),
            },
            trie: Arc::new(trie_output),
        };

        Ok(Self(OpBuiltPayload::new(
            job_ctx.payload_id(),
            sealed_block.into(),
            exec_info.total_fees,
            Some(executed),
        )))
    }
}

impl From<EmptyBlockPayload> for OpBuiltPayload {
    fn from(payload: EmptyBlockPayload) -> Self {
        payload.0
    }
}
