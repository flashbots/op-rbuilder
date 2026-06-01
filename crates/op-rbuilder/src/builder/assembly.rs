use std::sync::Arc;

use alloy_consensus::{
    BlockBody, EMPTY_OMMER_ROOT_HASH, Header, TxReceipt, constants::EMPTY_WITHDRAWALS, proofs,
};
use alloy_eips::{Encodable2718, eip7685::EMPTY_REQUESTS_HASH, merge::BEACON_NONCE};
use alloy_evm::block::BlockExecutionResult;
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use alloy_rpc_types_eth::Withdrawals;
use op_alloy_consensus::OpReceipt;
use op_alloy_rpc_types_engine::{
    OpFlashblockPayload, OpFlashblockPayloadBase, OpFlashblockPayloadDelta,
    OpFlashblockPayloadMetadata,
};
use reth_basic_payload_builder::PayloadConfig;
use reth_execution_types::BlockExecutionOutput;
use reth_node_api::{Block, BuiltPayloadExecutedBlock, PayloadBuilderError};
use reth_optimism_consensus::{calculate_receipt_root_no_memo_optimism, isthmus};
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilderAttributes};
use reth_optimism_primitives::OpTransactionSigned;
use reth_payload_builder::PayloadId;
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::{
    State,
    db::{BundleState, states::bundle_state::BundleRetention},
};
use revm::{Database, interpreter::as_u64_saturated};
use std::{collections::BTreeMap, time::Instant};
use tracing::{debug, info, warn};

use crate::{
    builder::{StateRootCalculator, payload::FlashblocksState, state_root::StateRootOutput},
    evm::OpBlockEvmFactory,
    hardforks::ActiveHardforks,
    metrics::OpRBuilderMetrics,
    primitives::reth::ExecutionInfo,
};

/// Pre-resolved parameters needed by `build_block`, decoupled from
/// `OpPayloadBuilderCtx`.
pub(super) struct BlockAssemblyInput {
    hardforks: ActiveHardforks,
    parent_header: SealedHeader,
    attributes: OpPayloadBuilderAttributes<OpTransactionSigned>,
    beneficiary: Address,
    block_number: u64,
    base_fee: u64,
    block_gas_limit: u64,
    withdrawals: Option<Withdrawals>,
    extra_data: Bytes,
}

#[derive(Clone)]
struct DerivedBlockArtifacts {
    state_root: B256,
    transactions_root: B256,
    receipts_root: B256,
    withdrawals_root: Option<B256>,
    logs_bloom: Bloom,
    excess_blob_gas: Option<u64>,
    blob_gas_used: Option<u64>,
    requests_hash: Option<B256>,
}

impl BlockAssemblyInput {
    pub(super) fn try_new(
        payload_config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
        evm_factory: &OpBlockEvmFactory,
        hardforks: ActiveHardforks,
    ) -> Result<Self, PayloadBuilderError> {
        let attributes = &payload_config.attributes;
        let block_env = &evm_factory.evm_env().block_env;

        let block_gas_limit = attributes.gas_limit.unwrap_or(block_env.gas_limit);
        let block_number = as_u64_saturated!(block_env.number);
        let base_fee = block_env.basefee;
        let beneficiary = block_env.beneficiary;

        let withdrawals = hardforks
            .is_shanghai_active()
            .then(|| attributes.withdrawals.clone());

        let extra_data = if hardforks.is_jovian_active() {
            attributes
                .get_jovian_extra_data(hardforks.base_fee_params())
                .map_err(PayloadBuilderError::other)?
        } else if hardforks.is_holocene_active() {
            attributes
                .get_holocene_extra_data(hardforks.base_fee_params())
                .map_err(PayloadBuilderError::other)?
        } else {
            Bytes::default()
        };

        Ok(Self {
            hardforks,
            parent_header: (*payload_config.parent_header).clone(),
            attributes: payload_config.attributes,
            beneficiary,
            block_number,
            base_fee,
            block_gas_limit,
            withdrawals,
            extra_data,
        })
    }

    fn payload_id(&self) -> PayloadId {
        self.attributes.id
    }

    fn merge_transitions_into_bundle_state<DB, P>(
        &self,
        state: &mut State<DB>,
        metrics: Arc<OpRBuilderMetrics>,
        enable_tx_tracking_debug_logs: bool,
    ) where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    {
        let state_merge_start_time = Instant::now();
        state.merge_transitions(BundleRetention::Reverts);
        let state_transition_merge_time = state_merge_start_time.elapsed();

        metrics
            .state_transition_merge_duration
            .record(state_transition_merge_time);
        metrics
            .state_transition_merge_gauge
            .set(state_transition_merge_time);

        if enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                block_number = self.block_number,
                duration_us = state_transition_merge_time.as_micros() as u64,
                stage = "state_merge"
            );
        }
    }

    fn check_block_number(&self) -> Result<(), PayloadBuilderError> {
        let block_number = self.block_number;
        let expected = self.parent_header.number + 1;
        if block_number != expected {
            return Err(PayloadBuilderError::Other(
                eyre::eyre!(
                    "build context block number mismatch: expected {}, got {}",
                    expected,
                    self.block_number
                )
                .into(),
            ));
        }

        Ok(())
    }

    fn request_hash(&self) -> Option<B256> {
        if self.hardforks.is_isthmus_active() {
            // always empty requests hash post isthmus
            Some(EMPTY_REQUESTS_HASH)
        } else {
            None
        }
    }

    fn withdrawals_root(
        &self,
        state_updates: &BundleState,
        state: impl StorageRootProvider,
    ) -> Result<Option<B256>, PayloadBuilderError> {
        let withdrawals_root = if self.hardforks.is_isthmus_active() {
            // withdrawals root field in block header is used for storage root
            // of L2 predeploy `l2tol1-message-passer`
            Some(
                isthmus::withdrawals_root(state_updates, state)
                    .map_err(PayloadBuilderError::other)?,
            )
        } else if self.hardforks.is_canyon_active() {
            Some(EMPTY_WITHDRAWALS)
        } else {
            None
        };

        Ok(withdrawals_root)
    }

    fn blob_fields(&self, info: &ExecutionInfo) -> (Option<u64>, Option<u64>) {
        if let Some(blob_fields) = info.optional_blob_fields {
            return blob_fields;
        }

        if self.hardforks.is_jovian_active() {
            let scalar = info
                .da_footprint_scalar
                .expect("Scalar must be defined for Jovian blocks");
            let result = info.cumulative_da_bytes_used * scalar as u64;
            (Some(0), Some(result))
        } else if self.hardforks.is_ecotone_active() {
            (Some(0), Some(0))
        } else {
            (None, None)
        }
    }

    fn compute_derived_artifacts<DB, P>(
        &self,
        state: &State<DB>,
        info: &ExecutionInfo,
        state_root: B256,
    ) -> Result<DerivedBlockArtifacts, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    {
        let receipts_root = calculate_receipt_root_no_memo_optimism(
            &info.receipts,
            &self.hardforks,
            self.attributes.timestamp(),
        );
        let transactions_root = proofs::calculate_transaction_root(&info.executed_transactions);
        let withdrawals_root =
            self.withdrawals_root(&state.bundle_state, state.database.as_ref())?;
        let logs_bloom = alloy_primitives::logs_bloom(info.receipts.iter().flat_map(|r| r.logs()));
        let (excess_blob_gas, blob_gas_used) = self.blob_fields(info);
        let requests_hash = self.request_hash();

        Ok(DerivedBlockArtifacts {
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            excess_blob_gas,
            blob_gas_used,
            requests_hash,
        })
    }

    fn construct_block(
        &self,
        info: &ExecutionInfo,
        derived_block_artifacts: DerivedBlockArtifacts,
    ) -> alloy_consensus::Block<OpTransactionSigned> {
        let DerivedBlockArtifacts {
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            excess_blob_gas,
            blob_gas_used,
            requests_hash,
        } = derived_block_artifacts;

        let header = Header {
            parent_hash: self.parent_header.hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: self.beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp: self.attributes.timestamp,
            mix_hash: self.attributes.prev_randao,
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(self.base_fee),
            number: self.parent_header.number + 1,
            gas_limit: self.block_gas_limit,
            difficulty: U256::ZERO,
            gas_used: info.cumulative_gas_used,
            extra_data: self.extra_data.clone(),
            parent_beacon_block_root: self.attributes.parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
            requests_hash,
            // EIP-7701/7934 — not activated on OP chains; emitted as None
            block_access_list_hash: None,
            slot_number: None,
        };

        alloy_consensus::Block::<OpTransactionSigned>::new(
            header,
            BlockBody {
                transactions: info.executed_transactions.clone(),
                ommers: vec![],
                withdrawals: self.withdrawals.clone(),
            },
        )
    }

    pub(super) fn assemble<DB, P>(
        self,
        state: &mut State<DB>,
        fb_state: Option<&mut FlashblocksState>,
        info: &mut ExecutionInfo,
        state_root_calc: &mut StateRootCalculator,
        metrics: Arc<OpRBuilderMetrics>,
        enable_tx_tracking_debug_logs: bool,
    ) -> Result<(OpBuiltPayload, OpFlashblockPayload), PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    {
        // We use it to preserve state, so we run merge_transitions on transition state at most once
        let untouched_transition_state = state.transition_state.clone();
        self.merge_transitions_into_bundle_state(
            state,
            metrics.clone(),
            enable_tx_tracking_debug_logs,
        );

        self.check_block_number()?;

        let flashblock_index_for_trace = fb_state
            .as_deref()
            .map(|s| s.flashblock_index())
            .unwrap_or(0);

        // Calculate the state root (returns defaults when disabled)
        let state_root_start_time = Instant::now();
        let StateRootOutput {
            state_root,
            hashed_state,
            trie_updates,
        } = state_root_calc
            .compute(state.database.as_ref(), &state.bundle_state)
            .inspect_err(|err| {
                warn!(
                    target: "payload_builder",
                    parent_header = %self.parent_header.hash(),
                    %err,
                    "failed to calculate state root for payload"
                );
            })
            .map_err(PayloadBuilderError::other)?;
        if state_root_calc.is_enabled() {
            let state_root_calculation_time = state_root_start_time.elapsed();
            metrics
                .state_root_calculation_duration
                .record(state_root_calculation_time);
            metrics
                .state_root_calculation_gauge
                .set(state_root_calculation_time);

            debug!(
                target: "payload_builder",
                flashblock_index = flashblock_index_for_trace,
                state_root = %state_root,
                duration_ms = state_root_calculation_time.as_millis(),
                "State root calculation completed"
            );

            if enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    block_number = self.block_number,
                    flashblock_index = flashblock_index_for_trace,
                    duration_ms = state_root_calculation_time.as_millis() as u64,
                    incremental = state_root_calc.has_cached_trie(),
                    cumulative_gas = info.cumulative_gas_used,
                    num_txs = info.executed_transactions.len(),
                    stage = "state_root_computed"
                );
            }
        }

        let derived_block_artifacts = self.compute_derived_artifacts(state, info, state_root)?;

        let block = self.construct_block(info, derived_block_artifacts.clone());

        let seal_start = Instant::now();
        let sealed_block = Arc::new(block.clone().seal_slow());
        let seal_duration = seal_start.elapsed();

        let block_hash = sealed_block.hash();

        let target_flashblock_count_for_trace = fb_state
            .as_deref()
            .map(|s| s.target_flashblock_count())
            .unwrap_or(0);

        info!(
            target: "payload_builder",
            id = %self.payload_id(),
            block_number = self.block_number,
            block_hash = %block_hash,
            flashblock_index = flashblock_index_for_trace,
            target_flashblocks = target_flashblock_count_for_trace,
            tx_count = info.executed_transactions.len(),
            gas_used = info.cumulative_gas_used,
            da_used = info.cumulative_da_bytes_used,
            state_root = %state_root,
            seal_duration_us = seal_duration.as_micros() as u64,
            "Block sealed"
        );

        if enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                block_number = self.block_number,
                flashblock_index = flashblock_index_for_trace,
                block_hash = ?block_hash,
                seal_duration_us = seal_duration.as_micros() as u64,
                build_block_total_time_since_state_root_start_us = state_root_start_time.elapsed().as_micros() as u64,
                cumulative_gas = info.cumulative_gas_used,
                num_txs = info.executed_transactions.len(),
                stage = "block_sealed"
            );
        }

        // need to read balances before take_bundle() below
        let new_account_balances = state
            .bundle_state
            .state
            .iter()
            .filter_map(|(address, account)| {
                account.info.as_ref().map(|info| (*address, info.balance))
            })
            .collect::<BTreeMap<Address, U256>>();

        let bundle_state = state.take_bundle();
        let execution_output = BlockExecutionOutput {
            state: bundle_state,
            result: BlockExecutionResult {
                receipts: info.receipts.clone(),
                requests: Default::default(),
                gas_used: info.cumulative_gas_used,
                blob_gas_used: derived_block_artifacts.blob_gas_used.unwrap_or_default(),
            },
        };

        let recovered_block = RecoveredBlock::new_unhashed(block, info.executed_senders.clone());

        // create the executed block data
        let executed = BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered_block),
            execution_output: Arc::new(execution_output),
            trie_updates,
            hashed_state: Arc::new(hashed_state),
        };
        debug!(
            target: "payload_builder",
            id = %self.payload_id(),
            "Executed block created"
        );

        // pick the new transactions from the info field and update the last flashblock index
        let (new_transactions, new_receipts) = if let Some(fb_state) = fb_state {
            let new_txs = fb_state.slice_new_transactions(&info.executed_transactions);
            let new_receipts = fb_state.slice_new_receipts(&info.receipts);
            fb_state.set_last_flashblock_tx_index(info.executed_transactions.len());
            (new_txs, new_receipts)
        } else {
            (
                info.executed_transactions.as_slice(),
                info.receipts.as_slice(),
            )
        };

        let new_transactions_encoded: Vec<Bytes> = new_transactions
            .iter()
            .map(|tx| tx.encoded_2718().into())
            .collect();

        let receipts_with_hash: BTreeMap<B256, OpReceipt> = new_transactions
            .iter()
            .zip(new_receipts.iter())
            .map(|(tx, receipt)| {
                // TODO: remove this once reth updates to use the op-alloy defined type as well.
                let converted_receipt = match receipt {
                    OpReceipt::Legacy(r) => op_alloy_consensus::OpReceipt::Legacy(r.clone()),
                    OpReceipt::Eip2930(r) => op_alloy_consensus::OpReceipt::Eip2930(r.clone()),
                    OpReceipt::Eip1559(r) => op_alloy_consensus::OpReceipt::Eip1559(r.clone()),
                    OpReceipt::Eip7702(r) => op_alloy_consensus::OpReceipt::Eip7702(r.clone()),
                    OpReceipt::Deposit(r) => op_alloy_consensus::OpReceipt::Deposit(
                        op_alloy_consensus::OpDepositReceipt {
                            inner: r.inner.clone(),
                            deposit_nonce: r.deposit_nonce,
                            deposit_receipt_version: r.deposit_receipt_version,
                        },
                    ),
                    // EIP-7918: PostExec receipts are protocol-internal and
                    // not produced by user txs in the standard block-building
                    // path. Treat as a Legacy passthrough; if PostExec lands
                    // in production, this match arm needs revisiting.
                    OpReceipt::PostExec(r) => op_alloy_consensus::OpReceipt::PostExec(r.clone()),
                };
                (tx.tx_hash(), converted_receipt)
            })
            .collect();

        let metadata = OpFlashblockPayloadMetadata {
            receipts: receipts_with_hash,
            new_account_balances,
            block_number: self.parent_header.number + 1,
        };

        let (_, blob_gas_used) = self.blob_fields(info);

        // Prepare the flashblocks message
        let fb_payload = OpFlashblockPayload {
            payload_id: self.payload_id(),
            index: 0,
            base: Some(OpFlashblockPayloadBase {
                parent_beacon_block_root: self.attributes.parent_beacon_block_root.ok_or_else(
                    || {
                        PayloadBuilderError::Other(
                            eyre::eyre!("parent beacon block root not found").into(),
                        )
                    },
                )?,
                parent_hash: self.parent_header.hash(),
                fee_recipient: self.attributes.suggested_fee_recipient,
                prev_randao: self.attributes.prev_randao,
                block_number: self.parent_header.number + 1,
                gas_limit: self.block_gas_limit,
                timestamp: self.attributes.timestamp,
                extra_data: self.extra_data.clone(),
                base_fee_per_gas: U256::from(self.base_fee),
            }),
            diff: OpFlashblockPayloadDelta {
                state_root,
                receipts_root: derived_block_artifacts.receipts_root,
                logs_bloom: derived_block_artifacts.logs_bloom,
                gas_used: info.cumulative_gas_used,
                block_hash,
                transactions: new_transactions_encoded,
                withdrawals: self.withdrawals.clone().unwrap_or_default().to_vec(),
                withdrawals_root: derived_block_artifacts.withdrawals_root.unwrap_or_default(),
                blob_gas_used,
            },
            metadata,
        };
        // Need to ensure `state.bundle = None`, was done previously with  `state.take_bundle()`
        state.transition_state = untouched_transition_state;

        Ok((
            OpBuiltPayload::new(
                self.payload_id(),
                sealed_block,
                info.total_fees,
                Some(executed),
            ),
            fb_payload,
        ))
    }
}
