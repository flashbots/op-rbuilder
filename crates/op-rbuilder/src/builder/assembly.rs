use std::sync::Arc;

use alloy_eips::Encodable2718;
use alloy_evm::block::BlockExecutionResult;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types_eth::Withdrawals;
use op_alloy_consensus::OpReceipt;
use op_alloy_rpc_types_engine::{
    OpFlashblockPayload, OpFlashblockPayloadBase, OpFlashblockPayloadDelta,
    OpFlashblockPayloadMetadata,
};
use reth_basic_payload_builder::PayloadConfig;
use reth_evm::{ConfigureEvm, EvmEnvFor, execute::BlockAssemblerInput};
use reth_execution_types::BlockExecutionOutput;
use reth_node_api::{Block, BuiltPayloadExecutedBlock, PayloadBuilderError};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{
    OpBlockAssembler, OpBlockExecutionCtx, OpEvmConfig, OpNextBlockEnvAttributes,
};
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilderAttributes};
use reth_optimism_primitives::OpTransactionSigned;
use reth_payload_builder::PayloadId;
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use reth_provider::{ProviderError, StateProvider};
use reth_revm::{State, db::states::bundle_state::BundleRetention};
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

type OpExecutorFactory = <OpEvmConfig as ConfigureEvm>::BlockExecutorFactory;

/// Pre-resolved parameters needed by `build_block`, decoupled from
/// `OpPayloadBuilderCtx`.
pub(super) struct BlockAssemblyInput {
    hardforks: ActiveHardforks,
    parent_header: SealedHeader,
    attributes: OpPayloadBuilderAttributes<OpTransactionSigned>,
    block_number: u64,
    base_fee: u64,
    block_gas_limit: u64,
    withdrawals: Option<Withdrawals>,
    extra_data: Bytes,
    evm_env: EvmEnvFor<OpEvmConfig>,
    execution_ctx: OpBlockExecutionCtx,
    block_assembler: OpBlockAssembler<OpChainSpec>,
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

        let execution_ctx = evm_factory
            .evm_config()
            .context_for_next_block(
                &payload_config.parent_header,
                OpNextBlockEnvAttributes {
                    timestamp: attributes.timestamp,
                    suggested_fee_recipient: beneficiary,
                    prev_randao: attributes.prev_randao,
                    gas_limit: block_gas_limit,
                    parent_beacon_block_root: attributes.parent_beacon_block_root,
                    extra_data: extra_data.clone(),
                },
            )
            .map_err(PayloadBuilderError::other)?;

        Ok(Self {
            hardforks,
            parent_header: (*payload_config.parent_header).clone(),
            attributes: payload_config.attributes,
            block_number,
            base_fee,
            block_gas_limit,
            withdrawals,
            extra_data,
            evm_env: evm_factory.evm_env().clone(),
            execution_ctx,
            block_assembler: evm_factory.evm_config().block_assembler().clone(),
        })
    }

    fn payload_id(&self) -> PayloadId {
        self.attributes.payload_id()
    }

    fn merge_transitions_into_bundle_state<DB, P>(
        &self,
        state: &mut State<DB>,
        metrics: Arc<OpRBuilderMetrics>,
        enable_tx_tracking_debug_logs: bool,
    ) where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateProvider,
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

    fn assemble_block<DB, P>(
        &self,
        state: &State<DB>,
        info: &ExecutionInfo,
        state_root: B256,
        execution_result: &BlockExecutionResult<OpReceipt>,
        blob_fields: (Option<u64>, Option<u64>),
    ) -> Result<alloy_consensus::Block<OpTransactionSigned>, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateProvider,
    {
        let state_provider = state.database.as_ref();
        let mut block = self
            .block_assembler
            .assemble_block(BlockAssemblerInput::<OpExecutorFactory>::new(
                self.evm_env.clone(),
                self.execution_ctx.clone(),
                &self.parent_header,
                info.executed_transactions.clone(),
                execution_result,
                &state.bundle_state,
                &state_provider,
                state_root,
                None,
            ))
            .map_err(PayloadBuilderError::other)?;

        // Payload validation can provide authoritative blob header fields that intentionally
        // bypass the normal hardfork-derived values used by OpBlockAssembler.
        if info.optional_blob_fields.is_some() {
            block.header.excess_blob_gas = blob_fields.0;
            block.header.blob_gas_used = blob_fields.1;
        }

        // OpBlockAssembler intentionally emits an empty OP withdrawals list.
        block.body.withdrawals = self.withdrawals.clone();

        Ok(block)
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
        P: StateProvider,
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

        let blob_fields = self.blob_fields(info);
        let execution_result = BlockExecutionResult {
            receipts: info.receipts.clone(),
            requests: Default::default(),
            gas_used: info.cumulative_gas_used,
            blob_gas_used: blob_fields.1.unwrap_or_default(),
        };
        let block = self.assemble_block(state, info, state_root, &execution_result, blob_fields)?;
        let receipts_root = block.header.receipts_root;
        let logs_bloom = block.header.logs_bloom;
        let withdrawals_root = block.header.withdrawals_root;

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
            result: execution_result,
        };

        let recovered_block = RecoveredBlock::new_unhashed(block, info.executed_senders.clone());

        // create the executed block data
        let executed = BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(recovered_block),
            execution_output: Arc::new(execution_output),
            trie_updates,
            hashed_state: Arc::new(hashed_state),
            changed_paths: None,
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
                    OpReceipt::PostExec(r) => op_alloy_consensus::OpReceipt::PostExec(r.clone()),
                    OpReceipt::Deposit(r) => op_alloy_consensus::OpReceipt::Deposit(
                        op_alloy_consensus::OpDepositReceipt {
                            inner: r.inner.clone(),
                            deposit_nonce: r.deposit_nonce,
                            deposit_receipt_version: r.deposit_receipt_version,
                        },
                    ),
                };
                (tx.tx_hash(), converted_receipt)
            })
            .collect();

        let metadata = OpFlashblockPayloadMetadata {
            receipts: receipts_with_hash,
            new_account_balances,
            block_number: self.parent_header.number + 1,
        };

        let blob_gas_used = blob_fields.1;

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
                fee_recipient: self.attributes.suggested_fee_recipient(),
                prev_randao: self.attributes.prev_randao,
                block_number: self.parent_header.number + 1,
                gas_limit: self.block_gas_limit,
                timestamp: self.attributes.timestamp,
                extra_data: self.extra_data.clone(),
                base_fee_per_gas: U256::from(self.base_fee),
            }),
            diff: OpFlashblockPayloadDelta {
                state_root,
                receipts_root,
                logs_bloom,
                gas_used: info.cumulative_gas_used,
                block_hash,
                transactions: new_transactions_encoded,
                withdrawals: self.withdrawals.clone().unwrap_or_default().to_vec(),
                withdrawals_root: withdrawals_root.unwrap_or_default(),
                blob_gas_used,
                // This builder does not produce SDM post-exec transactions
                post_exec_tx: None,
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

#[cfg(test)]
mod tests {
    use std::{ops::Range, sync::Arc};

    use alloy_consensus::{
        BlockBody, EMPTY_OMMER_ROOT_HASH, Header, SignableTransaction, TxEip1559, TxReceipt, proofs,
    };
    use alloy_eips::{eip4895::Withdrawal, eip7685::EMPTY_REQUESTS_HASH, merge::BEACON_NONCE};
    use alloy_evm::block::{BlockExecutionResult, BlockExecutor};
    use alloy_network::TxSignerSync;
    use alloy_primitives::{
        Address, B64, B256, Bytes, Signature, StorageKey, StorageValue, TxKind, U256, map::HashMap,
    };
    use alloy_rpc_types_eth::Withdrawals;
    use alloy_signer_local::PrivateKeySigner;
    use op_alloy_consensus::OpTxEnvelope;
    use op_revm::constants::{
        DA_FOOTPRINT_GAS_SCALAR_OFFSET, DA_FOOTPRINT_GAS_SCALAR_SLOT, L1_BLOCK_CONTRACT,
    };
    use reth_basic_payload_builder::PayloadConfig;
    use reth_chainspec::EthChainSpec;
    use reth_evm::{ConfigureEvm, execute::BlockBuilder};
    use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};
    use reth_optimism_consensus::{calculate_receipt_root_no_memo_optimism, isthmus};
    use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
    use reth_optimism_node::OpPayloadBuilderAttributes;
    use reth_optimism_primitives::OpTransactionSigned;
    use reth_payload_builder::PayloadId;
    use reth_primitives_traits::{Account, Block as _, Recovered, SealedHeader};
    use reth_provider::{
        AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, ProviderError,
        StateProofProvider, StateProvider, StateRootProvider, StorageRootProvider,
    };
    use reth_revm::{
        State,
        database::StateProviderDatabase,
        db::{BundleState, states::bundle_state::BundleRetention},
        test_utils::StateProviderTest,
    };
    use reth_storage_api::{errors::ProviderResult, noop::NoopProvider};
    use reth_trie::{
        AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, MultiProof,
        MultiProofTargets, StorageMultiProof, StorageProof, TrieInput, updates::TrieUpdates,
    };
    use revm::{
        Database,
        state::{AccountInfo, Bytecode},
    };

    use super::BlockAssemblyInput;
    use crate::{
        evm::OpBlockEvmFactory, hardforks::ActiveHardforks, primitives::reth::ExecutionInfo,
    };

    const BLOCK_GAS_LIMIT: u64 = 30_000_000;
    const DA_FOOTPRINT_SCALAR: u16 = 7;
    const LIVE_MESSAGE_PASSER_ROOT: B256 = B256::repeat_byte(0x5a);
    const LOG_EMITTER_CODE: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xa0, 0x00];

    #[derive(Debug)]
    struct FixedStorageRootProvider {
        root: B256,
    }

    /// Assembly only reads the message-passer storage root, so every other facet of the
    /// `StateProvider` bundle delegates to a noop provider. This lives in the test stub rather than
    /// production: production hands the assembler the real state provider.
    impl BlockHashReader for FixedStorageRootProvider {
        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
            NoopProvider::default().block_hash(number)
        }

        fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
            NoopProvider::default().canonical_hashes_range(start, end)
        }
    }

    impl AccountReader for FixedStorageRootProvider {
        fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
            NoopProvider::default().basic_account(address)
        }
    }

    impl BytecodeReader for FixedStorageRootProvider {
        fn bytecode_by_hash(
            &self,
            code_hash: &B256,
        ) -> ProviderResult<Option<reth_primitives_traits::Bytecode>> {
            NoopProvider::default().bytecode_by_hash(code_hash)
        }
    }

    impl StateRootProvider for FixedStorageRootProvider {
        fn state_root(&self, state: HashedPostState) -> ProviderResult<B256> {
            NoopProvider::default().state_root(state)
        }

        fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
            NoopProvider::default().state_root_from_nodes(input)
        }

        fn state_root_with_updates(
            &self,
            state: HashedPostState,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            NoopProvider::default().state_root_with_updates(state)
        }

        fn state_root_from_nodes_with_updates(
            &self,
            input: TrieInput,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            NoopProvider::default().state_root_from_nodes_with_updates(input)
        }
    }

    impl StateProofProvider for FixedStorageRootProvider {
        fn proof(
            &self,
            input: TrieInput,
            address: Address,
            slots: &[B256],
        ) -> ProviderResult<AccountProof> {
            NoopProvider::default().proof(input, address, slots)
        }

        fn multiproof(
            &self,
            input: TrieInput,
            targets: MultiProofTargets,
        ) -> ProviderResult<MultiProof> {
            NoopProvider::default().multiproof(input, targets)
        }

        fn witness(
            &self,
            input: TrieInput,
            target: HashedPostState,
            mode: ExecutionWitnessMode,
        ) -> ProviderResult<Vec<Bytes>> {
            NoopProvider::default().witness(input, target, mode)
        }
    }

    impl HashedPostStateProvider for FixedStorageRootProvider {
        fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
            NoopProvider::default().hashed_post_state(bundle_state)
        }
    }

    impl StateProvider for FixedStorageRootProvider {
        fn storage(
            &self,
            account: Address,
            storage_key: StorageKey,
        ) -> ProviderResult<Option<StorageValue>> {
            NoopProvider::default().storage(account, storage_key)
        }
    }

    impl StorageRootProvider for FixedStorageRootProvider {
        fn storage_root(
            &self,
            _address: Address,
            _hashed_storage: HashedStorage,
        ) -> ProviderResult<B256> {
            Ok(self.root)
        }

        fn storage_proof(
            &self,
            _address: Address,
            _slot: B256,
            _hashed_storage: HashedStorage,
        ) -> ProviderResult<StorageProof> {
            unreachable!("assembly only queries the message-passer storage root")
        }

        fn storage_multiproof(
            &self,
            _address: Address,
            _slots: &[B256],
            _hashed_storage: HashedStorage,
        ) -> ProviderResult<StorageMultiProof> {
            unreachable!("assembly only queries the message-passer storage root")
        }
    }

    /// In-memory EVM database whose `AsRef` view models the live trie provider used by assembly.
    #[derive(Debug)]
    struct AssemblyTestDatabase {
        inner: StateProviderDatabase<StateProviderTest>,
        storage_roots: FixedStorageRootProvider,
    }

    impl AsRef<FixedStorageRootProvider> for AssemblyTestDatabase {
        fn as_ref(&self) -> &FixedStorageRootProvider {
            &self.storage_roots
        }
    }

    impl Database for AssemblyTestDatabase {
        type Error = ProviderError;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.inner.basic(address)
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.inner.code_by_hash(code_hash)
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            self.inner.storage(address, index)
        }

        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            self.inner.block_hash(number)
        }
    }

    fn funded_provider(signer: Address) -> StateProviderTest {
        let mut provider = StateProviderTest::default();
        provider.insert_account(
            signer,
            Account {
                nonce: 0,
                balance: U256::from(100_000_000_000_000_000_000u128),
                bytecode_hash: None,
            },
            None,
            HashMap::default(),
        );
        provider.insert_account(
            Address::repeat_byte(0x51),
            Account {
                nonce: 1,
                ..Default::default()
            },
            Some(Bytes::from_static(LOG_EMITTER_CODE)),
            HashMap::default(),
        );

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[DA_FOOTPRINT_GAS_SCALAR_OFFSET..DA_FOOTPRINT_GAS_SCALAR_OFFSET + 2]
            .copy_from_slice(&DA_FOOTPRINT_SCALAR.to_be_bytes());
        let mut l1_storage = HashMap::default();
        l1_storage.insert(
            StorageKey::with_last_byte(1),
            StorageValue::from(1_000_000_000),
        );
        l1_storage.insert(StorageKey::with_last_byte(5), StorageValue::from(188));
        l1_storage.insert(StorageKey::with_last_byte(6), StorageValue::from(684_000));
        l1_storage.insert(
            StorageKey::from(DA_FOOTPRINT_GAS_SCALAR_SLOT),
            StorageValue::from_be_bytes(scalar_bytes),
        );
        provider.insert_account(
            L1_BLOCK_CONTRACT,
            Account {
                nonce: 1,
                ..Default::default()
            },
            None,
            l1_storage,
        );

        provider
    }

    fn sign_test_tx(
        signer: &PrivateKeySigner,
        nonce: u64,
        to: Address,
        chain_id: u64,
    ) -> Recovered<OpTransactionSigned> {
        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(to),
            ..Default::default()
        };
        let signature: Signature = signer.sign_transaction_sync(&mut tx).unwrap();
        let envelope = OpTxEnvelope::Eip1559(tx.into_signed(signature));
        Recovered::new_unchecked(OpTransactionSigned::from(envelope), signer.address())
    }

    fn parent_and_attributes(
        with_withdrawals: bool,
    ) -> (
        SealedHeader,
        OpPayloadBuilderAttributes<OpTransactionSigned>,
        OpNextBlockEnvAttributes,
    ) {
        let parent = SealedHeader::new(
            Header {
                number: 20_000_000,
                gas_limit: BLOCK_GAS_LIMIT,
                gas_used: BLOCK_GAS_LIMIT / 2,
                timestamp: 100,
                base_fee_per_gas: Some(1_000_000_000),
                ..Default::default()
            },
            B256::repeat_byte(0x11),
        );
        let withdrawals = if with_withdrawals {
            Withdrawals::new(vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: Address::repeat_byte(0x77),
                amount: 3,
            }])
        } else {
            Withdrawals::default()
        };
        let attributes = OpPayloadBuilderAttributes {
            id: PayloadId::new([0x42; 8]),
            parent: parent.hash(),
            timestamp: parent.timestamp + 2,
            suggested_fee_recipient: Address::repeat_byte(0x22),
            prev_randao: B256::repeat_byte(0x33),
            withdrawals,
            parent_beacon_block_root: Some(B256::repeat_byte(0x44)),
            gas_limit: Some(BLOCK_GAS_LIMIT),
            eip_1559_params: Some(B64::ZERO),
            min_base_fee: Some(1),
            ..Default::default()
        };
        let env_attributes = OpNextBlockEnvAttributes {
            timestamp: attributes.timestamp,
            suggested_fee_recipient: attributes.suggested_fee_recipient,
            prev_randao: attributes.prev_randao,
            gas_limit: attributes.gas_limit.unwrap(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            extra_data: Default::default(),
        };

        (parent, attributes, env_attributes)
    }

    // Reference oracle.
    fn reference_withdrawals_root(
        input: &BlockAssemblyInput,
        state_updates: &BundleState,
        state: impl StorageRootProvider,
    ) -> Result<Option<B256>, reth_node_api::PayloadBuilderError> {
        if input.hardforks.is_isthmus_active() {
            Ok(Some(
                isthmus::withdrawals_root(state_updates, state)
                    .map_err(reth_node_api::PayloadBuilderError::other)?,
            ))
        } else if input.hardforks.is_canyon_active() {
            Ok(Some(alloy_consensus::constants::EMPTY_WITHDRAWALS))
        } else {
            Ok(None)
        }
    }

    fn reference_blob_fields(
        input: &BlockAssemblyInput,
        info: &ExecutionInfo,
    ) -> (Option<u64>, Option<u64>) {
        if let Some(blob_fields) = info.optional_blob_fields {
            return blob_fields;
        }

        if input.hardforks.is_jovian_active() {
            let scalar = info
                .da_footprint_scalar
                .expect("Scalar must be defined for Jovian blocks");
            (Some(0), Some(info.cumulative_da_bytes_used * scalar as u64))
        } else if input.hardforks.is_ecotone_active() {
            (Some(0), Some(0))
        } else {
            (None, None)
        }
    }

    fn reference_construct_block<DB, P>(
        input: &BlockAssemblyInput,
        state: &State<DB>,
        info: &ExecutionInfo,
        state_root: B256,
    ) -> Result<alloy_consensus::Block<OpTransactionSigned>, reth_node_api::PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StorageRootProvider,
    {
        let receipts_root = calculate_receipt_root_no_memo_optimism(
            &info.receipts,
            &input.hardforks,
            input.attributes.timestamp,
        );
        let transactions_root = proofs::calculate_transaction_root(&info.executed_transactions);
        let withdrawals_root =
            reference_withdrawals_root(input, &state.bundle_state, state.database.as_ref())?;
        let logs_bloom =
            alloy_primitives::logs_bloom(info.receipts.iter().flat_map(|receipt| receipt.logs()));
        let (excess_blob_gas, blob_gas_used) = reference_blob_fields(input, info);
        let requests_hash = input
            .hardforks
            .is_isthmus_active()
            .then_some(EMPTY_REQUESTS_HASH);

        Ok(alloy_consensus::Block::new(
            Header {
                parent_hash: input.parent_header.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: input.evm_env.block_env.beneficiary,
                state_root,
                transactions_root,
                receipts_root,
                withdrawals_root,
                logs_bloom,
                timestamp: input.attributes.timestamp,
                mix_hash: input.attributes.prev_randao,
                nonce: BEACON_NONCE.into(),
                base_fee_per_gas: Some(input.base_fee),
                number: input.parent_header.number + 1,
                gas_limit: input.block_gas_limit,
                difficulty: U256::ZERO,
                gas_used: info.cumulative_gas_used,
                extra_data: input.extra_data.clone(),
                parent_beacon_block_root: input.attributes.parent_beacon_block_root,
                blob_gas_used,
                excess_blob_gas,
                requests_hash,
                block_access_list_hash: None,
                slot_number: None,
            },
            BlockBody {
                transactions: info.executed_transactions.clone(),
                ommers: vec![],
                withdrawals: input.withdrawals.clone(),
            },
        ))
    }

    fn assert_header_parity(
        case: &str,
        input: &BlockAssemblyInput,
        state: &State<AssemblyTestDatabase>,
        info: &ExecutionInfo,
    ) {
        let state_root = B256::repeat_byte(0x80 + info.executed_transactions.len() as u8);
        let blob_fields = input.blob_fields(info);
        let execution_result = BlockExecutionResult {
            receipts: info.receipts.clone(),
            requests: Default::default(),
            gas_used: info.cumulative_gas_used,
            blob_gas_used: blob_fields.1.unwrap_or_default(),
        };
        let assembled = input
            .assemble_block(state, info, state_root, &execution_result, blob_fields)
            .unwrap();
        let reference = reference_construct_block(input, state, info, state_root).unwrap();

        assert_eq!(assembled.header, reference.header, "{case}: header drift");
        assert_eq!(assembled.body, reference.body, "{case}: body drift");
        assert_eq!(
            assembled.clone().seal_slow().hash(),
            reference.seal_slow().hash(),
            "{case}: sealed block hash drift"
        );
        assert_eq!(assembled.header.state_root, state_root);
        if !info.executed_transactions.is_empty() {
            assert_ne!(
                assembled.header.logs_bloom,
                alloy_primitives::Bloom::default(),
                "{case}: executed log-emitter prefix must exercise bloom derivation"
            );
        }
        if input.hardforks.is_isthmus_active() {
            assert_eq!(
                assembled.header.withdrawals_root,
                Some(LIVE_MESSAGE_PASSER_ROOT),
                "{case}: Isthmus must use the live storage-root provider"
            );
        }
        if input.hardforks.is_jovian_active() && info.optional_blob_fields.is_none() {
            assert_eq!(
                assembled.header.blob_gas_used,
                Some(info.cumulative_da_bytes_used * info.da_footprint_scalar.unwrap() as u64),
                "{case}: Jovian blob_gas_used must carry the DA footprint"
            );
        }
    }

    fn execute_session(
        evm_config: &OpEvmConfig,
        parent: &SealedHeader,
        attributes: &OpNextBlockEnvAttributes,
        state: &mut State<AssemblyTestDatabase>,
        info: &mut ExecutionInfo,
        transactions: &[Recovered<OpTransactionSigned>],
        range: Range<usize>,
    ) {
        let mut builder = evm_config
            .builder_for_next_block(state, parent, attributes.clone())
            .unwrap();
        for index in range {
            let transaction = &transactions[index];
            let gas_used = builder.execute_transaction(transaction.clone()).unwrap();
            info.commit_executed_tx(
                transaction,
                gas_used.tx_gas_used(),
                index as u64 + 1,
                Some(index as u128 + 1),
                builder
                    .executor()
                    .receipts()
                    .last()
                    .cloned()
                    .expect("committed transaction has a receipt"),
            );
        }
    }

    fn run_prefix_matrix(config_name: &str, chain_spec: Arc<OpChainSpec>, with_withdrawals: bool) {
        let chain_id = chain_spec.chain_id();
        let signer = PrivateKeySigner::random();
        let transactions = [
            sign_test_tx(&signer, 0, Address::repeat_byte(0x51), chain_id),
            sign_test_tx(&signer, 1, Address::repeat_byte(0x52), chain_id),
            sign_test_tx(&signer, 2, Address::repeat_byte(0x53), chain_id),
        ];
        let (parent, attributes, mut env_attributes) = parent_and_attributes(with_withdrawals);
        let hardforks = ActiveHardforks::new(Arc::clone(&chain_spec), attributes.timestamp);
        let extra_data = if hardforks.is_jovian_active() {
            attributes
                .get_jovian_extra_data(hardforks.base_fee_params())
                .unwrap()
        } else if hardforks.is_holocene_active() {
            attributes
                .get_holocene_extra_data(hardforks.base_fee_params())
                .unwrap()
        } else {
            Default::default()
        };
        env_attributes.extra_data = extra_data;
        let evm_config = OpEvmConfig::optimism(Arc::clone(&chain_spec));
        let evm_factory =
            OpBlockEvmFactory::for_next_block(evm_config.clone(), &parent, &env_attributes)
                .unwrap();
        let payload_id = attributes.id;
        let payload_config = PayloadConfig::new(Arc::new(parent.clone()), attributes, payload_id);
        let input = BlockAssemblyInput::try_new(payload_config, &evm_factory, hardforks).unwrap();
        let database = AssemblyTestDatabase {
            inner: StateProviderDatabase::new(funded_provider(signer.address())),
            storage_roots: FixedStorageRootProvider {
                root: LIVE_MESSAGE_PASSER_ROOT,
            },
        };
        let mut state = State::builder()
            .with_database(database)
            .with_bundle_update()
            .build();
        let mut info = ExecutionInfo {
            da_footprint_scalar: input
                .hardforks
                .is_jovian_active()
                .then_some(DA_FOOTPRINT_SCALAR),
            ..Default::default()
        };

        assert_header_parity(
            &format!("{config_name}/first-with-base/empty"),
            &input,
            &state,
            &info,
        );

        execute_session(
            &evm_config,
            &parent,
            &env_attributes,
            &mut state,
            &mut info,
            &transactions,
            0..1,
        );
        state.merge_transitions(BundleRetention::Reverts);
        assert_header_parity(&format!("{config_name}/mid"), &input, &state, &info);

        execute_session(
            &evm_config,
            &parent,
            &env_attributes,
            &mut state,
            &mut info,
            &transactions,
            1..transactions.len(),
        );
        state.merge_transitions(BundleRetention::Reverts);
        assert_header_parity(&format!("{config_name}/last"), &input, &state, &info);

        if matches!(
            config_name,
            "isthmus-pre-jovian" | "jovian-with-withdrawals"
        ) {
            info.optional_blob_fields = Some((Some(17), Some(19)));
            assert_header_parity(
                &format!("{config_name}/last/validation-blob-override"),
                &input,
                &state,
                &info,
            );
        }
    }

    #[test]
    fn upstream_assembler_matches_reference_for_flashblock_prefix_matrix() {
        run_prefix_matrix(
            "holocene-pre-isthmus-pre-jovian",
            Arc::new(
                OpChainSpecBuilder::optimism_mainnet()
                    .holocene_activated()
                    .build(),
            ),
            false,
        );
        run_prefix_matrix(
            "isthmus-pre-jovian",
            Arc::new(
                OpChainSpecBuilder::optimism_mainnet()
                    .isthmus_activated()
                    .build(),
            ),
            false,
        );
        run_prefix_matrix(
            "jovian-with-withdrawals",
            Arc::new(
                OpChainSpecBuilder::optimism_mainnet()
                    .jovian_activated()
                    .build(),
            ),
            true,
        );
    }
}
