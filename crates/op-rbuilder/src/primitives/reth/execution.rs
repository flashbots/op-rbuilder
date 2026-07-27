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

    /// Records a transaction committed by an [`alloy_evm::block::BlockExecutor`].
    ///
    /// Executor receipts use session-local cumulative gas, so rebase them onto the block ledger.
    pub fn commit_executed_tx(
        &mut self,
        tx: &Recovered<OpTransactionSigned>,
        gas_used: u64,
        tx_da_size: u64,
        miner_fee: Option<u128>,
        mut receipt: OpReceipt,
    ) {
        self.cumulative_gas_used += gas_used;
        self.cumulative_da_bytes_used += tx_da_size;
        self.cumulative_uncompressed_bytes += tx.inner().encode_2718_len() as u64;

        receipt.as_receipt_mut().cumulative_gas_used = self.cumulative_gas_used;
        self.receipts.push(receipt);

        if let Some(miner_fee) = miner_fee {
            self.total_fees += U256::from(miner_fee) * U256::from(gas_used);
        }

        self.executed_senders.push(tx.signer());
        self.executed_transactions.push(tx.clone().into_inner());
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
    use crate::{evm::OpBlockEvmFactory, hardforks::ActiveHardforks};
    use alloy_consensus::{
        Eip658Value, Header, Receipt, SignableTransaction, Transaction, TxEip1559,
    };
    use alloy_eips::Encodable2718;
    use alloy_evm::{
        Evm,
        block::{BlockExecutor, CommitChanges, TxResult},
    };
    use alloy_network::TxSignerSync;
    use alloy_primitives::{
        Address, B256, Bytes, StorageKey, StorageValue, TxKind, U256, hex, map::HashMap,
    };
    use alloy_signer_local::PrivateKeySigner;
    use op_alloy_consensus::{OpReceipt, OpTxEnvelope};
    use op_revm::constants::{
        DA_FOOTPRINT_GAS_SCALAR_OFFSET, DA_FOOTPRINT_GAS_SCALAR_SLOT, L1_BLOCK_CONTRACT,
    };
    use reth_chainspec::EthChainSpec;
    use reth_evm::{
        ConfigureEvm,
        execute::{BlockBuilder, BlockExecutionError, BlockValidationError},
    };
    use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};
    use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
    use reth_optimism_primitives::OpTransactionSigned;
    use reth_primitives_traits::{Account, Recovered, SealedHeader};
    use reth_revm::{
        State, database::StateProviderDatabase, db::states::bundle_state::BundleRetention,
        test_utils::StateProviderTest,
    };
    use revm::context::result::ResultAndState;
    use std::{
        assert_matches,
        sync::{Arc, LazyLock},
    };

    static TEST_CHAIN_SPEC: LazyLock<Arc<OpChainSpec>> =
        LazyLock::new(|| Arc::new(OpChainSpecBuilder::optimism_mainnet().build()));

    fn sign_test_tx(
        signer: &PrivateKeySigner,
        nonce: u64,
        to: TxKind,
        input: alloy_primitives::Bytes,
    ) -> Recovered<OpTransactionSigned> {
        let mut tx = TxEip1559 {
            chain_id: TEST_CHAIN_SPEC.chain_id(),
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to,
            input,
            ..Default::default()
        };
        let signature = signer.sign_transaction_sync(&mut tx).unwrap();
        let envelope = OpTxEnvelope::Eip1559(tx.into_signed(signature));
        Recovered::new_unchecked(OpTransactionSigned::from(envelope), signer.address())
    }

    fn test_parent_and_attributes() -> (SealedHeader, OpNextBlockEnvAttributes) {
        let parent = SealedHeader::new(
            Header {
                number: 20_000_000,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: 1_720_000_000,
                base_fee_per_gas: Some(1_000_000_000),
                ..Default::default()
            },
            B256::repeat_byte(0x11),
        );
        let attributes = OpNextBlockEnvAttributes {
            timestamp: parent.timestamp + 2,
            suggested_fee_recipient: Address::repeat_byte(0x22),
            prev_randao: B256::repeat_byte(0x33),
            gas_limit: parent.gas_limit,
            parent_beacon_block_root: None,
            extra_data: Default::default(),
        };
        (parent, attributes)
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
        provider
    }

    fn assert_execution_info_parity(raw: &ExecutionInfo, builder: &ExecutionInfo) {
        assert_eq!(raw.receipts, builder.receipts);
        assert_eq!(raw.cumulative_gas_used, builder.cumulative_gas_used);
        assert_eq!(
            raw.cumulative_da_bytes_used,
            builder.cumulative_da_bytes_used
        );
        assert_eq!(
            raw.cumulative_uncompressed_bytes,
            builder.cumulative_uncompressed_bytes
        );
        assert_eq!(raw.total_fees, builder.total_fees);
        assert_eq!(raw.executed_transactions, builder.executed_transactions);
        assert_eq!(raw.executed_senders, builder.executed_senders);
    }

    #[test]
    fn block_builder_matches_raw_execution_for_receipts_gas_and_state() {
        let signer = PrivateKeySigner::random();
        let provider = funded_provider(signer.address());
        let (parent, attributes) = test_parent_and_attributes();
        let evm_config = OpEvmConfig::optimism(TEST_CHAIN_SPEC.clone());
        let evm_factory =
            OpBlockEvmFactory::for_next_block(evm_config.clone(), &parent, &attributes).unwrap();
        let hardforks = ActiveHardforks::new(TEST_CHAIN_SPEC.clone(), attributes.timestamp);
        let coinbase = attributes.suggested_fee_recipient;

        let transactions = [
            sign_test_tx(
                &signer,
                0,
                TxKind::Call(Address::repeat_byte(0x44)),
                Default::default(),
            ),
            sign_test_tx(
                &signer,
                1,
                TxKind::Call(Address::repeat_byte(0x55)),
                Default::default(),
            ),
            // Non-protected reverts are committed into the candidate.
            sign_test_tx(&signer, 2, TxKind::Create, hex!("60006000fd").into()),
        ];
        let declined_tx = sign_test_tx(&signer, 3, TxKind::Call(coinbase), Default::default());
        let prefix_receipt = OpReceipt::Legacy(Receipt {
            status: Eip658Value::Eip658(true),
            cumulative_gas_used: 42_000,
            logs: Vec::new(),
        });

        let mut raw_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut raw_info = ExecutionInfo {
            receipts: vec![prefix_receipt.clone()],
            cumulative_gas_used: 42_000,
            ..Default::default()
        };
        {
            let mut evm = evm_factory.evm(&mut raw_state);
            for (index, tx) in transactions.iter().enumerate() {
                let ResultAndState { result, state } = evm.transact(tx).unwrap();
                raw_info.commit_tx(
                    tx,
                    result,
                    state,
                    index as u64 + 1,
                    Some(index as u128 + 1),
                    None,
                    &evm_factory,
                    &hardforks,
                    &mut evm,
                );
            }
            let _ = evm.transact(&declined_tx).unwrap();
        }

        let mut builder_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut builder_info = ExecutionInfo {
            receipts: vec![prefix_receipt],
            cumulative_gas_used: 42_000,
            ..Default::default()
        };
        {
            let mut builder = evm_config
                .builder_for_next_block(&mut builder_state, &parent, attributes)
                .unwrap();
            for (index, tx) in transactions.iter().enumerate() {
                let gas_used = builder.execute_transaction(tx.clone()).unwrap();
                builder_info.commit_executed_tx(
                    tx,
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
            let committed = builder
                .execute_transaction_with_commit_condition(declined_tx, |result| {
                    assert!(
                        result.result().state.contains_key(&coinbase),
                        "commit closure can inspect the post-execution coinbase state"
                    );
                    CommitChanges::No
                })
                .unwrap();
            assert!(committed.is_none());
            assert_eq!(builder.executor().receipts().len(), transactions.len());
        }

        assert_execution_info_parity(&raw_info, &builder_info);
        raw_state.merge_transitions(BundleRetention::Reverts);
        builder_state.merge_transitions(BundleRetention::Reverts);
        assert_eq!(raw_state.bundle_state, builder_state.bundle_state);
    }

    #[test]
    fn sequential_block_builder_sessions_match_continuous_raw_execution() {
        let signer = PrivateKeySigner::random();
        let declined_signer = PrivateKeySigner::random();
        let mut provider = funded_provider(signer.address());
        provider.insert_account(
            declined_signer.address(),
            Account {
                nonce: 0,
                balance: U256::from(100_000_000_000_000_000_000u128),
                bytecode_hash: None,
            },
            None,
            HashMap::default(),
        );
        let (parent, attributes) = test_parent_and_attributes();
        let evm_config = OpEvmConfig::optimism(TEST_CHAIN_SPEC.clone());
        let evm_factory =
            OpBlockEvmFactory::for_next_block(evm_config.clone(), &parent, &attributes).unwrap();
        let hardforks = ActiveHardforks::new(TEST_CHAIN_SPEC.clone(), attributes.timestamp);
        let transactions = [
            sign_test_tx(
                &signer,
                0,
                TxKind::Call(Address::repeat_byte(0x44)),
                Default::default(),
            ),
            sign_test_tx(
                &signer,
                1,
                TxKind::Call(Address::repeat_byte(0x55)),
                Default::default(),
            ),
            sign_test_tx(&signer, 2, TxKind::Create, hex!("60006000fd").into()),
            sign_test_tx(
                &signer,
                3,
                TxKind::Call(Address::repeat_byte(0x66)),
                Default::default(),
            ),
        ];
        let declined_tx = sign_test_tx(
            &declined_signer,
            0,
            TxKind::Call(Address::repeat_byte(0x77)),
            Default::default(),
        );
        let tx_da_sizes = [3, 5, 7, 11];
        let miner_fees = [2, 3, 5, 7];

        let mut raw_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut raw_info = ExecutionInfo::with_capacity(transactions.len());
        {
            let mut evm = evm_factory.evm(&mut raw_state);
            for ((tx, tx_da_size), miner_fee) in
                transactions.iter().zip(tx_da_sizes).zip(miner_fees)
            {
                if tx.nonce() == 2 {
                    let _ = evm.transact(&declined_tx).unwrap();
                }
                let ResultAndState { result, state } = evm.transact(tx).unwrap();
                raw_info.commit_tx(
                    tx,
                    result,
                    state,
                    tx_da_size,
                    Some(miner_fee),
                    None,
                    &evm_factory,
                    &hardforks,
                    &mut evm,
                );
            }
        }

        let mut builder_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut builder_info = ExecutionInfo::with_capacity(transactions.len());
        for (session, range) in [0..2, 2..transactions.len()].into_iter().enumerate() {
            let mut builder = evm_config
                .builder_for_next_block(&mut builder_state, &parent, attributes.clone())
                .unwrap();
            if session == 1 {
                let receipts_before = builder_info.receipts.len();
                let cumulative_gas_before = builder_info.cumulative_gas_used;
                let executed_before = builder_info.executed_transactions.len();
                let bundle_before = builder.evm().db().bundle_state.clone();
                let declined = builder
                    .executor_mut()
                    .execute_transaction_with_commit_condition(&declined_tx, |_| CommitChanges::No)
                    .unwrap();

                assert!(declined.is_none());
                assert!(builder.executor().receipts().is_empty());
                assert_eq!(builder_info.receipts.len(), receipts_before);
                assert_eq!(builder_info.cumulative_gas_used, cumulative_gas_before);
                assert_eq!(builder_info.executed_transactions.len(), executed_before);
                assert_eq!(builder.evm().db().bundle_state, bundle_before);
            }
            for index in range {
                let tx = &transactions[index];
                let gas_used = builder.execute_transaction(tx.clone()).unwrap();
                builder_info.commit_executed_tx(
                    tx,
                    gas_used.tx_gas_used(),
                    tx_da_sizes[index],
                    Some(miner_fees[index]),
                    builder
                        .executor()
                        .receipts()
                        .last()
                        .cloned()
                        .expect("committed transaction has a receipt"),
                );
            }
            assert_eq!(builder.executor().receipts().len(), 2);
        }

        assert_execution_info_parity(&raw_info, &builder_info);
        raw_state.merge_transitions(BundleRetention::Reverts);
        builder_state.merge_transitions(BundleRetention::Reverts);
        assert_eq!(raw_state.bundle_state, builder_state.bundle_state);
    }

    #[test]
    fn jovian_da_footprint_budget_is_clamped_before_executor_execution() {
        const BLOCK_GAS_LIMIT: u64 = 100_000;
        const DA_FOOTPRINT_SCALAR: u16 = u16::MAX;

        let signer = PrivateKeySigner::random();
        let mut provider = funded_provider(signer.address());
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[DA_FOOTPRINT_GAS_SCALAR_OFFSET..DA_FOOTPRINT_GAS_SCALAR_OFFSET + 2]
            .copy_from_slice(&DA_FOOTPRINT_SCALAR.to_be_bytes());
        let mut l1_storage = HashMap::default();
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

        let (_, mut attributes) = test_parent_and_attributes();
        let parent = SealedHeader::new(
            Header {
                number: 20_000_000,
                gas_limit: BLOCK_GAS_LIMIT,
                timestamp: 1_720_000_000,
                base_fee_per_gas: Some(1_000_000_000),
                ..Default::default()
            },
            B256::repeat_byte(0x11),
        );
        attributes.gas_limit = BLOCK_GAS_LIMIT;
        let chain_spec = std::sync::Arc::new(
            OpChainSpecBuilder::optimism_mainnet()
                .jovian_activated()
                .build(),
        );
        let evm_config = OpEvmConfig::optimism(chain_spec);
        let tx = sign_test_tx(
            &signer,
            0,
            TxKind::Call(Address::repeat_byte(0x88)),
            Bytes::from(vec![0u8; 512]),
        );
        let tx_da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(tx.encoded_2718().as_slice());
        let info = ExecutionInfo {
            da_footprint_scalar: Some(DA_FOOTPRINT_SCALAR),
            ..Default::default()
        };
        let caller_budget = Some(u64::MAX);

        assert!(
            info.is_tx_over_limits(
                tx_da_size,
                BLOCK_GAS_LIMIT,
                None,
                None,
                tx.gas_limit(),
                caller_budget,
                tx.encode_2718_len() as u64,
                None,
            )
            .is_ok(),
            "an unclamped caller budget incorrectly lets the tx reach the executor"
        );

        let mut fatal_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut fatal_builder = evm_config
            .builder_for_next_block(&mut fatal_state, &parent, attributes.clone())
            .unwrap();
        let fatal = fatal_builder
            .executor_mut()
            .execute_transaction(&tx)
            .unwrap_err();
        assert_matches!(
            fatal,
            BlockExecutionError::Validation(BlockValidationError::Other(_))
        );
        assert!(fatal_builder.executor().receipts().is_empty());

        let mut clamped_state = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let mut clamped_builder = evm_config
            .builder_for_next_block(&mut clamped_state, &parent, attributes)
            .unwrap();
        let clamped_budget = caller_budget.map(|target| target.min(BLOCK_GAS_LIMIT));
        let skipped_without_executor_error = if info
            .is_tx_over_limits(
                tx_da_size,
                BLOCK_GAS_LIMIT,
                None,
                None,
                tx.gas_limit(),
                clamped_budget,
                tx.encode_2718_len() as u64,
                None,
            )
            .is_err()
        {
            Ok(None)
        } else {
            clamped_builder
                .executor_mut()
                .execute_transaction(&tx)
                .map(Some)
        };

        assert!(skipped_without_executor_error.unwrap().is_none());
        assert!(clamped_builder.executor().receipts().is_empty());
    }

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
