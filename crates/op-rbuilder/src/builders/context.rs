use alloy_consensus::{Eip658Value, Transaction, conditional::BlockConditionalAttributes};
use alloy_eips::{Encodable2718, Typed2718};
use alloy_evm::Database;
use alloy_op_evm::{OpEvmFactory, block::receipt_builder::OpReceiptBuilder};
use alloy_primitives::{Address, B256, BlockHash, Bytes, U256};
use alloy_rpc_types_eth::Withdrawals;
use core::fmt::Debug;
use op_alloy_consensus::OpDepositReceipt;
use op_revm::OpSpecId;
use reth::payload::PayloadBuilderAttributes;
use reth_basic_payload_builder::PayloadConfig;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::{
    ConfigureEvm, Evm, EvmEnv, EvmError, InvalidTxError, eth::receipt_builder::ReceiptBuilderCtx,
    op_revm::L1BlockInfo,
};
use reth_node_api::PayloadBuilderError;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes, OpRethReceiptBuilder};
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_payload_builder::{
    config::{OpDAConfig, OpGasLimitConfig},
    error::OpPayloadBuilderError,
};
use reth_optimism_primitives::{OpPrimitives, OpReceipt, OpTransactionSigned};
use reth_optimism_txpool::{
    conditional::MaybeConditionalTransaction,
    estimated_da_size::DataAvailabilitySized,
    interop::{MaybeInteropTransaction, is_valid_interop},
};
use reth_payload_builder::PayloadId;
use reth_primitives::SealedHeader;
use reth_primitives_traits::{InMemorySize, SignedTransaction};
use reth_revm::{State, context::Block};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction};
use revm::{
    DatabaseCommit, DatabaseRef,
    context::result::{EVMError, ResultAndState},
    interpreter::as_u64_saturated,
    primitives::{StorageKey, StorageValue},
    state::{AccountInfo, Bytecode},
};
use std::{convert::Infallible, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::{Span, debug, info, trace};

use crate::{
    block_stm::{evm::OpLazyEvmFactory, executor::Executor, db_adapter::VersionedDbError},
    gas_limiter::AddressGasLimiter,
    metrics::OpRBuilderMetrics,
    primitives::reth::{ExecutionInfo, TxnExecutionResult},
    resource_metering::ResourceMetering,
    traits::PayloadTxsBounds,
    tx::MaybeRevertingTransaction,
    tx_signer::Signer,
};

/// Container type that holds all necessities to build a new payload.
#[derive(Debug, Clone)]
pub struct OpPayloadBuilderCtx<ExtraCtx: Debug + Default = (), EvmFactory = OpEvmFactory> {
    /// The type that knows how to perform system calls and configure the evm.
    pub evm_config: OpEvmConfig<OpChainSpec, OpPrimitives, OpRethReceiptBuilder, EvmFactory>,
    /// The DA config for the payload builder
    pub da_config: OpDAConfig,
    // Gas limit configuration for the payload builder
    pub gas_limit_config: OpGasLimitConfig,
    /// The chainspec
    pub chain_spec: Arc<OpChainSpec>,
    /// How to build the payload.
    pub config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    /// Evm Settings
    pub evm_env: EvmEnv<OpSpecId>,
    /// Block env attributes for the current block.
    pub block_env_attributes: OpNextBlockEnvAttributes,
    /// Marker to check whether the job has been cancelled.
    pub cancel: CancellationToken,
    /// The builder signer
    pub builder_signer: Option<Signer>,
    /// The metrics for the builder
    pub metrics: Arc<OpRBuilderMetrics>,
    /// Extra context for the payload builder
    pub extra_ctx: ExtraCtx,
    /// Max gas that can be used by a transaction.
    pub max_gas_per_txn: Option<u64>,
    /// Rate limiting based on gas. This is an optional feature.
    pub address_gas_limiter: AddressGasLimiter,
    /// Per transaction resource metering information
    pub resource_metering: ResourceMetering,
    /// Number of parallel threads for transaction execution.
    pub parallel_threads: usize,
}

impl<ExtraCtx: Debug + Default, EF> OpPayloadBuilderCtx<ExtraCtx, EF> {
    pub(super) fn with_cancel(self, cancel: CancellationToken) -> Self {
        Self { cancel, ..self }
    }

    pub(super) fn with_extra_ctx(self, extra_ctx: ExtraCtx) -> Self {
        Self { extra_ctx, ..self }
    }

    /// Returns the parent block the payload will be build on.
    pub fn parent(&self) -> &SealedHeader {
        &self.config.parent_header
    }

    /// Returns the parent hash
    pub fn parent_hash(&self) -> BlockHash {
        self.parent().hash()
    }

    /// Returns the timestamp
    pub fn timestamp(&self) -> u64 {
        self.attributes().timestamp()
    }

    /// Returns the builder attributes.
    pub(super) const fn attributes(&self) -> &OpPayloadBuilderAttributes<OpTransactionSigned> {
        &self.config.attributes
    }

    /// Returns the withdrawals if shanghai is active.
    pub fn withdrawals(&self) -> Option<&Withdrawals> {
        self.chain_spec
            .is_shanghai_active_at_timestamp(self.attributes().timestamp())
            .then(|| &self.attributes().payload_attributes.withdrawals)
    }

    /// Returns the block gas limit to target.
    pub fn block_gas_limit(&self) -> u64 {
        match self.gas_limit_config.gas_limit() {
            Some(gas_limit) => gas_limit,
            None => self
                .attributes()
                .gas_limit
                .unwrap_or(self.evm_env.block_env.gas_limit),
        }
    }

    /// Returns the block number for the block.
    pub fn block_number(&self) -> u64 {
        as_u64_saturated!(self.evm_env.block_env.number)
    }

    /// Returns the current base fee
    pub fn base_fee(&self) -> u64 {
        self.evm_env.block_env.basefee
    }

    /// Returns the current blob gas price.
    pub fn get_blob_gasprice(&self) -> Option<u64> {
        self.evm_env
            .block_env
            .blob_gasprice()
            .map(|gasprice| gasprice as u64)
    }

    /// Returns the blob fields for the header.
    ///
    /// This will return the culmative DA bytes * scalar after Jovian
    /// after Ecotone, this will always return Some(0) as blobs aren't supported
    /// pre Ecotone, these fields aren't used.
    pub fn blob_fields<Extra: Debug + Default>(
        &self,
        info: &ExecutionInfo<Extra>,
    ) -> (Option<u64>, Option<u64>) {
        if self.is_jovian_active() {
            let scalar = info
                .da_footprint_scalar
                .expect("Scalar must be defined for Jovian blocks");
            let result = info.cumulative_da_bytes_used * scalar as u64;
            (Some(0), Some(result))
        } else if self.is_ecotone_active() {
            (Some(0), Some(0))
        } else {
            (None, None)
        }
    }

    /// Returns the extra data for the block.
    ///
    /// After holocene this extracts the extradata from the payload
    pub fn extra_data(&self) -> Result<Bytes, PayloadBuilderError> {
        if self.is_jovian_active() {
            self.attributes()
                .get_jovian_extra_data(
                    self.chain_spec.base_fee_params_at_timestamp(
                        self.attributes().payload_attributes.timestamp,
                    ),
                )
                .map_err(PayloadBuilderError::other)
        } else if self.is_holocene_active() {
            self.attributes()
                .get_holocene_extra_data(
                    self.chain_spec.base_fee_params_at_timestamp(
                        self.attributes().payload_attributes.timestamp,
                    ),
                )
                .map_err(PayloadBuilderError::other)
        } else {
            Ok(Default::default())
        }
    }

    /// Returns the current fee settings for transactions from the mempool
    pub fn best_transaction_attributes(&self) -> BestTransactionsAttributes {
        BestTransactionsAttributes::new(self.base_fee(), self.get_blob_gasprice())
    }

    /// Returns the unique id for this payload job.
    pub fn payload_id(&self) -> PayloadId {
        self.attributes().payload_id()
    }

    /// Returns true if regolith is active for the payload.
    pub fn is_regolith_active(&self) -> bool {
        self.chain_spec
            .is_regolith_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if ecotone is active for the payload.
    pub fn is_ecotone_active(&self) -> bool {
        self.chain_spec
            .is_ecotone_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if canyon is active for the payload.
    pub fn is_canyon_active(&self) -> bool {
        self.chain_spec
            .is_canyon_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if holocene is active for the payload.
    pub fn is_holocene_active(&self) -> bool {
        self.chain_spec
            .is_holocene_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if isthmus is active for the payload.
    pub fn is_isthmus_active(&self) -> bool {
        self.chain_spec
            .is_isthmus_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns true if isthmus is active for the payload.
    pub fn is_jovian_active(&self) -> bool {
        self.chain_spec
            .is_jovian_active_at_timestamp(self.attributes().timestamp())
    }

    /// Returns the chain id
    pub fn chain_id(&self) -> u64 {
        self.chain_spec.chain_id()
    }
}

impl<ExtraCtx: Debug + Default> OpPayloadBuilderCtx<ExtraCtx, OpEvmFactory> {
    /// Constructs a receipt for the given transaction.
    pub fn build_receipt<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, OpTransactionSigned, E>,
        deposit_nonce: Option<u64>,
    ) -> OpReceipt {
        let receipt_builder = self.evm_config.block_executor_factory().receipt_builder();
        match receipt_builder.build_receipt(ctx) {
            Ok(receipt) => receipt,
            Err(ctx) => {
                let receipt = alloy_consensus::Receipt {
                    // Success flag was added in `EIP-658: Embedding transaction status code
                    // in receipts`.
                    status: Eip658Value::Eip658(ctx.result.is_success()),
                    cumulative_gas_used: ctx.cumulative_gas_used,
                    logs: ctx.result.into_logs(),
                };

                receipt_builder.build_deposit_receipt(OpDepositReceipt {
                    inner: receipt,
                    deposit_nonce,
                    // The deposit receipt version was introduced in Canyon to indicate an
                    // update to how receipt hashes should be computed
                    // when set. The state transition process ensures
                    // this is only set for post-Canyon deposit
                    // transactions.
                    deposit_receipt_version: self.is_canyon_active().then_some(1),
                })
            }
        }
    }

    /// Executes all sequencer transactions that are included in the payload attributes.
    pub(super) fn execute_sequencer_transactions<E: Debug + Default>(
        &self,
        db: &mut State<impl Database>,
    ) -> Result<ExecutionInfo<E>, PayloadBuilderError> {
        let mut info = ExecutionInfo::with_capacity(self.attributes().transactions.len());

        let mut evm = self.evm_config.evm_with_env(&mut *db, self.evm_env.clone());

        for sequencer_tx in &self.attributes().transactions {
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

            // Cache the depositor account prior to the state transition for the deposit nonce.
            //
            // Note that this *only* needs to be done post-regolith hardfork, as deposit nonces
            // were not introduced in Bedrock. In addition, regular transactions don't have deposit
            // nonces, so we don't need to touch the DB for those.
            let depositor_nonce = (self.is_regolith_active() && sequencer_tx.is_deposit())
                .then(|| {
                    evm.db_mut()
                        .load_cache_account(sequencer_tx.signer())
                        .map(|acc| acc.account_info().unwrap_or_default().nonce)
                })
                .transpose()
                .map_err(|_| {
                    PayloadBuilderError::other(OpPayloadBuilderError::AccountLoadFailed(
                        sequencer_tx.signer(),
                    ))
                })?;

            let ResultAndState { result, state } = match evm.transact(&sequencer_tx) {
                Ok(res) => res,
                Err(err) => {
                    if err.is_invalid_tx_err() {
                        trace!(target: "payload_builder", %err, ?sequencer_tx, "Error in sequencer transaction, skipping.");
                        continue;
                    }
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            // add gas used by the transaction to cumulative gas used, before creating the receipt
            let gas_used = result.gas_used();
            info.cumulative_gas_used += gas_used;

            if !sequencer_tx.is_deposit() {
                info.cumulative_da_bytes_used += op_alloy_flz::tx_estimated_size_fjord_bytes(
                    sequencer_tx.encoded_2718().as_slice(),
                );
            }

            let ctx = ReceiptBuilderCtx {
                tx: sequencer_tx.inner(),
                evm: &evm,
                result,
                state: &state,
                cumulative_gas_used: info.cumulative_gas_used,
            };

            info.receipts.push(self.build_receipt(ctx, depositor_nonce));

            // commit changes
            evm.db_mut().commit(state);

            // append sender and transaction to the respective lists
            info.executed_senders.push(sequencer_tx.signer());
            info.executed_transactions.push(sequencer_tx.into_inner());
        }

        let da_footprint_gas_scalar = self
            .chain_spec
            .is_jovian_active_at_timestamp(self.attributes().timestamp())
            .then(|| {
                L1BlockInfo::fetch_da_footprint_gas_scalar(evm.db_mut())
                    .expect("DA footprint should always be available from the database post jovian")
            });

        info.da_footprint_scalar = da_footprint_gas_scalar;

        Ok(info)
    }

    /// Executes the given best transactions sequentially and updates the execution info.
    /// Used when `parallel_threads == 1`.
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    pub(super) fn execute_best_transactions<E: Debug + Default>(
        &self,
        info: &mut ExecutionInfo<E>,
        db: &mut State<impl Database>,
        best_txs: &mut impl PayloadTxsBounds,
        block_gas_limit: u64,
        block_da_limit: Option<u64>,
        block_da_footprint_limit: Option<u64>,
    ) -> Result<Option<()>, PayloadBuilderError> {
        // Capture parent span (build_flashblock) for proper linking
        let parent_span = Span::current();
        let _execute_span = tracing::info_span!(
            parent: &parent_span,
            "execute_txs",
            num_threads = 1,
            block_gas_limit = block_gas_limit
        )
        .entered();

        let execute_txs_start_time = Instant::now();
        let mut num_txs_considered = 0;
        let mut num_txs_simulated = 0;
        let mut num_txs_simulated_success = 0;
        let mut num_txs_simulated_fail = 0;
        let mut num_bundles_reverted = 0;
        let mut reverted_gas_used = 0;
        let base_fee = self.base_fee();
        let mut txn_idx: u32 = 0;

        let tx_da_limit = self.da_config.max_da_tx_size();
        let mut evm = self.evm_config.evm_with_env(&mut *db, self.evm_env.clone());

        debug!(
            target: "payload_builder",
            message = "Executing best transactions",
            block_da_limit = ?block_da_limit,
            tx_da_limit = ?tx_da_limit,
            block_gas_limit = ?block_gas_limit,
        );

        let block_attr = BlockConditionalAttributes {
            number: self.block_number(),
            timestamp: self.attributes().timestamp(),
        };

        while let Some(tx) = best_txs.next(()) {
            let _tx_span =
                tracing::info_span!("sequential_tx_execute", txn_idx = txn_idx).entered();
            txn_idx += 1;

            let interop = tx.interop_deadline();
            let reverted_hashes = tx.reverted_hashes().clone();
            let conditional = tx.conditional().cloned();

            let tx_da_size = tx.estimated_da_size();
            let tx = tx.into_consensus();
            let tx_hash = tx.tx_hash();

            // exclude reverting transaction if:
            // - the transaction comes from a bundle (is_some) and the hash **is not** in reverted hashes
            // Note that we need to use the Option to signal whether the transaction comes from a bundle,
            // otherwise, we would exclude all transactions that are not in the reverted hashes.
            let is_bundle_tx = reverted_hashes.is_some();
            let exclude_reverting_txs =
                is_bundle_tx && !reverted_hashes.unwrap().contains(&tx_hash);

            let log_txn = |result: TxnExecutionResult| {
                debug!(
                    target: "payload_builder",
                    message = "Considering transaction",
                    tx_hash = ?tx_hash,
                    tx_da_size = ?tx_da_size,
                    exclude_reverting_txs = ?exclude_reverting_txs,
                    result = %result,
                );
            };

            num_txs_considered += 1;

            let _resource_usage = self.resource_metering.get(&tx_hash);

            // TODO: ideally we should get this from the txpool stream
            if let Some(conditional) = conditional
                && !conditional.matches_block_attributes(&block_attr)
            {
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // TODO: remove this condition and feature once we are comfortable enabling interop for everything
            if cfg!(feature = "interop") {
                // We skip invalid cross chain txs, they would be removed on the next block update in
                // the maintenance job
                if let Some(interop) = interop
                    && !is_valid_interop(interop, self.config.attributes.timestamp())
                {
                    log_txn(TxnExecutionResult::InteropFailed);
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                }
            }

            // ensure we still have capacity for this transaction
            if let Err(result) = info.is_tx_over_limits(
                tx_da_size,
                block_gas_limit,
                tx_da_limit,
                block_da_limit,
                tx.gas_limit(),
                info.da_footprint_scalar,
                block_da_footprint_limit,
            ) {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                log_txn(result);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // A sequencer's block should never contain blob or deposit transactions from the pool.
            if tx.is_eip4844() || tx.is_deposit() {
                log_txn(TxnExecutionResult::SequencerTransaction);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // check if the job was cancelled, if so we can exit early
            if self.cancel.is_cancelled() {
                return Ok(Some(()));
            }

            let tx_simulation_start_time = Instant::now();
            let ResultAndState { result, state } = match evm.transact(&tx) {
                Ok(res) => res,
                Err(err) => {
                    if let Some(err) = err.as_invalid_tx_err() {
                        if err.is_nonce_too_low() {
                            // if the nonce is too low, we can skip this transaction
                            log_txn(TxnExecutionResult::NonceTooLow);
                            trace!(target: "payload_builder", %err, ?tx, "skipping nonce too low transaction");
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            log_txn(TxnExecutionResult::InternalError(err.clone()));
                            trace!(target: "payload_builder", %err, ?tx, "skipping invalid transaction and its descendants");
                            best_txs.mark_invalid(tx.signer(), tx.nonce());
                        }

                        continue;
                    }
                    // this is an error that we should treat as fatal for this attempt
                    log_txn(TxnExecutionResult::EvmError);
                    return Err(PayloadBuilderError::evm(err));
                }
            };

            self.metrics
                .tx_simulation_duration
                .record(tx_simulation_start_time.elapsed());
            self.metrics.tx_byte_size.record(tx.inner().size() as f64);
            num_txs_simulated += 1;

            // Run the per-address gas limiting before checking if the tx has
            // reverted or not, as this is a check against maliciously searchers
            // sending txs that are expensive to compute but always revert.
            let gas_used = result.gas_used();
            if self
                .address_gas_limiter
                .consume_gas(tx.signer(), gas_used)
                .is_err()
            {
                log_txn(TxnExecutionResult::MaxGasUsageExceeded);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            if result.is_success() {
                log_txn(TxnExecutionResult::Success);
                num_txs_simulated_success += 1;
                self.metrics.successful_tx_gas_used.record(gas_used as f64);
            } else {
                num_txs_simulated_fail += 1;
                reverted_gas_used += gas_used as i32;
                self.metrics.reverted_tx_gas_used.record(gas_used as f64);
                if is_bundle_tx {
                    num_bundles_reverted += 1;
                }
                if exclude_reverting_txs {
                    log_txn(TxnExecutionResult::RevertedAndExcluded);
                    info!(target: "payload_builder", tx_hash = ?tx.tx_hash(), result = ?result, "skipping reverted transaction");
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                } else {
                    log_txn(TxnExecutionResult::Reverted);
                }
            }

            // add gas used by the transaction to cumulative gas used, before creating the
            // receipt
            if let Some(max_gas_per_txn) = self.max_gas_per_txn
                && gas_used > max_gas_per_txn
            {
                log_txn(TxnExecutionResult::MaxGasUsageExceeded);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            info.cumulative_gas_used += gas_used;
            // record tx da size
            info.cumulative_da_bytes_used += tx_da_size;

            // Push transaction changeset and calculate header bloom filter for receipt.
            let ctx = ReceiptBuilderCtx {
                tx: tx.inner(),
                evm: &evm,
                result,
                state: &state,
                cumulative_gas_used: info.cumulative_gas_used,
            };
            info.receipts.push(self.build_receipt(ctx, None));

            // commit changes
            evm.db_mut().commit(state);

            // update add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            info.total_fees += U256::from(miner_fee) * U256::from(gas_used);

            // append sender and transaction to the respective lists
            info.executed_senders.push(tx.signer());
            info.executed_transactions.push(tx.into_inner());
        }

        let payload_transaction_simulation_time = execute_txs_start_time.elapsed();
        self.metrics.set_payload_builder_metrics(
            payload_transaction_simulation_time,
            num_txs_considered,
            num_txs_simulated,
            num_txs_simulated_success,
            num_txs_simulated_fail,
            num_bundles_reverted,
            reverted_gas_used,
        );

        debug!(
            target: "payload_builder",
            message = "Completed executing best transactions",
            txs_executed = num_txs_considered,
            txs_applied = num_txs_simulated_success,
            txs_rejected = num_txs_simulated_fail,
            bundles_reverted = num_bundles_reverted,
        );
        Ok(None)
    }
}

#[derive(Debug)]
struct MockDB;

impl revm::Database for MockDB {
    type Error = Infallible;

    /// Gets basic account information.
    fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        unreachable!()
    }

    /// Gets account code by its hash.
    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unreachable!()
    }

    /// Gets storage value of address at index.
    fn storage(
        &mut self,
        _address: Address,
        _index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        unreachable!()
    }

    /// Gets block hash by block number.
    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        unreachable!()
    }
}

impl<ExtraCtx: Debug + Default> OpPayloadBuilderCtx<ExtraCtx, OpEvmFactory> {
    /// Constructs a receipt for the given transaction.
    pub fn build_receipt_parallel<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, OpTransactionSigned, E>,
        deposit_nonce: Option<u64>,
    ) -> OpReceipt {
        let receipt_builder = self.evm_config.block_executor_factory().receipt_builder();
        match receipt_builder.build_receipt(ctx) {
            Ok(receipt) => receipt,
            Err(ctx) => {
                let receipt = alloy_consensus::Receipt {
                    // Success flag was added in `EIP-658: Embedding transaction status code
                    // in receipts`.
                    status: Eip658Value::Eip658(ctx.result.is_success()),
                    cumulative_gas_used: ctx.cumulative_gas_used,
                    logs: ctx.result.into_logs(),
                };

                receipt_builder.build_deposit_receipt(OpDepositReceipt {
                    inner: receipt,
                    deposit_nonce,
                    // The deposit receipt version was introduced in Canyon to indicate an
                    // update to how receipt hashes should be computed
                    // when set. The state transition process ensures
                    // this is only set for post-Canyon deposit
                    // transactions.
                    deposit_receipt_version: self.is_canyon_active().then_some(1),
                })
            }
        }
    }

    /// Executes the given best transactions in parallel using Block-STM.
    ///
    /// This implementation uses Block-STM for true parallel execution:
    /// - Each transaction gets its own `State<VersionedDatabaseRef>`
    /// - Reads route through MVHashMap to see earlier transactions' writes
    /// - Conflicts are detected via read/write set tracking
    /// - Commits happen in transaction order
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    pub(super) fn execute_best_transactions_parallel<E, DB>(
        &self,
        info: &mut ExecutionInfo<E>,
        db: &mut State<DB>,
        best_txs: &mut (impl PayloadTxsBounds + Send),
        block_gas_limit: u64,
        block_da_limit: Option<u64>,
        _block_da_footprint_limit: Option<u64>,
    ) -> Result<Option<()>, PayloadBuilderError>
    where
        ExtraCtx: Sync,
        E: Debug + Default + Send,
        DB: Database + DatabaseRef + Send + Sync,
    {
        let num_threads = self.parallel_threads;
        let tx_da_limit = self.da_config.max_da_tx_size();

        // Collect candidate transactions from the iterator.
        let mut candidate_txs = Vec::new();
        while let Some(tx) = best_txs.next(()) {
            candidate_txs.push(tx);
        }

        let num_candidates = candidate_txs.len();
        if num_candidates == 0 {
            return Ok(None);
        }

        // Capture parent span for cross-thread propagation (links to build_flashblock)
        let parent_span = Span::current();
        let _execute_span = tracing::info_span!(
            parent: &parent_span,
            "execute_txs",
            num_txns = num_candidates,
            num_threads = num_threads
        )
        .entered();

        info!(
            target: "payload_builder",
            message = "Executing best transactions (Block-STM)",
            block_da_limit = ?block_da_limit,
            tx_da_limit = ?tx_da_limit,
            block_gas_limit = ?block_gas_limit,
            num_threads = num_threads,
            num_candidates = num_candidates,
        );

        // Capture variables for closure
        let max_gas_per_txn = self.max_gas_per_txn;
        let address_gas_limiter = self.address_gas_limiter.clone();
        let da_footprint_gas_scalar = info.da_footprint_scalar;
        let block_da_footprint_limit = _block_da_footprint_limit;
        let base_cumulative_gas = info.cumulative_gas_used;
        let base_cumulative_da_bytes = info.cumulative_da_bytes_used;

        // Capture current span for cross-thread propagation (execute_txs span)
        let execute_txs_span = Span::current();
        let (results, shared_code_cache) = {
            let mut executor = Executor::new(num_threads, candidate_txs, &mut *db);

            // Spawn worker threads using Block-STM scheduler
            executor.execute_transactions_parallel(
                self.base_fee(),
                self.cancel.clone(),
                |tx, state, conflicting_keys, previous_result, tx_da_size| {
                    use crate::block_stm::types::{BlockResourceType, EvmStateKey};

                    // 1. Read BlockResourceUsed increments from other txs BEFORE execution to detect conflicts earlier
                    // These are increments from other transactions within this flashblock (not the base from sequencer)
                    let gas_increment = state.database.inner_mut()
                        .read_block_resource(BlockResourceType::Gas)?;
                    let da_increment = state.database.inner_mut()
                        .read_block_resource(BlockResourceType::DABytes)?;

                    trace!(
                        target: "payload_builder",
                        "Read increments: gas_increment={}, da_increment={}, base_gas={}, base_da={}",
                        gas_increment, da_increment, base_cumulative_gas, base_cumulative_da_bytes
                    );

                    // Calculate total cumulative values (base from sequencer + increments from other txs)
                    let cumulative_gas = base_cumulative_gas.saturating_add(gas_increment);
                    let cumulative_da_bytes = base_cumulative_da_bytes.saturating_add(da_increment);

                    // 2. Check if we can skip EVM execution
                    // Can skip if: conflicts are resource-only AND we have a previous result
                    let conflicts_are_resource_only = !conflicting_keys.is_empty()
                        && conflicting_keys.iter().all(|key| {
                            matches!(key, EvmStateKey::BlockResourceUsed(_))
                        });

                    let can_skip_evm = conflicts_are_resource_only
                        && previous_result.map(|r| r.result.is_some()).unwrap_or(false);

                    if !conflicting_keys.is_empty() {
                        trace!(
                            target: "payload_builder",
                            conflict_keys_count = conflicting_keys.len(),
                            resource_only = conflicts_are_resource_only,
                            has_previous = previous_result.is_some(),
                            skip_evm = can_skip_evm,
                            "Block-STM conflict check"
                        );
                    }

                    // 3. Execute or reuse
                    let (result, evm_state) = if can_skip_evm {
                        trace!(target: "payload_builder", "Skipping EVM re-execution (resource-only conflict)");
                        // Reuse previous result - extract just the loaded_state, not the full StateWithIncrements
                        let prev = previous_result.unwrap();
                        (prev.result.clone().unwrap(), prev.state.loaded_state.clone())
                    } else {
                        // Run EVM normally
                        let lazy_factory = OpLazyEvmFactory;
                        let mut evm = lazy_factory.create_evm(&mut *state, self.evm_env.clone());
                        let ResultAndState { result, state: evm_state } = evm.transact(&tx)?;

                        // Log storage changes in evm_state
                        let num_accounts_with_storage = evm_state.iter()
                            .filter(|(_, acct)| !acct.storage.is_empty())
                            .count();
                        if num_accounts_with_storage > 0 {
                            trace!(
                                target: "payload_builder",
                                num_accounts_with_storage,
                                "EVM execution complete with storage changes"
                            );
                            for (addr, account) in evm_state.iter() {
                                if !account.storage.is_empty() {
                                    trace!(
                                        target: "payload_builder",
                                        address = ?addr,
                                        num_storage_slots = account.storage.len(),
                                        "Account has storage in EVM state"
                                    );
                                }
                            }
                        }

                        // evm is dropped here, releasing the borrow on state
                        (result, evm_state)
                    };

                    // 5. Validate limits (pre-resource-write checks)
                    // Check per-tx DA limit
                    if tx_da_limit.is_some_and(|da_limit| tx_da_size > da_limit) {
                        return Err(EVMError::Database(VersionedDbError::BaseDbError(
                            format!("Transaction DA limit exceeded: {} > {}", tx_da_size, tx_da_limit.unwrap())
                        )));
                    }

                    // Check block DA limit
                    let total_da_bytes_used = cumulative_da_bytes.saturating_add(tx_da_size);
                    trace!(
                        target: "payload_builder",
                        cumulative_da_bytes,
                        tx_da_size,
                        total_da_bytes_used,
                        block_da_limit = ?block_da_limit,
                        "Checking block DA limit"
                    );
                    if block_da_limit.is_some_and(|da_limit| total_da_bytes_used > da_limit) {
                        return Err(EVMError::Database(VersionedDbError::BaseDbError(
                            format!("Block DA limit exceeded: {} + {} > {}",
                                cumulative_da_bytes, tx_da_size, block_da_limit.unwrap())
                        )));
                    }

                    // Check DA footprint (post-Jovian)
                    if let Some(da_footprint_gas_scalar) = da_footprint_gas_scalar {
                        let total_da_bytes_after = cumulative_da_bytes.saturating_add(tx_da_size);
                        let da_footprint_after = total_da_bytes_after.saturating_mul(da_footprint_gas_scalar as u64);
                        trace!(
                            target: "payload_builder",
                            "DA footprint check: total_da_bytes={}, scalar={}, footprint={}, limit={}",
                            total_da_bytes_after, da_footprint_gas_scalar, da_footprint_after,
                            block_da_footprint_limit.unwrap_or(block_gas_limit)
                        );
                        if da_footprint_after > block_da_footprint_limit.unwrap_or(block_gas_limit) {
                            return Err(EVMError::Database(VersionedDbError::BaseDbError(
                                format!("Block DA footprint limit exceeded: {} > {} (total_da_bytes={}, base={}, da_increment={}, tx_da={}, scalar={})",
                                    da_footprint_after, block_da_footprint_limit.unwrap_or(block_gas_limit),
                                    total_da_bytes_after, base_cumulative_da_bytes, da_increment, tx_da_size, da_footprint_gas_scalar)
                            )));
                        }
                    }

                    // 5. Validate gas limits and write updated BlockResourceUsed values
                    let tx_gas_used = result.gas_used();

                    // Check block gas limit
                    if cumulative_gas + tx_gas_used > block_gas_limit {
                        return Err(EVMError::Database(VersionedDbError::BaseDbError(
                            format!("Gas limit exceeded: {} + {} > {}",
                                cumulative_gas, tx_gas_used, block_gas_limit)
                        )));
                    }

                    // Check max gas per transaction
                    if let Some(max_gas) = max_gas_per_txn {
                        if tx_gas_used > max_gas {
                            return Err(EVMError::Database(VersionedDbError::BaseDbError(
                                format!("Transaction gas limit exceeded: {} > {}", tx_gas_used, max_gas)
                            )));
                        }
                    }

                    // Check address gas limiter
                    if address_gas_limiter.consume_gas(tx.signer(), tx_gas_used).is_err() {
                        return Err(EVMError::Database(VersionedDbError::BaseDbError(
                            format!("Address gas limit exceeded for {}", tx.signer())
                        )));
                    }

                    // 6. Write updated BlockResourceUsed cumulative values (EXCLUDING base from sequencer)
                    // Write the cumulative of user transactions ONLY (gas_increment + this tx)
                    // The base is added when reading for limit checks, preventing double-counting
                    let new_gas_cumulative = gas_increment + tx_gas_used;
                    let new_da_cumulative = da_increment + tx_da_size;

                    trace!(
                        target: "payload_builder",
                        "Writing increments: new_gas={}, new_da={} (gas_increment={} + tx_gas={}, da_increment={} + tx_da={})",
                        new_gas_cumulative, new_da_cumulative, gas_increment, tx_gas_used, da_increment, tx_da_size
                    );

                    state.database.inner_mut().write_block_resource(
                        BlockResourceType::Gas,
                        new_gas_cumulative
                    )?;
                    state.database.inner_mut().write_block_resource(
                        BlockResourceType::DABytes,
                        new_da_cumulative
                    )?;

                    Ok(ResultAndState { result, state: evm_state })
                },
                execute_txs_span.clone(),
            );

            executor.try_into_committed_results()?
        };
        // Process committed transactions in order up to the safe commit point.
        // When cancelled, only transactions [0..safe_commit_point] are guaranteed valid.
        let mut applied_count = 0;
        let num_results = results.len();
        for tx_result in results {
            let Some(result) = tx_result.result else {
                continue;
            };
            // Update cumulative gas before building receipt
            let gas_used = result.gas_used();
            info.cumulative_gas_used += gas_used;
            info.cumulative_da_bytes_used += tx_result.tx_da_size;
            info.total_fees += U256::from(tx_result.miner_fee) * U256::from(gas_used);

            // Load accounts into cache before committing
            // (State requires accounts to be in cache before applying changes)
            // Note: LazyEvmState has both loaded_state and pending_balance_increments
            for address in tx_result.state.loaded_state.keys() {
                let _ = db.load_cache_account(*address);
            }
            for address in tx_result.state.pending_balance_increments.keys() {
                let _ = db.load_cache_account(*address);
            }

            let mut resolved_state = tx_result
                .state
                .resolve_state(db)
                .map_err(|e| PayloadBuilderError::Other(e.to_string().into()))?;

            let mut mock_db = MockDB;
            let evm = self
                .evm_config
                .evm_with_env(&mut mock_db, self.evm_env.clone());

            // Build OpReceipt based on transaction type
            info.receipts.push(self.build_receipt_parallel(
                ReceiptBuilderCtx {
                    tx: &tx_result.tx,
                    evm: &evm,
                    result: result,
                    state: &resolved_state,
                    cumulative_gas_used: info.cumulative_gas_used,
                },
                None,
            ));

            // Populate code field from shared cache for newly deployed contracts
            // Without this, account.info.code is None and won't be stored in State.cache.contracts
            for (_addr, account) in resolved_state.iter_mut() {
                if let Some(code) = shared_code_cache.get(&account.info.code_hash) {
                    account.info.code = Some(code.clone());
                }
            }

            // Commit resolved state to actual DB
            let num_accounts_with_storage = resolved_state.iter()
                .filter(|(_, acct)| !acct.storage.is_empty())
                .count();
            trace!(
                target: "payload_builder",
                num_accounts = resolved_state.len(),
                num_accounts_with_storage,
                "Committing transaction state"
            );
            if num_accounts_with_storage > 0 {
                for (addr, account) in resolved_state.iter() {
                    if !account.storage.is_empty() {
                        let num_changed = account.storage.iter()
                            .filter(|(_, v)| v.is_changed())
                            .count();
                        trace!(
                            target: "payload_builder",
                            address = ?addr,
                            num_storage_slots = account.storage.len(),
                            num_changed_slots = num_changed,
                            is_touched = account.is_touched(),
                            is_selfdestructed = account.is_selfdestructed(),
                            "Account has storage in resolved_state before commit"
                        );
                    }
                }
            }
            db.commit(resolved_state);

            // Record transaction
            info.executed_senders.push(tx_result.tx.signer());
            info.executed_transactions.push(tx_result.tx.into_inner());

            applied_count += 1;
            trace!(
                cumulative_gas = info.cumulative_gas_used,
                "Committed transaction"
            );
        }

        info!(
            target: "payload_builder",
            "Block-STM commit phase complete: applied {} of {} candidates (safe_commit_point={})",
            applied_count, num_candidates, num_results
        );

        Ok(None)
    }
}
