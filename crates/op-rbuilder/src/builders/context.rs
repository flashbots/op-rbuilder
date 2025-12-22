use alloy_consensus::{Eip658Value, Transaction, conditional::BlockConditionalAttributes};
use alloy_eips::{Encodable2718, Typed2718};
use alloy_evm::Database;
use alloy_op_evm::{
    OpBlockExecutorFactory, OpEvmFactory, block::receipt_builder::OpReceiptBuilder,
};
use alloy_primitives::{Address, BlockHash, Bytes, U256};
use alloy_rpc_types_eth::Withdrawals;
use core::fmt::Debug;
use op_alloy_consensus::{OpDepositReceipt, OpTxType};
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
use reth_primitives_traits::{InMemorySize, Recovered, SignedTransaction};
use reth_revm::{State, context::Block};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction};
use revm::{
    DatabaseCommit, DatabaseRef, context::result::ResultAndState, interpreter::as_u64_saturated,
    primitives::HashMap, state::EvmState,
};
use std::{
    collections::hash_map::Entry,
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use tracing::{Span, debug, info, trace};

use crate::{
    block_stm::{
        MVHashMap, VersionedDatabase, evm::OpLazyEvmFactory, scheduler::Scheduler, types::Task,
        view::WriteSet,
    },
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

    pub(super) fn to_lazy_evm(self) -> OpPayloadBuilderCtx<ExtraCtx, OpLazyEvmFactory> {
        let OpPayloadBuilderCtx {
            evm_config,
            da_config,
            gas_limit_config,
            chain_spec,
            config,
            evm_env,
            block_env_attributes,
            cancel,
            builder_signer,
            metrics,
            extra_ctx,
            max_gas_per_txn,
            address_gas_limiter,
            resource_metering,
            parallel_threads,
        } = self;

        OpPayloadBuilderCtx {
            da_config,
            gas_limit_config,
            chain_spec: chain_spec.clone(),
            config,
            evm_env,
            block_env_attributes,
            cancel,
            builder_signer,
            metrics,
            extra_ctx,
            max_gas_per_txn,
            address_gas_limiter,
            resource_metering,
            parallel_threads,
            evm_config: OpEvmConfig {
                block_assembler: evm_config.block_assembler.clone(),
                executor_factory: OpBlockExecutorFactory::new(
                    *evm_config.executor_factory.receipt_builder(),
                    chain_spec,
                    OpLazyEvmFactory,
                ),
                _pd: Default::default(),
            },
        }
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

impl<ExtraCtx: Debug + Default> OpPayloadBuilderCtx<ExtraCtx, OpLazyEvmFactory> {
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

        let execute_txs_start_time = Instant::now();
        let base_fee = self.base_fee();
        let tx_da_limit = self.da_config.max_da_tx_size();

        let block_attr = BlockConditionalAttributes {
            number: self.block_number(),
            timestamp: self.attributes().timestamp(),
        };

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

        // Initialize Block-STM components
        let scheduler = Arc::new(Scheduler::new(num_candidates));
        let mv_hashmap = Arc::new(MVHashMap::new(num_candidates));

        // Store execution results per transaction (for deferred commit)
        let execution_results: Arc<Mutex<Vec<Option<TxExecutionResult>>>> =
            Arc::new(Mutex::new(vec![None; num_candidates]));

        // Shared state (info still needs mutex for cumulative values, best_txs for mark_invalid)
        let shared_info = Arc::new(Mutex::new(std::mem::take(info)));
        let shared_best_txs = Arc::new(Mutex::new(best_txs));
        let metrics = Arc::new(ParallelExecutionMetrics::new());

        // Shared reference to database for reads (workers only need DatabaseRef)
        let db_ref: &State<DB> = &*db;

        // Capture current span for cross-thread propagation
        let worker_parent_span = Span::current();

        // Spawn worker threads using Block-STM scheduler
        thread::scope(|s| {
            let num_threads = num_threads.min(num_candidates);

            for worker_id in 0..num_threads {
                let scheduler = Arc::clone(&scheduler);
                let mv_hashmap = Arc::clone(&mv_hashmap);
                let execution_results = Arc::clone(&execution_results);
                let _shared_info = Arc::clone(&shared_info);
                let shared_best_txs = Arc::clone(&shared_best_txs);
                let metrics = Arc::clone(&metrics);
                let candidate_txs = &candidate_txs;
                let address_gas_limiter = &self.address_gas_limiter;
                let max_gas_per_txn = self.max_gas_per_txn;
                let cancelled = &self.cancel;
                let evm_env = &self.evm_env;
                let base_db = db_ref; // Shared reference for reads
                let worker_parent_span = worker_parent_span.clone();

                s.spawn(move || {
                    // Create worker span as child of parent (linked to build_flashblock)
                    let _worker_span = tracing::info_span!(
                        parent: &worker_parent_span,
                        "block_stm_worker",
                        worker_id = worker_id
                    )
                    .entered();

                    scheduler.worker_start();

                    loop {
                        // Check for cancellation
                        if cancelled.is_cancelled() {
                            break;
                        }

                        // Get next task from Block-STM scheduler
                        let task = scheduler.next_task();

                        match task {
                            Task::Execute {
                                txn_idx,
                                incarnation,
                            } => {
                                let _tx_span = tracing::info_span!(
                                    "block_stm_tx_execute",
                                    txn_idx = txn_idx,
                                    incarnation = incarnation
                                )
                                .entered();

                                scheduler.start_execution(txn_idx, incarnation);

                                metrics
                                    .num_txs_considered
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                                let pool_tx = &candidate_txs[txn_idx as usize];
                                let tx_da_size = pool_tx.estimated_da_size();
                                let reverted_hashes = pool_tx.reverted_hashes().clone();
                                let conditional = pool_tx.conditional().cloned();
                                let tx = pool_tx.clone().into_consensus();
                                let tx_hash = tx.tx_hash();

                                let is_bundle_tx = reverted_hashes.is_some();
                                let exclude_reverting_txs =
                                    is_bundle_tx && !reverted_hashes.unwrap().contains(&tx_hash);

                                // Pre-execution checks (no DB access)
                                let skip_tx = if let Some(conditional) = conditional {
                                    !conditional.matches_block_attributes(&block_attr)
                                } else {
                                    false
                                } || tx.is_eip4844()
                                    || tx.is_deposit();

                                if skip_tx {
                                    shared_best_txs
                                        .lock()
                                        .unwrap()
                                        .mark_invalid(tx.signer(), tx.nonce());
                                    scheduler.finish_execution(
                                        txn_idx,
                                        incarnation,
                                        crate::block_stm::CapturedReads::new(),
                                        WriteSet::new(),
                                        0,
                                        false,
                                        &mv_hashmap,
                                    );
                                    continue;
                                }

                                // Create versioned database for this transaction
                                // Routes reads through MVHashMap, falls back to base state
                                let versioned_db = VersionedDatabase::new(
                                    txn_idx,
                                    incarnation,
                                    &mv_hashmap,
                                    base_db,
                                );

                                // Create State wrapper for EVM execution
                                let tx_state = State::builder().with_database(versioned_db).build();

                                // Wrap State with LazyDatabaseWrapper to support lazy balance increments
                                let mut lazy_state =
                                    crate::block_stm::evm::LazyDatabaseWrapper::new(tx_state);

                                // Execute transaction with versioned state
                                let exec_result = {
                                    let lazy_factory = crate::block_stm::evm::OpLazyEvmFactory;
                                    let mut evm =
                                        lazy_factory.create_evm(&mut lazy_state, evm_env.clone());
                                    evm.transact(&tx)
                                };

                                let exec_result = match exec_result {
                                    Ok(res) => res,
                                    Err(err) => {
                                        if let Some(err) = err.as_invalid_tx_err() {
                                            if !err.is_nonce_too_low() {
                                                shared_best_txs
                                                    .lock()
                                                    .unwrap()
                                                    .mark_invalid(tx.signer(), tx.nonce());
                                            }
                                        }
                                        // Get captured reads even on failure
                                        let captured_reads =
                                            lazy_state.inner().database.take_captured_reads();
                                        scheduler.finish_execution(
                                            txn_idx,
                                            incarnation,
                                            captured_reads,
                                            WriteSet::new(),
                                            0,
                                            false,
                                            &mv_hashmap,
                                        );
                                        continue;
                                    }
                                };

                                // Check if we read from an aborted transaction
                                if let Some(aborted_txn) = lazy_state.inner().database.was_aborted()
                                {
                                    trace!(
                                        worker_id = worker_id,
                                        txn_idx = txn_idx,
                                        aborted_txn = aborted_txn,
                                        "Read from aborted transaction, will re-execute"
                                    );
                                    let captured_reads =
                                        lazy_state.inner().database.take_captured_reads();
                                    scheduler.finish_execution(
                                        txn_idx,
                                        incarnation,
                                        captured_reads,
                                        WriteSet::new(),
                                        0,
                                        false,
                                        &mv_hashmap,
                                    );
                                    continue;
                                }

                                let ResultAndState { result, state } = exec_result;
                                let gas_used = result.gas_used();

                                // Post-execution checks
                                let should_skip = address_gas_limiter
                                    .consume_gas(tx.signer(), gas_used)
                                    .is_err()
                                    || (!result.is_success() && exclude_reverting_txs)
                                    || max_gas_per_txn.map(|max| gas_used > max).unwrap_or(false);

                                if should_skip {
                                    shared_best_txs
                                        .lock()
                                        .unwrap()
                                        .mark_invalid(tx.signer(), tx.nonce());
                                    let captured_reads =
                                        lazy_state.inner().database.take_captured_reads();
                                    scheduler.finish_execution(
                                        txn_idx,
                                        incarnation,
                                        captured_reads,
                                        WriteSet::new(),
                                        gas_used,
                                        false,
                                        &mv_hashmap,
                                    );
                                    continue;
                                }

                                // Build write set from state changes
                                let mut write_set: WriteSet = WriteSet::new();
                                let captured_reads =
                                    lazy_state.inner().database.take_captured_reads();

                                // Add writes only for values that actually changed
                                for (addr, account) in state.iter() {
                                    if account.is_touched() {
                                        // Get original values from captured reads (if available)
                                        let original_balance = captured_reads.get_balance(*addr);
                                        let original_nonce = captured_reads.get_nonce(*addr);
                                        let original_code_hash =
                                            captured_reads.get_code_hash(*addr);

                                        // Only write balance if it changed
                                        if original_balance != Some(account.info.balance) {
                                            write_set.write_balance(*addr, account.info.balance);
                                        }

                                        // Only write nonce if it changed
                                        if original_nonce != Some(account.info.nonce) {
                                            write_set.write_nonce(*addr, account.info.nonce);
                                        }

                                        // Only write code hash if it changed
                                        if original_code_hash != Some(account.info.code_hash) {
                                            write_set
                                                .write_code_hash(*addr, account.info.code_hash);
                                        }

                                        // Storage slots already have is_changed() check
                                        for (slot, value) in account.storage.iter() {
                                            if value.is_changed() {
                                                write_set.write_storage(
                                                    *addr,
                                                    *slot,
                                                    value.present_value,
                                                );
                                            }
                                        }
                                    }
                                }

                                let (_, pending_balance_increments) = lazy_state.into_inner();

                                // Add pending balance increments as deltas (commutative fee accumulation)
                                // These are tracked separately to allow parallel accumulation
                                for (addr, delta) in pending_balance_increments.iter() {
                                    write_set.add_balance_delta(*addr, *delta);
                                }

                                // Get captured reads for validation

                                // Store execution result for commit phase
                                let miner_fee = tx
                                    .effective_tip_per_gas(base_fee)
                                    .expect("fee is always valid");

                                // Extract success and logs from result
                                let success = result.is_success();
                                let logs = result.into_logs();

                                {
                                    let mut results = execution_results.lock().unwrap();
                                    results[txn_idx as usize] = Some(TxExecutionResult {
                                        tx,
                                        state: StateWithIncrements {
                                            loaded_state: state,
                                            pending_balance_increments,
                                        },
                                        success,
                                        logs,
                                        gas_used,
                                        tx_da_size,
                                        miner_fee,
                                    });
                                }

                                // Update metrics
                                metrics
                                    .num_txs_simulated
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                                if success {
                                    metrics
                                        .num_txs_simulated_success
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                } else {
                                    metrics
                                        .num_txs_simulated_fail
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    metrics.reverted_gas_used.fetch_add(
                                        gas_used as i32,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }

                                // Report to scheduler
                                scheduler.finish_execution(
                                    txn_idx,
                                    incarnation,
                                    captured_reads,
                                    write_set,
                                    gas_used,
                                    success,
                                    &mv_hashmap,
                                );

                                trace!(
                                    worker_id = worker_id,
                                    txn_idx = txn_idx,
                                    gas_used = gas_used,
                                    success = success,
                                    "Transaction execution complete"
                                );
                            }
                            Task::Validate { txn_idx: _ } => {
                                // Validation handled in scheduler's try_commit
                            }
                            Task::NoTask => {
                                if scheduler.is_done() {
                                    break;
                                }
                                scheduler.wait_for_work();
                            }
                            Task::Done => {
                                break;
                            }
                        }
                    }

                    scheduler.worker_done();
                });
            }
        });

        // Commit phase: apply results in order
        let results = Arc::try_unwrap(execution_results)
            .map_err(|_| PayloadBuilderError::Other("Failed to unwrap execution results".into()))?
            .into_inner()
            .unwrap();

        let mut info_guard = shared_info.lock().unwrap();

        // only save up to committed_idx
        let committed_idx = scheduler.get_commit_idx();
        let results = results.into_iter().take(committed_idx).collect::<Vec<_>>();

        // Process committed transactions in order
        for (txn_idx, result_opt) in results.into_iter().enumerate() {
            if let Some(tx_result) = result_opt {
                // Update cumulative gas before building receipt
                info_guard.cumulative_gas_used += tx_result.gas_used;
                info_guard.cumulative_da_bytes_used += tx_result.tx_da_size;
                info_guard.total_fees +=
                    U256::from(tx_result.miner_fee) * U256::from(tx_result.gas_used);

                // Build receipt with correct cumulative gas
                let receipt = alloy_consensus::Receipt {
                    status: Eip658Value::Eip658(tx_result.success),
                    cumulative_gas_used: info_guard.cumulative_gas_used,
                    logs: tx_result.logs,
                };

                // Build OpReceipt based on transaction type
                let op_receipt = match tx_result.tx.tx_type() {
                    OpTxType::Legacy => OpReceipt::Legacy(receipt),
                    OpTxType::Eip2930 => OpReceipt::Eip2930(receipt),
                    OpTxType::Eip1559 => OpReceipt::Eip1559(receipt),
                    OpTxType::Eip7702 => OpReceipt::Eip7702(receipt),
                    OpTxType::Deposit => {
                        // Deposits shouldn't come from the pool, but handle gracefully
                        OpReceipt::Deposit(OpDepositReceipt {
                            inner: receipt,
                            deposit_nonce: None,
                            deposit_receipt_version: None,
                        })
                    }
                };
                info_guard.receipts.push(op_receipt);

                // Load accounts into cache before committing
                // (State requires accounts to be in cache before applying changes)
                // Note: LazyEvmState has both loaded_state and pending_balance_increments
                for address in tx_result.state.loaded_state.keys() {
                    let _ = db.load_cache_account(*address);
                }
                for address in tx_result.state.pending_balance_increments.keys() {
                    let _ = db.load_cache_account(*address);
                }

                let resolved_state = tx_result
                    .state
                    .resolve_state(db)
                    .map_err(|e| PayloadBuilderError::Other(e.to_string().into()))?;

                // Commit resolved state to actual DB
                db.commit(resolved_state);

                // Record transaction
                info_guard.executed_senders.push(tx_result.tx.signer());
                info_guard
                    .executed_transactions
                    .push(tx_result.tx.into_inner());

                trace!(
                    txn_idx = txn_idx,
                    cumulative_gas = info_guard.cumulative_gas_used,
                    "Committed transaction"
                );
            }
        }

        // Restore info
        *info = std::mem::take(&mut *info_guard);
        drop(info_guard);

        // Get scheduler stats
        let sched_stats = scheduler.get_stats();
        debug!(
            target: "payload_builder",
            total_executions = sched_stats.total_executions,
            total_aborts = sched_stats.total_aborts,
            total_commits = sched_stats.total_commits,
            "Block-STM scheduler stats"
        );

        // Read metrics from atomics
        let num_txs_considered = metrics
            .num_txs_considered
            .load(std::sync::atomic::Ordering::Relaxed);
        let num_txs_simulated = metrics
            .num_txs_simulated
            .load(std::sync::atomic::Ordering::Relaxed);
        let num_txs_simulated_success = metrics
            .num_txs_simulated_success
            .load(std::sync::atomic::Ordering::Relaxed);
        let num_txs_simulated_fail = metrics
            .num_txs_simulated_fail
            .load(std::sync::atomic::Ordering::Relaxed);
        let num_bundles_reverted = metrics
            .num_bundles_reverted
            .load(std::sync::atomic::Ordering::Relaxed);
        let reverted_gas_used = metrics
            .reverted_gas_used
            .load(std::sync::atomic::Ordering::Relaxed);

        if self.cancel.is_cancelled() {
            debug!("Cancellation detected, returning");
            return Ok(Some(()));
        }

        let payload_transaction_simulation_time = execute_txs_start_time.elapsed();
        self.metrics.set_payload_builder_metrics(
            payload_transaction_simulation_time,
            num_txs_considered as i32,
            num_txs_simulated as i32,
            num_txs_simulated_success as i32,
            num_txs_simulated_fail as i32,
            num_bundles_reverted as i32,
            reverted_gas_used,
        );

        debug!(
            target: "payload_builder",
            message = "Completed executing best transactions (Block-STM)",
            txs_executed = num_txs_considered,
            txs_applied = num_txs_simulated_success,
            txs_rejected = num_txs_simulated_fail,
            bundles_reverted = num_bundles_reverted,
        );

        Ok(None)
    }
}

#[derive(Clone)]
struct StateWithIncrements {
    loaded_state: EvmState,
    pending_balance_increments: HashMap<Address, U256>,
}

impl StateWithIncrements {
    fn resolve_state<DB: Database>(self, db: &mut DB) -> Result<EvmState, DB::Error> {
        let mut state = self.loaded_state;
        for (addr, delta) in self.pending_balance_increments.iter() {
            match state.entry(*addr) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().info.balance = entry.get().info.balance.saturating_add(*delta);
                }
                Entry::Vacant(entry) => {
                    let mut account = db.basic(*addr)?.unwrap_or_default();
                    account.balance = account.balance.saturating_add(*delta);
                    entry.insert(account.into());
                }
            }
        }
        Ok(state)
    }
}

/// Result of executing a single transaction in parallel.
/// Stored for deferred commit during the commit phase.
#[derive(Clone)]
struct TxExecutionResult {
    /// The transaction that was executed
    tx: Recovered<op_alloy_consensus::OpTxEnvelope>,
    /// State changes from execution (using alloy's HashMap for compatibility)
    state: StateWithIncrements,
    /// Whether execution succeeded
    success: bool,
    /// Logs from execution (needed for receipt building)
    logs: Vec<alloy_primitives::Log>,
    /// Gas used
    gas_used: u64,
    /// DA size
    tx_da_size: u64,
    /// Miner fee per gas
    miner_fee: u128,
}

/// Atomic metrics counters for parallel execution.
struct ParallelExecutionMetrics {
    num_txs_considered: std::sync::atomic::AtomicUsize,
    num_txs_simulated: std::sync::atomic::AtomicUsize,
    num_txs_simulated_success: std::sync::atomic::AtomicUsize,
    num_txs_simulated_fail: std::sync::atomic::AtomicUsize,
    num_bundles_reverted: std::sync::atomic::AtomicUsize,
    reverted_gas_used: std::sync::atomic::AtomicI32,
}

impl ParallelExecutionMetrics {
    fn new() -> Self {
        Self {
            num_txs_considered: std::sync::atomic::AtomicUsize::new(0),
            num_txs_simulated: std::sync::atomic::AtomicUsize::new(0),
            num_txs_simulated_success: std::sync::atomic::AtomicUsize::new(0),
            num_txs_simulated_fail: std::sync::atomic::AtomicUsize::new(0),
            num_bundles_reverted: std::sync::atomic::AtomicUsize::new(0),
            reverted_gas_used: std::sync::atomic::AtomicI32::new(0),
        }
    }
}
