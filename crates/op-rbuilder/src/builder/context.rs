use alloy_consensus::{Transaction, conditional::BlockConditionalAttributes};
use alloy_eips::{Encodable2718, Typed2718, eip2718::WithEncoded};
use alloy_evm::{
    Database, Evm,
    block::{BlockExecutor as AlloyBlockExecutor, CommitChanges, TxResult},
};
use alloy_primitives::{B256, BlockHash, U256};
use op_revm::L1BlockInfo;
use reth_basic_payload_builder::PayloadConfig;
use reth_evm::{
    ConfigureEvm,
    execute::{BlockBuilder, BlockExecutionError, BlockValidationError},
};
use reth_node_api::PayloadBuilderError;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_payload_builder::{
    config::{OpDAConfig, OpGasLimitConfig},
    error::OpPayloadBuilderError,
};
use reth_optimism_primitives::OpTransactionSigned;
use reth_optimism_txpool::{
    conditional::MaybeConditionalTransaction, estimated_da_size::DataAvailabilitySized,
};
use reth_payload_builder::PayloadId;
use reth_primitives_traits::{InMemorySize, SealedHeader, SignedTransaction};
use reth_provider::ProviderError;
use reth_revm::{State, context::Block};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction};
use revm::{Database as _, interpreter::as_u64_saturated};
use std::{sync::Arc, time::Instant};
use tracing::{debug, info, trace};

use crate::{
    backrun_bundle::{BackrunBundleArgs, BackrunBundlePayloadPool},
    builder::{
        assembly::BlockAssemblyInput, builder_tx::BuilderTxEnv,
        cancellation::FlashblockJobCancellation,
    },
    evm::OpBlockEvmFactory,
    hardforks::ActiveHardforks,
    limiter::{AddressLimiter, AddressLimiterGuard},
    metrics::OpRBuilderMetrics,
    primitives::reth::{ExecutionInfo, TxnExecutionResult},
    traits::PayloadTxsBounds,
};

/// Configuration that is constant for the entire builder lifetime and shared
/// across every payload job via [`Arc`].
///
/// Every field here is either set once at builder construction (CLI args /
/// `BuilderConfig`) or is itself an `Arc`/handle whose backing data lives
/// outside the per-job context (e.g. metrics registry, global backrun pool,
/// per-address gas limiter buckets).
#[derive(Debug, Clone)]
pub struct OpPayloadBuilderCtx {
    /// EVM configuration used to build a per-job [`OpBlockEvmFactory`].
    pub evm_config: OpEvmConfig,
    /// The DA config for the payload builder
    pub da_config: OpDAConfig,
    /// Gas limit configuration for the payload builder
    pub gas_limit_config: OpGasLimitConfig,
    /// The chainspec
    pub chain_spec: Arc<OpChainSpec>,
    /// The metrics for the builder
    pub metrics: Arc<OpRBuilderMetrics>,
    /// Max gas that can be used by a transaction.
    pub max_gas_per_txn: Option<u64>,
    /// Maximum cumulative uncompressed (EIP-2718 encoded) block size in bytes.
    pub max_uncompressed_block_size: Option<u64>,
    /// Canonical per-address rate limiter (gas and/or compute time). Each
    /// payload job begins a per-build [`AddressLimiterGuard`] off this; the
    /// only direct mutation here is the per-block `refill_buckets`.
    pub address_limiter: AddressLimiter,
    /// Backrun bundle configuration.
    pub backrun_bundle_args: BackrunBundleArgs,
    /// Skip reverted txs in subsequent flashblocks
    pub exclude_reverts_between_flashblocks: bool,
    /// Enable tx tracking logs
    pub enable_tx_tracking_debug_logs: bool,
    /// Whether to disable state root calculation for each flashblock
    pub disable_state_root: bool,
    /// Whether to enable incremental state root calculation using cached trie nodes
    pub enable_incremental_state_root: bool,
}

/// Container type that holds all necessities to build a new payload.
/// This struct is constructed once per payload job.
#[derive(Clone, derive_more::Constructor, derive_more::Deref)]
#[allow(clippy::too_many_arguments)]
pub struct OpPayloadJobCtx {
    /// Builder-lifetime configuration shared with all other in-flight jobs.
    #[deref]
    builder_ctx: Arc<OpPayloadBuilderCtx>,
    /// Factory for creating EVM instances (bundles evm_config + evm_env).
    evm_factory: OpBlockEvmFactory,
    /// How to build the payload.
    config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    /// Block env attributes for the current block.
    block_env_attributes: OpNextBlockEnvAttributes,
    /// Hardfork activation state for this block's timestamp.
    hardforks: ActiveHardforks,
    /// Marker to check whether the job has been cancelled.
    cancel: FlashblockJobCancellation,
    /// Per-block view into the global backrun bundle pool.
    backrun_pool: Option<BackrunBundlePayloadPool>,
    /// Per-build guard onto the canonical [`AddressLimiter`] held by
    /// `builder_ctx`. Charges accumulate privately here and auto-commit back
    /// into the canonical when the last [`Arc`] is dropped. Shadows the
    /// `address_limiter` field reached via `Deref` to `OpPayloadBuilderCtx`,
    /// so `self.address_limiter` inside this ctx always hits the guard.
    ///
    /// Wrapped in [`Arc`] so the continuous build path can clone this ctx
    /// across flashblock intervals while every clone still drives a single
    /// shared guard. The guard auto-commits when the last clone is dropped.
    address_limiter: Arc<AddressLimiterGuard>,
}

impl OpPayloadJobCtx {
    pub(super) fn with_cancel(self, cancel: FlashblockJobCancellation) -> Self {
        Self { cancel, ..self }
    }

    pub fn builder_tx_env(&self) -> BuilderTxEnv<'_> {
        BuilderTxEnv {
            evm_factory: &self.evm_factory,
            hardforks: &self.hardforks,
            base_fee: self.base_fee(),
            block_number: self.block_number(),
            block_gas_limit: self.block_gas_limit(),
            parent_hash: self.parent_hash(),
            max_uncompressed_block_size: self.max_uncompressed_block_size,
        }
    }

    /// Returns the parent block the payload will be build on.
    pub fn parent(&self) -> &SealedHeader {
        &self.config.parent_header
    }

    /// Returns the parent hash
    pub fn parent_hash(&self) -> BlockHash {
        self.parent().hash()
    }

    /// Returns the builder attributes.
    pub(crate) const fn attributes(&self) -> &OpPayloadBuilderAttributes<OpTransactionSigned> {
        &self.config.attributes
    }

    /// Returns this job's cancellation handle.
    pub(crate) fn cancel(&self) -> &FlashblockJobCancellation {
        &self.cancel
    }

    /// Returns this job's per-build [`AddressLimiterGuard`]. All clones of this
    /// ctx share the same guard via [`Arc`]; the canonical commit fires when
    /// the last clone drops.
    pub(crate) fn address_limiter(&self) -> &AddressLimiterGuard {
        &self.address_limiter
    }

    /// Returns the block gas limit to target.
    pub fn block_gas_limit(&self) -> u64 {
        match self.gas_limit_config.gas_limit() {
            Some(gas_limit) => gas_limit,
            None => self
                .attributes()
                .gas_limit
                .unwrap_or(self.evm_factory.evm_env().block_env.gas_limit),
        }
    }

    /// Returns the block number for the block.
    pub fn block_number(&self) -> u64 {
        as_u64_saturated!(self.evm_factory.evm_env().block_env.number)
    }

    /// Returns the current base fee
    pub fn base_fee(&self) -> u64 {
        self.evm_factory.evm_env().block_env.basefee
    }

    /// Returns the current blob gas price.
    pub fn get_blob_gasprice(&self) -> Option<u64> {
        self.evm_factory
            .evm_env()
            .block_env
            .blob_gasprice()
            .map(|gasprice| gasprice as u64)
    }

    /// Returns the current fee settings for transactions from the mempool
    pub fn best_transaction_attributes(&self) -> BestTransactionsAttributes {
        BestTransactionsAttributes::new(self.base_fee(), self.get_blob_gasprice())
    }

    /// Returns the unique id for this payload job.
    pub fn payload_id(&self) -> PayloadId {
        self.attributes().payload_id()
    }

    pub(super) fn execute_pre_steps<DB>(
        &self,
        state: &mut State<DB>,
    ) -> Result<ExecutionInfo, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + std::fmt::Debug,
    {
        // 1. apply pre-execution changes
        self.evm_factory
            .evm_config()
            .builder_for_next_block(state, self.parent(), self.block_env_attributes.clone())
            .map_err(PayloadBuilderError::other)?
            .apply_pre_execution_changes()?;

        // 2. execute sequencer transactions
        let info = self.execute_sequencer_transactions(state)?;

        Ok(info)
    }

    /// Executes all sequencer transactions that are included in the payload attributes.
    fn execute_sequencer_transactions(
        &self,
        db: &mut State<impl Database>,
    ) -> Result<ExecutionInfo, PayloadBuilderError> {
        let mut info = ExecutionInfo::with_capacity(self.attributes().transactions.len());
        let mut builder = self
            .evm_factory
            .evm_config()
            .builder_for_next_block(db, self.parent(), self.block_env_attributes.clone())
            .map_err(PayloadBuilderError::other)?;

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
            let recovered_tx = sequencer_tx
                .value()
                .try_clone_into_recovered()
                .map_err(|_| {
                    PayloadBuilderError::other(OpPayloadBuilderError::TransactionEcRecoverFailed)
                })?;
            let sequencer_tx = WithEncoded::new(sequencer_tx.encoded_bytes().clone(), recovered_tx);

            // Bypasses the unused builder transaction vec.
            // Note: For BAL must bump bal_index explicitly on executor-level transaction paths.
            let gas_used = match builder.executor_mut().execute_transaction(&sequencer_tx) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    trace!(
                        target: "payload_builder",
                        error = %error,
                        ?sequencer_tx,
                        "Error in sequencer transaction, skipping."
                    );
                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    return Err(PayloadBuilderError::EvmExecutionError(Box::new(err)));
                }
            };

            let tx_da_size = if !sequencer_tx.value().is_deposit() {
                op_alloy_flz::tx_estimated_size_fjord_bytes(sequencer_tx.encoded_bytes())
            } else {
                0
            };

            info.commit_executed_tx(
                sequencer_tx.value(),
                gas_used.tx_gas_used(),
                tx_da_size,
                None,
                builder
                    .executor()
                    .receipts()
                    .last()
                    .cloned()
                    .ok_or_else(missing_committed_receipt)?,
            );
        }

        let da_footprint_gas_scalar = self.hardforks.is_jovian_active().then(|| {
            L1BlockInfo::fetch_da_footprint_gas_scalar(builder.evm_mut().db_mut())
                .expect("DA footprint should always be available from the database post jovian")
        });

        info.da_footprint_scalar = da_footprint_gas_scalar;

        Ok(info)
    }

    fn record_limit_rejection_metrics(&self, result: &TxnExecutionResult) {
        match result {
            TxnExecutionResult::TransactionDALimitExceeded => {
                self.metrics.tx_da_size_exceeded_total.increment(1);
            }
            TxnExecutionResult::BlockDALimitExceeded(..) => {
                self.metrics.block_da_size_exceeded_total.increment(1);
            }
            TxnExecutionResult::TransactionGasLimitExceeded(..) => {
                self.metrics.block_gas_limit_exceeded_total.increment(1);
            }
            TxnExecutionResult::BlockUncompressedSizeExceeded(..) => {
                self.metrics
                    .block_uncompressed_size_exceeded_total
                    .increment(1);
            }
            _ => {}
        }
    }

    pub(super) fn block_assembly_input(&self) -> Result<BlockAssemblyInput, PayloadBuilderError> {
        BlockAssemblyInput::try_new(
            self.config.clone(),
            &self.evm_factory,
            self.hardforks.clone(),
        )
    }

    /// Executes the given best transactions and updates the execution info.
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    #[expect(clippy::too_many_arguments)]
    #[tracing::instrument(level = "info", skip_all)]
    pub(super) fn execute_best_transactions(
        &self,
        info: &mut ExecutionInfo,
        db: &mut State<impl Database>,
        best_txs: &mut impl PayloadTxsBounds,
        block_gas_limit: u64,
        block_da_limit: Option<u64>,
        block_da_footprint_limit: Option<u64>,
        max_uncompressed_block_size: Option<u64>,
        flashblock_index: u64,
    ) -> Result<Option<()>, PayloadBuilderError> {
        let execute_txs_start_time = Instant::now();
        let mut num_txs_considered = 0;
        let mut num_txs_simulated = 0;
        let mut num_txs_simulated_success = 0;
        let mut num_txs_simulated_fail = 0;
        let mut num_bundles_reverted = 0;
        let mut reverted_gas_used: u64 = 0;
        let mut num_backruns_considered = 0usize;
        let mut num_backruns_successful = 0usize;
        let mut backrun_processing_time = std::time::Duration::ZERO;
        let tx_da_limit = self.da_config.max_da_tx_size();
        let mut builder = self
            .evm_factory
            .evm_config()
            .builder_for_next_block(db, self.parent(), self.block_env_attributes.clone())
            .map_err(PayloadBuilderError::other)?;
        let (base_fee, block_number, coinbase) = {
            let block = builder.evm().block();
            (
                block.basefee(),
                as_u64_saturated!(block.number()),
                block.beneficiary(),
            )
        };

        debug!(
            target: "payload_builder",
            id = %self.payload_id(),
            block_da_limit = ?block_da_limit,
            tx_da_limit = ?tx_da_limit,
            block_gas_limit = ?block_gas_limit,
            max_uncompressed_block_size = ?max_uncompressed_block_size,
            "Executing best transactions",
        );

        let block_attr = BlockConditionalAttributes {
            number: block_number,
            timestamp: self.attributes().timestamp(),
        };

        while let Some(tx) = best_txs.next(()) {
            let conditional = tx.conditional().cloned();
            let tx_da_size = tx.estimated_da_size();

            let is_bundle_tx = tx.is_bundle();
            let exclude_reverting_txs = tx.revert_protected();

            let encoded_tx = tx.into_consensus_with2718();
            let tx = encoded_tx.value();
            let tx_hash = tx.tx_hash();
            let tx_uncompressed_size = tx.encode_2718_len() as u64;

            if self.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    tx_hash = %tx_hash,
                    block_number,
                    flashblock_index,
                    stage = "builder_popped"
                );
            }

            let log_txn = |result: TxnExecutionResult| {
                if self.enable_tx_tracking_debug_logs {
                    debug!(
                        target: "tx_trace",
                        id = %self.payload_id(),
                        tx_hash = %tx_hash,
                        tx_da_size,
                        exclude_reverting_txs,
                        result = %result,
                        "Considering transaction",
                    );
                }
            };

            num_txs_considered += 1;

            // TODO: ideally we should get this from the txpool stream
            if let Some(conditional) = conditional
                && !conditional.matches_block_attributes(&block_attr)
            {
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // ensure we still have capacity for this transaction
            if let Err(result) = info.is_tx_over_limits(
                tx_da_size,
                block_gas_limit,
                tx_da_limit,
                block_da_limit,
                tx.gas_limit(),
                block_da_footprint_limit,
                tx_uncompressed_size,
                max_uncompressed_block_size,
            ) {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                self.record_limit_rejection_metrics(&result);
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

            // Skip addresses that are in debt from previous gas/compute usage
            if !self.address_limiter.is_debt_free(&tx.signer()) {
                log_txn(TxnExecutionResult::SenderBudgetExhausted);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // check if the job was cancelled, if so we can exit early
            if self.cancel.is_cancelled() {
                return Ok(Some(()));
            }

            let tx_simulation_start_time = Instant::now();
            let mut gas_used = 0;
            let mut tx_succeeded = false;
            let mut gas_limit_exceeded = false;
            let committed = match builder
                .executor_mut()
                .execute_transaction_with_commit_condition(&encoded_tx, |result| {
                    gas_used = result.result().result.tx_gas_used();
                    tx_succeeded = result.result().result.is_success();
                    gas_limit_exceeded = self
                        .max_gas_per_txn
                        .is_some_and(|max_gas_per_txn| gas_used > max_gas_per_txn);

                    let simulation_duration = tx_simulation_start_time.elapsed();
                    self.metrics
                        .tx_simulation_duration
                        .record(simulation_duration);
                    self.metrics.tx_byte_size.record(tx.inner().size() as f64);
                    if self.enable_tx_tracking_debug_logs {
                        debug!(
                            target: "tx_trace",
                            tx_hash = %tx_hash,
                            block_number,
                            flashblock_index,
                            gas_used,
                            success = tx_succeeded,
                            evm_duration_us = simulation_duration.as_micros() as u64,
                            stage = "evm_executed"
                        );
                    }

                    // Declined simulations still consume sender budget to meter expensive spam.
                    self.address_limiter.consume_gas(tx.signer(), gas_used);
                    self.address_limiter
                        .consume_compute(tx.signer(), simulation_duration);

                    if gas_limit_exceeded || (!tx_succeeded && exclude_reverting_txs) {
                        CommitChanges::No
                    } else {
                        CommitChanges::Yes
                    }
                }) {
                Ok(committed) => committed,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        log_txn(TxnExecutionResult::NonceTooLow);
                        trace!(
                            target: "payload_builder",
                            error = %error,
                            ?tx,
                            "skipping nonce too low transaction"
                        );
                    } else {
                        // if the transaction is invalid, we can skip it and all of its
                        // descendants
                        log_txn(TxnExecutionResult::InternalError(error.to_string()));
                        trace!(
                            target: "payload_builder",
                            error = %error,
                            ?tx,
                            "skipping invalid transaction and its descendants"
                        );
                        best_txs.mark_invalid(tx.signer(), tx.nonce());
                    }

                    continue;
                }
                Err(err) => {
                    // this is an error that we should treat as fatal for this attempt
                    log_txn(TxnExecutionResult::EvmError);
                    return Err(PayloadBuilderError::evm(err));
                }
            };

            num_txs_simulated += 1;

            if tx_succeeded {
                log_txn(TxnExecutionResult::Success);
                num_txs_simulated_success += 1;
                self.metrics.successful_tx_gas_used.record(gas_used as f64);
            } else {
                num_txs_simulated_fail += 1;
                reverted_gas_used += gas_used;
                self.metrics.reverted_tx_gas_used.record(gas_used as f64);
                if is_bundle_tx {
                    num_bundles_reverted += 1;
                }
                if exclude_reverting_txs {
                    log_txn(TxnExecutionResult::RevertedAndExcluded);
                    trace!(
                        target: "payload_builder",
                        tx_hash = %tx.tx_hash(),
                        signer = %tx.signer(),
                        gas_used,
                        "skipping reverted transaction"
                    );
                    if self.exclude_reverts_between_flashblocks {
                        best_txs.mark_excluded(B256::new(*tx_hash));
                        info.reverted_bundle_tx_hashes.push(B256::new(*tx_hash));
                    }
                    best_txs.mark_invalid(tx.signer(), tx.nonce());
                    continue;
                } else {
                    log_txn(TxnExecutionResult::Reverted);
                }
            }

            if gas_limit_exceeded {
                log_txn(TxnExecutionResult::MaxGasUsageExceeded);
                best_txs.mark_invalid(tx.signer(), tx.nonce());
                continue;
            }

            // Future closure declines must not leak into commit bookkeeping.
            if committed.is_none() {
                continue;
            }

            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");

            info.commit_executed_tx(
                tx,
                gas_used,
                tx_da_size,
                Some(miner_fee),
                builder
                    .executor()
                    .receipts()
                    .last()
                    .cloned()
                    .ok_or_else(missing_committed_receipt)?,
            );

            let target_hash = B256::new(*tx_hash);

            if self.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    tx_hash = %target_hash,
                    block_number,
                    flashblock_index,
                    cumulative_gas = info.cumulative_gas_used,
                    stage = "builder_committed"
                );
            }

            let can_backrun = self.backrun_bundle_args.backruns_enabled
                && tx_succeeded
                && !self.backrun_bundle_args.is_limit_reached(
                    num_backruns_considered,
                    num_backruns_successful,
                    0,
                    0,
                );

            if can_backrun && let Some(ref backrun_pool) = self.backrun_pool {
                let backrun_start_time = Instant::now();
                let gas_left = block_gas_limit.saturating_sub(info.cumulative_gas_used);
                let backruns = backrun_pool.get_backruns(
                    &target_hash,
                    |addr| builder.evm_mut().db_mut().basic(addr).ok().flatten(),
                    base_fee,
                    gas_left,
                    self.backrun_bundle_args
                        .max_considered_backruns_per_transaction,
                    miner_fee,
                );

                let mut tx_backruns_landed = 0;

                for (tx_backruns_considered, bundle) in backruns.into_iter().enumerate() {
                    if self.backrun_bundle_args.is_limit_reached(
                        num_backruns_considered,
                        num_backruns_successful,
                        tx_backruns_considered,
                        tx_backruns_landed,
                    ) {
                        break;
                    }

                    // Backrun tx commit checklist:
                    // This is a set of steps that are performed for normal transactions above that we need to
                    // replicate for backrun transactions
                    // - [x] num_txs_considered inc
                    // - [x] check conditional (block and flashblock number)
                    // - [x] check if tx over limits
                    // - [x] reject blobs and deposit txs
                    // - [x] exit early before evm execution if cancelled
                    // - [x] meter simulation duration
                    // - [x] meter tx_byte_size
                    // - [x] use gas limiter
                    // - [x] log when tx execution fails
                    // - [x] inc num_txs_simulated_success or num_txs_simulated_fail
                    // - [x] inc reverted_gas_used
                    // - [x] metrics use successful_tx_gas_used and reverted_tx_gas_used
                    // - [x] inc num_bundles_reverted
                    // - [x] enforce self.max_gas_per_txn
                    // - [x] increase info.{cumulative_gas_used, cumulative_da_bytes_used}
                    // - [x] push receipt to info.receipts
                    // - [x] commit changes to db
                    // - [x] increase info.total_fees
                    // - [x] update info.{executed_senders, executed_transactions}

                    // In addition to that for backruns we do:
                    // - [x] if enforce_strict_priority_fee_ordering
                    //       check backrun priority fee == target priority fee
                    //       and check that stated coinbase profit <= real coinbase profit
                    // - [x] if !enforce_strict_priority_fee_ordering
                    // check backrun priority fee >= target priority fee

                    let br_hash = bundle.backrun_tx.hash();

                    let log_br_txn = |result: TxnExecutionResult| {
                        if self.enable_tx_tracking_debug_logs {
                            debug!(
                                target: "tx_trace",
                                message = "Considering backrun",
                                tx_hash = %br_hash,
                                result = %result,
                            )
                        }
                    };

                    num_txs_considered += 1;
                    num_backruns_considered += 1;

                    if !bundle.is_valid(block_attr.number, flashblock_index) {
                        log_br_txn(TxnExecutionResult::ConditionalCheckFailed);
                        continue;
                    }

                    let Some(backrun_priority_fee) =
                        bundle.backrun_tx.effective_tip_per_gas(base_fee)
                    else {
                        log_br_txn(TxnExecutionResult::InternalError(
                            "gas price less than base fee".to_string(),
                        ));
                        continue;
                    };

                    if self
                        .backrun_bundle_args
                        .enforce_strict_priority_fee_ordering
                    {
                        if backrun_priority_fee != miner_fee {
                            log_br_txn(TxnExecutionResult::BackrunPriorityFeeInvalid);
                            continue;
                        }
                    } else if backrun_priority_fee < miner_fee {
                        log_br_txn(TxnExecutionResult::BackrunPriorityFeeInvalid);
                        continue;
                    }

                    if bundle.backrun_tx.is_eip4844() || bundle.backrun_tx.is_deposit() {
                        log_br_txn(TxnExecutionResult::SequencerTransaction);
                        continue;
                    }

                    let br_tx_da_size = bundle.estimated_da_size;
                    let br_tx_uncompressed_size = bundle.backrun_tx.encode_2718_len() as u64;
                    if let Err(result) = info.is_tx_over_limits(
                        br_tx_da_size,
                        block_gas_limit,
                        tx_da_limit,
                        block_da_limit,
                        bundle.backrun_tx.gas_limit(),
                        block_da_footprint_limit,
                        br_tx_uncompressed_size,
                        max_uncompressed_block_size,
                    ) {
                        self.record_limit_rejection_metrics(&result);
                        log_br_txn(result);
                        continue;
                    }

                    // Skip addresses that are in debt from previous gas/compute usage
                    if !self
                        .address_limiter
                        .is_debt_free(&bundle.backrun_tx.signer())
                    {
                        log_br_txn(TxnExecutionResult::SenderBudgetExhausted);
                        continue;
                    }

                    if self.cancel.is_cancelled() {
                        return Ok(Some(()));
                    }

                    let coinbase_balance_before = builder
                        .evm_mut()
                        .db_mut()
                        .basic(coinbase)
                        .ok()
                        .flatten()
                        .map(|a| a.balance)
                        .unwrap_or(U256::ZERO);

                    let br_simulation_start = Instant::now();
                    let mut br_gas_used = 0;
                    let mut br_succeeded = false;
                    let mut br_gas_limit_exceeded = false;
                    let mut coinbase_profit_too_low = false;
                    let committed = match builder
                        .executor_mut()
                        .execute_transaction_with_commit_condition(&*bundle.backrun_tx, |result| {
                            let result = result.result();
                            br_gas_used = result.result.tx_gas_used();
                            br_succeeded = result.result.is_success();
                            br_gas_limit_exceeded = self
                                .max_gas_per_txn
                                .is_some_and(|max_gas_per_txn| br_gas_used > max_gas_per_txn);

                            let simulation_duration = br_simulation_start.elapsed();
                            self.metrics
                                .tx_simulation_duration
                                .record(simulation_duration);
                            self.metrics
                                .tx_byte_size
                                .record(bundle.backrun_tx.inner().size() as f64);
                            self.address_limiter
                                .consume_gas(bundle.backrun_tx.signer(), br_gas_used);
                            self.address_limiter
                                .consume_compute(bundle.backrun_tx.signer(), simulation_duration);

                            if br_succeeded
                                && !br_gas_limit_exceeded
                                && self
                                    .backrun_bundle_args
                                    .enforce_strict_priority_fee_ordering
                            {
                                let stated = bundle.coinbase_profit.unwrap_or_default();
                                let coinbase_balance_after = result
                                    .state
                                    .get(&coinbase)
                                    .map(|a| a.info.balance)
                                    .unwrap_or_default();
                                let actual =
                                    coinbase_balance_after.saturating_sub(coinbase_balance_before);
                                coinbase_profit_too_low = actual < stated;
                            }

                            if !br_succeeded || br_gas_limit_exceeded || coinbase_profit_too_low {
                                CommitChanges::No
                            } else {
                                CommitChanges::Yes
                            }
                        }) {
                        Ok(committed) => committed,
                        Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                            error,
                            ..
                        })) => {
                            log_br_txn(TxnExecutionResult::InternalError(error.to_string()));
                            continue;
                        }
                        Err(_) => {
                            log_br_txn(TxnExecutionResult::EvmError);
                            continue;
                        }
                    };
                    num_txs_simulated += 1;

                    if !br_succeeded {
                        num_txs_simulated_fail += 1;
                        num_bundles_reverted += 1;
                        reverted_gas_used += br_gas_used;
                        self.metrics.reverted_tx_gas_used.record(br_gas_used as f64);
                        log_br_txn(TxnExecutionResult::RevertedAndExcluded);
                        continue;
                    }

                    if br_gas_limit_exceeded {
                        log_br_txn(TxnExecutionResult::MaxGasUsageExceeded);
                        continue;
                    }

                    if coinbase_profit_too_low {
                        log_br_txn(TxnExecutionResult::CoinbaseProfitTooLow);
                        continue;
                    }

                    // Future closure declines must not leak into commit bookkeeping.
                    if committed.is_none() {
                        continue;
                    }

                    num_txs_simulated_success += 1;
                    num_backruns_successful += 1;
                    self.metrics
                        .successful_tx_gas_used
                        .record(br_gas_used as f64);
                    log_br_txn(TxnExecutionResult::Success);

                    info.commit_executed_tx(
                        &bundle.backrun_tx,
                        br_gas_used,
                        br_tx_da_size,
                        Some(backrun_priority_fee),
                        builder
                            .executor()
                            .receipts()
                            .last()
                            .cloned()
                            .ok_or_else(missing_committed_receipt)?,
                    );

                    tx_backruns_landed += 1;
                }
                backrun_processing_time += backrun_start_time.elapsed();
            }
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
            num_backruns_considered as f64,
            num_backruns_successful as f64,
            backrun_processing_time,
        );

        info!(
            target: "payload_builder",
            id = %self.payload_id(),
            txs_executed = num_txs_considered,
            txs_applied = num_txs_simulated_success,
            txs_rejected = num_txs_simulated_fail,
            bundles_reverted = num_bundles_reverted,
            backruns_considered = num_backruns_considered,
            backruns_successful = num_backruns_successful,
            "Completed executing best transactions",
        );
        Ok(None)
    }
}

fn missing_committed_receipt() -> PayloadBuilderError {
    PayloadBuilderError::Other(
        eyre::eyre!("executor recorded no receipt for a committed transaction").into(),
    )
}
