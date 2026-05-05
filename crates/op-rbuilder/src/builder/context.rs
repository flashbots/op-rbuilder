use alloy_consensus::{Transaction, conditional::BlockConditionalAttributes};
use alloy_eips::{Encodable2718, Typed2718};
use alloy_evm::Database;
use alloy_primitives::{B256, BlockHash, Bytes, U256};
use alloy_rpc_types_eth::Withdrawals;
use op_revm::L1BlockInfo;
use reth_basic_payload_builder::PayloadConfig;
use reth_chainspec::EthChainSpec;
use reth_evm::{Evm, EvmError, InvalidTxError, eth::receipt_builder::ReceiptBuilderCtx};
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
use reth_payload_primitives::PayloadBuilderAttributes;
use reth_primitives_traits::{InMemorySize, SealedHeader, SignedTransaction};
use reth_revm::{State, context::Block};
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction};
use revm::{
    Database as _, DatabaseCommit, context::result::ResultAndState, interpreter::as_u64_saturated,
};
use std::{ops::Deref, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

use crate::{
    backrun_bundle::{BackrunBundleArgs, BackrunBundleGlobalPool, BackrunBundlePayloadPool},
    builder::{builder_tx::BuilderTxEnv, receipt::build_receipt},
    evm::OpBlockEvmFactory,
    gas_limiter::AddressGasLimiter,
    hardforks::ActiveHardforks,
    metrics::{OpRBuilderMetrics, record_tx_simulation_duration},
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
#[derive(Debug)]
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
    /// Rate limiting based on gas. This is an optional feature.
    pub address_gas_limiter: AddressGasLimiter,
    /// Global pool of backrun bundles (per-block views are derived in the per-job ctx).
    pub backrun_bundle_pool: BackrunBundleGlobalPool,
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
pub struct OpPayloadJobCtx {
    /// Builder-lifetime configuration shared with all other in-flight jobs.
    pub builder_ctx: Arc<OpPayloadBuilderCtx>,
    /// Factory for creating EVM instances (bundles evm_config + evm_env).
    pub evm_factory: OpBlockEvmFactory,
    /// How to build the payload.
    pub config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    /// Block env attributes for the current block.
    pub block_env_attributes: OpNextBlockEnvAttributes,
    /// Hardfork activation state for this block's timestamp.
    pub hardforks: ActiveHardforks,
    /// Marker to check whether the job has been cancelled.
    pub cancel: CancellationToken,
    /// Per-block view into the global backrun bundle pool.
    pub backrun_pool: BackrunBundlePayloadPool,
}

impl Deref for OpPayloadJobCtx {
    type Target = OpPayloadBuilderCtx;

    fn deref(&self) -> &Self::Target {
        &self.builder_ctx
    }
}

impl OpPayloadJobCtx {
    pub(super) fn with_cancel(self, cancel: CancellationToken) -> Self {
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
        self.hardforks
            .is_shanghai_active()
            .then(|| &self.attributes().payload_attributes.withdrawals)
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

    /// Returns the blob fields for the header.
    ///
    /// This will return the culmative DA bytes * scalar after Jovian
    /// after Ecotone, this will always return Some(0) as blobs aren't supported
    /// pre Ecotone, these fields aren't used.
    pub fn blob_fields(&self, info: &ExecutionInfo) -> (Option<u64>, Option<u64>) {
        // For payload validation
        if let Some(blob_fields) = info.optional_blob_fields {
            return blob_fields;
        }
        // Compute from execution info
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

    /// Returns the extra data for the block.
    ///
    /// After holocene this extracts the extradata from the payload
    pub fn extra_data(&self) -> Result<Bytes, PayloadBuilderError> {
        if self.hardforks.is_jovian_active() {
            self.attributes()
                .get_jovian_extra_data(
                    self.chain_spec.base_fee_params_at_timestamp(
                        self.attributes().payload_attributes.timestamp,
                    ),
                )
                .map_err(PayloadBuilderError::other)
        } else if self.hardforks.is_holocene_active() {
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

    /// Executes all sequencer transactions that are included in the payload attributes.
    pub(super) fn execute_sequencer_transactions(
        &self,
        db: &mut State<impl Database>,
    ) -> Result<ExecutionInfo, PayloadBuilderError> {
        let mut info = ExecutionInfo::with_capacity(self.attributes().transactions.len());

        let mut evm = self.evm_factory.evm(&mut *db);

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
            let depositor_nonce = (self.hardforks.is_regolith_active()
                && sequencer_tx.is_deposit())
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
                        trace!(
                            target: "payload_builder",
                            error = %err,
                            ?sequencer_tx,
                            "Error in sequencer transaction, skipping."
                        );
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
            info.cumulative_uncompressed_bytes += sequencer_tx.encode_2718_len() as u64;

            let receipt_ctx = ReceiptBuilderCtx {
                tx_type: sequencer_tx.tx_type(),
                evm: &evm,
                result,
                state: &state,
                cumulative_gas_used: info.cumulative_gas_used,
            };

            info.receipts.push(build_receipt(
                &self.evm_factory,
                &self.hardforks,
                receipt_ctx,
                depositor_nonce,
            ));

            // commit changes
            evm.db_mut().commit(state);

            // append sender and transaction to the respective lists
            info.executed_senders.push(sequencer_tx.signer());
            info.executed_transactions.push(sequencer_tx.into_inner());
        }

        let da_footprint_gas_scalar = self.hardforks.is_jovian_active().then(|| {
            L1BlockInfo::fetch_da_footprint_gas_scalar(evm.db_mut())
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
        let base_fee = self.base_fee();

        let tx_da_limit = self.da_config.max_da_tx_size();
        let mut evm = self.evm_factory.evm(&mut *db);

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
            number: self.block_number(),
            timestamp: self.attributes().timestamp(),
        };

        while let Some(tx) = best_txs.next(()) {
            let conditional = tx.conditional().cloned();
            let tx_da_size = tx.estimated_da_size();

            let is_bundle_tx = tx.is_bundle();
            let revert_protected = tx.revert_protected();

            let tx = tx.into_consensus();
            let tx_hash = tx.tx_hash();
            let tx_uncompressed_size = tx.encode_2718_len() as u64;

            if self.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    tx_hash = %tx_hash,
                    block_number = self.block_number(),
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
                        revert_protected,
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
                info.da_footprint_scalar,
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
                            trace!(
                                target: "payload_builder",
                                error = %err,
                                ?tx,
                                "skipping nonce too low transaction"
                            );
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            log_txn(TxnExecutionResult::InternalError(err.to_string()));
                            trace!(
                                target: "payload_builder",
                                error = %err,
                                ?tx,
                                "skipping invalid transaction and its descendants"
                            );
                            best_txs.mark_invalid(tx.signer(), tx.nonce());
                        }

                        continue;
                    }
                    // this is an error that we should treat as fatal for this attempt
                    log_txn(TxnExecutionResult::EvmError);
                    return Err(PayloadBuilderError::evm(err));
                }
            };

            let tx_simulation_elapsed = tx_simulation_start_time.elapsed();
            record_tx_simulation_duration(
                tx_simulation_elapsed,
                is_bundle_tx,
                !result.is_success(),
                revert_protected,
            );
            self.metrics.tx_byte_size.record(tx.inner().size() as f64);
            num_txs_simulated += 1;

            // Run the per-address gas limiting before checking if the tx has
            // reverted or not, as this is a check against maliciously searchers
            // sending txs that are expensive to compute but always revert.
            let gas_used = result.gas_used();
            if self.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    tx_hash = %tx_hash,
                    block_number = self.block_number(),
                    flashblock_index,
                    gas_used,
                    success = result.is_success(),
                    evm_duration_us = tx_simulation_elapsed.as_micros() as u64,
                    stage = "evm_executed"
                );
            }

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
                reverted_gas_used += gas_used;
                self.metrics.reverted_tx_gas_used.record(gas_used as f64);
                if is_bundle_tx {
                    num_bundles_reverted += 1;
                }
                if revert_protected {
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
            // record uncompressed tx size
            info.cumulative_uncompressed_bytes += tx_uncompressed_size;

            let tx_succeeded = result.is_success();

            // Push transaction changeset and calculate header bloom filter for receipt.
            let receipt_ctx = ReceiptBuilderCtx {
                tx_type: tx.tx_type(),
                evm: &evm,
                result,
                state: &state,
                cumulative_gas_used: info.cumulative_gas_used,
            };
            info.receipts.push(build_receipt(
                &self.evm_factory,
                &self.hardforks,
                receipt_ctx,
                None,
            ));

            // commit changes
            evm.db_mut().commit(state);

            // update add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            info.total_fees += U256::from(miner_fee) * U256::from(gas_used);

            let target_hash = B256::new(*tx_hash);

            // append sender and transaction to the respective lists
            info.executed_senders.push(tx.signer());
            info.executed_transactions.push(tx.into_inner());

            if self.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    tx_hash = %target_hash,
                    block_number = self.block_number(),
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

            if can_backrun {
                let backrun_start_time = Instant::now();
                let gas_left = block_gas_limit.saturating_sub(info.cumulative_gas_used);
                let backruns = self.backrun_pool.get_backruns(
                    &target_hash,
                    |addr| evm.db_mut().basic(addr).ok().flatten(),
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
                        info.da_footprint_scalar,
                        block_da_footprint_limit,
                        br_tx_uncompressed_size,
                        max_uncompressed_block_size,
                    ) {
                        self.record_limit_rejection_metrics(&result);
                        log_br_txn(result);
                        continue;
                    }

                    if self.cancel.is_cancelled() {
                        return Ok(Some(()));
                    }

                    let coinbase = self.evm_factory.evm_env().block_env.beneficiary;
                    let coinbase_balance_before = evm
                        .db_mut()
                        .basic(coinbase)
                        .ok()
                        .flatten()
                        .map(|a| a.balance)
                        .unwrap_or(U256::ZERO);

                    let br_simulation_start = Instant::now();
                    let ResultAndState {
                        result: br_result,
                        state: br_state,
                    } = match evm.transact(&*bundle.backrun_tx) {
                        Ok(res) => res,
                        Err(err) => {
                            if let Some(err) = err.as_invalid_tx_err() {
                                log_br_txn(TxnExecutionResult::InternalError(err.to_string()));
                            } else {
                                log_br_txn(TxnExecutionResult::EvmError);
                            }
                            continue;
                        }
                    };
                    record_tx_simulation_duration(
                        br_simulation_start.elapsed(),
                        true,
                        !br_result.is_success(),
                        true,
                    );
                    self.metrics
                        .tx_byte_size
                        .record(bundle.backrun_tx.inner().size() as f64);
                    num_txs_simulated += 1;

                    let br_gas_used = br_result.gas_used();

                    if self
                        .address_gas_limiter
                        .consume_gas(bundle.backrun_tx.signer(), br_gas_used)
                        .is_err()
                    {
                        log_br_txn(TxnExecutionResult::MaxGasUsageExceeded);
                        continue;
                    }

                    if !br_result.is_success() {
                        num_txs_simulated_fail += 1;
                        num_bundles_reverted += 1;
                        reverted_gas_used += br_gas_used;
                        self.metrics.reverted_tx_gas_used.record(br_gas_used as f64);
                        log_br_txn(TxnExecutionResult::RevertedAndExcluded);
                        continue;
                    }

                    if let Some(max_gas_per_txn) = self.max_gas_per_txn
                        && br_gas_used > max_gas_per_txn
                    {
                        log_br_txn(TxnExecutionResult::MaxGasUsageExceeded);
                        continue;
                    }

                    if self
                        .backrun_bundle_args
                        .enforce_strict_priority_fee_ordering
                    {
                        let stated = bundle.coinbase_profit.unwrap_or_default();
                        let coinbase_balance_after = br_state
                            .get(&coinbase)
                            .map(|a| a.info.balance)
                            .unwrap_or_default();
                        let actual = coinbase_balance_after.saturating_sub(coinbase_balance_before);
                        if actual < stated {
                            log_br_txn(TxnExecutionResult::CoinbaseProfitTooLow);
                            continue;
                        }
                    }

                    num_txs_simulated_success += 1;
                    num_backruns_successful += 1;
                    self.metrics
                        .successful_tx_gas_used
                        .record(br_gas_used as f64);
                    log_br_txn(TxnExecutionResult::Success);
                    info.cumulative_gas_used += br_gas_used;
                    info.cumulative_da_bytes_used += br_tx_da_size;
                    info.cumulative_uncompressed_bytes += br_tx_uncompressed_size;

                    let receipt_ctx = ReceiptBuilderCtx {
                        tx_type: bundle.backrun_tx.tx_type(),
                        evm: &evm,
                        result: br_result,
                        state: &br_state,
                        cumulative_gas_used: info.cumulative_gas_used,
                    };
                    info.receipts.push(build_receipt(
                        &self.evm_factory,
                        &self.hardforks,
                        receipt_ctx,
                        None,
                    ));
                    evm.db_mut().commit(br_state);

                    info.total_fees += U256::from(backrun_priority_fee) * U256::from(br_gas_used);

                    info.executed_senders.push(bundle.backrun_tx.signer());
                    info.executed_transactions
                        .push(bundle.backrun_tx.inner().clone());

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
