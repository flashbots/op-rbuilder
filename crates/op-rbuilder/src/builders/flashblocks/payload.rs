use super::{config::FlashblocksConfig, wspub::WebSocketPublisher};
use crate::{
    backrun_bundle::BackrunBundlesPayloadCtx,
    builders::{
        BuilderConfig,
        builder_tx::BuilderTransactions,
        context::OpPayloadBuilderCtx,
        flashblocks::{
            best_txs::BestFlashblocksTxs, config::FlashBlocksConfigExt, timing::FlashblockScheduler,
        },
        generator::{BlockCell, BuildArguments, PayloadBuilder},
    },
    gas_limiter::AddressGasLimiter,
    metrics::OpRBuilderMetrics,
    primitives::reth::ExecutionInfo,
    tokio_metrics::FlashblocksTaskMetrics,
    traits::{ClientBounds, PoolBounds},
};
use alloy_consensus::{
    BlockBody, EMPTY_OMMER_ROOT_HASH, Header, TxReceipt, constants::EMPTY_WITHDRAWALS, proofs,
};
use alloy_eips::{Encodable2718, eip7685::EMPTY_REQUESTS_HASH, merge::BEACON_NONCE};
use alloy_evm::block::BlockExecutionResult;
use alloy_primitives::{Address, B256, Bytes, U256};
use eyre::WrapErr as _;
use op_alloy_rpc_types_engine::{
    OpFlashblockPayload, OpFlashblockPayloadBase, OpFlashblockPayloadDelta,
    OpFlashblockPayloadMetadata,
};
use reth::payload::PayloadBuilderAttributes;
use reth_basic_payload_builder::BuildOutcome;
use reth_chainspec::EthChainSpec;
use reth_evm::{ConfigureEvm, execute::BlockBuilder};
use reth_execution_types::BlockExecutionOutput;
use reth_node_api::{Block, BuiltPayloadExecutedBlock, PayloadBuilderError};
use reth_optimism_consensus::{calculate_receipt_root_no_memo_optimism, isthmus};
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilderAttributes};
use reth_optimism_primitives::{OpReceipt, OpTransactionSigned};
use reth_payload_util::BestPayloadTransactions;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::{
    State, database::StateProviderDatabase, db::states::bundle_state::BundleRetention,
};
use reth_transaction_pool::TransactionPool;
use reth_trie::{HashedPostState, updates::TrieUpdates};
use revm::Database;
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, metadata::Level, span, warn};

/// Converts a reth OpReceipt to an op-alloy OpReceipt
/// TODO: remove this once reth updates to use the op-alloy defined type as well.
fn convert_receipt(receipt: &OpReceipt) -> op_alloy_consensus::OpReceipt {
    match receipt {
        OpReceipt::Legacy(r) => op_alloy_consensus::OpReceipt::Legacy(r.clone()),
        OpReceipt::Eip2930(r) => op_alloy_consensus::OpReceipt::Eip2930(r.clone()),
        OpReceipt::Eip1559(r) => op_alloy_consensus::OpReceipt::Eip1559(r.clone()),
        OpReceipt::Eip7702(r) => op_alloy_consensus::OpReceipt::Eip7702(r.clone()),
        OpReceipt::Deposit(r) => {
            op_alloy_consensus::OpReceipt::Deposit(op_alloy_consensus::OpDepositReceipt {
                inner: r.inner.clone(),
                deposit_nonce: r.deposit_nonce,
                deposit_receipt_version: r.deposit_receipt_version,
            })
        }
    }
}

type NextBestFlashblocksTxs<Pool> = BestFlashblocksTxs<
    <Pool as TransactionPool>::Transaction,
    Box<
        dyn reth_transaction_pool::BestTransactions<
                Item = Arc<
                    reth_transaction_pool::ValidPoolTransaction<
                        <Pool as TransactionPool>::Transaction,
                    >,
                >,
            >,
    >,
>;

#[derive(Debug, Default, Clone)]
pub(super) struct FlashblocksState {
    /// Current flashblock index
    flashblock_index: u64,
    /// Target flashblock count per block
    target_flashblock_count: u64,
    /// Total gas left for the current flashblock
    target_gas_for_batch: u64,
    /// Total DA bytes left for the current flashblock
    target_da_for_batch: Option<u64>,
    /// Total DA footprint left for the current flashblock
    target_da_footprint_for_batch: Option<u64>,
    /// Gas limit per flashblock
    gas_per_batch: u64,
    /// DA bytes limit per flashblock
    da_per_batch: Option<u64>,
    /// DA footprint limit per flashblock
    da_footprint_per_batch: Option<u64>,
    /// Whether to disable state root calculation for each flashblock
    disable_state_root: bool,
    /// Index into ExecutionInfo tracking the last consumed flashblock
    /// Used for slicing transactions/receipts per flashblock
    last_flashblock_tx_index: usize,
}

impl FlashblocksState {
    fn new(target_flashblock_count: u64, disable_state_root: bool) -> Self {
        Self {
            target_flashblock_count,
            disable_state_root,
            ..Default::default()
        }
    }

    /// Creates state for the next flashblock with updated limits
    fn next(
        &self,
        target_gas_for_batch: u64,
        target_da_for_batch: Option<u64>,
        target_da_footprint_for_batch: Option<u64>,
    ) -> Self {
        Self {
            flashblock_index: self.flashblock_index + 1,
            target_gas_for_batch,
            target_da_for_batch,
            target_da_footprint_for_batch,
            target_flashblock_count: self.target_flashblock_count,
            gas_per_batch: self.gas_per_batch,
            da_per_batch: self.da_per_batch,
            da_footprint_per_batch: self.da_footprint_per_batch,
            disable_state_root: self.disable_state_root,
            last_flashblock_tx_index: self.last_flashblock_tx_index,
        }
    }

    fn with_batch_limits(
        mut self,
        gas_per_batch: u64,
        da_per_batch: Option<u64>,
        da_footprint_per_batch: Option<u64>,
        target_gas_for_batch: u64,
        target_da_for_batch: Option<u64>,
        target_da_footprint_for_batch: Option<u64>,
    ) -> Self {
        self.gas_per_batch = gas_per_batch;
        self.da_per_batch = da_per_batch;
        self.da_footprint_per_batch = da_footprint_per_batch;
        self.target_gas_for_batch = target_gas_for_batch;
        self.target_da_for_batch = target_da_for_batch;
        self.target_da_footprint_for_batch = target_da_footprint_for_batch;
        self
    }

    fn flashblock_index(&self) -> u64 {
        self.flashblock_index
    }

    fn target_flashblock_count(&self) -> u64 {
        self.target_flashblock_count
    }

    fn is_first_flashblock(&self) -> bool {
        self.flashblock_index == 0
    }

    fn is_last_flashblock(&self) -> bool {
        self.flashblock_index == self.target_flashblock_count
    }

    fn target_gas_for_batch(&self) -> u64 {
        self.target_gas_for_batch
    }

    fn target_da_for_batch(&self) -> Option<u64> {
        self.target_da_for_batch
    }

    fn target_da_footprint_for_batch(&self) -> Option<u64> {
        self.target_da_footprint_for_batch
    }

    fn gas_per_batch(&self) -> u64 {
        self.gas_per_batch
    }

    fn da_per_batch(&self) -> Option<u64> {
        self.da_per_batch
    }

    fn da_footprint_per_batch(&self) -> Option<u64> {
        self.da_footprint_per_batch
    }

    fn disable_state_root(&self) -> bool {
        self.disable_state_root
    }

    fn set_last_flashblock_tx_index(&mut self, index: usize) {
        self.last_flashblock_tx_index = index;
    }

    /// Extracts new transactions since the last flashblock
    fn slice_new_transactions<'a>(
        &self,
        all_transactions: &'a [OpTransactionSigned],
    ) -> &'a [OpTransactionSigned] {
        &all_transactions[self.last_flashblock_tx_index..]
    }

    /// Extracts new receipts since the last flashblock
    fn slice_new_receipts<'a>(&self, all_receipts: &'a [OpReceipt]) -> &'a [OpReceipt] {
        &all_receipts[self.last_flashblock_tx_index..]
    }
}

// Flashblocks-specific helper methods moved to FlashblocksState

/// Optimism's payload builder
#[derive(Debug, Clone)]
pub(super) struct OpPayloadBuilder<Pool, Client, BuilderTx> {
    /// The type responsible for creating the evm.
    pub evm_config: OpEvmConfig,
    /// The transaction pool
    pub pool: Pool,
    /// Node client
    pub client: Client,
    /// Sender for sending built flashblock payloads to [`PayloadHandler`],
    /// which broadcasts outgoing flashblock payloads via p2p.
    pub built_fb_payload_tx: mpsc::Sender<OpBuiltPayload>,
    /// Sender for sending built full block payloads to [`PayloadHandler`],
    /// which updates the engine tree state.
    pub built_payload_tx: mpsc::Sender<OpBuiltPayload>,
    /// WebSocket publisher for broadcasting flashblocks
    /// to all connected subscribers.
    pub ws_pub: Arc<WebSocketPublisher>,
    /// System configuration for the builder
    pub config: BuilderConfig<FlashblocksConfig>,
    /// The metrics for the builder
    pub metrics: Arc<OpRBuilderMetrics>,
    /// The end of builder transaction type
    pub builder_tx: BuilderTx,
    /// Rate limiting based on gas. This is an optional feature.
    pub address_gas_limiter: AddressGasLimiter,
    /// Tokio task metrics for monitoring spawned tasks
    pub task_metrics: Arc<FlashblocksTaskMetrics>,
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx> {
    /// `OpPayloadBuilder` constructor.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        evm_config: OpEvmConfig,
        pool: Pool,
        client: Client,
        config: BuilderConfig<FlashblocksConfig>,
        builder_tx: BuilderTx,
        built_fb_payload_tx: mpsc::Sender<OpBuiltPayload>,
        built_payload_tx: mpsc::Sender<OpBuiltPayload>,
        ws_pub: Arc<WebSocketPublisher>,
        metrics: Arc<OpRBuilderMetrics>,
        task_metrics: Arc<FlashblocksTaskMetrics>,
    ) -> Self {
        let address_gas_limiter = AddressGasLimiter::new(config.gas_limiter_config.clone());
        Self {
            evm_config,
            pool,
            client,
            built_fb_payload_tx,
            built_payload_tx,
            ws_pub,
            config,
            metrics,
            builder_tx,
            address_gas_limiter,
            task_metrics,
        }
    }
}

impl<Pool, Client, BuilderTx> reth_basic_payload_builder::PayloadBuilder
    for OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: Clone + Send + Sync,
    Client: Clone + Send + Sync,
    BuilderTx: Clone + Send + Sync,
{
    type Attributes = OpPayloadBuilderAttributes<OpTransactionSigned>;
    type BuiltPayload = OpBuiltPayload;

    fn try_build(
        &self,
        _args: reth_basic_payload_builder::BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        unimplemented!()
    }

    fn build_empty_payload(
        &self,
        _config: reth_basic_payload_builder::PayloadConfig<
            Self::Attributes,
            reth_basic_payload_builder::HeaderForPayload<Self::BuiltPayload>,
        >,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        unimplemented!()
    }
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds,
    Client: ClientBounds,
    BuilderTx: BuilderTransactions + Send + Sync,
{
    fn get_op_payload_builder_ctx(
        &self,
        config: reth_basic_payload_builder::PayloadConfig<
            OpPayloadBuilderAttributes<op_alloy_consensus::OpTxEnvelope>,
        >,
        cancel: CancellationToken,
    ) -> eyre::Result<OpPayloadBuilderCtx> {
        let chain_spec = self.client.chain_spec();
        let timestamp = config.attributes.timestamp();

        let extra_data = if chain_spec.is_jovian_active_at_timestamp(timestamp) {
            config
                .attributes
                .get_jovian_extra_data(chain_spec.base_fee_params_at_timestamp(timestamp))
                .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
        } else if chain_spec.is_holocene_active_at_timestamp(timestamp) {
            config
                .attributes
                .get_holocene_extra_data(chain_spec.base_fee_params_at_timestamp(timestamp))
                .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
        } else {
            Default::default()
        };

        let block_env_attributes = OpNextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
            prev_randao: config.attributes.prev_randao(),
            gas_limit: config
                .attributes
                .gas_limit
                .unwrap_or(config.parent_header.gas_limit),
            parent_beacon_block_root: config
                .attributes
                .payload_attributes
                .parent_beacon_block_root,
            extra_data,
        };

        let evm_config = self.evm_config.clone();

        let evm_env = evm_config
            .next_evm_env(&config.parent_header, &block_env_attributes)
            .wrap_err("failed to create next evm env")?;

        let backrun_ctx = BackrunBundlesPayloadCtx {
            pool: self
                .config
                .backrun_bundle_pool
                .block_pool(config.parent_header.number + 1),
            args: self.config.backrun_bundle_args.clone(),
        };

        Ok(OpPayloadBuilderCtx {
            evm_config: self.evm_config.clone(),
            chain_spec,
            config,
            evm_env,
            block_env_attributes,
            cancel,
            da_config: self.config.da_config.clone(),
            gas_limit_config: self.config.gas_limit_config.clone(),
            builder_signer: self.config.builder_signer,
            metrics: self.metrics.clone(),
            max_gas_per_txn: self.config.max_gas_per_txn,
            address_gas_limiter: self.address_gas_limiter.clone(),
            backrun_ctx,
        })
    }

    /// Constructs an Optimism payload from the transactions sent via the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Optimism client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    fn build_payload(
        &self,
        args: BuildArguments<OpPayloadBuilderAttributes<OpTransactionSigned>, OpBuiltPayload>,
        best_payload: BlockCell<OpBuiltPayload>,
    ) -> Result<(), PayloadBuilderError> {
        let block_build_start_time = Instant::now();
        let BuildArguments {
            mut cached_reads,
            config,
            cancel: block_cancel,
        } = args;

        // We log only every 100th block to reduce usage
        let span = if cfg!(feature = "telemetry")
            && config
                .parent_header
                .number
                .is_multiple_of(self.config.sampling_ratio)
        {
            span!(Level::INFO, "build_payload")
        } else {
            tracing::Span::none()
        };
        let _entered = span.enter();
        span.record(
            "payload_id",
            config.attributes.payload_attributes.id.to_string(),
        );

        let disable_state_root = self.config.specific.disable_state_root;
        let ctx = self
            .get_op_payload_builder_ctx(config.clone(), block_cancel.clone())
            .map_err(|e| PayloadBuilderError::Other(e.into()))?;

        // Initialize flashblocks state for this block
        let mut fb_state =
            FlashblocksState::new(self.config.flashblocks_per_block(), disable_state_root);

        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;
        let db = StateProviderDatabase::new(&state_provider);
        self.address_gas_limiter.refresh(ctx.block_number());

        // 1. execute the pre steps and seal an early block with that
        let sequencer_tx_start_time = Instant::now();
        let mut state = State::builder()
            .with_database(cached_reads.as_db_mut(db))
            .with_bundle_update()
            .build();

        let mut info = execute_pre_steps(&mut state, &ctx)?;
        let sequencer_tx_time = sequencer_tx_start_time.elapsed();
        ctx.metrics.sequencer_tx_duration.record(sequencer_tx_time);
        ctx.metrics.sequencer_tx_gauge.set(sequencer_tx_time);

        // We add first builder tx right after deposits
        if !ctx.attributes().no_tx_pool
            && let Err(e) = self.builder_tx.add_builder_txs(
                &state_provider,
                &mut info,
                &ctx,
                &mut state,
                false,
                fb_state.is_first_flashblock(),
                fb_state.is_last_flashblock(),
            )
        {
            error!(
                target: "payload_builder",
                "Error adding builder txs to fallback block: {}",
                e
            );
        };

        let (payload, fb_payload) = build_block(
            &mut state,
            &ctx,
            Some(&mut fb_state),
            &mut info,
            !disable_state_root || ctx.attributes().no_tx_pool, // need to calculate state root for CL sync
        )?;

        self.built_fb_payload_tx
            .try_send(payload.clone())
            .map_err(PayloadBuilderError::other)?;
        if let Err(e) = self.built_payload_tx.try_send(payload.clone()) {
            warn!(
                target: "payload_builder",
                error = %e,
                "Failed to send updated payload"
            );
        }
        best_payload.set(payload);

        info!(
            target: "payload_builder",
            id = %fb_payload.payload_id,
            "Fallback block built"
        );

        // not emitting flashblock if no_tx_pool in FCU, it's just syncing
        if !ctx.attributes().no_tx_pool {
            let flashblock_byte_size = self
                .ws_pub
                .publish(&fb_payload)
                .map_err(PayloadBuilderError::other)?;
            ctx.metrics
                .flashblock_byte_size_histogram
                .record(flashblock_byte_size as f64);
        }

        if ctx.attributes().no_tx_pool {
            info!(
                target: "payload_builder",
                "No transaction pool, skipping transaction pool processing",
            );

            let total_block_building_time = block_build_start_time.elapsed();
            ctx.metrics
                .total_block_built_duration
                .record(total_block_building_time);
            ctx.metrics
                .total_block_built_gauge
                .set(total_block_building_time);
            ctx.metrics
                .payload_num_tx
                .record(info.executed_transactions.len() as f64);
            ctx.metrics
                .payload_num_tx_gauge
                .set(info.executed_transactions.len() as f64);

            // return early since we don't need to build a block with transactions from the pool
            return Ok(());
        }

        // We adjust our flashblocks timings based on time the fcu block building signal arrived
        let timestamp = config.attributes.timestamp();
        let flashblock_scheduler =
            FlashblockScheduler::new(&self.config.specific, self.config.block_time, timestamp);
        info!(
            target: "payload_builder",
            id = %fb_payload.payload_id,
            schedule = ?flashblock_scheduler,
            "Computed flashblock timing schedule"
        );
        let target_flashblocks = flashblock_scheduler.target_flashblocks();

        let expected_flashblocks = self.config.flashblocks_per_block();
        if target_flashblocks < expected_flashblocks {
            warn!(
                target: "payload_builder",
                expected_flashblocks,
                target_flashblocks,
                "FCU arrived late, building fewer flashblocks"
            );
            ctx.metrics
                .reduced_flashblocks_number
                .record((expected_flashblocks - target_flashblocks) as f64);
        }

        let gas_per_batch = ctx.block_gas_limit() / target_flashblocks;
        let da_per_batch = ctx
            .da_config
            .max_da_block_size()
            .map(|da_limit| da_limit / target_flashblocks);
        // Check that builder tx won't affect fb limit too much
        if let Some(da_limit) = da_per_batch {
            // We error if we can't insert any tx aside from builder tx in flashblock
            if info.cumulative_da_bytes_used >= da_limit {
                error!(
                    "Builder tx da size subtraction caused max_da_block_size to be 0. No transaction would be included."
                );
            }
        }
        let da_footprint_per_batch = info
            .da_footprint_scalar
            .map(|_| ctx.block_gas_limit() / target_flashblocks);

        fb_state = fb_state.with_batch_limits(
            gas_per_batch,
            da_per_batch,
            da_footprint_per_batch,
            gas_per_batch,
            da_per_batch,
            da_footprint_per_batch,
        );
        fb_state = FlashblocksState {
            flashblock_index: 1,
            target_flashblock_count: target_flashblocks,
            ..fb_state
        };

        let fb_cancel = block_cancel.child_token();
        let mut ctx = self
            .get_op_payload_builder_ctx(config, fb_cancel.clone())
            .map_err(|e| PayloadBuilderError::Other(e.into()))?;

        // Create best_transaction iterator
        let mut best_txs = BestFlashblocksTxs::new(BestPayloadTransactions::new(
            self.pool
                .best_transactions_with_attributes(ctx.best_transaction_attributes()),
        ));

        let (tx, rx) = std::sync::mpsc::sync_channel((expected_flashblocks + 1) as usize);
        tokio::spawn(
            self.task_metrics
                .flashblock_timer
                .instrument(flashblock_scheduler.run(
                    tx,
                    block_cancel.clone(),
                    fb_cancel,
                    fb_payload.payload_id,
                )),
        );

        // Process flashblocks - block on async channel receive
        loop {
            // Wait for signal before building flashblock.
            if let Ok(new_fb_cancel) = rx.recv() {
                debug!(
                    target: "payload_builder",
                    id = %fb_payload.payload_id,
                    flashblock_index = fb_state.flashblock_index(),
                    block_number = ctx.block_number(),
                    "Received signal to build flashblock",
                );
                ctx = ctx.with_cancel(new_fb_cancel);
            } else {
                // Channel closed - block building cancelled
                self.record_flashblocks_metrics(&ctx, &fb_state, &info, target_flashblocks, &span);
                return Ok(());
            }

            let fb_span = if span.is_none() {
                tracing::Span::none()
            } else {
                span!(
                    parent: &span,
                    Level::INFO,
                    "build_flashblock",
                )
            };
            let _entered = fb_span.enter();

            // Build flashblock after receiving signal
            let next_flashblock_state = match self.build_next_flashblock(
                &ctx,
                &mut fb_state,
                &mut info,
                &mut state,
                &state_provider,
                &mut best_txs,
                &block_cancel,
                &best_payload,
            ) {
                Ok(Some(next_flashblock_state)) => next_flashblock_state,
                Ok(None) => {
                    self.record_flashblocks_metrics(
                        &ctx,
                        &fb_state,
                        &info,
                        target_flashblocks,
                        &span,
                    );
                    return Ok(());
                }
                Err(err) => {
                    error!(
                        target: "payload_builder",
                        id = %fb_payload.payload_id,
                        flashblock_index = fb_state.flashblock_index(),
                        block_number = ctx.block_number(),
                        ?err,
                        "Failed to build flashblock",
                    );
                    return Err(PayloadBuilderError::Other(err.into()));
                }
            };

            fb_state = next_flashblock_state;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_next_flashblock<
        DB: Database<Error = ProviderError> + std::fmt::Debug + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    >(
        &self,
        ctx: &OpPayloadBuilderCtx,
        fb_state: &mut FlashblocksState,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        state_provider: impl reth::providers::StateProvider + Clone,
        best_txs: &mut NextBestFlashblocksTxs<Pool>,
        block_cancel: &CancellationToken,
        best_payload: &BlockCell<OpBuiltPayload>,
    ) -> eyre::Result<Option<FlashblocksState>> {
        let flashblock_index = fb_state.flashblock_index();
        let mut target_gas_for_batch = fb_state.target_gas_for_batch();
        let mut target_da_for_batch = fb_state.target_da_for_batch();
        let mut target_da_footprint_for_batch = fb_state.target_da_footprint_for_batch();

        info!(
            target: "payload_builder",
            block_number = ctx.block_number(),
            flashblock_index,
            target_gas = target_gas_for_batch,
            gas_used = info.cumulative_gas_used,
            target_da = target_da_for_batch,
            da_used = info.cumulative_da_bytes_used,
            block_gas_used = ctx.block_gas_limit(),
            target_da_footprint = target_da_footprint_for_batch,
            "Building flashblock",
        );
        let flashblock_build_start_time = Instant::now();

        let builder_txs = self
            .builder_tx
            .add_builder_txs(
                &state_provider,
                info,
                ctx,
                state,
                true,
                fb_state.is_first_flashblock(),
                fb_state.is_last_flashblock(),
            )
            .inspect_err(
                |e| error!(target: "payload_builder", "Error simulating builder txs: {}", e),
            )
            .unwrap_or_default();

        // only reserve builder tx gas / da size that has not been committed yet
        // committed builder txs would have counted towards the gas / da used
        let builder_tx_gas = builder_txs
            .iter()
            .filter(|tx| !tx.is_top_of_block)
            .fold(0, |acc, tx| acc + tx.gas_used);
        let builder_tx_da_size: u64 = builder_txs
            .iter()
            .filter(|tx| !tx.is_top_of_block)
            .fold(0, |acc, tx| acc + tx.da_size);
        target_gas_for_batch = target_gas_for_batch.saturating_sub(builder_tx_gas);

        // saturating sub just in case, we will log an error if da_limit too small for builder_tx_da_size
        if let Some(da_limit) = target_da_for_batch.as_mut() {
            *da_limit = da_limit.saturating_sub(builder_tx_da_size);
        }

        if let (Some(footprint), Some(scalar)) = (
            target_da_footprint_for_batch.as_mut(),
            info.da_footprint_scalar,
        ) {
            *footprint = footprint.saturating_sub(builder_tx_da_size.saturating_mul(scalar as u64));
        }

        let best_txs_start_time = Instant::now();
        best_txs.refresh_iterator(
            BestPayloadTransactions::new(
                self.pool
                    .best_transactions_with_attributes(ctx.best_transaction_attributes()),
            ),
            flashblock_index,
        );
        let transaction_pool_fetch_time = best_txs_start_time.elapsed();
        ctx.metrics
            .transaction_pool_fetch_duration
            .record(transaction_pool_fetch_time);
        ctx.metrics
            .transaction_pool_fetch_gauge
            .set(transaction_pool_fetch_time);

        let tx_execution_start_time = Instant::now();
        ctx.execute_best_transactions(
            info,
            state,
            best_txs,
            target_gas_for_batch.min(ctx.block_gas_limit()),
            target_da_for_batch,
            target_da_footprint_for_batch,
            Some(fb_state.flashblock_index),
        )
        .wrap_err("failed to execute best transactions")?;
        // Extract last transactions
        let new_transactions: Vec<_> = fb_state
            .slice_new_transactions(&info.executed_transactions)
            .iter()
            .map(|tx| tx.tx_hash())
            .collect();
        best_txs.mark_commited(new_transactions);

        // We got block cancelled, we won't need anything from the block at this point
        // Caution: this assume that block cancel token only cancelled when new FCU is received
        if block_cancel.is_cancelled() {
            return Ok(None);
        }

        let payload_transaction_simulation_time = tx_execution_start_time.elapsed();
        ctx.metrics
            .payload_transaction_simulation_duration
            .record(payload_transaction_simulation_time);
        ctx.metrics
            .payload_transaction_simulation_gauge
            .set(payload_transaction_simulation_time);

        if let Err(e) = self.builder_tx.add_builder_txs(
            &state_provider,
            info,
            ctx,
            state,
            false,
            fb_state.is_first_flashblock(),
            fb_state.is_last_flashblock(),
        ) {
            error!(target: "payload_builder", "Error simulating builder txs: {}", e);
        }

        let total_block_built_duration = Instant::now();
        let disable_state_root = fb_state.disable_state_root();
        let build_result = build_block(
            state,
            ctx,
            Some(fb_state),
            info,
            !disable_state_root || ctx.attributes().no_tx_pool,
        );
        let total_block_built_duration = total_block_built_duration.elapsed();
        ctx.metrics
            .total_block_built_duration
            .record(total_block_built_duration);
        ctx.metrics
            .total_block_built_gauge
            .set(total_block_built_duration);

        match build_result {
            Err(err) => {
                ctx.metrics.invalid_built_blocks_count.increment(1);
                Err(err).wrap_err("failed to build payload")
            }
            Ok((new_payload, mut fb_payload)) => {
                fb_payload.index = flashblock_index;
                fb_payload.base = None;

                // If main token got canceled in here that means we received get_payload and we should drop everything and now update best_payload
                // To ensure that we will return same blocks as rollup-boost (to leverage caches)
                if block_cancel.is_cancelled() {
                    return Ok(None);
                }
                let flashblock_byte_size = self
                    .ws_pub
                    .publish(&fb_payload)
                    .wrap_err("failed to publish flashblock via websocket")?;
                self.built_fb_payload_tx
                    .try_send(new_payload.clone())
                    .wrap_err("failed to send built payload to handler")?;
                if let Err(e) = self.built_payload_tx.try_send(new_payload.clone()) {
                    warn!(
                        target: "payload_builder",
                        error = %e,
                        "Failed to send updated payload"
                    );
                }
                best_payload.set(new_payload);

                // Record flashblock build duration
                ctx.metrics
                    .flashblock_build_duration
                    .record(flashblock_build_start_time.elapsed());
                ctx.metrics
                    .flashblock_byte_size_histogram
                    .record(flashblock_byte_size as f64);
                ctx.metrics
                    .flashblock_num_tx_histogram
                    .record(info.executed_transactions.len() as f64);

                // Update bundle_state for next iteration
                if let Some(da_limit) = fb_state.da_per_batch() {
                    if let Some(da) = target_da_for_batch.as_mut() {
                        *da += da_limit;
                    } else {
                        error!(
                            "Builder end up in faulty invariant, if da_per_batch is set then total_da_per_batch must be set"
                        );
                    }
                }

                let target_gas_for_batch =
                    fb_state.target_gas_for_batch() + fb_state.gas_per_batch();

                if let (Some(footprint), Some(da_footprint_limit)) = (
                    target_da_footprint_for_batch.as_mut(),
                    fb_state.da_footprint_per_batch(),
                ) {
                    *footprint += da_footprint_limit;
                }

                let next_flashblock_state = fb_state.next(
                    target_gas_for_batch,
                    target_da_for_batch,
                    target_da_footprint_for_batch,
                );

                info!(
                    target: "payload_builder",
                    event = "flashblock_built",
                    id = %ctx.payload_id(),
                    flashblock_index = flashblock_index,
                    current_gas = info.cumulative_gas_used,
                    current_da = info.cumulative_da_bytes_used,
                    target_flashblocks = fb_state.target_flashblock_count(),
                    "Flashblock built"
                );

                Ok(Some(next_flashblock_state))
            }
        }
    }

    /// Do some logging and metric recording when we stop build flashblocks
    fn record_flashblocks_metrics(
        &self,
        ctx: &OpPayloadBuilderCtx,
        fb_state: &FlashblocksState,
        info: &ExecutionInfo,
        flashblocks_per_block: u64,
        span: &tracing::Span,
    ) {
        ctx.metrics.block_built_success.increment(1);
        ctx.metrics
            .flashblock_count
            .record(fb_state.flashblock_index() as f64);
        ctx.metrics
            .missing_flashblocks_count
            .record(flashblocks_per_block.saturating_sub(fb_state.flashblock_index()) as f64);
        ctx.metrics
            .payload_num_tx
            .record(info.executed_transactions.len() as f64);
        ctx.metrics
            .payload_num_tx_gauge
            .set(info.executed_transactions.len() as f64);

        info!(
            target: "payload_builder",
            event = "build_complete",
            id = %ctx.payload_id(),
            flashblocks_per_block = flashblocks_per_block,
            flashblock_index = fb_state.flashblock_index(),
            "Flashblocks building complete"
        );

        span.record("flashblock_count", fb_state.flashblock_index());
    }
}

#[async_trait::async_trait]
impl<Pool, Client, BuilderTx> PayloadBuilder for OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds,
    Client: ClientBounds,
    BuilderTx: BuilderTransactions + Clone + Send + Sync,
{
    type Attributes = OpPayloadBuilderAttributes<OpTransactionSigned>;
    type BuiltPayload = OpBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
        best_payload: BlockCell<Self::BuiltPayload>,
    ) -> Result<(), PayloadBuilderError> {
        self.build_payload(args, best_payload)
    }
}

fn execute_pre_steps<DB>(
    state: &mut State<DB>,
    ctx: &OpPayloadBuilderCtx,
) -> Result<ExecutionInfo, PayloadBuilderError>
where
    DB: Database<Error = ProviderError> + std::fmt::Debug,
{
    // 1. apply pre-execution changes
    ctx.evm_config
        .builder_for_next_block(state, ctx.parent(), ctx.block_env_attributes.clone())
        .map_err(PayloadBuilderError::other)?
        .apply_pre_execution_changes()?;

    // 2. execute sequencer transactions
    let info = ctx.execute_sequencer_transactions(state)?;

    Ok(info)
}

pub(super) fn build_block<DB, P>(
    state: &mut State<DB>,
    ctx: &OpPayloadBuilderCtx,
    fb_state: Option<&mut FlashblocksState>,
    info: &mut ExecutionInfo,
    calculate_state_root: bool,
) -> Result<(OpBuiltPayload, OpFlashblockPayload), PayloadBuilderError>
where
    DB: Database<Error = ProviderError> + AsRef<P>,
    P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
{
    // We use it to preserve state, so we run merge_transitions on transition state at most once
    let untouched_transition_state = state.transition_state.clone();
    let state_merge_start_time = Instant::now();
    state.merge_transitions(BundleRetention::Reverts);
    let state_transition_merge_time = state_merge_start_time.elapsed();
    ctx.metrics
        .state_transition_merge_duration
        .record(state_transition_merge_time);
    ctx.metrics
        .state_transition_merge_gauge
        .set(state_transition_merge_time);

    let block_number = ctx.block_number();
    let expected = ctx.parent().number + 1;
    if block_number != expected {
        return Err(PayloadBuilderError::Other(
            eyre::eyre!(
                "build context block number mismatch: expected {}, got {}",
                expected,
                block_number
            )
            .into(),
        ));
    }

    let receipts_root = calculate_receipt_root_no_memo_optimism(
        &info.receipts,
        &ctx.chain_spec,
        ctx.attributes().timestamp(),
    );
    let logs_bloom = alloy_primitives::logs_bloom(info.receipts.iter().flat_map(|r| r.logs()));

    // TODO: maybe recreate state with bundle in here
    // calculate the state root
    let state_root_start_time = Instant::now();
    let mut state_root = B256::ZERO;
    let mut trie_output = TrieUpdates::default();
    let mut hashed_state = HashedPostState::default();

    if calculate_state_root {
        let state_provider = state.database.as_ref();
        hashed_state = state_provider.hashed_post_state(&state.bundle_state);
        (state_root, trie_output) = {
            state
                .database
                .as_ref()
                .state_root_with_updates(hashed_state.clone())
                .inspect_err(|err| {
                    warn!(target: "payload_builder",
                    parent_header=%ctx.parent().hash(),
                        %err,
                        "failed to calculate state root for payload"
                    );
                })?
        };
        let state_root_calculation_time = state_root_start_time.elapsed();
        ctx.metrics
            .state_root_calculation_duration
            .record(state_root_calculation_time);
        ctx.metrics
            .state_root_calculation_gauge
            .set(state_root_calculation_time);
    }

    let mut requests_hash = None;
    let withdrawals_root = if ctx
        .chain_spec
        .is_isthmus_active_at_timestamp(ctx.attributes().timestamp())
    {
        // always empty requests hash post isthmus
        requests_hash = Some(EMPTY_REQUESTS_HASH);

        // withdrawals root field in block header is used for storage root of L2 predeploy
        // `l2tol1-message-passer`
        Some(
            isthmus::withdrawals_root(&state.bundle_state, state.database.as_ref())
                .map_err(PayloadBuilderError::other)?,
        )
    } else if ctx
        .chain_spec
        .is_canyon_active_at_timestamp(ctx.attributes().timestamp())
    {
        Some(EMPTY_WITHDRAWALS)
    } else {
        None
    };

    // create the block header
    let transactions_root = proofs::calculate_transaction_root(&info.executed_transactions);

    let (excess_blob_gas, blob_gas_used) = ctx.blob_fields(info);
    let extra_data = ctx.extra_data()?;

    // need to read balances before take_bundle() below
    let new_account_balances = state
        .bundle_state
        .state
        .iter()
        .filter_map(|(address, account)| account.info.as_ref().map(|info| (*address, info.balance)))
        .collect::<BTreeMap<Address, U256>>();

    let bundle_state = state.take_bundle();
    let execution_output = BlockExecutionOutput {
        state: bundle_state,
        result: BlockExecutionResult {
            receipts: info.receipts.clone(),
            requests: Default::default(),
            gas_used: info.cumulative_gas_used,
            blob_gas_used: blob_gas_used.unwrap_or_default(),
        },
    };

    let header = Header {
        parent_hash: ctx.parent().hash(),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: ctx.evm_env.block_env.beneficiary,
        state_root,
        transactions_root,
        receipts_root,
        withdrawals_root,
        logs_bloom,
        timestamp: ctx.attributes().payload_attributes.timestamp,
        mix_hash: ctx.attributes().payload_attributes.prev_randao,
        nonce: BEACON_NONCE.into(),
        base_fee_per_gas: Some(ctx.base_fee()),
        number: ctx.parent().number + 1,
        gas_limit: ctx.block_gas_limit(),
        difficulty: U256::ZERO,
        gas_used: info.cumulative_gas_used,
        extra_data,
        parent_beacon_block_root: ctx.attributes().payload_attributes.parent_beacon_block_root,
        blob_gas_used,
        excess_blob_gas,
        requests_hash,
    };

    // seal the block
    let block = alloy_consensus::Block::<OpTransactionSigned>::new(
        header,
        BlockBody {
            transactions: info.executed_transactions.clone(),
            ommers: vec![],
            withdrawals: ctx.withdrawals().cloned(),
        },
    );

    let recovered_block =
        RecoveredBlock::new_unhashed(block.clone(), info.executed_senders.clone());
    // create the executed block data

    let executed = BuiltPayloadExecutedBlock {
        recovered_block: Arc::new(recovered_block),
        execution_output: Arc::new(execution_output),
        trie_updates: either::Either::Left(Arc::new(trie_output)),
        hashed_state: either::Either::Left(Arc::new(hashed_state)),
    };
    debug!(
        target: "payload_builder",
        id = %ctx.payload_id(),
        "Executed block created"
    );

    let sealed_block = Arc::new(block.seal_slow());
    debug!(
        target: "payload_builder",
        id = %ctx.payload_id(),
        ?sealed_block,
        "Sealed built block"
    );

    let block_hash = sealed_block.hash();

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

    let receipts_with_hash: BTreeMap<B256, op_alloy_consensus::OpReceipt> = new_transactions
        .iter()
        .zip(new_receipts.iter())
        .map(|(tx, receipt)| (tx.tx_hash(), convert_receipt(receipt)))
        .collect();

    let metadata = OpFlashblockPayloadMetadata {
        receipts: receipts_with_hash,
        new_account_balances,
        block_number: ctx.parent().number + 1,
    };

    let (_, blob_gas_used) = ctx.blob_fields(info);

    // Prepare the flashblocks message
    let fb_payload = OpFlashblockPayload {
        payload_id: ctx.payload_id(),
        index: 0,
        base: Some(OpFlashblockPayloadBase {
            parent_beacon_block_root: ctx
                .attributes()
                .payload_attributes
                .parent_beacon_block_root
                .ok_or_else(|| {
                    PayloadBuilderError::Other(
                        eyre::eyre!("parent beacon block root not found").into(),
                    )
                })?,
            parent_hash: ctx.parent().hash(),
            fee_recipient: ctx.attributes().suggested_fee_recipient(),
            prev_randao: ctx.attributes().payload_attributes.prev_randao,
            block_number: ctx.parent().number + 1,
            gas_limit: ctx.block_gas_limit(),
            timestamp: ctx.attributes().payload_attributes.timestamp,
            extra_data: ctx.extra_data()?,
            base_fee_per_gas: U256::from(ctx.base_fee()),
        }),
        diff: OpFlashblockPayloadDelta {
            state_root,
            receipts_root,
            logs_bloom,
            gas_used: info.cumulative_gas_used,
            block_hash,
            transactions: new_transactions_encoded,
            withdrawals: ctx.withdrawals().cloned().unwrap_or_default().to_vec(),
            withdrawals_root: withdrawals_root.unwrap_or_default(),
            blob_gas_used,
        },
        metadata,
    };
    // Need to ensure `state.bundle = None`, was done previously with  `state.take_bundle()`
    state.transition_state = untouched_transition_state;

    Ok((
        OpBuiltPayload::new(
            ctx.payload_id(),
            sealed_block,
            info.total_fees,
            Some(executed),
        ),
        fb_payload,
    ))
}
