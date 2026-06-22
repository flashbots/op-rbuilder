use super::{state_root::StateRootCalculator, wspub::WebSocketPublisher};
use crate::{
    builder::{
        BuilderConfig,
        best_txs::{FlashblockPoolTxCursor, FlashblockTxTracker},
        builder_tx::{BuilderTransactions, reserve_builder_tx_budget},
        cancellation::{CancellationReason, FlashblockJobCancellation, PayloadJobCancellation},
        context::{OpPayloadBuilderCtx, OpPayloadJobCtx},
        generator::{BuildArguments, PayloadBuilder},
        timing::{FlashblockScheduler, compute_slot_offset_ms},
    },
    evm::OpBlockEvmFactory,
    hardforks::ActiveHardforks,
    limiter::AddressLimiter,
    metrics::{OpRBuilderMetrics, record_flashblock_publish_timing},
    primitives::reth::ExecutionInfo,
    runtime_ext::RuntimeExt,
    tokio_metrics::FlashblocksTaskMetrics,
    traits::{ClientBounds, PoolBounds},
};
use alloy_primitives::B256;
use eyre::WrapErr as _;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_chainspec::EthChainSpec;
use reth_node_api::PayloadBuilderError;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilderAttributes};
use reth_optimism_payload_builder::OpPayloadAttrs;
use reth_optimism_primitives::{OpReceipt, OpTransactionSigned};
use reth_payload_builder::PayloadId;
use reth_payload_util::BestPayloadTransactions;
use reth_revm::{
    State,
    cached::CachedReads,
    database::StateProviderDatabase,
    db::{CacheState, TransitionState},
};
use reth_tasks::Runtime;
use std::{
    ops::Deref,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, metadata::Level, span, warn};

#[derive(Debug, Default, Clone)]
pub(crate) struct FlashblocksState {
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
    /// Index into ExecutionInfo tracking the last consumed flashblock
    /// Used for slicing transactions/receipts per flashblock
    last_flashblock_tx_index: usize,
}

pub(crate) struct BuildState {
    pub(crate) ctx: OpPayloadJobCtx,
    pub(crate) info: ExecutionInfo,
    pub(crate) cache: CacheState,
    pub(crate) transition: Option<TransitionState>,
    pub(crate) tx_tracker: FlashblockTxTracker,
    pub(crate) fb_state: FlashblocksState,
    /// Per-interval state-root calculator. Cloned per candidate inside the
    /// build task so each seal sees the same baseline, then replaced with the
    /// winner's calculator before the next interval begins.
    pub(crate) state_root_calc: StateRootCalculator,
}

/// References borrowed by the continuous build job for the duration of a single
/// payload.
pub(crate) struct JobDeps<'a> {
    pub(crate) span: &'a tracing::Span,
    pub(crate) best_payload_tx: &'a watch::Sender<Option<OpBuiltPayload>>,
    pub(crate) payload_cancel: &'a PayloadJobCancellation,
}

struct FallbackBuildOutput<Cache, Transition> {
    ctx: OpPayloadJobCtx,
    info: ExecutionInfo,
    payload: OpBuiltPayload,
    fb_payload: OpFlashblockPayload,
    cache: Cache,
    transition: Transition,
    fb_state: FlashblocksState,
    state_root_calc: StateRootCalculator,
}

struct FlashblockBuildOutput {
    state: BuildState,
    build_result: eyre::Result<Option<BuiltFlashblockOutput>>,
}

struct BuiltFlashblockOutput {
    next_flashblock_state: FlashblocksState,
    new_payload: OpBuiltPayload,
    fb_payload: OpFlashblockPayload,
    build_duration: Duration,
}

#[derive(derive_more::Constructor)]
pub(crate) struct PayloadBuildStats {
    cancellation: PayloadJobCancellation,
    span: tracing::Span,
    flashblock_index: u64,
    num_txs: usize,
    uncompressed_byte_size: u64,
    target_flashblocks: u64,
}

impl FlashblocksState {
    fn new(target_flashblock_count: u64) -> Self {
        Self {
            target_flashblock_count,
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
            last_flashblock_tx_index: self.last_flashblock_tx_index,
        }
    }

    /// Advance the batch budgets for the next flashblock after sealing the
    /// current one.
    ///
    /// `target_da_for_batch` and `target_da_footprint_for_batch` are the
    /// post-build residuals carried over from this flashblock; each is
    /// incremented by the corresponding per-batch limit. `target_gas` is
    /// recomputed from `self.target_gas_for_batch` (pre-build) plus
    /// `gas_per_batch`.
    pub(crate) fn next_after_seal(
        &self,
        mut target_da_for_batch: Option<u64>,
        mut target_da_footprint_for_batch: Option<u64>,
    ) -> Self {
        if let Some(da_limit) = self.da_per_batch {
            if let Some(da) = target_da_for_batch.as_mut() {
                *da += da_limit;
            } else {
                error!(
                    "Builder end up in faulty invariant, if da_per_batch is set then total_da_per_batch must be set"
                );
            }
        }

        let target_gas_for_batch = self.target_gas_for_batch + self.gas_per_batch;

        if let (Some(footprint), Some(da_footprint_limit)) = (
            target_da_footprint_for_batch.as_mut(),
            self.da_footprint_per_batch,
        ) {
            *footprint += da_footprint_limit;
        }

        self.next(
            target_gas_for_batch,
            target_da_for_batch,
            target_da_footprint_for_batch,
        )
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

    pub(crate) fn flashblock_index(&self) -> u64 {
        self.flashblock_index
    }

    pub(crate) fn target_flashblock_count(&self) -> u64 {
        self.target_flashblock_count
    }

    fn meta(&self) -> FlashblockMeta {
        FlashblockMeta {
            flashblock_index: self.flashblock_index,
            target_flashblock_count: self.target_flashblock_count,
        }
    }

    pub(crate) fn is_first_flashblock(&self) -> bool {
        self.flashblock_index == 0
    }

    pub(crate) fn is_last_flashblock(&self) -> bool {
        self.flashblock_index == self.target_flashblock_count
    }

    pub(crate) fn target_gas_for_batch(&self) -> u64 {
        self.target_gas_for_batch
    }

    pub(crate) fn target_da_for_batch(&self) -> Option<u64> {
        self.target_da_for_batch
    }

    pub(crate) fn target_da_footprint_for_batch(&self) -> Option<u64> {
        self.target_da_footprint_for_batch
    }

    pub(super) fn set_last_flashblock_tx_index(&mut self, index: usize) {
        self.last_flashblock_tx_index = index;
    }

    /// Extracts new transactions since the last flashblock
    pub(crate) fn slice_new_transactions<'a>(
        &self,
        all_transactions: &'a [OpTransactionSigned],
    ) -> &'a [OpTransactionSigned] {
        &all_transactions[self.last_flashblock_tx_index..]
    }

    /// Extracts new receipts since the last flashblock
    pub(super) fn slice_new_receipts<'a>(&self, all_receipts: &'a [OpReceipt]) -> &'a [OpReceipt] {
        &all_receipts[self.last_flashblock_tx_index..]
    }
}

/// Projection of [`FlashblocksState`] describing where the current
/// build sits within the slot's flashblock sequence.
#[derive(Debug, Clone, Copy)]
struct FlashblockMeta {
    flashblock_index: u64,
    target_flashblock_count: u64,
}

impl FlashblockMeta {
    fn is_first(&self) -> bool {
        self.flashblock_index == 0
    }

    fn is_last(&self) -> bool {
        self.flashblock_index == self.target_flashblock_count
    }
}

/// Optimism's payload builder
#[derive(Debug)]
pub(crate) struct OpPayloadBuilder<Pool, Client, BuilderTx> {
    inner: Arc<OpPayloadBuilderInner<Pool, Client, BuilderTx>>,
}

#[derive(Debug)]
pub(crate) struct OpPayloadBuilderInner<Pool, Client, BuilderTx> {
    /// Builder context
    builder_ctx: Arc<OpPayloadBuilderCtx>,
    /// The transaction pool
    pool: Pool,
    /// Node client
    client: Client,
    /// Sender for sending built flashblock payloads to [`PayloadHandler`],
    /// which broadcasts outgoing flashblock payloads via p2p.
    built_fb_payload_tx: mpsc::Sender<OpBuiltPayload>,
    /// Sender for sending built full block payloads to [`PayloadHandler`],
    /// which updates the engine tree state.
    built_payload_tx: mpsc::Sender<OpBuiltPayload>,
    /// WebSocket publisher for broadcasting flashblocks
    /// to all connected subscribers.
    ws_pub: WebSocketPublisher,
    /// System configuration for the builder
    config: BuilderConfig,
    /// The end of builder transaction type
    builder_tx: BuilderTx,
    /// Tokio task metrics for monitoring spawned tasks
    task_metrics: Arc<FlashblocksTaskMetrics>,
    /// Monotonic epoch that advances on pool mutations.
    pool_change_epoch: Arc<AtomicU64>,
    /// Task executor used to offload blocking work.
    executor: Runtime,
}

impl<Pool, Client, BuilderTx> OpPayloadBuilderInner<Pool, Client, BuilderTx> {
    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    pub(crate) fn ws_pub(&self) -> &WebSocketPublisher {
        &self.ws_pub
    }

    pub(crate) fn config(&self) -> &BuilderConfig {
        &self.config
    }

    pub(crate) fn metrics(&self) -> &OpRBuilderMetrics {
        &self.builder_ctx.metrics
    }

    pub(crate) fn builder_tx(&self) -> &BuilderTx {
        &self.builder_tx
    }

    pub(crate) fn pool_change_epoch(&self) -> &AtomicU64 {
        &self.pool_change_epoch
    }

    pub(crate) fn executor(&self) -> &Runtime {
        &self.executor
    }
}

impl<Pool, Client, BuilderTx> Deref for OpPayloadBuilder<Pool, Client, BuilderTx> {
    type Target = OpPayloadBuilderInner<Pool, Client, BuilderTx>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl<Pool, Client, BuilderTx> Clone for OpPayloadBuilder<Pool, Client, BuilderTx> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Client: ClientBounds,
{
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        evm_config: OpEvmConfig,
        pool: Pool,
        client: Client,
        config: BuilderConfig,
        builder_tx: BuilderTx,
        built_fb_payload_tx: mpsc::Sender<OpBuiltPayload>,
        built_payload_tx: mpsc::Sender<OpBuiltPayload>,
        ws_pub: WebSocketPublisher,
        metrics: Arc<OpRBuilderMetrics>,
        task_metrics: Arc<FlashblocksTaskMetrics>,
        pool_change_epoch: Arc<AtomicU64>,
        executor: Runtime,
    ) -> Self {
        let address_limiter = AddressLimiter::new(
            config.gas_limiter_config.clone(),
            config.compute_limiter_config.clone(),
        );
        let builder_ctx = Arc::new(OpPayloadBuilderCtx {
            evm_config,
            da_config: config.da_config.clone(),
            gas_limit_config: config.gas_limit_config.clone(),
            chain_spec: client.chain_spec(),
            metrics,
            max_gas_per_txn: config.max_gas_per_txn,
            max_uncompressed_block_size: config.max_uncompressed_block_size,
            address_limiter,
            backrun_bundle_args: config.backrun_bundle_args.clone(),
            exclude_reverts_between_flashblocks: config.exclude_reverts_between_flashblocks,
            enable_tx_tracking_debug_logs: config.enable_tx_tracking_debug_logs,
            disable_state_root: config.flashblocks_config.disable_state_root,
            enable_incremental_state_root: config.flashblocks_config.enable_incremental_state_root,
        });
        Self {
            inner: Arc::new(OpPayloadBuilderInner {
                builder_ctx,
                pool,
                client,
                built_fb_payload_tx,
                built_payload_tx,
                ws_pub,
                config,
                builder_tx,
                task_metrics,
                pool_change_epoch,
                executor,
            }),
        }
    }
}

impl<Pool, Client, BuilderTx> OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    fn get_op_payload_job_ctx(
        &self,
        config: reth_basic_payload_builder::PayloadConfig<
            OpPayloadBuilderAttributes<op_alloy_consensus::OpTxEnvelope>,
        >,
        cancel: FlashblockJobCancellation,
    ) -> eyre::Result<OpPayloadJobCtx> {
        let builder_ctx = &self.builder_ctx;
        let timestamp = config.attributes.timestamp();
        let hardforks = ActiveHardforks::new(Arc::clone(&builder_ctx.chain_spec), timestamp);

        let extra_data = if hardforks.is_jovian_active() {
            config
                .attributes
                .get_jovian_extra_data(
                    builder_ctx
                        .chain_spec
                        .base_fee_params_at_timestamp(timestamp),
                )
                .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
        } else if hardforks.is_holocene_active() {
            config
                .attributes
                .get_holocene_extra_data(
                    builder_ctx
                        .chain_spec
                        .base_fee_params_at_timestamp(timestamp),
                )
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
            parent_beacon_block_root: config.attributes.parent_beacon_block_root,
            extra_data,
        };

        let evm_factory = OpBlockEvmFactory::for_next_block(
            builder_ctx.evm_config.clone(),
            &config.parent_header,
            &block_env_attributes,
        )
        .wrap_err("failed to create next evm env")?;

        let backrun_pool = self
            .pool
            .backrun_bundle_pool()
            .map(|pool| pool.block_pool(config.parent_header.number + 1));

        let address_limiter = Arc::new(builder_ctx.address_limiter.begin());

        Ok(OpPayloadJobCtx::new(
            Arc::clone(builder_ctx),
            evm_factory,
            config,
            block_env_attributes,
            hardforks,
            cancel,
            backrun_pool,
            address_limiter,
        ))
    }

    /// Constructs an Optimism payload from the transactions sent via the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Optimism client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    async fn build_payload(
        &self,
        args: BuildArguments<OpPayloadBuilderAttributes<OpTransactionSigned>, OpBuiltPayload>,
        best_payload_tx: watch::Sender<Option<OpBuiltPayload>>,
    ) -> Result<(), PayloadBuilderError> {
        let payload_id = args.config.payload_id();

        let start = Instant::now();
        let payload_stats = self.build_payload_inner(args, best_payload_tx).await?;
        self.record_payload_stats(payload_stats, start.elapsed(), payload_id);

        Ok(())
    }

    async fn build_payload_inner(
        &self,
        args: BuildArguments<OpPayloadBuilderAttributes<OpTransactionSigned>, OpBuiltPayload>,
        best_payload_tx: watch::Sender<Option<OpBuiltPayload>>,
    ) -> Result<PayloadBuildStats, PayloadBuilderError> {
        let BuildArguments {
            cached_reads,
            config,
            cancel: payload_cancel,
        } = args;

        // The build_payload span is created and instrumented in try_build() using
        // tracing::Instrument, which safely manages it across async .await points.
        let span = tracing::Span::current();
        span.record("payload_id", config.attributes.id.to_string());

        self.builder_ctx
            .address_limiter
            .refill_buckets(config.parent_header.number + 1);

        let ctx = self
            .get_op_payload_job_ctx(config.clone(), payload_cancel.flashblock_child())
            .map_err(|e| PayloadBuilderError::Other(e.into()))?;

        // Initialize flashblocks state for this block
        let fb_state = FlashblocksState::new(
            self.config
                .flashblocks_config
                .flashblocks_per_block(self.config.block_time),
        );
        let state_root_calc = StateRootCalculator::new(
            !ctx.disable_state_root || ctx.attributes().no_tx_pool,
            ctx.enable_incremental_state_root,
        );

        // Phase 1: Build the fallback block.
        let fallback_span = if span.is_none() {
            tracing::Span::none()
        } else {
            info_span!(parent: &span, "build_fallback")
        };
        let FallbackBuildOutput {
            ctx,
            info,
            payload,
            fb_payload,
            cache,
            transition,
            mut fb_state,
            state_root_calc,
        } = tracing::Instrument::instrument(
            self.executor.run_blocking_task({
                let builder = self.clone();
                move || {
                    builder
                        .build_fallback_block(ctx, fb_state, cached_reads, state_root_calc)
                        .map_err(|e| PayloadBuilderError::Other(e.into()))
                }
            }),
            fallback_span,
        )
        .await?;

        if payload_cancel.is_cancelled() {
            return Ok(PayloadBuildStats::new(
                payload_cancel,
                span,
                fb_state.flashblock_index(),
                info.executed_transactions.len(),
                info.cumulative_uncompressed_bytes,
                0,
            ));
        }

        best_payload_tx.send_replace(Some(payload.clone()));
        self.notify_built_payload(payload);

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

            let slot_offset_ms =
                compute_slot_offset_ms(config.attributes.timestamp(), self.config.block_time);
            record_flashblock_publish_timing(fb_payload.index, slot_offset_ms);

            if self.config.enable_tx_tracking_debug_logs {
                debug!(
                    target: "tx_trace",
                    payload_id = %ctx.payload_id(),
                    block_number = ctx.block_number(),
                    flashblock_index = fb_payload.index,
                    byte_size = flashblock_byte_size,
                    total_txs = info.executed_transactions.len(),
                    slot_offset_ms,
                    stage = "fb_published"
                );
            }
            ctx.metrics
                .flashblock_byte_size_histogram
                .record(flashblock_byte_size as f64);
        }

        if ctx.attributes().no_tx_pool {
            info!(
                target: "payload_builder",
                "No transaction pool, skipping transaction pool processing",
            );

            // return early since we don't need to build a block with transactions from the pool
            return Ok(PayloadBuildStats::new(
                payload_cancel,
                span,
                fb_state.flashblock_index(),
                info.executed_transactions.len(),
                info.cumulative_uncompressed_bytes,
                0,
            ));
        }

        // We adjust our flashblocks timings based on time the fcu block building signal arrived
        let flashblock_scheduler = FlashblockScheduler::new(
            &self.config.flashblocks_config,
            self.config.block_time,
            config.attributes.timestamp(),
        );

        let target_flashblocks = flashblock_scheduler.target_flashblocks();
        info!(
            target: "payload_builder",
            id = %fb_payload.payload_id,
            target_flashblocks,
            schedule = ?flashblock_scheduler,
            "Computed flashblock timing schedule"
        );

        let expected_flashblocks = self
            .config
            .flashblocks_config
            .flashblocks_per_block(self.config.block_time);
        if target_flashblocks < expected_flashblocks {
            warn!(
                target: "payload_builder",
                expected_flashblocks,
                target_flashblocks,
                "FCU arrived late, building fewer flashblocks"
            );
            ctx.metrics
                .reduced_flashblocks_number
                .increment(expected_flashblocks - target_flashblocks);
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

        let fb_cancel = payload_cancel.flashblock_child();
        let ctx = self
            .get_op_payload_job_ctx(config, fb_cancel.clone())
            .map_err(|e| PayloadBuilderError::Other(e.into()))?;

        let (tx, rx) = mpsc::channel((expected_flashblocks + 1) as usize);
        tokio::spawn(
            self.task_metrics
                .flashblock_timer
                .instrument(flashblock_scheduler.run(
                    tx,
                    payload_cancel.clone(),
                    fb_cancel,
                    fb_payload.payload_id,
                )),
        );

        // State data was extracted in Phase 1 block scope above.
        // We carry (CacheState, Option<TransitionState>) between iterations
        // and reconstruct State<DB> inside each sync scope.
        let tx_tracker = FlashblockTxTracker::default();
        let parent_hash = ctx.parent_hash();

        let deps = JobDeps {
            span: &span,
            best_payload_tx: &best_payload_tx,
            payload_cancel: &payload_cancel,
        };
        let base_state = BuildState {
            ctx,
            info,
            cache,
            transition,
            tx_tracker,
            fb_state,
            state_root_calc,
        };

        if self.config.flashblocks_config.continuous_build {
            self.run_continuous_flashblocks(deps, target_flashblocks, parent_hash, rx, base_state)
                .await
        } else {
            self.run_naive_flashblocks(deps, target_flashblocks, parent_hash, rx, base_state)
                .await
        }
    }

    pub(crate) async fn run_naive_flashblocks(
        &self,
        deps: JobDeps<'_>,
        target_flashblocks: u64,
        parent_hash: B256,
        mut fb_trigger_rx: mpsc::Receiver<FlashblockJobCancellation>,
        base_state: BuildState,
    ) -> Result<PayloadBuildStats, PayloadBuilderError> {
        let BuildState {
            mut ctx,
            mut info,
            mut cache,
            mut transition,
            mut tx_tracker,
            mut fb_state,
            mut state_root_calc,
        } = base_state;

        loop {
            // Phase 1: Wait for scheduler trigger, or exit on cancellation.
            let new_fb_cancel = tokio::select! {
                biased;
                _ = deps.payload_cancel.wait_for_cancellation() => {
                    return Ok(PayloadBuildStats::new(
                        deps.payload_cancel.clone(),
                        deps.span.clone(),
                        fb_state.flashblock_index(),
                        info.executed_transactions.len(),
                        info.cumulative_uncompressed_bytes,
                        target_flashblocks,
                    ));
                }
                trigger = fb_trigger_rx.recv() => match trigger {
                    Some(t) => t,
                    None => {
                        // Channel closed — scheduler exhausted or canceled
                        return Ok(PayloadBuildStats::new(
                            deps.payload_cancel.clone(),
                            deps.span.clone(),
                            fb_state.flashblock_index(),
                            info.executed_transactions.len(),
                            info.cumulative_uncompressed_bytes,
                            target_flashblocks,
                        ));
                    }
                },
            };

            debug!(
                target: "payload_builder",
                id = %ctx.payload_id(),
                flashblock_index = fb_state.flashblock_index(),
                block_number = ctx.block_number(),
                "Received signal to build flashblock",
            );
            ctx = ctx.with_cancel(new_fb_cancel);

            let fb_span = if deps.span.is_none() {
                tracing::Span::none()
            } else {
                span!(
                    parent: deps.span,
                    Level::INFO,
                    "build_flashblock",
                    flashblock_index = fb_state.flashblock_index(),
                    block_number = ctx.block_number(),
                    tx_count = tracing::field::Empty,
                    gas_used = tracing::field::Empty,
                )
            };

            // Phase 2: Build flashblock (blocking task), or exit on cancellation.
            let num_txs = info.executed_transactions.len();
            let uncompressed_byte_size = info.cumulative_uncompressed_bytes;
            let flashblock_index = fb_state.flashblock_index();
            let build_output = tokio::select! {
                biased;
                _ = deps.payload_cancel.wait_for_cancellation() => {
                    if deps.payload_cancel.is_resolved() {
                        // Suppressed flashblock: we received getResolve during flashblock building
                        self.builder_ctx.metrics.flashblock_publish_suppressed_total.increment(1);
                    }
                    return Ok(PayloadBuildStats::new(
                        deps.payload_cancel.clone(),
                        deps.span.clone(),
                        flashblock_index,
                        num_txs,
                        uncompressed_byte_size,
                        target_flashblocks,
                    ));
                }
                result = self.executor.run_blocking_task({
                    let builder = self.clone();
                    let block_cancel = deps.payload_cancel.token();
                    let fb_span = fb_span.clone();
                    let build_state = BuildState {
                        ctx,
                        info,
                        cache,
                        transition,
                        tx_tracker,
                        fb_state,
                        state_root_calc,
                    };
                    move || {
                        let _enter = fb_span.enter();
                        builder.build_next_flashblock(build_state, parent_hash, &block_cancel)
                            .map_err(|e| PayloadBuilderError::Other(e.into()))
                    }
                }) => result?,
            };

            let FlashblockBuildOutput {
                state: new_state,
                build_result,
            } = build_output;
            BuildState {
                ctx,
                info,
                cache,
                transition,
                tx_tracker,
                fb_state,
                state_root_calc,
            } = new_state;

            // Record span attributes now that we have results
            fb_span.record("tx_count", info.executed_transactions.len() as u64);
            fb_span.record("gas_used", info.cumulative_gas_used);

            // Phase 3: Publish
            // no .await between check and publish (structural guarantee).
            // If resolved or new_fcu fired during the build, skip publishing.
            if deps.payload_cancel.is_resolved() || deps.payload_cancel.is_new_fcu() {
                if deps.payload_cancel.is_resolved() {
                    ctx.metrics.flashblock_publish_suppressed_total.increment(1);
                }
                return Ok(PayloadBuildStats::new(
                    deps.payload_cancel.clone(),
                    deps.span.clone(),
                    fb_state.flashblock_index(),
                    info.executed_transactions.len(),
                    info.cumulative_uncompressed_bytes,
                    target_flashblocks,
                ));
            }

            let next_flashblock_state = match build_result {
                Ok(Some(built_flashblock)) => {
                    let Some(next_flashblock_state) = self
                        .publish_flashblock_payload(
                            &ctx,
                            deps.best_payload_tx,
                            &fb_state,
                            deps.payload_cancel,
                            built_flashblock,
                        )
                        .map_err(|e| PayloadBuilderError::Other(e.into()))?
                    else {
                        return Ok(PayloadBuildStats::new(
                            deps.payload_cancel.clone(),
                            deps.span.clone(),
                            fb_state.flashblock_index(),
                            info.executed_transactions.len(),
                            info.cumulative_uncompressed_bytes,
                            target_flashblocks,
                        ));
                    };

                    next_flashblock_state
                }
                Ok(None) => {
                    return Ok(PayloadBuildStats::new(
                        deps.payload_cancel.clone(),
                        deps.span.clone(),
                        fb_state.flashblock_index(),
                        info.executed_transactions.len(),
                        info.cumulative_uncompressed_bytes,
                        target_flashblocks,
                    ));
                }
                Err(err) => {
                    ctx.metrics.payload_job_cancellation_error.increment(1);
                    deps.span.record("cancellation_reason", "error");
                    error!(
                        target: "payload_builder",
                        id = %ctx.payload_id(),
                        flashblock_index = fb_state.flashblock_index(),
                        block_number = ctx.block_number(),
                        %err,
                        "Failed to build flashblock",
                    );
                    return Err(PayloadBuilderError::Other(err.into()));
                }
            };

            fb_state = next_flashblock_state;
        }
    }

    /// Execute the pre-steps and seal an early fallback block
    fn build_fallback_block(
        &self,
        ctx: OpPayloadJobCtx,
        mut fb_state: FlashblocksState,
        mut cached_reads: CachedReads,
        mut state_root_calc: StateRootCalculator,
    ) -> eyre::Result<FallbackBuildOutput<CacheState, Option<TransitionState>>> {
        let state_provider = self.client.state_by_block_hash(ctx.parent().hash())?;
        let db = StateProviderDatabase::new(&state_provider);

        let sequencer_tx_start_time = Instant::now();
        let mut state = State::builder()
            .with_database(cached_reads.as_db_mut(db))
            .with_bundle_update()
            .build();

        let mut info = ctx.execute_pre_steps(&mut state)?;
        let sequencer_tx_time = sequencer_tx_start_time.elapsed();
        ctx.metrics.sequencer_tx_duration.record(sequencer_tx_time);
        ctx.metrics.sequencer_tx_gauge.set(sequencer_tx_time);

        // We add first builder tx right after deposits
        if !ctx.attributes().no_tx_pool {
            let flashblock = fb_state.meta();
            if let Err(e) = self.builder_tx.add_builder_txs(
                &state_provider,
                &mut info,
                &ctx.builder_tx_env(),
                &mut state,
                false,
                flashblock.is_first(),
                flashblock.is_last(),
            ) {
                error!(
                    target: "payload_builder",
                    "Error adding builder txs to fallback block: {}",
                    e
                );
            }
        }

        let (payload, fb_payload) = ctx.block_assembly_input()?.assemble(
            &mut state,
            Some(&mut fb_state),
            &mut info,
            &mut state_root_calc,
            ctx.metrics.clone(),
            ctx.enable_tx_tracking_debug_logs,
        )?;

        // we can safely take from state as we drop it at the end of the scope
        let cache = std::mem::take(&mut state.cache);
        let transition = state.transition_state.take();
        Ok(FallbackBuildOutput {
            ctx,
            info,
            payload,
            fb_payload,
            cache,
            transition,
            fb_state,
            state_root_calc,
        })
    }

    pub(crate) fn notify_built_payload(&self, payload: OpBuiltPayload) {
        if let Err(e) = self.built_fb_payload_tx.try_send(payload.clone()) {
            warn!(
                target: "payload_builder",
                error = %e,
                "Failed to send built flashblock payload to handler"
            );
        }

        if let Err(e) = self.built_payload_tx.try_send(payload) {
            warn!(
                target: "payload_builder",
                error = %e,
                "Failed to send updated payload"
            );
        }
    }

    fn publish_flashblock_payload(
        &self,
        ctx: &OpPayloadJobCtx,
        best_payload_tx: &watch::Sender<Option<OpBuiltPayload>>,
        fb_state: &FlashblocksState,
        payload_cancel: &PayloadJobCancellation,
        built_flashblock: BuiltFlashblockOutput,
    ) -> eyre::Result<Option<FlashblocksState>> {
        let BuiltFlashblockOutput {
            next_flashblock_state,
            new_payload,
            fb_payload,
            build_duration,
        } = built_flashblock;

        if payload_cancel.is_cancelled() {
            if payload_cancel.is_resolved() {
                ctx.metrics.flashblock_publish_suppressed_total.increment(1);
            }
            return Ok(None);
        }

        // After this point, all side effects are synchronous. If cancellation wins the race after
        // this check, still publish the local payload so getPayload can include this flashblock.
        let flashblock_byte_size = self
            .ws_pub
            .publish(&fb_payload)
            .wrap_err("failed to publish flashblock via websocket")?;
        let flashblock_tx_count = fb_payload.raw_transactions().len();

        best_payload_tx.send_replace(Some(new_payload.clone()));
        self.notify_built_payload(new_payload);

        let slot_offset_ms =
            compute_slot_offset_ms(ctx.attributes().timestamp(), self.config.block_time);
        record_flashblock_publish_timing(fb_state.flashblock_index(), slot_offset_ms);

        if self.config.enable_tx_tracking_debug_logs {
            debug!(
                target: "tx_trace",
                payload_id = %ctx.payload_id(),
                block_number = ctx.block_number(),
                flashblock_index = fb_state.flashblock_index(),
                byte_size = flashblock_byte_size,
                total_txs = flashblock_tx_count,
                slot_offset_ms,
                stage = "fb_published"
            );
        }

        ctx.metrics.flashblock_build_duration.record(build_duration);
        ctx.metrics
            .flashblock_byte_size_histogram
            .record(flashblock_byte_size as f64);
        ctx.metrics
            .flashblock_num_tx_histogram
            .record(flashblock_tx_count as f64);

        Ok(Some(next_flashblock_state))
    }

    fn build_next_flashblock(
        &self,
        build_state: BuildState,
        parent_hash: B256,
        block_cancel: &CancellationToken,
    ) -> eyre::Result<FlashblockBuildOutput> {
        let BuildState {
            ctx,
            mut fb_state,
            mut info,
            cache,
            transition,
            mut tx_tracker,
            mut state_root_calc,
        } = build_state;

        let state_provider = self.client.state_by_block_hash(parent_hash)?;
        let mut evm_state = State::builder()
            .with_database(StateProviderDatabase::new(&state_provider))
            .with_cached_prestate(cache)
            .with_bundle_update()
            .build();
        evm_state.transition_state = transition;

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

        let flashblock = fb_state.meta();
        let builder_txs = self
            .builder_tx
            .add_builder_txs(
                &state_provider,
                &mut info,
                &ctx.builder_tx_env(),
                &mut evm_state,
                true,
                flashblock.is_first(),
                flashblock.is_last(),
            )
            .inspect_err(
                |e| error!(target: "payload_builder", error = %e, "Error simulating builder txs"),
            )
            .unwrap_or_default();

        // only reserve builder tx gas / da size that has not been committed yet
        // committed builder txs would have counted towards the gas / da used
        let max_uncompressed_block_size = reserve_builder_tx_budget(
            &builder_txs,
            &mut target_gas_for_batch,
            &mut target_da_for_batch,
            &mut target_da_footprint_for_batch,
            info.da_footprint_scalar,
            ctx.max_uncompressed_block_size,
            info.cumulative_uncompressed_bytes,
        );

        let best_txs_start_time = Instant::now();
        let mut best_txs = FlashblockPoolTxCursor::new(&mut tx_tracker);
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
            &mut info,
            &mut evm_state,
            &mut best_txs,
            target_gas_for_batch.min(ctx.block_gas_limit()),
            target_da_for_batch,
            target_da_footprint_for_batch,
            max_uncompressed_block_size,
            fb_state.flashblock_index,
        )
        .wrap_err("failed to execute best transactions")?;
        // Extract last transactions
        let new_transactions: Vec<_> = fb_state
            .slice_new_transactions(&info.executed_transactions)
            .iter()
            .map(|tx| tx.tx_hash())
            .collect::<Vec<_>>();
        best_txs.mark_committed(new_transactions);

        // Remove reverted bundle txs from the pool so they aren't re-simulated in future blocks
        if !info.reverted_bundle_tx_hashes.is_empty() {
            let hashes = info.reverted_bundle_tx_hashes.drain(..).collect();
            self.pool.remove_transactions(hashes);
        }

        // Block cancelled (new FCU, getPayload resolved, or deadline). Skip publishing.
        if block_cancel.is_cancelled() {
            let cache = std::mem::take(&mut evm_state.cache);
            let transition = evm_state.transition_state.take();
            return Ok(FlashblockBuildOutput {
                state: BuildState {
                    ctx,
                    info,
                    cache,
                    transition,
                    tx_tracker,
                    fb_state,
                    state_root_calc,
                },
                build_result: Ok(None),
            });
        }

        let payload_transaction_simulation_time = tx_execution_start_time.elapsed();
        ctx.metrics
            .payload_transaction_simulation_duration
            .record(payload_transaction_simulation_time);
        ctx.metrics
            .payload_transaction_simulation_gauge
            .set(payload_transaction_simulation_time);

        let flashblock = fb_state.meta();
        if let Err(e) = self.builder_tx.add_builder_txs(
            &state_provider,
            &mut info,
            &ctx.builder_tx_env(),
            &mut evm_state,
            false,
            flashblock.is_first(),
            flashblock.is_last(),
        ) {
            error!(target: "payload_builder", error = %e, "Error simulating builder txs");
        }

        let (new_payload, mut fb_payload) = ctx
            .block_assembly_input()?
            .assemble(
                &mut evm_state,
                Some(&mut fb_state),
                &mut info,
                &mut state_root_calc,
                ctx.metrics.clone(),
                ctx.enable_tx_tracking_debug_logs,
            )
            .inspect_err(|_| ctx.metrics.invalid_built_blocks_count.increment(1))
            .context("failed to build payload")?;

        fb_payload.index = flashblock_index;
        fb_payload.base = None;

        // Block canceled (new FCU, getPayload resolved, or deadline). The async outer
        // loop owns publishing and re-checks cancellation before every side effect.
        if block_cancel.is_cancelled() {
            let cache = std::mem::take(&mut evm_state.cache);
            let transition = evm_state.transition_state.take();
            return Ok(FlashblockBuildOutput {
                state: BuildState {
                    ctx,
                    info,
                    cache,
                    transition,
                    tx_tracker,
                    fb_state,
                    state_root_calc,
                },
                build_result: Ok(None),
            });
        }

        // Advance batch budgets for the next flashblock.
        let next_flashblock_state =
            fb_state.next_after_seal(target_da_for_batch, target_da_footprint_for_batch);

        let cache = std::mem::take(&mut evm_state.cache);
        let transition = evm_state.transition_state.take();
        Ok(FlashblockBuildOutput {
            state: BuildState {
                ctx,
                info,
                cache,
                transition,
                tx_tracker,
                fb_state,
                state_root_calc,
            },
            build_result: Ok(Some(BuiltFlashblockOutput {
                next_flashblock_state,
                new_payload,
                fb_payload,
                build_duration: flashblock_build_start_time.elapsed(),
            })),
        })
    }

    fn record_payload_stats(
        &self,
        payload_stats: PayloadBuildStats,
        block_build_duration: Duration,
        payload_id: PayloadId,
    ) {
        let metrics = self.builder_ctx.metrics.clone();

        let PayloadBuildStats {
            cancellation,
            span,
            flashblock_index,
            num_txs,
            uncompressed_byte_size,
            target_flashblocks,
        } = payload_stats;

        if cancellation.is_cancelled() {
            let reason_str = match cancellation.reason() {
                Some(CancellationReason::Resolved) => {
                    metrics.payload_job_cancellation_resolved.increment(1);
                    "resolved"
                }
                Some(CancellationReason::NewFcu) => {
                    metrics.payload_job_cancellation_new_fcu.increment(1);
                    "new_fcu"
                }
                Some(CancellationReason::Deadline) => {
                    metrics.payload_job_cancellation_deadline.increment(1);
                    "deadline"
                }
                None => {
                    metrics.payload_job_cancellation_complete.increment(1);
                    "complete"
                }
            };
            span.record("cancellation_reason", reason_str);
            info!(
                target: "payload_builder",
                cancellation_reason = reason_str,
                "Payload job cancelled"
            );
        }

        metrics.payload_num_tx.record(num_txs as f64);
        metrics.payload_num_tx_gauge.set(num_txs as f64);
        metrics
            .total_block_built_duration
            .record(block_build_duration);
        metrics.total_block_built_gauge.set(block_build_duration);

        metrics.block_built_success.increment(1);
        metrics.flashblock_count.record(flashblock_index as f64);
        metrics
            .missing_flashblocks_count
            .increment(target_flashblocks.saturating_sub(flashblock_index));
        metrics
            .block_uncompressed_size
            .record(uncompressed_byte_size as f64);

        info!(
            target: "payload_builder",
            event = "build_complete",
            id = %payload_id,
            target_flashblocks,
            flashblock_index,
            "Flashblocks building complete"
        );

        span.record("flashblocks_built", flashblock_index);
    }
}

#[async_trait::async_trait]
impl<Pool, Client, BuilderTx> PayloadBuilder for OpPayloadBuilder<Pool, Client, BuilderTx>
where
    Pool: PoolBounds + 'static,
    Client: ClientBounds + 'static,
    BuilderTx: BuilderTransactions + Send + Sync + 'static,
{
    type Attributes = OpPayloadAttrs;
    type BuiltPayload = OpBuiltPayload;

    async fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
        best_payload_tx: watch::Sender<Option<Self::BuiltPayload>>,
    ) -> Result<(), PayloadBuilderError> {
        let payload_id = args.config.payload_id;
        let builder_attrs = OpPayloadBuilderAttributes::<OpTransactionSigned>::from_rpc_attrs(
            args.config.parent_header.hash(),
            payload_id,
            args.config.attributes.0,
        )
        .map_err(PayloadBuilderError::other)?;
        let args: BuildArguments<OpPayloadBuilderAttributes<OpTransactionSigned>, OpBuiltPayload> =
            BuildArguments {
                cached_reads: args.cached_reads,
                config: reth_basic_payload_builder::PayloadConfig {
                    parent_header: args.config.parent_header,
                    attributes: builder_attrs,
                    payload_id,
                },
                cancel: args.cancel,
            };

        let span = if cfg!(feature = "telemetry")
            && args
                .config
                .parent_header
                .number
                .is_multiple_of(self.config.sampling_ratio)
        {
            info_span!(
                "build_payload",
                payload_id = tracing::field::Empty,
                block_number = args.config.parent_header.number + 1,
                parent_hash = %args.config.parent_header.hash(),
                flashblocks_built = tracing::field::Empty,
                cancellation_reason = tracing::field::Empty,
            )
        } else {
            tracing::Span::none()
        };
        tracing::Instrument::instrument(self.build_payload(args, best_payload_tx), span).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fb_state(
        gas_per_batch: u64,
        da_per_batch: Option<u64>,
        da_footprint_per_batch: Option<u64>,
        target_gas: u64,
        target_da: Option<u64>,
        target_da_footprint: Option<u64>,
    ) -> FlashblocksState {
        FlashblocksState::new(5).with_batch_limits(
            gas_per_batch,
            da_per_batch,
            da_footprint_per_batch,
            target_gas,
            target_da,
            target_da_footprint,
        )
    }

    #[test]
    fn test_next_after_seal_increments_index() {
        let state = make_fb_state(100_000, None, None, 100_000, None, None);
        assert_eq!(state.flashblock_index, 0);

        let next = state.next_after_seal(None, None);
        assert_eq!(next.flashblock_index, 1);

        let next2 = next.next_after_seal(None, None);
        assert_eq!(next2.flashblock_index, 2);
    }

    #[test]
    fn test_next_after_seal_advances_gas() {
        let state = make_fb_state(100_000, None, None, 100_000, None, None);
        let next = state.next_after_seal(None, None);

        assert_eq!(next.target_gas_for_batch, 200_000);
        assert_eq!(next.gas_per_batch, 100_000, "per-batch stays constant");
    }

    #[test]
    fn test_next_after_seal_advances_da() {
        let state = make_fb_state(100_000, Some(1_000), None, 100_000, Some(1_000), None);
        // Simulate no DA consumption during the flashblock: residual equals the starting budget.
        let next = state.next_after_seal(Some(1_000), None);

        assert_eq!(next.target_da_for_batch, Some(2_000));
        assert_eq!(next.da_per_batch, Some(1_000));
    }

    #[test]
    fn test_next_after_seal_carries_consumed_da() {
        // 300 of 1_000 DA was consumed this flashblock; next starts with 700 + 1_000 = 1_700.
        let state = make_fb_state(100_000, Some(1_000), None, 100_000, Some(1_000), None);
        let next = state.next_after_seal(Some(700), None);

        assert_eq!(next.target_da_for_batch, Some(1_700));
    }

    #[test]
    fn test_next_after_seal_advances_da_footprint() {
        let state = make_fb_state(100_000, None, Some(5_000), 100_000, None, Some(5_000));
        let next = state.next_after_seal(None, Some(5_000));

        assert_eq!(next.target_da_footprint_for_batch, Some(10_000));
    }

    #[test]
    fn test_next_after_seal_no_da_when_none() {
        let state = make_fb_state(100_000, None, None, 100_000, None, None);
        let next = state.next_after_seal(None, None);

        assert_eq!(next.target_da_for_batch, None);
        assert_eq!(next.target_da_footprint_for_batch, None);
    }

    #[test]
    fn test_next_after_seal_preserves_config() {
        let state = FlashblocksState::new(10).with_batch_limits(
            50_000,
            Some(500),
            Some(250),
            50_000,
            Some(500),
            Some(250),
        );

        let next = state.next_after_seal(Some(500), Some(250));

        assert_eq!(next.target_flashblock_count, 10);
    }
}
