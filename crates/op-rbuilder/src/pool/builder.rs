#[cfg(feature = "rules")]
use crate::rules::ScoreOrdering;
use op_alloy_consensus::interop::SafetyLevel;
use reth_chain_state::CanonStateSubscriptions;
use reth_node_builder::{
    BuilderContext, FullNodeTypes,
    components::{PoolBuilder, PoolBuilderConfigOverrides},
};
use reth_optimism_chainspec::OpHardforks;
use reth_optimism_node::OpPoolBuilder;
use reth_optimism_txpool::supervisor::{DEFAULT_SUPERVISOR_URL, SupervisorClient};
use reth_tracing::tracing::{debug, info};
#[cfg(not(feature = "rules"))]
use reth_transaction_pool::CoinbaseTipOrdering;
use reth_transaction_pool::{Pool, TransactionValidationTaskExecutor, TransactionValidator};
use std::marker::PhantomData;

#[cfg(feature = "rules")]
pub type PoolOrdering<T> = ScoreOrdering<T>;

#[cfg(not(feature = "rules"))]
pub type PoolOrdering<T> = CoinbaseTipOrdering<T>;

/// Marker type indicating no validator wrapper has been set
/// Used to enforce at compile time that `with_validator_wrapper()` is called.
pub struct NoWrapper;

/// Marker type indicating a validator wrapper has been set
pub struct WithWrapper<F>(F);

/// Custom OP pool builder that extends OpPoolBuilder with custom validator support.
///
/// This wraps the standard OpPoolBuilder and adds the ability to inject a custom
/// validator wrapper while keeping all other behavior identical.
/// Original code from Reth: https://github.com/paradigmxyz/reth/blob/84785f025eac5eed123997454998db77a299e1e5/crates/optimism/node/src/node.rs#L875-L1031
///
/// # Type Parameters
/// * `T` - The transaction type (typically `FBPooledTransaction`)
/// * `W` - Wrapper state: `NoWrapper` before calling `with_validator_wrapper()`,
///   `WithWrapper<F>` after. This enforces at compile time that a wrapper is provided.
///
/// # Example
/// ```ignore
/// // This compiles - wrapper is provided:
/// let builder = CustomOpPoolBuilder::default()
///     .with_validator_wrapper(|v| MyValidator::new(v));
///
/// // This won't compile - no wrapper provided:
/// // let builder: CustomOpPoolBuilder<_, NoWrapper> = CustomOpPoolBuilder::default();
/// // builder.build_pool(ctx); // Error: PoolBuilder not implemented for NoWrapper
/// ```
#[derive(Clone)]
pub struct CustomOpPoolBuilder<T, W = NoWrapper> {
    /// The inner OP pool builder - delegates all standard behavior to this
    inner: OpPoolBuilder<T>,
    /// Validator wrapper state (typestate pattern)
    wrapper: W,
    /// Phantom data for transaction type
    _phantom: PhantomData<T>,
}

impl<T> Default for CustomOpPoolBuilder<T, NoWrapper> {
    fn default() -> Self {
        Self {
            inner: OpPoolBuilder::default(),
            wrapper: NoWrapper,
            _phantom: PhantomData,
        }
    }
}

impl<T, W> CustomOpPoolBuilder<T, W> {
    /// Create a new CustomOpPoolBuilder from an OpPoolBuilder
    pub fn new(inner: OpPoolBuilder<T>) -> CustomOpPoolBuilder<T, NoWrapper> {
        CustomOpPoolBuilder {
            inner,
            wrapper: NoWrapper,
            _phantom: PhantomData,
        }
    }

    // Forward all OpPoolBuilder methods

    pub fn with_enable_tx_conditional(mut self, enable: bool) -> Self {
        self.inner = self.inner.with_enable_tx_conditional(enable);
        self
    }

    pub fn with_pool_config_overrides(mut self, overrides: PoolBuilderConfigOverrides) -> Self {
        self.inner = self.inner.with_pool_config_overrides(overrides);
        self
    }

    pub fn with_supervisor(mut self, url: String, safety_level: SafetyLevel) -> Self {
        self.inner = self.inner.with_supervisor(url, safety_level);
        self
    }
}

impl<T> CustomOpPoolBuilder<T, NoWrapper> {
    /// Set a custom validator wrapper function.
    ///
    /// This function will be called with the built OpTransactionValidator,
    /// allowing you to wrap it with your custom validation logic.
    ///
    /// **Required**: This method must be called before `build_pool()` can be used.
    /// The typestate pattern enforces this at compile time.
    pub fn with_validator_wrapper<F>(self, wrapper: F) -> CustomOpPoolBuilder<T, WithWrapper<F>> {
        CustomOpPoolBuilder {
            inner: self.inner,
            wrapper: WithWrapper(wrapper),
            _phantom: PhantomData,
        }
    }
}

// Only implement PoolBuilder for CustomOpPoolBuilder with a wrapper set
impl<Node, T, F, V> PoolBuilder<Node> for CustomOpPoolBuilder<T, WithWrapper<F>>
where
    Node:
        FullNodeTypes<Types: reth_node_api::NodeTypes<ChainSpec: reth_optimism_forks::OpHardforks>>,
    T: reth_transaction_pool::EthPoolTransaction<Consensus = reth_node_api::TxTy<Node::Types>>
        + reth_optimism_txpool::OpPooledTx
        + Clone,
    F: FnOnce(reth_optimism_txpool::OpTransactionValidator<Node::Provider, T>) -> V + Send,
    V: TransactionValidator<Transaction = T> + 'static,
{
    type Pool = Pool<
        TransactionValidationTaskExecutor<V>,
        PoolOrdering<T>,
        reth_transaction_pool::blobstore::DiskFileBlobStore,
    >;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let CustomOpPoolBuilder {
            inner,
            wrapper: WithWrapper(wrapper),
            ..
        } = self;
        let OpPoolBuilder {
            pool_config_overrides,
            enable_tx_conditional,
            supervisor_http,
            supervisor_safety_level,
            ..
        } = inner;

        if ctx
            .chain_spec()
            .is_interop_active_at_timestamp(ctx.head().timestamp)
            && supervisor_http == DEFAULT_SUPERVISOR_URL
        {
            info!(
                target: "reth::cli",
                url=%DEFAULT_SUPERVISOR_URL,
                "Default supervisor url is used, consider changing --rollup.supervisor-http."
            );
        }

        let supervisor_client = SupervisorClient::builder(supervisor_http.clone())
            .minimum_safety(supervisor_safety_level)
            .build()
            .await;

        let blob_store = reth_node_builder::components::create_blob_store(ctx)?;
        let op_validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .no_eip4844()
            .with_head_timestamp(ctx.head().timestamp)
            .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
            .kzg_settings(ctx.kzg_settings()?)
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
            .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
            .with_additional_tasks(
                pool_config_overrides
                    .additional_validation_tasks
                    .unwrap_or_else(|| ctx.config().txpool.additional_validation_tasks),
            )
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone())
            .map(|validator| {
                reth_optimism_txpool::OpTransactionValidator::new(validator)
                    // In --dev mode we can't require gas fees because we're unable to decode
                    // the L1 block info
                    .require_l1_data_gas_fee(!ctx.config().dev.dev)
                    .with_supervisor(supervisor_client.clone())
            });

        info!(
            target: "reth::cli",
            "Custom transaction validator enabled"
        );

        let mut wrapper = Some(wrapper);
        let final_validator = op_validator.map(move |validator| {
            let wrapper = wrapper
                .take()
                .expect("validator wrapper should be called exactly once");
            wrapper(validator)
        });

        let final_pool_config = pool_config_overrides.clone().apply(ctx.pool_config());

        #[cfg(feature = "rules")]
        let transaction_pool = reth_node_builder::components::TxPoolBuilder::new(ctx)
            .with_validator(final_validator)
            .build_with_ordering_and_spawn_maintenance_task(
                ScoreOrdering::default(),
                blob_store,
                final_pool_config,
            )?;

        #[cfg(not(feature = "rules"))]
        let transaction_pool = reth_node_builder::components::TxPoolBuilder::new(ctx)
            .with_validator(final_validator)
            .build_and_spawn_maintenance_task(blob_store, final_pool_config)?;

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        // The Op txpool maintenance task is only spawned when interop is active
        if ctx
            .chain_spec()
            .is_interop_active_at_timestamp(ctx.head().timestamp)
        {
            // spawn the Op txpool maintenance task
            let chain_events = ctx.provider().canonical_state_stream();
            ctx.task_executor().spawn_critical(
                "Op txpool interop maintenance task",
                reth_optimism_txpool::maintain::maintain_transaction_pool_interop_future(
                    transaction_pool.clone(),
                    chain_events,
                    supervisor_client,
                ),
            );
            debug!(target: "reth::cli", "Spawned Op interop txpool maintenance task");
        }

        if enable_tx_conditional {
            // spawn the Op txpool maintenance task
            let chain_events = ctx.provider().canonical_state_stream();
            ctx.task_executor().spawn_critical(
                "Op txpool conditional maintenance task",
                reth_optimism_txpool::maintain::maintain_transaction_pool_conditional_future(
                    transaction_pool.clone(),
                    chain_events,
                ),
            );
            debug!(target: "reth::cli", "Spawned Op conditional txpool maintenance task");
        }

        Ok(transaction_pool)
    }
}
