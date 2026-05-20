use std::sync::Arc;

use alloy_primitives::TxHash;
use futures::{FutureExt, Stream, StreamExt};
use moka::sync::Cache;
use reth_chain_state::CanonStateSubscriptions;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{BuilderContext, components::PoolBuilder};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpPoolBuilder;
use reth_optimism_txpool::{OpPooledTx, OpTransactionPool, OpTransactionValidator};
use reth_primitives_traits::{Block, NodePrimitives};
use reth_provider::{
    BlockReaderIdExt, CanonStateNotification, ChainSpecProvider, NodePrimitivesProvider,
};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    AllTransactionsEvents, EthPoolTransaction, FullTransactionEvent, TransactionPool,
    TransactionValidationTaskExecutor, blobstore::DiskFileBlobStore,
};

use crate::{
    args::OpRbuilderArgs,
    backrun_bundle::{
        BackrunBundleArgs, BackrunBundleGlobalPool, maintain_backrun_bundle_pool_future,
    },
    pool::{
        Flashpool,
        metrics::PoolMetrics,
        presim::{TopOfBlockSimulator, maintain_pending_simulations, maintain_tip_state},
    },
    tx::FBPooledTransaction,
};

pub struct FlashpoolBuilder {
    op_pool_builder: OpPoolBuilder<FBPooledTransaction>,

    enable_revert_protection: bool,
    pre_simulate_bundles: bool,
    presim_max_concurrent: usize,
    block_time_secs: u64,

    backrun_bundle_args: BackrunBundleArgs,
}

impl FlashpoolBuilder {
    pub fn new(builder_args: &OpRbuilderArgs) -> Self {
        let rollup_args = &builder_args.rollup_args;
        let op_pool_builder = OpPoolBuilder::<FBPooledTransaction>::default()
            .with_enable_tx_conditional(
                // Revert protection uses the same internal pool logic as conditional transactions
                // to garbage collect transactions out of the bundle range.
                rollup_args.enable_tx_conditional || builder_args.enable_revert_protection,
            );

        Self {
            op_pool_builder,
            enable_revert_protection: builder_args.enable_revert_protection,
            pre_simulate_bundles: builder_args.pre_simulate_bundles,
            presim_max_concurrent: builder_args.presim_max_concurrent,
            block_time_secs: builder_args.chain_block_time / 1000,
            backrun_bundle_args: builder_args.backrun_bundle.clone(),
        }
    }
}

impl<Node, Evm> PoolBuilder<Node, Evm> for FlashpoolBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: OpHardforks>>,
    Node::Provider: ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt<Header = alloy_consensus::Header>,
    <Node::Provider as NodePrimitivesProvider>::Primitives:
        NodePrimitives<Block: Block<Header = alloy_consensus::Header>>,
    FBPooledTransaction: EthPoolTransaction<Consensus = TxTy<Node::Types>> + OpPooledTx,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>> + Clone + 'static,
{
    type Pool = Flashpool<
        OpTransactionPool<Node::Provider, DiskFileBlobStore, Evm, FBPooledTransaction>,
        TransactionValidationTaskExecutor<
            OpTransactionValidator<Node::Provider, FBPooledTransaction, Evm>,
        >,
    >;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let Self {
            op_pool_builder,
            enable_revert_protection,
            pre_simulate_bundles,
            presim_max_concurrent,
            block_time_secs,
            backrun_bundle_args,
        } = self;

        let inner_pool = op_pool_builder.build_pool(ctx, evm_config).await?;

        let reverted_cache = enable_revert_protection.then_some(setup_revert_protection(
            ctx.task_executor(),
            inner_pool.all_transactions_event_listener(),
        ));

        let validator = inner_pool.validator().clone();
        let metrics = Arc::new(PoolMetrics::default());

        let simulator = if pre_simulate_bundles {
            let simulator = Arc::new(TopOfBlockSimulator::new(
                presim_max_concurrent,
                metrics.clone(),
            ));

            let chain_events = ctx.provider().canonical_state_stream();
            let op_evm_config = OpEvmConfig::optimism(ctx.provider().chain_spec());
            ctx.task_executor().spawn_task(
                maintain_tip_state(
                    simulator.clone(),
                    ctx.provider().clone(),
                    op_evm_config,
                    block_time_secs,
                    metrics.clone(),
                    chain_events,
                )
                .boxed(),
            );

            let pending_events = inner_pool.all_transactions_event_listener();
            ctx.task_executor().spawn_task(
                maintain_pending_simulations(
                    simulator.clone(),
                    inner_pool.clone(),
                    metrics.clone(),
                    pending_events,
                )
                .boxed(),
            );

            Some(simulator)
        } else {
            None
        };

        let backrun_bundle_pool = setup_backruns(
            backrun_bundle_args,
            ctx.provider().canonical_state_stream(),
            ctx.task_executor(),
        );

        Ok(Flashpool {
            inner: inner_pool,
            validator,
            simulator,
            backrun_bundle_pool,
            task_executor: ctx.task_executor().clone(),
            reverted_cache,
            metrics,
        })
    }
}

fn setup_revert_protection(
    task_executor: &TaskExecutor,
    mut events: AllTransactionsEvents<FBPooledTransaction>,
) -> Cache<TxHash, ()> {
    let reverted_cache: Cache<_, ()> = Cache::builder().max_capacity(100).build();
    // Reverted transactions are removed from the pool by the conditional-tx GC
    // maintenance task. This is spawned during `OpPoolBuilder::build_pool` and
    // accesses the inner `OpTransactionPool` directly, calling
    // `remove_transactions`. Unfortunately, this bypasses our Flashpool
    // wrapper. So to ensure the reverted_cache is populated, we need to
    // subscribe to pool events and insert on Discarded events.
    task_executor.spawn_task({
        let reverted_cache = reverted_cache.clone();
        async move {
            while let Some(event) = events.next().await {
                if let FullTransactionEvent::Discarded(hash) = event {
                    reverted_cache.insert(hash, ());
                }
            }
        }
    });

    reverted_cache
}

fn setup_backruns<N, St>(
    backrun_bundle_args: BackrunBundleArgs,
    events: St,
    task_executor: &TaskExecutor,
) -> Option<BackrunBundleGlobalPool>
where
    N: NodePrimitives,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    if !backrun_bundle_args.backruns_enabled {
        return None;
    }

    let backrun_bundle_pool =
        BackrunBundleGlobalPool::new(backrun_bundle_args.enforce_strict_priority_fee_ordering);

    let task_executor_clone = task_executor.clone();
    task_executor.spawn_task(maintain_backrun_bundle_pool_future(
        backrun_bundle_pool.clone(),
        events,
        task_executor_clone,
    ));

    Some(backrun_bundle_pool)
}
