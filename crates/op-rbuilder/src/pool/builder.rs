use alloy_primitives::TxHash;
use futures::StreamExt;
use moka::sync::Cache;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{BuilderContext, components::PoolBuilder};
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpPoolBuilder;
use reth_optimism_txpool::{OpPooledTx, OpTransactionPool};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    AllTransactionsEvents, EthPoolTransaction, FullTransactionEvent, TransactionPool,
    blobstore::DiskFileBlobStore,
};

use crate::{args::OpRbuilderArgs, pool::Flashpool, tx::FBPooledTransaction};

pub struct FlashpoolBuilder {
    op_pool_builder: OpPoolBuilder<FBPooledTransaction>,

    enable_revert_protection: bool,
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
        }
    }
}

impl<Node, Evm> PoolBuilder<Node, Evm> for FlashpoolBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: OpHardforks>>,
    FBPooledTransaction: EthPoolTransaction<Consensus = TxTy<Node::Types>> + OpPooledTx,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Node::Types>> + Clone + 'static,
{
    type Pool =
        Flashpool<OpTransactionPool<Node::Provider, DiskFileBlobStore, Evm, FBPooledTransaction>>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let Self {
            op_pool_builder,
            enable_revert_protection,
        } = self;

        let inner_pool = op_pool_builder.build_pool(ctx, evm_config).await?;

        let reverted_cache = enable_revert_protection.then_some(setup_revert_protection(
            ctx.task_executor(),
            inner_pool.all_transactions_event_listener(),
        ));

        Ok(Flashpool {
            inner: inner_pool,
            reverted_cache,
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
