use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{BuilderContext, components::PoolBuilder};
use reth_optimism_forks::OpHardforks;
use reth_optimism_node::OpPoolBuilder;
use reth_optimism_txpool::{OpPooledTx, OpTransactionPool};
use reth_transaction_pool::{EthPoolTransaction, blobstore::DiskFileBlobStore};

use crate::{args::OpRbuilderArgs, pool::Flashpool, tx::FBPooledTransaction};

pub struct FlashpoolBuilder {
    op_pool_builder: OpPoolBuilder<FBPooledTransaction>,
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

        Self { op_pool_builder }
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
        Ok(Flashpool {
            inner: self.op_pool_builder.build_pool(ctx, evm_config).await?,
        })
    }
}
