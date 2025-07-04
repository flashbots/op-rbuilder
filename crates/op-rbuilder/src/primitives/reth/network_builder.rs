use alloy_rpc_types_eth::Peers;
use reth::api::{NodeTypes, PrimitivesTy, TxTy};
use reth::chainspec::Hardforks;
use reth::network::{NetworkHandle, NetworkManager};
use reth::network::primitives::BasicNetworkPrimitives;
use reth_network_peers::PeerId;
use reth_node_api::FullNodeTypes;
use reth_node_builder::BuilderContext;
use reth_node_builder::components::NetworkBuilder;
use reth_optimism_node::OpNetworkBuilder;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use tracing::info;

#[derive(Clone, Debug)]
struct CustomOpNetworkBuilder{
    inner: OpNetworkBuilder,
    peers: Vec<PeerId>
}

impl CustomOpNetworkBuilder {
    fn new(inner: OpNetworkBuilder, peers: Vec<PeerId>) -> Self {
        CustomOpNetworkBuilder{
            inner,
            peers,
        }
    }
}


impl<Node, Pool> NetworkBuilder<Node, Pool> for CustomOpNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: Hardforks>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
    + Unpin
    + 'static,
{
    type Network =
    NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let network_config = self.0.network_config(ctx)?;
        let network = NetworkManager::builder(network_config).await?;
        let handle = ctx.start_network_with(network, pool, ctx.config().network.transactions_manager_config(), RbuilderTransactionPropagation);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "P2P networking initialized");

        Ok(handle)
    }
}

