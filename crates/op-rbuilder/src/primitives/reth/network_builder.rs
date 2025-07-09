use crate::primitives::reth::transaction_policy::RbuilderTransactionPropagation;
use reth::{
    api::{NodeTypes, PrimitivesTy, TxTy},
    chainspec::Hardforks,
    network::{
        primitives::BasicNetworkPrimitives, transactions::TransactionPropagationMode,
        NetworkHandle, NetworkManager, PeersInfo,
    },
};
use reth_network_peers::PeerId;
use reth_node_api::FullNodeTypes;
use reth_node_builder::{components::NetworkBuilder, BuilderContext};
use reth_optimism_node::OpNetworkBuilder;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use tracing::info;

#[derive(Clone, Debug)]
pub struct CustomOpNetworkBuilder {
    pub inner: OpNetworkBuilder,
    pub peers: Vec<PeerId>,
}

impl CustomOpNetworkBuilder {
    pub fn new(
        disable_txpool_gossip: bool,
        disable_discovery_v4: bool,
        peers: Vec<PeerId>,
    ) -> Self {
        CustomOpNetworkBuilder {
            inner: OpNetworkBuilder::new(disable_txpool_gossip, disable_discovery_v4),
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
        let network_config = self.inner.network_config(ctx)?;
        let network = NetworkManager::builder(network_config).await?;
        let mut manager_config = ctx.config().network.transactions_manager_config();
        manager_config.propagation_mode = TransactionPropagationMode::All;
        let handle = ctx.start_network_with(
            network,
            pool,
            manager_config,
            RbuilderTransactionPropagation::new(self.peers),
        );
        info!(target: "reth::cli", enode=%handle.local_node_record(), "Custom P2P networking initialized");

        Ok(handle)
    }
}
