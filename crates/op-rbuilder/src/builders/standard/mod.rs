use payload::StandardPayloadBuilderBuilder;
use reth_node_builder::components::BasicPayloadServiceBuilder;

use crate::traits::{NodeBounds, PoolBounds};
use reth_provider::{BlockReader, DatabaseProviderFactory, StateCommitmentProvider};

use super::BuilderConfig;

mod payload;

/// Block building strategy that builds blocks using the standard approach by
/// producing blocks every chain block time.
pub struct StandardBuilder;

impl super::PayloadBuilder for StandardBuilder {
    type Config = ();

    type ServiceBuilder<Node, Pool>
        = BasicPayloadServiceBuilder<StandardPayloadBuilderBuilder>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
        Node::Provider: StateCommitmentProvider,
        <Node::Provider as DatabaseProviderFactory>::Provider: BlockReader;

    fn new_service<Node, Pool>(
        config: BuilderConfig<Self::Config>,
    ) -> eyre::Result<Self::ServiceBuilder<Node, Pool>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
        Node::Provider: StateCommitmentProvider,
        <Node::Provider as DatabaseProviderFactory>::Provider: BlockReader,
    {
        Ok(BasicPayloadServiceBuilder::new(
            StandardPayloadBuilderBuilder(config),
        ))
    }
}
