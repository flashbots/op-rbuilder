use super::BuilderConfig;
use crate::traits::{NodeBounds, PoolBounds};
use config::FlashblocksConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use service::FlashblocksServiceBuilder;

mod builder;
mod config;
mod context;
mod empty;
mod job;
mod service;
mod wspub;

/// Block building strategy that progressively builds chunks of a block and makes them available
/// through a websocket update, then merges them into a full block every chain block time.
pub struct FlashblocksExperimentalBuilder;

impl super::PayloadBuilder for FlashblocksExperimentalBuilder {
    type Config = FlashblocksConfig;

    type ServiceBuilder<Node, Pool>
        = FlashblocksServiceBuilder
    where
        Node: NodeBounds,
        Pool: PoolBounds;

    fn new_service<Node, Pool>(
        config: BuilderConfig<Self::Config>,
    ) -> eyre::Result<Self::ServiceBuilder<Node, Pool>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
    {
        Ok(FlashblocksServiceBuilder(config))
    }
}

type PayloadAttributes = OpPayloadBuilderAttributes<OpTransactionSigned>;
