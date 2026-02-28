use crate::{
    builders::standard::service::StandardServiceBuilder,
    traits::{NodeBounds, PoolBounds},
};

use super::BuilderConfig;

mod builder_tx;
mod payload;
mod service;

/// Block building strategy that builds blocks using the standard approach by
/// producing blocks every chain block time.
pub struct StandardBuilder;

impl super::PayloadBuilder for StandardBuilder {
    type ServiceBuilder<Node, Pool>
        = StandardServiceBuilder
    where
        Node: NodeBounds,
        Pool: PoolBounds;

    fn new_service<Node, Pool>(
        config: BuilderConfig,
    ) -> eyre::Result<Self::ServiceBuilder<Node, Pool>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
    {
        Ok(StandardServiceBuilder(config))
    }
}
