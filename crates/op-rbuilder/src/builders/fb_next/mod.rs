//! Flashblocks experimental block builder
//!
//! This is an experimental implementation of the flashblocks builder that builds
//! chunks of a block every short interval and makes them available through a
//! websocket update, then merges them into a full block every chain block time.
//!
//! TODO:
//! Once it is stabilized we will need to merge it into the main flashblocks builder.

use super::{BlockBuilderSystem, BuilderConfig};
use crate::traits::{NodeBounds, PoolBounds};
use config::FlashblocksConfig;
use service::FlashblocksServiceBuilder;

mod block;
mod config;
mod empty;
mod job;
mod payload;
mod service;
mod wspub;

/// Block building strategy that progressively builds chunks of a block and makes them available
/// through a websocket update, then merges them into a full block every chain block time.
pub struct FlashblocksExperimentalBuilder;

impl BlockBuilderSystem for FlashblocksExperimentalBuilder {
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
