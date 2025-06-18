//! Experimental block builder
//!
//! This is an experimental block builder that uses `rblib` API for building blocks.

use super::PayloadBuilder;
use crate::{
    builders::BuilderConfig,
    traits::{NodeBounds, PoolBounds},
};
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use service::ExperimentalServiceBuilder;

mod empty;
mod job;
mod service;

/// Block building strategy that has feature parity with StandardBuilder but uses the `rblib` API.
pub struct ExperimentalBuilder;

impl PayloadBuilder for ExperimentalBuilder {
    type Config = ();

    type ServiceBuilder<Node, Pool>
        = ExperimentalServiceBuilder
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
        Ok(ExperimentalServiceBuilder(config))
    }
}

pub type PayloadAttributes = OpPayloadBuilderAttributes<OpTransactionSigned>;
