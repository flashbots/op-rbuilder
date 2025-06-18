//! Builder Service Management
//!
//! This module contains types that are an interface between Reth node and the block building
//! service. This is where we acquire references to various node components and pass them
//! to parts of the block building service implementation.
//!
//! This is also the entrypoint for Reth to spawn the service and signal various system events
//! such as node startup, payload job requests, and others.

use std::sync::Arc;
use std::ops::Deref;
use reth_node_api::{NodeTypes, PayloadBuilderError};
use reth_node_builder::{components::PayloadServiceBuilder, BuilderContext};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::CanonStateSubscriptions;
use tracing::info;

use crate::{
    builders::BuilderConfig,
    traits::{ClientBounds, NodeBounds, PoolBounds},
};
use super::job::PayloadJob;
use super::PayloadAttributes;

/// This type is used by reth during node construction to create *one* instance of the
/// [`PayloadBuilderHandle`] for the experimental builder.
///
/// `spawn_payload_builder_service` is called by the node builder once and here we
/// have all the logic necessary to create a self-contained instance of the block building
/// service. This is where we take references to other components of the node, such as the
/// data provider, the pool, evm config and others.
///
/// The type that interfaces with the node is called `PayloadJobGenerator`, which is called
/// by Reth whenever the CL wants to start building a new payload. In case of Optimism L2,
/// this is done by the sequencer for every new block that is produced.
pub struct ExperimentalServiceBuilder(pub(super) BuilderConfig<()>);
impl<Node, Pool> PayloadServiceBuilder<Node, Pool, OpEvmConfig> for ExperimentalServiceBuilder
where
    Node: NodeBounds,
    Pool: PoolBounds,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        _: OpEvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
        tracing::debug!("Spawning experimental payload builder service");
        let job_generator = PayloadJobGenerator::new(
            pool,
            ctx.provider().clone(),
            OpEvmConfig::optimism(ctx.chain_spec()),
            self.0.clone(),
        );

        let (payload_service, payload_builder) =
            PayloadBuilderService::new(job_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor().spawn_critical(
            "experimental flashblocks payload builder service",
            Box::pin(payload_service),
        );

        Ok(payload_builder)
    }
}

/// This type is stored inside the [`PayloadBuilderService`] type in Reth. There's one instance of this
/// type per node and it is instantiated during the node startup inside `spawn_payload_builder_service`.
///
/// The responsibility of this type is to respond to new payload requests when FCU calls come from the
/// CL Node. Each FCU call will generate a new PayloadID on its side and will pass it to the
/// `new_payload_job` method.
pub struct PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    pool: Pool,
    ctx: Arc<ServiceContext<Client>>,
}

impl<Pool, Client> PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    pub fn new(
        pool: Pool,
        client: Client,
        evm_config: OpEvmConfig,
        builder_config: BuilderConfig<()>,
    ) -> Self {
        Self {
            pool,
            ctx: Arc::new(ServiceContext::new(client, evm_config, builder_config)),
        }
    }
}

impl<Pool, Client> reth_payload_builder::PayloadJobGenerator for PayloadJobGenerator<Pool, Client>
where
    Pool: PoolBounds,
    Client: ClientBounds,
{
    type Job = PayloadJob<Client>;

    fn new_payload_job(&self, attr: PayloadAttributes) -> Result<Self::Job, PayloadBuilderError> {
        info!("PayloadJobGenerator::new_payload_job {attr:#?}");
        Ok(PayloadJob::new(attr, Arc::clone(&self.ctx))?)
    }
}

/// Holds types that give access to the reth instance we're running in, that is relevant throughout
/// the whole block building service lifecycle. One instance of this type is created during system
/// startup and access to it is provided to all individual short-lived tasks.
pub struct ServiceContext<Client>
where
    Client: ClientBounds,
{
    provider: Client,
    evm_config: OpEvmConfig,
    builder_config: BuilderConfig<()>,
}

impl<Client> ServiceContext<Client>
where
    Client: ClientBounds,
{
    /// Create a new builder context.
    pub fn new(client: Client, evm_config: OpEvmConfig, builder_config: BuilderConfig<()>) -> Self {
        Self {
            provider: client,
            evm_config,
            builder_config,
        }
    }

    /// Access to the underlying chain state provider of the node.
    pub const fn provider(&self) -> &Client {
        &self.provider
    }

    /// Get the EVM configuration associated with this node.
    pub const fn evm_config(&self) -> &OpEvmConfig {
        &self.evm_config
    }

    /// Get the builder configuration associated with this node.
    pub const fn builder_config(&self) -> &BuilderConfig<()> {
        &self.builder_config
    }
}

impl<Client> Deref for ServiceContext<Client>
where
    Client: ClientBounds,
{
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}
