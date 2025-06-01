use super::{builder::PayloadJobGenerator, FlashblocksConfig};
use crate::{
    builders::BuilderConfig,
    traits::{NodeBounds, PoolBounds},
};
use reth_node_api::NodeTypes;
use reth_node_builder::{components::PayloadServiceBuilder, BuilderContext};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::CanonStateSubscriptions;

pub struct FlashblocksServiceBuilder(pub BuilderConfig<FlashblocksConfig>);

impl<Node, Pool> PayloadServiceBuilder<Node, Pool, OpEvmConfig> for FlashblocksServiceBuilder
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
        tracing::debug!("Spawning flashblocks payload builder service");
        let job_generator = PayloadJobGenerator::new(
            pool,
            ctx.provider().clone(),
            OpEvmConfig::optimism(ctx.chain_spec()),
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
