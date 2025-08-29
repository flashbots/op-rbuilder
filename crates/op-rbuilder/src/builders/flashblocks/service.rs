use super::{FlashblocksConfig, payload::OpPayloadBuilder};
use crate::{
    builders::{
        BuilderConfig, BuilderTx, builder_tx::StandardBuilderTx,
        generator::BlockPayloadJobGenerator,
    },
    flashtestations::service::spawn_flashtestations_service,
    traits::{NodeBounds, PoolBounds},
};
use reth_basic_payload_builder::BasicPayloadJobGeneratorConfig;
use reth_node_api::NodeTypes;
use reth_node_builder::{BuilderContext, components::PayloadServiceBuilder};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::CanonStateSubscriptions;
use std::sync::Arc;

pub struct FlashblocksServiceBuilder(pub BuilderConfig<FlashblocksConfig>);

impl FlashblocksServiceBuilder {
    fn spawn_payload_builder_service<Node, Pool, BT>(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        builder_tx: BT,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
        BT: BuilderTx + Unpin + Clone + Send + Sync + 'static,
    {
        let once_lock = Arc::new(std::sync::OnceLock::new());

        let payload_builder = OpPayloadBuilder::new(
            OpEvmConfig::optimism(ctx.chain_spec()),
            pool,
            ctx.provider().clone(),
            self.0.clone(),
            builder_tx,
            once_lock.clone(),
        )?;

        let payload_job_config = BasicPayloadJobGeneratorConfig::default();

        let payload_generator = BlockPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
            true,
            self.0.block_time_leeway,
        );

        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        once_lock
            .set(payload_service.payload_events_handle())
            .map_err(|_| eyre::eyre!("Cannot initialize payload service handle"))?;

        ctx.task_executor()
            .spawn_critical("custom payload builder service", Box::pin(payload_service));

        tracing::info!("Flashblocks payload builder service started");

        Ok(payload_builder)
    }
}

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
        let signer = self.0.builder_signer;
        if self.0.flashtestations_config.flashtestations_enabled {
            let flashtestations_service = match spawn_flashtestations_service(
                self.0.flashtestations_config.clone(),
                ctx,
            )
            .await
            {
                Ok(service) => service,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to spawn flashtestations service, falling back to standard builder tx");
                    return self.spawn_payload_builder_service(
                        ctx,
                        pool,
                        StandardBuilderTx { signer },
                    );
                }
            };

            if self.0.flashtestations_config.enable_block_proofs {
                return self.spawn_payload_builder_service(ctx, pool, flashtestations_service);
            }
        }
        self.spawn_payload_builder_service(ctx, pool, StandardBuilderTx { signer })
    }
}
