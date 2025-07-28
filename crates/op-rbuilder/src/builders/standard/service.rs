use reth_basic_payload_builder::{BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig};
use reth_node_api::NodeTypes;
use reth_node_builder::{components::PayloadServiceBuilder, BuilderContext};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::CanonStateSubscriptions;

use crate::{
    builders::{
        standard::payload::StandardOpPayloadBuilder, BuilderConfig, BuilderTransactions,
        StandardBuilderTx,
    },
    flashtestations::service::bootstrap_flashtestations,
    traits::{NodeBounds, PoolBounds},
};

pub struct StandardServiceBuilder(pub BuilderConfig<()>);

impl StandardServiceBuilder {
    pub fn spawn_payload_builder_service<Node, Pool, BuilderTx>(
        self,
        evm_config: OpEvmConfig,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        builder_tx: BuilderTx,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
        BuilderTx: BuilderTransactions + Unpin + Clone + Send + Sync + 'static,
    {
        let payload_builder = StandardOpPayloadBuilder::new(
            evm_config,
            pool,
            ctx.provider().clone(),
            self.0.clone(),
            builder_tx,
        );

        let conf = ctx.config().builder.clone();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval)
            .deadline(conf.deadline)
            .max_payload_tasks(conf.max_payload_tasks);

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
        );
        let (payload_service, payload_service_handle) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor()
            .spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_service_handle)
    }
}

impl<Node, Pool> PayloadServiceBuilder<Node, Pool, OpEvmConfig> for StandardServiceBuilder
where
    Node: NodeBounds,
    Pool: PoolBounds,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: OpEvmConfig,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
        let signer = self.0.builder_signer;
        if self.0.flashtestations_config.flashtestations_enabled {
            let flashtestation_builder_tx = match bootstrap_flashtestations(
                self.0.flashtestations_config.clone(),
                ctx,
                signer,
            )
            .await
            {
                Ok(flashtestation_builder_tx) => flashtestation_builder_tx,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to bootstrap flashtestations, falling back to standard builder tx");
                    return self.spawn_payload_builder_service(
                        evm_config,
                        ctx,
                        pool,
                        StandardBuilderTx::new(signer),
                    );
                }
            };

            if self.0.flashtestations_config.enable_block_proofs {
                return self.spawn_payload_builder_service(
                    evm_config,
                    ctx,
                    pool,
                    flashtestation_builder_tx,
                );
            }
        }

        self.spawn_payload_builder_service(evm_config, ctx, pool, StandardBuilderTx::new(signer))
    }
}
