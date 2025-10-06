use super::{FlashblocksConfig, payload::OpPayloadBuilder};
use crate::{
    builders::{
        BuilderConfig,
        builder_tx::BuilderTransactions,
        flashblocks::{
            builder_tx::{FlashblocksBuilderTx, FlashblocksNumberBuilderTx},
            p2p::{AGENT_VERSION, FLASHBLOCKS_STREAM_PROTOCOL, Message},
            payload::FlashblocksExtraCtx,
            payload_handler::PayloadHandler,
        },
        generator::BlockPayloadJobGenerator,
    },
    flashtestations::service::bootstrap_flashtestations,
    traits::{NodeBounds, PoolBounds},
};
use eyre::WrapErr as _;
use reth_basic_payload_builder::BasicPayloadJobGeneratorConfig;
use reth_node_api::NodeTypes;
use reth_node_builder::{BuilderContext, components::PayloadServiceBuilder};
use reth_optimism_evm::OpEvmConfig;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_provider::CanonStateSubscriptions;

pub struct FlashblocksServiceBuilder(pub BuilderConfig<FlashblocksConfig>);

impl FlashblocksServiceBuilder {
    fn spawn_payload_builder_service<Node, Pool, BuilderTx>(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        builder_tx: BuilderTx,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>>
    where
        Node: NodeBounds,
        Pool: PoolBounds,
        BuilderTx: BuilderTransactions<FlashblocksExtraCtx> + Unpin + Clone + Send + Sync + 'static,
    {
        let (incoming_message_rx, outgoing_message_tx) = if self.0.p2p_enabled {
            let mut builder = p2p::NodeBuilder::new();

            if let Some(ref private_key_file) = self.0.p2p_private_key_file
                && !private_key_file.is_empty()
            {
                let private_key_hex = std::fs::read_to_string(private_key_file)
                    .wrap_err_with(|| {
                        format!("failed to read p2p private key file: {private_key_file}")
                    })?
                    .trim()
                    .to_string();
                builder = builder.with_keypair_hex_string(private_key_hex);
            }

            let known_peers: Vec<p2p::Multiaddr> = self
                .0
                .p2p_known_peers
                .split(',')
                .map(|s| s.to_string())
                .filter_map(|s| s.parse().ok())
                .collect();

            let p2p::NodeBuildResult {
                node,
                outgoing_message_tx,
                mut incoming_message_rxs,
            } = builder
                .with_agent_version(AGENT_VERSION.to_string())
                .with_protocol(FLASHBLOCKS_STREAM_PROTOCOL)
                .with_known_peers(known_peers)
                .with_port(self.0.p2p_port)
                .try_build::<Message>()
                .wrap_err("failed to build flashblocks p2p node")?;
            let multiaddrs = node.multiaddrs();
            ctx.task_executor().spawn(async move {
                if let Err(e) = node.run().await {
                    tracing::error!(error = %e, "p2p node exited");
                }
            });
            tracing::info!(multiaddrs = ?multiaddrs, "flashblocks p2p node started");

            let incoming_message_rx = incoming_message_rxs
                .remove(&FLASHBLOCKS_STREAM_PROTOCOL)
                .expect("flashblocks p2p protocol must be found in receiver map");
            (incoming_message_rx, outgoing_message_tx)
        } else {
            let (_incoming_message_tx, incoming_message_rx) = tokio::sync::mpsc::channel(16);
            let (outgoing_message_tx, _outgoing_message_rx) = tokio::sync::mpsc::channel(16);
            (incoming_message_rx, outgoing_message_tx)
        };

        let (built_payload_tx, built_payload_rx) = tokio::sync::mpsc::channel(16);
        let payload_builder = OpPayloadBuilder::new(
            OpEvmConfig::optimism(ctx.chain_spec()),
            pool,
            ctx.provider().clone(),
            self.0.clone(),
            builder_tx,
            built_payload_tx,
        )
        .wrap_err("failed to create flashblocks payload builder")?;

        let payload_job_config = BasicPayloadJobGeneratorConfig::default();

        let payload_generator = BlockPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            payload_job_config,
            payload_builder,
            true,
            self.0.block_time_leeway,
        );

        let (payload_service, payload_builder_handle) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        let payload_handler = PayloadHandler::new(
            built_payload_rx,
            incoming_message_rx,
            outgoing_message_tx,
            payload_service.payload_events_handle(),
        );

        ctx.task_executor()
            .spawn_critical("custom payload builder service", Box::pin(payload_service));
        ctx.task_executor().spawn_critical(
            "flashblocks payload handler",
            Box::pin(payload_handler.run()),
        );

        tracing::info!("Flashblocks payload builder service started");
        Ok(payload_builder_handle)
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
        let signer = self.0.builder_signer;
        let flashtestations_builder_tx = if self.0.flashtestations_config.flashtestations_enabled {
            match bootstrap_flashtestations(self.0.flashtestations_config.clone(), ctx).await {
                Ok(builder_tx) => Some(builder_tx),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to bootstrap flashtestations, builder will not include flashtestations txs");
                    None
                }
            }
        } else {
            None
        };

        if let Some(flashblocks_number_contract_address) =
            self.0.specific.flashblocks_number_contract_address
        {
            self.spawn_payload_builder_service(
                ctx,
                pool,
                FlashblocksNumberBuilderTx::new(
                    signer,
                    flashblocks_number_contract_address,
                    flashtestations_builder_tx,
                ),
            )
        } else {
            self.spawn_payload_builder_service(
                ctx,
                pool,
                FlashblocksBuilderTx::new(signer, flashtestations_builder_tx),
            )
        }
    }
}
