use super::{
    builders::{BuilderConfig, PayloadBuilder},
    monitor_tx_pool::monitor_tx_pool,
    primitives::reth::engine_api_builder::OpEngineApiBuilder,
    revert_protection::{EthApiOverrideServer, RevertProtectionExt},
    tx::FBPooledTransaction,
};
use crate::{OpRbuilderArgs, VERSION};
use core::fmt::Debug;
use eyre::{eyre, Result};
use futures::{future, Future};
use reth::builder::{NodeBuilder, WithLaunchContext};
use reth_cli_commands::launcher::Launcher;
use reth_db::mdbx::DatabaseEnv;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::chainspec::OpChainSpecParser;
use reth_optimism_node::{
    args::RollupArgs,
    node::{OpAddOnsBuilder, OpEngineValidatorBuilder, OpPoolBuilder},
    OpNode,
};
use reth_transaction_pool::TransactionPool;
use std::{marker::PhantomData, sync::Arc};

pub struct NoLauncher;

impl Launcher<OpChainSpecParser, OpRbuilderArgs> for NoLauncher {
    fn entrypoint(
        self,
        _builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, OpChainSpec>>,
        _builder_args: OpRbuilderArgs,
    ) -> impl Future<Output = Result<()>> {
        future::ok(())
    }
}

pub struct BuilderLauncher<B> {
    _builder: PhantomData<B>,
}

impl<B> BuilderLauncher<B>
where
    B: PayloadBuilder,
{
    pub fn new() -> Self {
        Self {
            _builder: PhantomData,
        }
    }

    /*
    fn op_node(
        builder_args: &OpRbuilderArgs,
    ) -> Result<()> {
        let builder_config = BuilderConfig::<B::Config>::try_from(builder_args.clone())
                .map_err(|_| eyre!("Failed to convert rollup args to builder config"))?;
        let rollup_args = builder_args.rollup_args.clone();
        let op_node = OpNode::new(rollup_args);
        let comp = op_node
            .components()
            .pool(
                OpPoolBuilder::<FBPooledTransaction>::default()
                .with_enable_tx_conditional(
                    // Revert protection uses the same internal pool logic as conditional transactions
                    // to garbage collect transactions out of the bundle range.
                    rollup_args.enable_tx_conditional
                    || builder_args.enable_revert_protection,
                )
                .with_supervisor(
                    rollup_args.supervisor_http.clone(),
                    rollup_args.supervisor_safety_level,
                ),
            )
            .payload(B::new_service(builder_config)?);
        Ok(comp)
    }
    */

    /*
    fn add_ons(builder_args: &OpRbuilderArgs) -> RcpAddOns {
        let builder_config = BuilderConfig::<B::Config>::try_from(builder_args.clone())
            .expect("Failed to convert rollup args to builder config");
        let da_config = builder_config.da_config.clone();
        let rollup_args = &builder_args.rollup_args;
        let default_builder = OpEngineApiBuilder::<OpEngineValidatorBuilder>::default()
            .with_engine_peers(builder_args.engine_peers.clone());
        OpAddOnsBuilder::default()
            .with_sequencer(rollup_args.sequencer.clone())
            .with_enable_tx_conditional(rollup_args.enable_tx_conditional)
            .with_da_config(da_config)
            .build()
            .rpc_add_ons
            .with_engine_api(default_builder)
    }
    */
}

impl<B> Launcher<OpChainSpecParser, OpRbuilderArgs> for BuilderLauncher<B>
where
    B: PayloadBuilder,
    BuilderConfig<B::Config>: TryFrom<OpRbuilderArgs>,
    <BuilderConfig<B::Config> as TryFrom<OpRbuilderArgs>>::Error: Debug,
{
    fn entrypoint(
        self,
        builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, OpChainSpec>>,
        builder_args: OpRbuilderArgs,
    ) -> impl Future<Output = Result<()>> {
        async move {
            let builder_config = BuilderConfig::<B::Config>::try_from(builder_args.clone())
                .expect("Failed to convert rollup args to builder config");
            let default_builder: OpEngineApiBuilder<OpEngineValidatorBuilder> =
                OpEngineApiBuilder::default().with_engine_peers(builder_args.engine_peers.clone());
            let da_config = builder_config.da_config.clone();
            let rollup_args = builder_args.rollup_args;
            let op_node = OpNode::new(rollup_args.clone());
            let handle = builder
                .with_types::<OpNode>()
                .with_components(
                    op_node
                        .components()
                        .pool(
                            OpPoolBuilder::<FBPooledTransaction>::default()
                                .with_enable_tx_conditional(
                                    // Revert protection uses the same internal pool logic as conditional transactions
                                    // to garbage collect transactions out of the bundle range.
                                    rollup_args.enable_tx_conditional
                                        || builder_args.enable_revert_protection,
                                )
                                .with_supervisor(
                                    rollup_args.supervisor_http.clone(),
                                    rollup_args.supervisor_safety_level,
                                ),
                        )
                        .payload(B::new_service(builder_config)?),
                )
                .with_add_ons(
                    OpAddOnsBuilder::default()
                        .with_sequencer(rollup_args.sequencer.clone())
                        .with_enable_tx_conditional(rollup_args.enable_tx_conditional)
                        .with_da_config(da_config)
                        .build()
                        .rpc_add_ons
                        .with_engine_api(default_builder),
                )
                .extend_rpc_modules(move |ctx| {
                    if builder_args.enable_revert_protection {
                        tracing::info!("Revert protection enabled");

                        let pool = ctx.pool().clone();
                        let provider = ctx.provider().clone();
                        let revert_protection_ext = RevertProtectionExt::new(pool, provider);

                        ctx.modules
                            .merge_configured(revert_protection_ext.into_rpc())?;
                    }

                    Ok(())
                })
                .on_node_started(move |ctx| {
                    VERSION.register_version_metrics();
                    if builder_args.log_pool_transactions {
                        tracing::info!("Logging pool transactions");
                        ctx.task_executor.spawn_critical(
                            "txlogging",
                            Box::pin(async move {
                                monitor_tx_pool(ctx.pool.all_transactions_event_listener()).await;
                            }),
                        );
                    }

                    Ok(())
                })
                .launch()
                .await?;

            handle.node_exit_future.await
        }
    }
}
