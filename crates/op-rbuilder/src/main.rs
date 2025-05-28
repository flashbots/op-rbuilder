use args::*;
use builders::{BuilderConfig, BuilderMode, FlashblocksBuilder, StandardBuilder};
use core::fmt::Debug;
use eyre::Result;
use futures::{future, Future};
use reth::builder::{NodeBuilder, WithLaunchContext};
use reth_cli_commands::launcher::Launcher;
use reth_db::mdbx::DatabaseEnv;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::{chainspec::OpChainSpecParser, commands::Commands};
use reth_optimism_node::{
    node::{OpAddOnsBuilder, OpEngineValidatorBuilder, OpPoolBuilder},
    OpNode,
};
use std::{marker::PhantomData, sync::Arc};

use reth_transaction_pool::TransactionPool;

/// CLI argument parsing.
pub mod args;
mod builders;
mod metrics;
mod monitor_tx_pool;
mod primitives;
mod revert_protection;
mod traits;
mod tx;
mod tx_signer;

use metrics::{
    VersionInfo, BUILD_PROFILE_NAME, CARGO_PKG_VERSION, VERGEN_BUILD_TIMESTAMP,
    VERGEN_CARGO_FEATURES, VERGEN_CARGO_TARGET_TRIPLE, VERGEN_GIT_SHA,
};
use monitor_tx_pool::monitor_tx_pool;
use primitives::reth::engine_api_builder::OpEngineApiBuilder;
use revert_protection::{EthApiOverrideServer, RevertProtectionExt};
use tx::FBPooledTransaction;

// Prefer jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const VERSION: VersionInfo = VersionInfo {
    version: CARGO_PKG_VERSION,
    build_timestamp: VERGEN_BUILD_TIMESTAMP,
    cargo_features: VERGEN_CARGO_FEATURES,
    git_sha: VERGEN_GIT_SHA,
    target_triple: VERGEN_CARGO_TARGET_TRIPLE,
    build_profile: BUILD_PROFILE_NAME,
};

fn main() -> Result<()> {
    let cli = Cli::parsed();
    let mode = match &cli.command {
        Commands::Node(command) => Some(command.ext.builder_mode()),
        _ => None,
    };

    let mut cli_app = cli.configure();

    // TODO: Add telemetry here

    cli_app.init_tracing()?;
    match mode {
        Some(BuilderMode::Standard) => {
            tracing::info!("Starting OP builder in standard mode");
            let launcher = BuilderLauncher::<StandardBuilder>::new();
            cli_app.run(launcher)?;
        }
        Some(BuilderMode::Flashblocks) => {
            tracing::info!("Starting OP builder in flashblocks mode");
            let launcher = BuilderLauncher::<FlashblocksBuilder>::new();
            cli_app.run(launcher)?;
        }
        None => {
            cli_app.run(NoLauncher)?;
        }
    }

    Ok(())
}

struct NoLauncher;

impl Launcher<OpChainSpecParser, OpRbuilderArgs> for NoLauncher {
    fn entrypoint(
        self,
        _builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, OpChainSpec>>,
        _builder_args: OpRbuilderArgs,
    ) -> impl Future<Output = Result<()>> {
        future::ok(())
    }
}

struct BuilderLauncher<B> {
    _builder: PhantomData<B>,
}

impl<B> BuilderLauncher<B> {
    fn new() -> Self {
        Self {
            _builder: PhantomData,
        }
    }
}

impl<B> Launcher<OpChainSpecParser, OpRbuilderArgs> for BuilderLauncher<B>
where
    B: builders::PayloadBuilder,
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

/// Starts the OP builder node with a given payload builder implementation.
fn start_builder_node<B: builders::PayloadBuilder>(cli: Cli)
where
    BuilderConfig<<B as builders::PayloadBuilder>::Config>: TryFrom<OpRbuilderArgs>,
    <BuilderConfig<<B as builders::PayloadBuilder>::Config> as TryFrom<OpRbuilderArgs>>::Error:
        Debug,
{
    cli.run(|builder, builder_args| async move {
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
    })
    .unwrap();
}
