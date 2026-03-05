use eyre::Result;
use reth_optimism_rpc::OpEthApiBuilder;

use crate::{
    args::*,
    builders::{BuilderConfig, BuilderMode, FlashblocksBuilder, PayloadBuilder, StandardBuilder},
    metrics::{VERSION, record_flag_gauge_metrics},
    monitor_tx_pool::monitor_tx_pool,
    pool::{CustomOpPoolBuilder, RuleBasedValidator},
    primitives::reth::engine_api_builder::OpEngineApiBuilder,
    revert_protection::{EthApiExtServer, RevertProtectionExt},
    tx::FBPooledTransaction,
};
use core::fmt::Debug;
use moka::future::Cache;
use reth::{
    builder::{NodeBuilder, WithLaunchContext},
    core::exit::NodeExitFuture,
};
use reth_cli_commands::launcher::Launcher;
use reth_db::mdbx::DatabaseEnv;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::chainspec::OpChainSpecParser;
use reth_optimism_node::{
    OpNode, OpPoolBuilder,
    node::{OpAddOns, OpAddOnsBuilder, OpEngineValidatorBuilder},
};
use reth_transaction_pool::TransactionPool;
use std::{any::Any, marker::PhantomData, sync::Arc};

pub fn launch() -> Result<()> {
    let cli = Cli::parsed();
    let mode = cli.builder_mode();

    #[cfg(feature = "telemetry")]
    let telemetry_args = match &cli.command {
        reth_optimism_cli::commands::Commands::Node(node_command) => {
            node_command.ext.telemetry.clone()
        }
        _ => Default::default(),
    };

    #[cfg(not(feature = "telemetry"))]
    let cli_app = cli.configure();

    #[cfg(feature = "telemetry")]
    let mut cli_app = cli.configure();
    #[cfg(feature = "telemetry")]
    {
        use crate::primitives::telemetry::setup_telemetry_layer;
        let telemetry_layer = setup_telemetry_layer(&telemetry_args)?;
        cli_app.access_tracing_layers()?.add_layer(telemetry_layer);
    }

    match mode {
        BuilderMode::Standard => {
            tracing::info!("Starting OP builder in standard mode");
            let launcher = BuilderLauncher::<StandardBuilder>::new();
            cli_app.run(launcher)?;
        }
        BuilderMode::Flashblocks => {
            tracing::info!("Starting OP builder in flashblocks mode");
            let launcher = BuilderLauncher::<FlashblocksBuilder>::new();
            cli_app.run(launcher)?;
        }
    }
    Ok(())
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
}

impl<B> Default for BuilderLauncher<B>
where
    B: PayloadBuilder,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B> Launcher<OpChainSpecParser, OpRbuilderArgs> for BuilderLauncher<B>
where
    B: PayloadBuilder,
    BuilderConfig<B::Config>: TryFrom<OpRbuilderArgs>,
    <BuilderConfig<B::Config> as TryFrom<OpRbuilderArgs>>::Error: Debug,
{
    async fn entrypoint(
        self,
        builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, OpChainSpec>>,
        builder_args: OpRbuilderArgs,
    ) -> Result<()> {
        let builder_config = BuilderConfig::<B::Config>::try_from(builder_args.clone())
            .expect("Failed to convert rollup args to builder config");

        record_flag_gauge_metrics(&builder_args);

        let da_config = builder_config.da_config.clone();
        let gas_limit_config = builder_config.gas_limit_config.clone();
        let rollup_args = builder_args.rollup_args;
        let op_node = OpNode::new(rollup_args.clone());
        let reverted_cache = Cache::builder().max_capacity(100).build();
        let reverted_cache_copy = reverted_cache.clone();

        // Initialize rules system.
        let (rules_enabled, rule_fetcher, rule_refresh_interval_seconds) =
            if builder_args.rules.rules_enabled {
                use crate::rules::RulesRegistryConfig;

                tracing::info!("Rule based block building enabled");

                // Load registry configuration if provided.
                let (fetcher, refresh_interval) = if let Some(config_path) =
                    &builder_args.rules.config_path
                {
                    tracing::info!(path = ?config_path, "Loading rules registry configuration");

                    match RulesRegistryConfig::load(config_path).await {
                        Ok(config) => {
                            if config.is_registry_config_empty() {
                                tracing::warn!("Rules registry config is empty");
                                (None, config.refresh_interval)
                            } else {
                                match config.build_fetcher() {
                                    Ok(f) => {
                                        let interval = config.refresh_interval;
                                        tracing::info!(
                                            refresh_interval_secs = interval,
                                            "Using refresh interval from config"
                                        );
                                        (Some(f), interval)
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to build rule fetcher");
                                        (None, config.refresh_interval)
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                path = ?config_path,
                                "Failed to load rules registry config"
                            );
                            (None, 0)
                        }
                    }
                } else {
                    tracing::debug!("No rules registry config provided, using empty ruleset");
                    (None, 0)
                };

                // Fetch initial rules and update global state.
                if let Some(ref f) = fetcher {
                    f.refresh_global_ruleset().await;
                }

                (true, fetcher, refresh_interval)
            } else {
                tracing::debug!("Rules system disabled at runtime");
                (false, None, 0)
            };

        // Revert protection uses the same internal pool logic as conditional transactions
        // to garbage collect transactions out of the bundle range.
        let enable_tx_conditional_or_revert =
            rollup_args.enable_tx_conditional || builder_args.enable_revert_protection;

        // Keep the launched node alive for the lifetime of the process so RPC handles remain open.
        let (node_exit_future, _node_handle): (NodeExitFuture, Box<dyn Any + Send>) =
            if rules_enabled {
                tracing::info!("Integrating rules validator with transaction pool");

                let mut addons: OpAddOns<
                    _,
                    OpEthApiBuilder,
                    OpEngineValidatorBuilder,
                    OpEngineApiBuilder<OpEngineValidatorBuilder>,
                > = OpAddOnsBuilder::default()
                    .with_sequencer(rollup_args.sequencer.clone())
                    .with_enable_tx_conditional(rollup_args.enable_tx_conditional)
                    .with_da_config(da_config)
                    .with_gas_limit_config(gas_limit_config)
                    .build();
                if cfg!(feature = "custom-engine-api") {
                    let engine_builder: OpEngineApiBuilder<OpEngineValidatorBuilder> =
                        OpEngineApiBuilder::default();
                    addons = addons.with_engine_api(engine_builder);
                }

                let pool_builder = CustomOpPoolBuilder::<FBPooledTransaction>::default()
                    .with_enable_tx_conditional(enable_tx_conditional_or_revert)
                    .with_supervisor(
                        rollup_args.supervisor_http.clone(),
                        rollup_args.supervisor_safety_level,
                    )
                    .with_validator_wrapper(RuleBasedValidator::new);

                let components = op_node
                    .components()
                    .pool(pool_builder)
                    .payload(B::new_service(builder_config)?);

                let node_handle = builder
                    .with_types::<OpNode>()
                    .with_components(components)
                    .with_add_ons(addons)
                    .extend_rpc_modules(move |ctx| {
                        if builder_args.enable_revert_protection {
                            tracing::info!("Revert protection enabled");

                            let pool = ctx.pool().clone();
                            let provider = ctx.provider().clone();
                            let revert_protection_ext = RevertProtectionExt::new(
                                pool,
                                provider,
                                ctx.registry.eth_api().clone(),
                                reverted_cache,
                            );

                            ctx.modules
                                .add_or_replace_configured(revert_protection_ext.into_rpc())?;
                        }
                        Ok(())
                    })
                    .on_node_started(move |ctx| {
                        VERSION.register_version_metrics();
                        if builder_args.log_pool_transactions {
                            tracing::info!("Logging pool transactions");
                            let listener = ctx.pool.all_transactions_event_listener();
                            let task =
                                monitor_tx_pool(listener, reverted_cache_copy, rules_enabled);
                            ctx.task_executor.spawn_critical("txlogging", task);
                        }

                        // Start auto-refresh only when rules are enabled.
                        if rules_enabled && let Some(fetcher) = rule_fetcher {
                            fetcher.start_auto_refresh(rule_refresh_interval_seconds);
                        }

                        Ok(())
                    })
                    .launch()
                    .await?;

                (node_handle.node_exit_future, Box::new(node_handle.node))
            } else {
                tracing::info!("Rules disabled at runtime, using default transaction pool builder");

                let mut addons: OpAddOns<
                    _,
                    OpEthApiBuilder,
                    OpEngineValidatorBuilder,
                    OpEngineApiBuilder<OpEngineValidatorBuilder>,
                > = OpAddOnsBuilder::default()
                    .with_sequencer(rollup_args.sequencer.clone())
                    .with_enable_tx_conditional(rollup_args.enable_tx_conditional)
                    .with_da_config(da_config)
                    .with_gas_limit_config(gas_limit_config)
                    .build();
                if cfg!(feature = "custom-engine-api") {
                    let engine_builder: OpEngineApiBuilder<OpEngineValidatorBuilder> =
                        OpEngineApiBuilder::default();
                    addons = addons.with_engine_api(engine_builder);
                }

                let pool_builder = OpPoolBuilder::<FBPooledTransaction>::default()
                    .with_enable_tx_conditional(enable_tx_conditional_or_revert)
                    .with_supervisor(
                        rollup_args.supervisor_http.clone(),
                        rollup_args.supervisor_safety_level,
                    );

                let components = op_node
                    .components()
                    .pool(pool_builder)
                    .payload(B::new_service(builder_config)?);

                let node_handle = builder
                    .with_types::<OpNode>()
                    .with_components(components)
                    .with_add_ons(addons)
                    .extend_rpc_modules(move |ctx| {
                        if builder_args.enable_revert_protection {
                            tracing::info!("Revert protection enabled");

                            let pool = ctx.pool().clone();
                            let provider = ctx.provider().clone();
                            let revert_protection_ext = RevertProtectionExt::new(
                                pool,
                                provider,
                                ctx.registry.eth_api().clone(),
                                reverted_cache,
                            );

                            ctx.modules
                                .add_or_replace_configured(revert_protection_ext.into_rpc())?;
                        }
                        Ok(())
                    })
                    .on_node_started(move |ctx| {
                        VERSION.register_version_metrics();
                        if builder_args.log_pool_transactions {
                            tracing::info!("Logging pool transactions");
                            let listener = ctx.pool.all_transactions_event_listener();
                            let task =
                                monitor_tx_pool(listener, reverted_cache_copy, rules_enabled);
                            ctx.task_executor.spawn_critical("txlogging", task);
                        }

                        // Start auto-refresh only when rules are enabled.
                        if rules_enabled && let Some(fetcher) = rule_fetcher {
                            fetcher.start_auto_refresh(rule_refresh_interval_seconds);
                        }

                        Ok(())
                    })
                    .launch()
                    .await?;

                (node_handle.node_exit_future, Box::new(node_handle.node))
            };

        node_exit_future.await?;
        Ok(())
    }
}
