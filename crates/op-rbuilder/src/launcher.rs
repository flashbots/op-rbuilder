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
    rules::{
        IngressRegimeConfig, OrderingRegimeConfig, TxPoolPolicyConfig, set_ingress_ruleset,
        set_ordering_ruleset,
    },
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
    OpNode,
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

        let policy_config = if let Some(config_path) = &builder_args.rules.config_path {
            tracing::info!(path = ?config_path, "Loading txpool policy configuration");
            match TxPoolPolicyConfig::load(config_path).await {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        path = ?config_path,
                        "Failed to load txpool policy config; falling back to defaults"
                    );
                    TxPoolPolicyConfig::default()
                }
            }
        } else {
            tracing::debug!(
                "No rules config path provided; using default txpool policy (allow_all + priority_fee)"
            );
            TxPoolPolicyConfig::default()
        };

        let ingress_deny_enabled = policy_config.ingress.uses_rules();
        let ordering_scoring_enabled = policy_config.ordering.uses_scoring();
        let ordering_unscored_score = policy_config.ordering.unscored_score();

        let ingress_rule_fetcher = policy_config
            .ingress
            .sources()
            .filter(|sources| !sources.is_empty())
            .map(|sources| {
                tracing::info!(
                    refresh_interval_secs = sources.refresh_interval,
                    sources = sources.file.len(),
                    "Configured ingress rule sources"
                );
                (sources.build_fetcher(), sources.refresh_interval)
            });

        let ordering_rule_fetcher = policy_config
            .ordering
            .sources()
            .filter(|sources| !sources.is_empty())
            .map(|sources| {
                tracing::info!(
                    refresh_interval_secs = sources.refresh_interval,
                    sources = sources.file.len(),
                    "Configured ordering rule sources"
                );
                (sources.build_fetcher(), sources.refresh_interval)
            });

        if ingress_deny_enabled {
            if let Some((fetcher, _)) = &ingress_rule_fetcher {
                fetcher.refresh_ruleset_with(set_ingress_ruleset).await;
            } else {
                tracing::warn!(
                    "Ingress deny regime selected with no configured sources; using empty ingress ruleset"
                );
                set_ingress_ruleset(Default::default());
            }
        } else {
            set_ingress_ruleset(Default::default());
        }

        if ordering_scoring_enabled {
            if let Some((fetcher, _)) = &ordering_rule_fetcher {
                fetcher.refresh_ruleset_with(set_ordering_ruleset).await;
            } else {
                tracing::warn!(
                    "Ordering boost regime selected with no configured sources; using empty ordering ruleset"
                );
                set_ordering_ruleset(Default::default());
            }
        } else {
            set_ordering_ruleset(Default::default());
        }

        // Revert protection uses the same internal pool logic as conditional transactions
        // to garbage collect transactions out of the bundle range.
        let enable_tx_conditional_or_revert =
            rollup_args.enable_tx_conditional || builder_args.enable_revert_protection;
        let enable_revert_protection = builder_args.enable_revert_protection;
        let log_pool_transactions = builder_args.log_pool_transactions;

        // Keep the launched node alive for the lifetime of the process so RPC handles remain open.
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

        tracing::info!(
            ingress_regime = %match &policy_config.ingress {
                IngressRegimeConfig::AllowAll => "allow_all",
                IngressRegimeConfig::DenyRules { .. } => "deny_rules",
            },
            ordering_regime = %match &policy_config.ordering {
                OrderingRegimeConfig::PriorityFee => "priority_fee",
                OrderingRegimeConfig::PriorityFeeWithBoost { .. } => "priority_fee_with_boost",
            },
            "Configuring txpool policy regimes"
        );

        let pool_builder = CustomOpPoolBuilder::<FBPooledTransaction>::default()
            .with_enable_tx_conditional(enable_tx_conditional_or_revert)
            .with_supervisor(
                rollup_args.supervisor_http.clone(),
                rollup_args.supervisor_safety_level,
            )
            .with_scoring_enabled(ordering_scoring_enabled)
            .with_unscored_score(ordering_unscored_score)
            .with_validator_wrapper(move |validator| {
                RuleBasedValidator::new(validator)
                    .with_ingress_deny_enabled(ingress_deny_enabled)
                    .with_scoring_enabled(ordering_scoring_enabled)
            });

        let components = op_node
            .components()
            .pool(pool_builder)
            .payload(B::new_service(builder_config)?);

        let node_handle = builder
            .with_types::<OpNode>()
            .with_components(components)
            .with_add_ons(addons)
            .extend_rpc_modules(move |ctx| {
                if enable_revert_protection {
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
                if log_pool_transactions {
                    tracing::info!("Logging pool transactions");
                    let listener = ctx.pool.all_transactions_event_listener();
                    let task =
                        monitor_tx_pool(listener, reverted_cache_copy, ordering_scoring_enabled);
                    ctx.task_executor.spawn_critical("txlogging", task);
                }

                if let Some((fetcher, interval_secs)) = ingress_rule_fetcher {
                    fetcher.start_auto_refresh_with(interval_secs, set_ingress_ruleset);
                }
                if let Some((fetcher, interval_secs)) = ordering_rule_fetcher {
                    fetcher.start_auto_refresh_with(interval_secs, set_ordering_ruleset);
                }

                Ok(())
            })
            .launch()
            .await?;

        let (node_exit_future, _node_handle): (NodeExitFuture, Box<dyn Any + Send>) =
            (node_handle.node_exit_future, Box::new(node_handle.node));

        node_exit_future.await?;
        Ok(())
    }
}
