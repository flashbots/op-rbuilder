use std::sync::Arc;

use eyre::Result;
use futures::FutureExt;
use reth_optimism_rpc::OpEthApiBuilder;
use tokio::sync::mpsc;
use tracing::info;

use crate::{
    args::*,
    backrun_bundle::{
        BackrunBundleApiServer, BackrunBundleRpc, maintain_backrun_bundle_pool_future,
    },
    builder::{BuilderConfig, FlashblocksServiceBuilder},
    metrics::{OpRBuilderMetrics, VERSION, record_flag_gauge_metrics},
    monitor_tx_pool::monitor_tx_pool,
    pool::run_pool_insertion_task,
    presim::{TopOfBlockSimulator, maintain_pending_simulations, maintain_tip_state},
    revert_protection::{EthApiExtServer, RevertProtectionExt},
    tx::FBPooledTransaction,
};
use moka::future::Cache;
use reth::builder::{NodeBuilder, WithLaunchContext};
use reth_cli_commands::launcher::Launcher;
use reth_db::mdbx::DatabaseEnv;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::chainspec::OpChainSpecParser;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_node::{
    OpNode,
    node::{OpAddOns, OpAddOnsBuilder, OpEngineValidatorBuilder, OpPoolBuilder},
};
use reth_provider::{CanonStateSubscriptions, ChainSpecProvider};
use reth_transaction_pool::TransactionPool;

pub fn launch() -> Result<()> {
    let cli = Cli::parsed();

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

        // macos fix: suppress known TLS destruction ordering panic on macOS
        #[cfg(target_os = "macos")]
        otel_shutdown_hook();
    }

    #[cfg(feature = "loki")]
    {
        if let Some(loki_url) = &telemetry_args.loki_url {
            use crate::primitives::telemetry::setup_loki_layer;
            let (loki_layer, loki_task) = setup_loki_layer(loki_url)?;
            cli_app.access_tracing_layers()?.add_layer(loki_layer);

            // Spawn the background task that ships logs to Loki.
            // Needs its own runtime since we're not yet inside tokio.
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build loki runtime")
                    .block_on(loki_task);
            });
        }
    }

    cli_app.run(BuilderLauncher)?;
    Ok(())
}

struct BuilderLauncher;

impl Launcher<OpChainSpecParser, OpRbuilderArgs> for BuilderLauncher {
    async fn entrypoint(
        self,
        builder: WithLaunchContext<NodeBuilder<DatabaseEnv, OpChainSpec>>,
        builder_args: OpRbuilderArgs,
    ) -> Result<()> {
        let builder_config = BuilderConfig::try_from(builder_args.clone())
            .expect("Failed to convert rollup args to builder config");

        record_flag_gauge_metrics(&builder_args);

        let da_config = builder_config.da_config.clone();
        let gas_limit_config = builder_config.gas_limit_config.clone();
        let rollup_args = builder_args.rollup_args;
        let op_node = OpNode::new(rollup_args.clone());
        let reverted_cache = Cache::builder().max_capacity(100).build();
        let reverted_cache_copy = reverted_cache.clone();
        let backrun_bundle_enabled = builder_args.backrun_bundle.backruns_enabled;
        let block_time_secs = builder_config.block_time.as_millis() as u64 / 1000;
        let backrun_bundle_pool = builder_config.backrun_bundle_pool.clone();
        let backrun_bundle_pool_maintain = backrun_bundle_pool.clone();

        let (pool_tx, pool_rx) = mpsc::unbounded_channel();

        let simulator = if builder_args.pre_simulate_bundles {
            Some(Arc::new(TopOfBlockSimulator::new()))
        } else {
            None
        };
        let simulator_for_rpc = simulator.clone();
        let simulator_for_maintenance = simulator.clone();

        let addons: OpAddOns<_, OpEthApiBuilder, OpEngineValidatorBuilder> =
            OpAddOnsBuilder::default()
                .with_sequencer(rollup_args.sequencer.clone())
                .with_enable_tx_conditional(rollup_args.enable_tx_conditional)
                .with_da_config(da_config)
                .with_gas_limit_config(gas_limit_config)
                .build();

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
                    .payload(FlashblocksServiceBuilder::new(builder_config)),
            )
            .with_add_ons(addons)
            .extend_rpc_modules(move |ctx| {
                if builder_args.enable_revert_protection {
                    info!("Revert protection enabled");

                    let provider = ctx.provider().clone();
                    let revert_protection_ext = RevertProtectionExt::new(
                        provider,
                        ctx.registry.eth_api().clone(),
                        reverted_cache,
                        pool_tx,
                    );

                    ctx.modules
                        .add_or_replace_configured(revert_protection_ext.into_rpc())?;
                }

                if builder_args.backrun_bundle.backruns_enabled {
                    let backrun_rpc = BackrunBundleRpc::new(
                        backrun_bundle_pool.clone(),
                        ctx.provider().clone(),
                        builder_args
                            .backrun_bundle
                            .enforce_strict_priority_fee_ordering,
                    );
                    ctx.modules
                        .add_or_replace_configured(backrun_rpc.into_rpc())?;
                }

                Ok(())
            })
            .on_node_started(move |ctx| {
                VERSION.register_version_metrics();

                let metrics = Arc::new(OpRBuilderMetrics::default());

                ctx.task_executor.spawn_critical_task(
                    "bundleInsertion",
                    run_pool_insertion_task(
                        ctx.task_executor.clone(),
                        ctx.pool.clone(),
                        pool_rx,
                        simulator_for_rpc,
                        metrics.clone(),
                        builder_args.presim_max_concurrency,
                    ),
                );

                if builder_args.log_pool_transactions {
                    info!("Logging pool transactions");
                    let listener = ctx.pool.all_transactions_event_listener();
                    let task = monitor_tx_pool(
                        listener,
                        reverted_cache_copy,
                        builder_args.enable_tx_tracking_debug_logs,
                    );
                    ctx.task_executor.spawn_critical_task("txlogging", task);
                }

                if backrun_bundle_enabled {
                    let chain_events = ctx.provider.canonical_state_stream();
                    let task_executor = ctx.task_executor.clone();
                    ctx.task_executor
                        .spawn_task(maintain_backrun_bundle_pool_future(
                            backrun_bundle_pool_maintain,
                            chain_events,
                            task_executor,
                        ));
                }

                if let Some(simulator) = simulator_for_maintenance {
                    let chain_events = ctx.provider.canonical_state_stream();
                    let evm_config = OpEvmConfig::optimism(ctx.provider.chain_spec());
                    ctx.task_executor.spawn_task(
                        maintain_tip_state(
                            simulator.clone(),
                            ctx.provider.clone(),
                            evm_config,
                            block_time_secs,
                            metrics.clone(),
                            chain_events,
                        )
                        .boxed(),
                    );

                    let pending_events = ctx.pool.all_transactions_event_listener();
                    ctx.task_executor.spawn_task(
                        maintain_pending_simulations(
                            ctx.task_executor.clone(),
                            simulator,
                            ctx.pool.clone(),
                            metrics,
                            pending_events,
                        )
                        .boxed(),
                    );
                }

                Ok(())
            })
            .launch()
            .await?;

        handle.node_exit_future.await?;
        Ok(())
    }
}

/// Panic hook for known macOS TLS destruction ordering crash OpenTelemetry
#[cfg(all(feature = "telemetry", target_os = "macos"))]
fn otel_shutdown_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let is_tls_panic = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.contains("Thread Local Storage value during or after destruction"))
            .or_else(|| {
                info.payload()
                    .downcast_ref::<&str>()
                    .map(|s| s.contains("Thread Local Storage value during or after destruction"))
            })
            .unwrap_or(false);

        if is_tls_panic {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}
