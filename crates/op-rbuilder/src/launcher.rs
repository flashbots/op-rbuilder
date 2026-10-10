use alloy_consensus::BlockHeader;
use eyre::Result;
use futures_util::StreamExt;
use reth_node_api::{ConsensusEngineEvent, ForkchoiceStatus};
use reth_optimism_rpc::OpEthApiBuilder;
use tracing::{debug, info};

use crate::{
    args::*,
    backrun_bundle::{BackrunBundleApiServer, BackrunBundleRpc},
    builder::{BuilderConfig, FlashblocksServiceBuilder},
    metrics::{VERSION, record_flag_gauge_metrics},
    monitor_tx_pool::monitor_tx_pool,
    pool::{FlashpoolBuilder, FlashpoolExt},
    revert_protection::{EthApiExtServer, RevertProtectionExt},
};
use reth::builder::{NodeBuilder, WithLaunchContext};
use reth_cli_commands::launcher::Launcher;
use reth_db::mdbx::DatabaseEnv;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::chainspec::OpChainSpecParser;
use reth_optimism_node::{
    OpNode,
    node::{OpAddOns, OpAddOnsBuilder, OpEngineValidatorBuilder},
};
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
        let rollup_args = &builder_args.rollup_args;
        let op_node = OpNode::new(rollup_args.clone());

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
                    .pool(FlashpoolBuilder::new(&builder_args))
                    .payload(FlashblocksServiceBuilder::new(builder_config)),
            )
            .with_add_ons(addons)
            .extend_rpc_modules(move |ctx| {
                if builder_args.enable_revert_protection {
                    info!("Revert protection enabled");

                    let pool = ctx.pool().clone();
                    let provider = ctx.provider().clone();
                    let revert_protection_ext =
                        RevertProtectionExt::new(pool, provider, ctx.registry.eth_api().clone());

                    ctx.modules
                        .add_or_replace_configured(revert_protection_ext.into_rpc())?;
                }

                if let Some(backrun_bundle_pool) = ctx.pool().backrun_bundle_pool() {
                    let backrun_rpc = BackrunBundleRpc::new(
                        backrun_bundle_pool,
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
                if builder_args.log_pool_transactions {
                    info!("Logging pool transactions");
                    let listener = ctx.pool.all_transactions_event_listener();
                    let task =
                        monitor_tx_pool(listener, builder_args.enable_tx_tracking_debug_logs);
                    ctx.task_executor.spawn_critical_task("txlogging", task);
                }

                let mut engine_events = ctx.engine_events.new_listener();
                ctx.task_executor.spawn_task(async move {
                    while let Some(event) = engine_events.next().await {
                        match event {
                            ConsensusEngineEvent::CanonicalBlockAdded(executed, _) => {
                                let block = executed.sealed_block();
                                debug!(
                                    target: "op_rbuilder::chain",
                                    number = block.number(),
                                    hash = %block.hash(),
                                    txs = block.transaction_count(),
                                    "Block added to canonical chain"
                                );
                            }
                            ConsensusEngineEvent::CanonicalChainCommitted(head, _) => {
                                debug!(
                                    target: "op_rbuilder::chain",
                                    number = head.number(),
                                    hash = %head.hash(),
                                    "Canonical chain committed"
                                );
                            }
                            ConsensusEngineEvent::BlockReceived(num_hash) => {
                                debug!(
                                    target: "op_rbuilder::chain",
                                    number = num_hash.number,
                                    hash = %num_hash.hash,
                                    "Received new payload from consensus engine"
                                );
                            }
                            ConsensusEngineEvent::ForkchoiceUpdated(
                                state,
                                ForkchoiceStatus::Valid,
                            ) => {
                                debug!(
                                    target: "op_rbuilder::chain",
                                    head = %state.head_block_hash,
                                    safe = %state.safe_block_hash,
                                    finalized = %state.finalized_block_hash,
                                    "Forkchoice updated"
                                );
                            }
                            _ => {}
                        }
                    }
                });

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
