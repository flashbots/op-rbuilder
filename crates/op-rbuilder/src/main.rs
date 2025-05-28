use args::*;
use builders::{BuilderConfig, BuilderMode, FlashblocksBuilder, StandardBuilder};
use core::fmt::Debug;
use reth_optimism_node::{
    node::{OpAddOnsBuilder, OpPoolBuilder},
    OpNode,
};
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

use monitor_tx_pool::monitor_tx_pool;
use revert_protection::{EthApiOverrideServer, RevertProtectionExt};
use tx::FBPooledTransaction;

// Prefer jemalloc for performance reasons.
#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    let cli = Cli::parsed();
    cli.logs
        .init_tracing()
        .expect("Failed to initialize tracing");

    match cli.builder_mode() {
        BuilderMode::Standard => {
            tracing::info!("Starting OP builder in standard mode");
            start_builder_node::<StandardBuilder>(cli);
        }
        BuilderMode::Flashblocks => {
            tracing::info!("Starting OP builder in flashblocks mode");
            start_builder_node::<FlashblocksBuilder>(cli);
        }
    };
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
                    .build(),
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
                VersionInfo::from_env().register_version_metrics();
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

/// Contains version information for the application.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// The version of the application.
    pub version: &'static str,
    /// The build timestamp of the application.
    pub build_timestamp: &'static str,
    /// The cargo features enabled for the build.
    pub cargo_features: &'static str,
    /// The Git SHA of the build.
    pub git_sha: &'static str,
    /// The target triple for the build.
    pub target_triple: &'static str,
    /// The build profile (e.g., debug or release).
    pub build_profile: &'static str,
}

impl VersionInfo {
    pub const fn from_env() -> Self {
        Self {
            // The latest version from Cargo.toml.
            version: env!("CARGO_PKG_VERSION"),

            // The build timestamp.
            build_timestamp: env!("VERGEN_BUILD_TIMESTAMP"),

            // The build features.
            cargo_features: env!("VERGEN_CARGO_FEATURES"),

            // The 8 character short SHA of the latest commit.
            git_sha: env!("VERGEN_GIT_SHA"),

            // The target triple.
            target_triple: env!("VERGEN_CARGO_TARGET_TRIPLE"),

            // The build profile name.
            build_profile: env!("OP_RBUILDER_BUILD_PROFILE"),
        }
    }
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self::from_env()
    }
}

impl VersionInfo {
    /// This exposes reth's version information over prometheus.
    pub fn register_version_metrics(&self) {
        let labels: [(&str, &str); 6] = [
            ("version", self.version),
            ("build_timestamp", self.build_timestamp),
            ("cargo_features", self.cargo_features),
            ("git_sha", self.git_sha),
            ("target_triple", self.target_triple),
            ("build_profile", self.build_profile),
        ];

        let gauge = ::metrics::gauge!("builder_info", &labels);
        gauge.set(1);
    }
}
