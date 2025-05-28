use args::*;
use builders::{BuilderMode, FlashblocksBuilder, StandardBuilder};
use eyre::Result;
use reth_optimism_cli::commands::Commands;

/// CLI argument parsing.
pub mod args;
mod builders;
mod launcher;
mod metrics;
mod monitor_tx_pool;
mod primitives;
mod revert_protection;
mod traits;
mod tx;
mod tx_signer;

use launcher::{BuilderLauncher, NoLauncher};
use metrics::{
    VersionInfo, BUILD_PROFILE_NAME, CARGO_PKG_VERSION, VERGEN_BUILD_TIMESTAMP,
    VERGEN_CARGO_FEATURES, VERGEN_CARGO_TARGET_TRIPLE, VERGEN_GIT_SHA,
};

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

    #[cfg(feature = "tracing")]
    {
        let otlp = reth_tracing_otlp::layer("op-reth");
        cli_app.access_tracing_layers()?.add_layer(otlp);
    }

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
