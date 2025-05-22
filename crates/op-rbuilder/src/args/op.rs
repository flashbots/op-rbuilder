//! Additional Node command arguments.
//!
//! Copied from OptimismNode to allow easy extension.

//! clap [Args](clap::Args) for optimism rollup configuration
use crate::{primitives::reth::engine_api_builder::EnginePeer, tx_signer::Signer};
use alloy_rpc_types_engine::JwtSecret;
use anyhow::{anyhow, Result};
use reth_optimism_node::args::RollupArgs;
use std::path::PathBuf;
use url::Url;

/// Parameters for rollup configuration
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "Rollup")]
pub struct OpRbuilderArgs {
    /// Rollup configuration
    #[command(flatten)]
    pub rollup_args: RollupArgs,
    /// Builder secret key for signing last transaction in block
    #[arg(long = "rollup.builder-secret-key", env = "BUILDER_SECRET_KEY")]
    pub builder_signer: Option<Signer>,

    /// chain block time in milliseconds
    #[arg(
        long = "rollup.chain-block-time",
        default_value = "1000",
        env = "CHAIN_BLOCK_TIME"
    )]
    pub chain_block_time: u64,

    /// Signals whether to log pool transaction events
    #[arg(long = "builder.log-pool-transactions", default_value = "false")]
    pub log_pool_transactions: bool,

    /// How much time extra to wait for the block building job to complete and not get garbage collected
    #[arg(long = "builder.extra-block-deadline-secs", default_value = "20")]
    pub extra_block_deadline_secs: u64,
    /// Whether to enable revert protection by default
    #[arg(long = "builder.enable-revert-protection", default_value = "false")]
    pub enable_revert_protection: bool,

    /// Path to builder playgorund to automatically start up the node connected to it
    #[arg(
        long = "builder.playground",
        num_args = 0..=1,
        default_missing_value = "$HOME/.playground/devnet/",
        value_parser = expand_path,
        env = "PLAYGROUND_DIR",
    )]
    pub playground: Option<PathBuf>,
    #[command(flatten)]
    pub flashblocks: FlashblocksArgs,
    /// List or builders in the network that FCU would be propagated to
    #[arg(long = "builder.engine-api-peer", value_parser = parse_engine_peer_arg, action = clap::ArgAction::Append)]
    pub engine_peers: Vec<EnginePeer>,
}

fn expand_path(s: &str) -> Result<PathBuf> {
    shellexpand::full(s)
        .map_err(|e| anyhow!("expansion error for `{s}`: {e}"))?
        .into_owned()
        .parse()
        .map_err(|e| anyhow!("invalid path after expansion: {e}"))
}

/// Parse engine peer configuration string for clap argument parsing.
///
/// Format: "url@jwt_path" (JWT path is required)
/// - url: HTTP/HTTPS endpoint of the peer builder
/// - jwt_path: File path to JWT token for authentication (required after @)
fn parse_engine_peer_arg(s: &str) -> Result<EnginePeer> {
    let s = s.trim();

    if s.is_empty() {
        return Err(anyhow!("Engine peer cannot be empty"));
    }

    // Find the @ delimiter - it's required
    // Caution: this will misshandle cases when pathname contains `@` symbols, we do not expect such filenames tho
    let (url_part, jwt_path_part) = s.rsplit_once('@').ok_or_else(|| anyhow!("Engine peer must include JWT path after '@' (format: url@jwt_path). Urls with @ in the path are not accepted."))?;

    if url_part.is_empty() {
        return Err(anyhow!("URL part cannot be empty"));
    }

    if jwt_path_part.is_empty() {
        return Err(anyhow!("JWT path cannot be empty (format: url@jwt_path)"));
    }

    let url = Url::parse(url_part)?;

    let jwt_path = PathBuf::from(jwt_path_part);

    let jwt_secret = JwtSecret::from_file(&jwt_path)?;

    Ok(EnginePeer::new(url, jwt_secret))
}

/// Parameters for Flashblocks configuration
/// The names in the struct are prefixed with `flashblocks` to avoid conflicts
/// with the standard block building configuration since these args are flattened
/// into the main `OpRbuilderArgs` struct with the other rollup/node args.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct FlashblocksArgs {
    /// When set to true, the builder will build flashblocks
    /// and will build standard blocks at the chain block time.
    ///
    /// The default value will change in the future once the flashblocks
    /// feature is stable.
    #[arg(
        long = "flashblocks.enabled",
        default_value = "false",
        env = "ENABLE_FLASHBLOCKS"
    )]
    pub enabled: bool,

    /// The port that we bind to for the websocket server that provides flashblocks
    #[arg(
        long = "flashblocks.port",
        env = "FLASHBLOCKS_WS_PORT",
        default_value = "1111"
    )]
    pub flashblocks_port: u16,

    /// The address that we bind to for the websocket server that provides flashblocks
    #[arg(
        long = "flashblocks.addr",
        env = "FLASHBLOCKS_WS_ADDR",
        default_value = "127.0.0.1"
    )]
    pub flashblocks_addr: String,

    /// flashblock block time in milliseconds
    #[arg(
        long = "flashblock.block-time",
        default_value = "250",
        env = "FLASHBLOCK_BLOCK_TIME"
    )]
    pub flashblocks_block_time: u64,
}
