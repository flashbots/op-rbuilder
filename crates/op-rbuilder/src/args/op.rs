//! Additional Node command arguments.
//!
//! Copied from OptimismNode to allow easy extension.

//! clap [Args](clap::Args) for optimism rollup configuration
use crate::{primitives::reth::engine_api_builder::EnginePeer, tx_signer::Signer};
use alloy_rpc_types_engine::JwtSecret;
use anyhow::{anyhow, Result};
use reth_optimism_node::args::RollupArgs;
use serde::Deserialize;
use std::path::PathBuf;
use url::Url;

/// Configuration structure for engine peers loaded from TOML
#[derive(Debug, Clone, Deserialize)]
pub struct EnginePeersConfig {
    /// Default JWT file path used by all peers unless overridden
    pub default_jwt_path: PathBuf,
    /// List of engine peers
    pub peers: Vec<EnginePeerConfig>,
}

/// Configuration for a single engine peer
#[derive(Debug, Clone, Deserialize)]
pub struct EnginePeerConfig {
    /// URL of the engine peer
    pub url: Url,
    /// Optional JWT path override for this peer
    pub jwt_path: Option<PathBuf>,
}

/// Parameters for rollup configuration
#[derive(Debug, Clone, Default, clap::Args)]
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
    /// Path to TOML configuration file for engine peers
    #[arg(long = "builder.engine-peers-config", env = "ENGINE_PEERS_CONFIG", value_parser = parse_engine_peers_config)]
    pub engine_peers: Vec<EnginePeer>,
}

fn expand_path(s: &str) -> Result<PathBuf> {
    shellexpand::full(s)
        .map_err(|e| anyhow!("expansion error for `{s}`: {e}"))?
        .into_owned()
        .parse()
        .map_err(|e| anyhow!("invalid path after expansion: {e}"))
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
        long = "flashblocks.block-time",
        default_value = "250",
        env = "FLASHBLOCK_BLOCK_TIME"
    )]
    pub flashblocks_block_time: u64,
}

impl EnginePeersConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            anyhow!(
                "Failed to read engine peers config file {}: {}",
                path.display(),
                e
            )
        })?;

        let config: Self = toml::from_str(&content).map_err(|e| {
            anyhow!(
                "Failed to parse engine peers config file {}: {}",
                path.display(),
                e
            )
        })?;

        Ok(config)
    }

    /// Convert to vector of EnginePeer instances
    pub fn to_engine_peers(&self) -> Result<Vec<EnginePeer>> {
        let mut engine_peers = Vec::new();

        for peer in &self.peers {
            let jwt_path = peer.jwt_path.as_ref().unwrap_or(&self.default_jwt_path);
            let jwt_secret = JwtSecret::from_file(jwt_path)
                .map_err(|e| anyhow!("Failed to load JWT from {}: {}", jwt_path.display(), e))?;

            engine_peers.push(EnginePeer::new(peer.url.clone(), jwt_secret));
        }

        Ok(engine_peers)
    }
}

/// Parse engine peers configuration from TOML file for clap
fn parse_engine_peers_config(s: &str) -> Result<Vec<EnginePeer>> {
    let path = PathBuf::from(s);
    let config = EnginePeersConfig::from_file(&path)?;
    config.to_engine_peers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_engine_peers_config_parsing() -> Result<()> {
        // Create temporary JWT files for testing
        let mut temp_default_jwt = NamedTempFile::new()?;
        let mut temp_custom_jwt = NamedTempFile::new()?;

        // Write dummy JWT content (for testing purposes)
        temp_default_jwt.write_all(b"dummy.jwt.token")?;
        temp_custom_jwt.write_all(b"custom.jwt.token")?;
        temp_default_jwt.flush()?;
        temp_custom_jwt.flush()?;

        let toml_content = format!(
            r#"
default_jwt_path = "{}"

[[peers]]
url = "http://builder1.example.com:8551"

[[peers]]
url = "http://builder2.example.com:8551"
jwt_path = "{}"
"#,
            temp_default_jwt.path().display(),
            temp_custom_jwt.path().display()
        );

        let config: EnginePeersConfig = toml::from_str(&toml_content)?;

        assert_eq!(config.peers.len(), 2);

        // First peer should use default JWT
        assert_eq!(
            config.peers[0].url.as_str(),
            "http://builder1.example.com:8551"
        );

        // Second peer should have custom JWT
        assert_eq!(
            config.peers[1].url.as_str(),
            "http://builder2.example.com:8551"
        );

        // Test that we can convert to engine peers successfully
        let engine_peers = config.to_engine_peers()?;
        assert_eq!(engine_peers.len(), 2);

        Ok(())
    }

    #[test]
    fn test_engine_peers_config_from_file() -> Result<()> {
        // Create temporary JWT file
        let mut temp_jwt = NamedTempFile::new()?;
        temp_jwt.write_all(b"test.jwt.token")?;
        temp_jwt.flush()?;

        let toml_content = format!(
            r#"
default_jwt_path = "{}"

[[peers]]
url = "http://test.example.com:8551"
"#,
            temp_jwt.path().display()
        );

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(toml_content.as_bytes())?;
        temp_file.flush()?;

        let config = EnginePeersConfig::from_file(&temp_file.path().to_path_buf())?;

        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].url.as_str(), "http://test.example.com:8551");

        Ok(())
    }
}
