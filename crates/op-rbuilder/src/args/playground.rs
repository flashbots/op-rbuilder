//! Automatic devnet configuration for `--builder.playground`.
//!
//! This module is used mostly for testing purposes. It lets op-rbuilder
//! automatically configure itself to run against a local OP stack devnet,
//! detecting which of two artifact layouts the target directory holds
//! (see `detect_layout`):
//!
//! - decker (primary): the artifacts directory decker's opstack recipe
//!   generates for an external, host-run op-rbuilder, e.g. via
//!
//!     decker up opstack --opt externalBuilder=op-rbuilder --opt builderBinary=true
//!
//!   See https://github.com/flashbots/decker. Ports and the sequencer EL's
//!   p2p identity are fixed decker contract constants (see below) rather
//!   than being read from the directory.
//!
//! - builder-playground (legacy, still supported): the directory produced by
//!
//!     go run main.go cook opstack --external-builder http://host.docker.internal:4444
//!
//!   from https://github.com/flashbots/builder-playground. Unlike decker,
//!   ports/keys aren't exposed anywhere else, so this layout also parses the
//!   generated docker-compose.yaml to recover them.
//!
//! Once the devnet is up, build op-rbuilder with flashblocks support:
//!
//!   cargo build --bin op-rbuilder -p op-rbuilder
//!
//! then run the following command to start op-rbuilder against it:
//!
//!   target/debug/op-rbuilder node --builder.playground
//!
//! This will automatically try to detect the devnet configuration and apply
//! it to the op-rbuilder startup settings. With no directory given, the bare
//! flag resolves to the first of `./.decker/runtime/artifacts` or
//! `$HOME/.local/state/builder-playground/devnet` that exists (see
//! `args::op::expand_path`).
//!
//! Optionally you can specify the `--builder.playground` flag with a different
//! directory to use. This is useful for testing against different devnet
//! configurations.

use alloy_primitives::hex;
use clap::{CommandFactory, parser::ValueSource};
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    time::Duration,
};
use eyre::{Result, eyre};
use reth_cli::chainspec::ChainSpecParser;
use reth_network_peers::{PeerId, TrustedPeer};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_cli::{chainspec::OpChainSpecParser, commands::Commands};
use secp256k1::SecretKey;
use serde_json::Value;
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
    sync::Arc,
};
use url::{Host, Url};

use super::Cli;

const DECKER_BUILDER_AUTHRPC_PORT: u16 = 9651;
const DECKER_SEQUENCER_EL_P2P_PORT: u16 = 30303;
const DECKER_SEQUENCER_EL_PEER_ID: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";

/// Which artifact generator produced the playground directory.
enum Layout {
    /// builder-playground's `go run main.go cook opstack` output: ports/keys
    /// are recovered by parsing its generated docker-compose.yaml.
    Legacy,
    /// decker's devnet artifacts directory: ports/peer-id are fixed decker
    /// contract constants.
    Decker,
}

fn detect_layout(path: &Path) -> Result<Layout> {
    if path.join("docker-compose.yaml").exists() {
        Ok(Layout::Legacy)
    } else if path.join("l2-genesis.json").exists() {
        Ok(Layout::Decker)
    } else {
        Err(eyre!(
            "{} matches neither the legacy builder-playground layout (docker-compose.yaml) \
             nor the decker devnet artifacts layout (l2-genesis.json)",
            path.display()
        ))
    }
}

pub(super) struct PlaygroundOptions {
    /// Sets node.chain in NodeCommand
    pub chain: Arc<OpChainSpec>,

    /// Sets node.rpc.http_port in NodeCommand
    pub http_port: u16,

    /// Sets node.rpc.auth_addr in NodeCommand
    pub authrpc_addr: IpAddr,

    /// Sets node.rpc.authrpc_port in NodeCommand
    pub authrpc_port: u16,

    /// Sets node.rpc.authrpc_jwtsecret in NodeCommand
    pub authrpc_jwtsecret: PathBuf,

    /// Sets node.network.port in NodeCommand
    pub port: u16,

    /// Sets the node.network.trusted_peers in NodeCommand
    pub trusted_peer: TrustedPeer,

    /// Sets node.ext.flashblock_block_time in NodeCommand
    pub chain_block_time: Duration,
}

impl PlaygroundOptions {
    /// Creates a new `PlaygroundOptions` instance with the specified genesis path.
    pub(super) fn new(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(eyre!(
                "Playground data directory {} does not exist",
                path.display()
            ));
        }
        let layout = detect_layout(path)?;

        let chain = OpChainSpecParser::parse(&existing_path(path, "l2-genesis.json")?)?;

        let authrpc_addr = Ipv4Addr::UNSPECIFIED.into();
        let http_port = pick_preferred_port(2222, 3000..9999);
        let authrpc_jwtsecret = existing_path(path, "jwtsecret")?.into();
        let port = pick_preferred_port(30333, 30000..65535);
        let chain_block_time = extract_chain_block_time(path)?;

        let (authrpc_port, trusted_peer) = match layout {
            Layout::Legacy => (
                extract_authrpc_port(path)?,
                TrustedPeer::from_secret_key(
                    Host::Ipv4(Ipv4Addr::LOCALHOST),
                    extract_trusted_peer_port(path)?,
                    &extract_deterministic_p2p_key(path)?,
                ),
            ),
            Layout::Decker => {
                let id = DECKER_SEQUENCER_EL_PEER_ID
                    .parse::<PeerId>()
                    .map_err(|e| eyre!("invalid decker sequencer EL peer id: {e}"))?;
                (
                    DECKER_BUILDER_AUTHRPC_PORT,
                    TrustedPeer::new(
                        Host::Ipv4(Ipv4Addr::LOCALHOST),
                        DECKER_SEQUENCER_EL_P2P_PORT,
                        id,
                    ),
                )
            }
        };

        Ok(Self {
            chain,
            http_port,
            authrpc_addr,
            authrpc_port,
            authrpc_jwtsecret,
            port,
            trusted_peer,
            chain_block_time,
        })
    }

    pub(super) fn apply(self, cli: Cli) -> Cli {
        let mut cli = cli;
        let Commands::Node(ref mut node) = cli.command else {
            // playground defaults are only relevant if running the node commands.
            return cli;
        };

        if !node.network.trusted_peers.contains(&self.trusted_peer) {
            node.network.trusted_peers.push(self.trusted_peer);
        }

        // populate the command line arguments only if they were never set by the user
        // either via the command line or an environment variable. Otherwise, don't
        // override the user provided values.
        let matches = Cli::command().get_matches();
        let matches = matches
            .subcommand_matches("node")
            .expect("validated that we are in the node command");

        if matches.value_source("chain").is_default() {
            node.chain = self.chain;
        }

        if matches.value_source("http").is_default() {
            node.rpc.http = true;
        }

        if matches.value_source("http_port").is_default() {
            node.rpc.http_port = self.http_port;
        }

        if matches.value_source("port").is_default() {
            node.network.port = self.port;
        }

        if matches.value_source("auth_addr").is_default() {
            node.rpc.auth_addr = self.authrpc_addr;
        }

        if matches.value_source("auth_port").is_default() {
            node.rpc.auth_port = self.authrpc_port;
        }

        if matches.value_source("auth_jwtsecret").is_default() {
            node.rpc.auth_jwtsecret = Some(self.authrpc_jwtsecret);
        }

        if matches.value_source("disable_discovery").is_default() {
            node.network.discovery.disable_discovery = true;
        }

        if matches.value_source("chain_block_time").is_default() {
            node.ext.chain_block_time = self.chain_block_time.as_millis() as u64;
        }

        cli
    }
}

fn existing_path(base: &Path, relative: &str) -> Result<String> {
    let path = base.join(relative);
    if path.exists() {
        Ok(path.to_string_lossy().to_string())
    } else {
        Err(eyre::eyre!(
            "Expected file {relative} is not present in playground directory {}",
            base.display()
        ))
    }
}

fn pick_random_port(range: Range<u16>) -> u16 {
    use rand::Rng;
    let mut rng = rand::rng();

    loop {
        // Generate a random port number between 30000 and 65535
        let port = rng.random_range(range.clone());

        // Check if the port is already in use
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        if std::net::TcpListener::bind(socket).is_ok() {
            return port;
        }
    }
}

fn pick_preferred_port(preferred: u16, fallback_range: Range<u16>) -> u16 {
    if !is_port_free(preferred) {
        return pick_random_port(fallback_range);
    }

    preferred
}

fn is_port_free(port: u16) -> bool {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    std::net::TcpListener::bind(socket).is_ok()
}

fn extract_chain_block_time(basepath: &Path) -> Result<Duration> {
    Ok(Duration::from_secs(
        serde_json::from_str::<Value>(&read_to_string(existing_path(basepath, "rollup.json")?)?)?
            .get("block_time")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| eyre::eyre!("Missing chain_block_time in rollup.json"))?,
    ))
}

fn extract_deterministic_p2p_key(basepath: &Path) -> Result<SecretKey> {
    let key = read_to_string(existing_path(basepath, "enode-key-1.txt")?)?;
    Ok(SecretKey::from_slice(
        &hex::decode(key).map_err(|e| eyre!("Invalid hex key: {e}"))?,
    )?)
}

fn read_docker_compose(basepath: &Path) -> Result<serde_yaml::Value> {
    // this happens only once on statup so it's fine to read the file multiple times
    let docker_compose = read_to_string(existing_path(basepath, "docker-compose.yaml")?)?;
    serde_yaml::from_str(&docker_compose).map_err(|e| eyre!("Invalid docker-compose file: {e}"))
}

fn extract_service_command_flag(basepath: &Path, service: &str, flag: &str) -> Result<String> {
    let docker_compose = read_docker_compose(basepath)?;
    let args = docker_compose["services"][service]["command"]
        .as_sequence()
        .ok_or(eyre!(
            "docker-compose.yaml is missing command line arguments for {service}"
        ))?
        .iter()
        .map(|s| {
            s.as_str().ok_or_else(|| {
                eyre!("docker-compose.yaml service command line argument is not a string")
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let index = args
        .iter()
        .position(|arg| *arg == flag)
        .ok_or_else(|| eyre!("docker_compose: {flag} not found on {service} service"))?;

    let value = args
        .get(index + 1)
        .ok_or_else(|| eyre!("docker_compose: {flag} value not found"))?;

    Ok(value.to_string())
}

fn extract_authrpc_port(basepath: &Path) -> Result<u16> {
    let builder_url = extract_service_command_flag(basepath, "rollup-boost", "--builder-url")?;
    let url = Url::parse(&builder_url).map_err(|e| eyre!("Invalid builder-url: {e}"))?;
    url.port().ok_or_else(|| eyre!("missing builder-url port"))
}

fn extract_trusted_peer_port(basepath: &Path) -> Result<u16> {
    let docker_compose = read_docker_compose(basepath)?;

    // first we need to find the internal port of the op-geth service from the docker-compose.yaml
    // command line arguments used to start the op-geth service

    let Some(opgeth_args) = docker_compose["services"]["op-geth"]["command"][1].as_str() else {
        return Err(eyre!(
            "docker-compose.yaml is missing command line arguments for op-geth"
        ));
    };

    let opgeth_args = opgeth_args.split_whitespace().collect::<Vec<_>>();
    let port_param_position = opgeth_args
        .iter()
        .position(|arg| *arg == "--port")
        .ok_or_else(|| eyre!("docker_compose: --port param not found on op-geth service"))?;

    let port_value = opgeth_args
        .get(port_param_position + 1)
        .ok_or_else(|| eyre!("docker_compose: --port value not found"))?;

    let port_value = port_value
        .parse::<u16>()
        .map_err(|e| eyre!("Invalid port value: {e}"))?;

    // now we need to find the external port of the op-geth service from the docker-compose.yaml
    // ports mapping used to start the op-geth service
    let Some(opgeth_ports) = docker_compose["services"]["op-geth"]["ports"].as_sequence() else {
        return Err(eyre!(
            "docker-compose.yaml is missing ports mapping for op-geth"
        ));
    };
    let ports_mapping = opgeth_ports
        .iter()
        .map(|s| {
            s.as_str().ok_or_else(|| {
                eyre!("docker-compose.yaml service ports mapping in op-geth is not a string")
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // port mappings is in the format [..., "127.0.0.1:30304:30303", ...]
    // we need to find the mapping that contains the port value we found earlier
    // and extract the external port from it
    let port_mapping = ports_mapping
        .iter()
        .find(|mapping| mapping.contains(&format!(":{port_value}")))
        .ok_or_else(|| {
            eyre!("docker_compose: external port mapping not found for {port_value} for op-geth")
        })?;

    // extract the external port from the mapping
    let port_mapping = port_mapping
        .split(':')
        .nth(1)
        .ok_or_else(|| eyre!("docker_compose: external port mapping for op-geth is not valid"))?;

    port_mapping
        .parse::<u16>()
        .map_err(|e| eyre!("Invalid external port mapping value for op-geth: {e}"))
}

trait IsDefaultSource {
    fn is_default(&self) -> bool;
}

impl IsDefaultSource for Option<ValueSource> {
    fn is_default(&self) -> bool {
        matches!(self, Some(ValueSource::DefaultValue)) || self.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const GENESIS_JSON: &str = include_str!("../tests/framework/artifacts/genesis.json.tmpl");

    /// secp256k1 secret key `1`'s uncompressed pubkey
    const SECP256K1_GENERATOR_POINT_ID: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    /// Writes the files shared by both layouts (chain spec, jwt, block time).
    fn write_common_artifacts(dir: &Path, block_time_secs: u64) {
        fs::write(dir.join("l2-genesis.json"), GENESIS_JSON).unwrap();
        fs::write(dir.join("jwtsecret"), "test-jwt-secret").unwrap();
        fs::write(
            dir.join("rollup.json"),
            format!(r#"{{"block_time": {block_time_secs}}}"#),
        )
        .unwrap();
    }

    /// Adds the legacy-only markers on top of the shared artifacts: a
    /// docker-compose.yaml (rollup-boost's `--builder-url` and op-geth's
    /// `--port`/ports mapping) and the trusted-peer secret key file.
    fn write_legacy_artifacts(dir: &Path, block_time_secs: u64) {
        write_common_artifacts(dir, block_time_secs);
        fs::write(
            dir.join("enode-key-1.txt"),
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        fs::write(
            dir.join("docker-compose.yaml"),
            r#"
services:
  op-geth:
    command:
      - /bin/sh
      - "-c geth --port 30303 --networkid 901"
    ports:
      - "127.0.0.1:30304:30303"
  rollup-boost:
    command:
      - rollup-boost
      - --builder-url
      - http://host.docker.internal:4444
"#,
        )
        .unwrap();
    }

    #[test]
    fn test_detect_layout_is_legacy_when_docker_compose_present() {
        let dir = tempfile::tempdir().unwrap();
        write_legacy_artifacts(dir.path(), 2);
        assert!(matches!(detect_layout(dir.path()).unwrap(), Layout::Legacy));
    }

    #[test]
    fn test_detect_layout_is_decker_when_only_l2_genesis_present() {
        let dir = tempfile::tempdir().unwrap();
        write_common_artifacts(dir.path(), 2);
        assert!(matches!(detect_layout(dir.path()).unwrap(), Layout::Decker));
    }

    #[test]
    fn test_detect_layout_errors_when_neither_marker_present() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_layout(dir.path()).is_err());
    }

    #[test]
    fn test_decker_layout_uses_fixed_authrpc_port_and_trusted_peer() {
        let dir = tempfile::tempdir().unwrap();
        write_common_artifacts(dir.path(), 7);

        let options = PlaygroundOptions::new(dir.path()).expect("decker layout should parse");

        assert_eq!(options.authrpc_port, DECKER_BUILDER_AUTHRPC_PORT);
        assert_eq!(options.chain_block_time, Duration::from_secs(7));
        assert_eq!(
            options.trusted_peer.host,
            Host::<String>::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(options.trusted_peer.tcp_port, DECKER_SEQUENCER_EL_P2P_PORT);
        assert_eq!(
            options.trusted_peer.id,
            DECKER_SEQUENCER_EL_PEER_ID.parse::<PeerId>().unwrap()
        );
    }

    #[test]
    fn test_legacy_layout_still_parses_docker_compose() {
        let dir = tempfile::tempdir().unwrap();
        write_legacy_artifacts(dir.path(), 3);

        let options = PlaygroundOptions::new(dir.path()).expect("legacy layout should parse");

        assert_eq!(options.authrpc_port, 4444);
        assert_eq!(options.chain_block_time, Duration::from_secs(3));
        assert_eq!(
            options.trusted_peer.host,
            Host::<String>::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(options.trusted_peer.tcp_port, 30304);
        assert_eq!(
            options.trusted_peer.id,
            SECP256K1_GENERATOR_POINT_ID.parse::<PeerId>().unwrap()
        );
    }

    #[test]
    fn test_new_errors_on_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        drop(dir); // removes the directory, guaranteeing `path` doesn't exist

        assert!(PlaygroundOptions::new(&path).is_err());
    }
}
