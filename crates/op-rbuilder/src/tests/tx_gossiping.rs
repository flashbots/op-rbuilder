use alloy_provider::Provider;
use clap_builder::Parser;
use reth_optimism_cli::commands::Commands;
use crate::builders::StandardBuilder;
use crate::tests::{default_node_config, ChainDriver, ChainDriverExt, Ipc, LocalInstance};

#[tokio::test]
async fn test_txgossiping(rbuilder: LocalInstance) {
    let mut config = default_node_config();
    config.network.p2p_secret_key =
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let instance = LocalInstance::new_with_config::<StandardBuilder>(node_command.ext.clone(), config).await.expect("valid instance");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("local driver");
    driver.fund_default_accounts().await.expect("fund_default_accounts");
}