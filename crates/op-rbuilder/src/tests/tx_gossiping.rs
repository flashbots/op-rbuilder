use alloy_provider::Provider;
use clap_builder::Parser;
use reth::rpc::builder::RpcModuleSelection;
use reth_optimism_cli::commands::Commands;
use crate::builders::StandardBuilder;
use crate::tests::{default_node_config, ChainDriver, ChainDriverExt, Ipc, LocalInstance};
use alloy::rpc::types::admin::NodeInfo;

#[tokio::test]
async fn test_txgossiping() {
    let mut config = default_node_config();
    config.rpc.http_api = Some(RpcModuleSelection::All);
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let instance = LocalInstance::new_with_config::<StandardBuilder>(node_command.ext.clone(), config).await.expect("valid instance");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("local driver");
    driver.fund_default_accounts().await.expect("fund_default_accounts");
    let node_info: NodeInfo = driver.provider()
        .raw_request("admin_nodeInfo".into(), ())   // empty params list
        .await.expect("request local node");
    println!("local node enode: {}", node_info.enode);
}