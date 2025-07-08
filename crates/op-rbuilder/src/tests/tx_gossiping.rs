use std::str::FromStr;
use alloy_provider::Provider;
use clap_builder::Parser;
use reth::rpc::builder::RpcModuleSelection;
use reth_optimism_cli::commands::Commands;
use crate::builders::StandardBuilder;
use crate::tests::{default_node_config, ChainDriver, ChainDriverExt, ExternalNode, Ipc, LocalInstance};
use alloy::rpc::types::admin::NodeInfo;
use alloy_provider::ext::TxPoolApi;
use reth_network_peers::TrustedPeer;
use testcontainers::bollard::Docker;
use tracing::info;

#[tokio::test]
async fn test_txgossiping() {
    let docker = Docker::connect_with_local_defaults().expect("Failed to connect to docker");
    let node1 = ExternalNode::reth().await.expect("ext node 1");
    let node2 = ExternalNode::reth().await.expect("ext node 2");

    let node1_info = node1.provider()
        .raw_request::<_, NodeInfo>("admin_nodeInfo".into(), ())   // empty params list
        .await.expect("request local node");
    let node2_info = node2.provider()
        .raw_request::<_, NodeInfo>("admin_nodeInfo".into(), ())   // empty params list
        .await.expect("request local node");
    let node1_ip = docker.inspect_container(node1.container_id().as_str(), None).await.expect("inspection container").network_settings.unwrap().ip_address;
    let node2_ip = docker.inspect_container(node2.container_id().as_str(), None).await.expect("inspection container").network_settings.unwrap().ip_address;
    let enode1 = node1_info.enode.replace("127.0.0.1", node1_ip.expect("node1 ip").as_str());
    let enode2 = node2_info.enode.replace("127.0.0.1", node2_ip.expect("node2 ip").as_str());
    let enode1 = TrustedPeer::from_str(enode1.as_str()).expect("enode1");
    let enode2 = TrustedPeer::from_str(enode2.as_str()).expect("enode2");
    info!("enode1: {:?}, enode2: {:?}", enode1, enode2);

    // Create node and set node1 as trusted peer and node2 as rbuilder peer

    let mut config = default_node_config();

    config.network.trusted_peers = vec![enode1.clone(), enode2.clone()];
    config.network.trusted_only = true;
    config.network.bootnodes = Some(vec![enode1.clone(), enode2.clone()]);
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let mut command = node_command.ext.clone();
    command.rbuilder_peers = vec![enode2.clone()];
    let instance = LocalInstance::new_with_config::<StandardBuilder>(command, config).await.expect("testing node");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("driver");
    let provider1 = node1.provider().clone();
    let provider2 = node2.provider().clone();
    let driver = driver.with_validation_node(node1).await.unwrap();
    let driver = driver.with_validation_node(node2).await.unwrap();
    let tx = driver.create_transaction().send().await.expect("query tx");
    tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
    driver.build_new_block().await.unwrap();
    driver.build_new_block().await.unwrap();
    let tx = driver.create_transaction().send().await.expect("query tx");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    info!("{:?}", provider1.txpool_content().await.unwrap());
    info!("{:?}", provider2.txpool_content().await.unwrap());
    info!("{:?}", driver.provider().txpool_content().await.unwrap());
}
