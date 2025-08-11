use crate::{
    builders::StandardBuilder,
    tests::{default_node_config, setup_external_peer_node, ChainDriver, Ipc, LocalInstance},
};
use alloy_provider::ext::TxPoolApi;
use clap_builder::Parser;
use reth::network::transactions::config::TransactionPropagationKind;
use reth_optimism_cli::commands::Commands;

#[tokio::test]
async fn test_txgossiping_with_peer() {
    let (node1, enode1) = setup_external_peer_node().await;
    let (node2, enode2) = setup_external_peer_node().await;
    let mut config = default_node_config();

    // Create node and connect it make created external nodes it's peers
    // Only the second node would be set as rbuilder peer and would receive transactions
    config.network.trusted_peers = vec![enode1.clone(), enode2.clone()];
    config.network.trusted_only = true;
    config.network.tx_propagation_policy = TransactionPropagationKind::All;
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let mut command = node_command.ext.clone();
    // We enable peering and appoint node2 as rbuilder peer
    command.rbuilder_peers = vec![enode2.clone()];
    let instance = LocalInstance::new_with_config::<StandardBuilder>(command, config)
        .await
        .expect("testing node");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("driver");
    let provider1 = node1.provider().clone();
    let provider2 = node2.provider().clone();
    let driver = driver.with_validation_node(node1).await.unwrap();
    let driver = driver.with_validation_node(node2).await.unwrap();
    let _ = driver.build_new_block().await;
    // We send 3 transaction, wait some time and expect that none of the peers would receive transaction
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    assert!(
        provider1.txpool_content().await.unwrap().pending.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider1.txpool_content().await.unwrap().queued.is_empty(),
        "Transaction should not be propagated"
    );
    assert_eq!(
        provider2.txpool_status().await.unwrap().pending,
        3,
        "Rbuilder peer should contain same transactions"
    );
    assert_eq!(
        driver.provider().txpool_status().await.unwrap().pending,
        3,
        "Main node should contain 3 transaction"
    );
}

/// This test sets tx propagation to trusted peers only, but we are using custom network so it won't
/// have any effect. We haven't set builder peers so no transaction would be propagated.
#[tokio::test]
async fn test_txgossiping_no_rbuilder_peers() {
    let (node1, enode1) = setup_external_peer_node().await;
    let (node2, enode2) = setup_external_peer_node().await;
    let mut config = default_node_config();

    // Create node and connect it make created external nodes it's peers
    // Only the second node would be set as rbuilder peer and would receive transactions
    config.network.trusted_peers = vec![enode1.clone(), enode2.clone()];
    config.network.trusted_only = true;
    config.network.tx_propagation_policy = TransactionPropagationKind::All;
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let instance =
        LocalInstance::new_with_config::<StandardBuilder>(node_command.ext.clone(), config)
            .await
            .expect("testing node");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("driver");
    let provider1 = node1.provider().clone();
    let provider2 = node2.provider().clone();
    let driver = driver.with_validation_node(node1).await.unwrap();
    let driver = driver.with_validation_node(node2).await.unwrap();
    let _ = driver.build_new_block().await;
    // We send 3 transaction, wait some time and expect that none of the peers would receive transaction
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    assert!(
        provider1.txpool_content().await.unwrap().pending.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider1.txpool_content().await.unwrap().queued.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider2.txpool_content().await.unwrap().pending.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider2.txpool_content().await.unwrap().queued.is_empty(),
        "Transaction should not be propagated"
    );
    assert_eq!(
        driver.provider().txpool_status().await.unwrap().pending,
        3,
        "Main node should contain 3 transaction"
    );
}

/// This test sets tx propagation to trusted peers only, but we are using custom network so it won't
/// have any effect. We haven't set builder peers so no transaction would be propagated.
#[tokio::test]
async fn test_txgossiping_no_rbuilder_gossiping() {
    let (node1, enode1) = setup_external_peer_node().await;
    let (node2, enode2) = setup_external_peer_node().await;
    let mut config = default_node_config();

    // Create node and connect it make created external nodes it's peers
    // Only the second node would be set as rbuilder peer and would receive transactions
    config.network.trusted_peers = vec![enode1.clone(), enode2.clone()];
    config.network.trusted_only = true;
    config.network.tx_propagation_policy = TransactionPropagationKind::All;
    let args = crate::args::Cli::parse_from(["dummy", "node"]);
    let Commands::Node(ref node_command) = args.command else {
        unreachable!()
    };
    let mut command = node_command.ext.clone();
    // We enabled regular mechanism, bit have not provided rbuilder peers, this should result in no propagation
    command.rollup_args.disable_txpool_gossip = false;
    // We add rbuilder peer too, to ensure that it won't receive txs
    command.rbuilder_peers = vec![enode2.clone()];
    let instance =
        LocalInstance::new_with_config::<StandardBuilder>(node_command.ext.clone(), config)
            .await
            .expect("testing node");
    let driver = ChainDriver::<Ipc>::local(&instance).await.expect("driver");
    let provider1 = node1.provider().clone();
    let provider2 = node2.provider().clone();
    let driver = driver.with_validation_node(node1).await.unwrap();
    let driver = driver.with_validation_node(node2).await.unwrap();
    let _ = driver.build_new_block().await;
    // We send 3 transaction, wait some time and expect that none of the peers would receive transaction
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    let _ = driver.create_transaction().send().await.expect("query tx");
    // Sleep to wait for propagation
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    assert!(
        provider1.txpool_content().await.unwrap().pending.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider1.txpool_content().await.unwrap().queued.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider2.txpool_content().await.unwrap().pending.is_empty(),
        "Transaction should not be propagated"
    );
    assert!(
        provider2.txpool_content().await.unwrap().queued.is_empty(),
        "Transaction should not be propagated"
    );
    assert_eq!(
        driver.provider().txpool_status().await.unwrap().pending,
        3,
        "Main node should contain 3 transaction"
    );
}
