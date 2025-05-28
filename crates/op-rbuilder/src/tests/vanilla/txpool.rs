use crate::tests::{framework::TestHarnessBuilder, ONE_ETH};
use alloy_provider::ext::TxPoolApi;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::ws_client::WsClientBuilder;

/// This test ensures that pending pool custom limit is respected and priority tx would be included even when pool if full.
#[tokio::test]
async fn pending_pool_limit() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("pending_pool_limit")
        .with_namespaces("txpool,eth,debug,admin")
        .with_extra_params("--txpool.pending-max-count 50")
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // Send 50 txs from different addrs
    let accounts = generator.create_funded_accounts(2, ONE_ETH).await?;
    let acc_no_priority = accounts.first().unwrap();
    let acc_with_priority = accounts.last().unwrap();

    for _ in 0..50 {
        let _ = harness
            .create_transaction()
            .with_signer(*acc_no_priority)
            .send()
            .await?;
    }

    let pool = harness
        .provider()
        .expect("provider not available")
        .txpool_status()
        .await?;
    assert_eq!(
        pool.pending, 50,
        "Pending pool must contain at max 50 txs {:?}",
        pool
    );

    // Send 10 txs that should be included in the block
    let mut txs = Vec::new();
    for _ in 0..10 {
        let tx = harness
            .create_transaction()
            .with_signer(*acc_with_priority)
            .with_max_priority_fee_per_gas(10)
            .send()
            .await?;
        txs.push(*tx.tx_hash());
    }

    let pool = harness
        .provider()
        .expect("provider not available")
        .txpool_status()
        .await?;
    assert_eq!(
        pool.pending, 50,
        "Pending pool must contain at max 50 txs {:?}",
        pool
    );

    // After we try building block our reverting tx would be removed and other tx will move to queue pool
    let block = generator.generate_block().await?;

    // Ensure that 10 extra txs got included
    assert!(block.includes_vec(txs));

    Ok(())
}

#[rpc(client, namespace = "txpool")]
pub trait TxpoolExtApi {
    /// Creates a subscription that returns the txpool events.
    #[subscription(name = "subscribeEvents", item = usize)]
    fn subscribe_events(&self) -> SubscriptionResult;
}

/// This test ensures that if we enable the txpool monitor, there is a websocket
/// on which we can subscribe and receive txpool events.
#[tokio::test]
async fn txpool_monitor() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("txpool_monitor")
        .with_namespaces("txpool,eth,debug,admin,txpool")
        .build()
        .await?;

    let ws_url = format!("ws://127.0.0.1:{}", harness.builder_ws_port);
    let client = WsClientBuilder::default().build(&ws_url).await.unwrap();

    // send 10 transactions
    for _ in 0..10 {
        let tx = harness.create_transaction().send().await?;
        println!("tx: {:?}", tx);
    }

    // If we subscribe now, we should receive 10 events, one for each tx since they are internally buffered
    let mut sub = TxpoolExtApiClient::subscribe_events(&client)
        .await
        .expect("failed to subscribe");

    println!("sub: {:?}", sub.next().await);

    Ok(())
}
