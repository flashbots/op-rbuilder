use crate::{
    args::OpRbuilderArgs,
    tests::{LocalInstance, TransactionBuilderExt},
    tx_signer::Signer,
};
use futures::StreamExt;
use macros::*;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 2000,
    ..Default::default()
})]
async fn chain_produces_blocks(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    // Create a struct to hold received messages
    let received_messages = Arc::new(Mutex::new(Vec::new()));
    let messages_clone = received_messages.clone();
    let cancellation_token = CancellationToken::new();
    let ws_url = rbuilder.flashblocks_ws_url();

    // Spawn WebSocket listener task
    let cancellation_token_clone = cancellation_token.clone();
    let ws_handle: JoinHandle<eyre::Result<()>> = tokio::spawn(async move {
        let (ws_stream, _) = connect_async(ws_url).await?;
        let (_, mut read) = ws_stream.split();

        loop {
            tokio::select! {
              _ = cancellation_token_clone.cancelled() => {
                  break Ok(());
              }
              Some(Ok(Message::Text(text))) = read.next() => {
                messages_clone.lock().push(text);
              }
            }
        }
    });

    for _ in 0..10 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver.transaction().random_valid_transfer().send().await?;
        }

        let block = driver.build_new_block().await?;
        println!("Block built with hash: {block:#?}");
        assert_eq!(block.transactions.len(), 7); // 5 normal txn + deposit + builder txn

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    cancellation_token.cancel();
    assert!(ws_handle.await.is_ok(), "WebSocket listener task failed");

    assert!(
        !received_messages
            .lock()
            .iter()
            .any(|msg| msg.contains("Building flashblock")),
        "No messages received from WebSocket"
    );

    Ok(())
}
