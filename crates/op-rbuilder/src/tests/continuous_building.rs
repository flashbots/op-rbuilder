use crate::{
    args::{FlashblocksArgs, OpRbuilderArgs},
    tests::{BlockTransactionsExt, LocalInstance, TransactionBuilderExt},
};
use core::time::Duration;
use macros::rb_test;
use tokio::join;
use tracing::info;

/// Returns a block timestamp `chain_block_time` seconds in the future.
///
/// Passing this to `build_new_block_with_txs_timestamp` gives us:
/// - No alignment sleep (FCU fires immediately) for determinism
/// - A future payload deadline with proper flashblock schedule and full intervals
fn future_block_timestamp(chain_block_time: Duration) -> Duration {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    now + chain_block_time
}

/// Verifies continuous building with production-like settings: 200ms flashblocks in a 2s block.
///
/// Sends a transaction midway through flashblock 1's interval (200–400ms) and asserts it is
/// picked up by flashblock 1 — not deferred to a later flashblock. This proves the continuous
/// building loop keeps incorporating new mempool transactions within the current interval.
///
/// Flashblock 0 is ignored as it only contains deposit + builder transactions (no mempool txs).
///
/// Uses a future block timestamp passed directly to skip the variable 0–1s alignment sleep
/// in `build_new_block_with_current_timestamp`, making sleep-based timing deterministic.
#[rb_test(flashblocks, multi_threaded, args = OpRbuilderArgs {
    chain_block_time: 2000,
    flashblocks: FlashblocksArgs {
        flashblocks_block_time: 200,
        flashblocks_enable_continuous_building: true,
        ..Default::default()
    },
    ..Default::default()
})]
async fn test_continuous_building_with_new_transactions(
    rbuilder: LocalInstance,
) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();
    let block_timestamp =
        future_block_timestamp(Duration::from_millis(rbuilder.args().chain_block_time));

    let (build_result, send_result) = join!(
        // Branch A: build a block (FCU fires immediately -> sleep chain_block_time -> getPayload)
        async {
            driver
                .build_new_block_with_txs_timestamp(
                    vec![],
                    None,
                    Some(block_timestamp),
                    None,
                    Some(0),
                )
                .await
        },
        // Branch B: send a transaction at ~300ms, near the end of fb 1 interval (200–400ms).
        // With continuous building the builder should pick this up in fb 1 rather than fb 2.
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let tx = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
            let tx_hash = *tx.tx_hash();
            Ok::<_, eyre::Error>(tx_hash)
        }
    );

    let block = build_result?;
    let tx_hash = send_result?;

    assert!(
        block.includes(&tx_hash),
        "Transaction sent at ~350ms should be in the final block"
    );

    let fb_index = flashblocks_listener
        .find_transaction_flashblock(&tx_hash)
        .expect("Transaction should appear in a flashblock");

    assert_eq!(
        fb_index, 1,
        "Transaction sent at ~350ms should appear in flashblock 1, got index {fb_index}"
    );

    flashblocks_listener.stop().await
}
