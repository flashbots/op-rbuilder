use core::sync::atomic::AtomicBool;
use std::collections::HashSet;

use alloy_primitives::TxHash;
use tokio::join;

use super::super::{ChainDriver, LocalInstance, TransactionBuilderExt};

#[tokio::test]

/// This is a smoke test that ensures that transactions are included in blocks
/// and that the block generator is functioning correctly.
async fn chain_produces_blocks() -> eyre::Result<()> {
    let rbuilder = LocalInstance::standard().await?;
    let driver = ChainDriver::new(&rbuilder).await?;

    const SAMPLE_SIZE: usize = 10;

    // ensure that each block has at least two transactions when
    // no user transactions are sent.
    // the deposit transaction and the block generator's transaction
    for _ in 0..SAMPLE_SIZE {
        let block = driver.build_new_block().await?;
        let transactions = block.transactions;

        assert_eq!(
            transactions.len(),
            2,
            "Empty blocks should have exactly two transactions"
        );
    }

    // ensure that transactions are included in blocks and each block has all the transactions
    // sent to it during its block time + the two mandatory transactions
    for _ in 0..SAMPLE_SIZE {
        let count = rand::random_range(1..8);
        let mut tx_hashes = HashSet::<TxHash>::default();

        for _ in 0..count {
            let tx = driver
                .transaction()
                .random_valid_transfer()
                .send()
                .await
                .expect("Failed to send transaction");
            tx_hashes.insert(*tx.tx_hash());
        }

        let block = driver.build_new_block().await?;
        let txs = block.transactions;

        assert_eq!(
            txs.len(),
            2 + count,
            "Block should have {} transactions",
            2 + count
        );

        for tx_hash in tx_hashes {
            assert!(
                txs.hashes().any(|hash| hash == tx_hash),
                "Transaction {} should be included in the block",
                tx_hash
            );
        }
    }

    Ok(())
}

/// Ensures that payloads are generated correctly even when the builder is busy
/// with other requests, such as fcu or getPayload.
#[tokio::test]
async fn produces_blocks_under_load_within_deadline() -> eyre::Result<()> {
    let rbuilder = LocalInstance::standard().await?;
    let driver = ChainDriver::new(&rbuilder).await?;

    let done = AtomicBool::new(false);

    let (populate, produce) = join!(
        async {
            // Keep the builder busy with new transactions.
            loop {
                let _ = driver.transaction().random_valid_transfer().send().await?;
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
            Ok::<(), eyre::Error>(())
        },
        async {
            // give it some time for the transactions queue to fill up
            // and the producer to send many txs.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            for _ in 0..10 {
                // Ensure that the builder can still produce blocks under
                // heavy load of incoming transactions.
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    driver.build_new_block(),
                )
                .await
                .map_err(|_| eyre::eyre!("Timeout while waiting for block"))?;
            }
            
            // we're happy with one block produced under load
            // set the done flag to true to stop the transaction population
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            
            Ok::<(), eyre::Error>(())
        }
    );

    assert!(populate.is_ok(), "Failed to populate transactions");
    assert!(produce.is_ok(), "Failed to produce block under load");

    Ok(())
}
