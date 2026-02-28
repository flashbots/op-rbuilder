use crate::{
    args::OpRbuilderArgs,
    tests::{BuilderTxValidation, LocalInstance, OpRbuilderArgsTestExt, TransactionBuilderExt},
};
use alloy_primitives::{Bytes, TxHash};
use alloy_provider::{Provider, RootProvider};
use op_alloy_network::Optimism;

use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use macros::rb_test;
use std::collections::HashSet;
use tokio::{join, task::yield_now};
use tracing::info;

async fn raw_tx_size_bytes(
    provider: &RootProvider<Optimism>,
    tx_hash: TxHash,
) -> eyre::Result<u64> {
    let raw: Option<Bytes> = provider
        .raw_request("eth_getRawTransactionByHash".into(), (tx_hash,))
        .await?;
    Ok(raw
        .ok_or_else(|| eyre::eyre!("raw transaction not found for hash {tx_hash}"))?
        .len() as u64)
}

/// This is a smoke test that ensures that transactions are included in blocks
/// and that the block generator is functioning correctly.
///
/// Generated blocks are also validated against an external op-reth node to
/// ensure their correctness.
#[rb_test]
async fn chain_produces_blocks(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    #[cfg(target_os = "linux")]
    let driver = driver
        .with_validation_node(crate::tests::ExternalNode::reth().await?)
        .await?;

    const SAMPLE_SIZE: usize = 10;

    // ensure that each block has at least two transactions when
    // no user transactions are sent.
    // the deposit transaction and the block generator's transaction
    for _ in 0..SAMPLE_SIZE {
        let block = driver.build_new_block_with_current_timestamp(None).await?;

        // Validate builder transactions are present (must be done before moving transactions)
        block.assert_builder_tx_count(2);

        let transactions = block.transactions;

        // in flashblocks we add an additional transaction on the first
        // flashblocks and then one on the last flashblock
        assert_eq!(
            transactions.len(),
            3,
            "Empty blocks should have exactly three transactions"
        );
    }

    // ensure that transactions are included in blocks and each block has all the transactions
    // sent to it during its block time + the two mandatory transactions
    for _ in 0..SAMPLE_SIZE {
        let count = rand::random_range(1..8);
        let mut tx_hashes = HashSet::<TxHash>::default();

        for _ in 0..count {
            let tx = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await
                .expect("Failed to send transaction");
            tx_hashes.insert(*tx.tx_hash());
        }

        let block = driver.build_new_block_with_current_timestamp(None).await?;

        // Validate builder transactions are present (must be done before moving transactions)
        block.assert_builder_tx_count(2);

        let txs = block.transactions;

        // we add an additional transaction on the first flashblock and then one
        // on the last flashblock
        assert_eq!(
            txs.len(),
            3 + count,
            "Block should have {} transactions",
            3 + count
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
#[rb_test(multi_threaded)]
async fn produces_blocks_under_load_within_deadline(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?.with_gas_limit(1_000_000);

    let done = AtomicBool::new(false);

    let (populate, produce) = join!(
        async {
            // Keep the builder busy with new transactions.
            loop {
                match driver
                    .create_transaction()
                    .random_valid_transfer()
                    .send()
                    .await
                {
                    Ok(_) => {}
                    Err(e) if e.to_string().contains("txpool is full") => {
                        // If the txpool is full, give it a short break
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => return Err(e),
                };

                if done.load(Ordering::Relaxed) {
                    break;
                }

                yield_now().await;
            }
            Ok::<(), eyre::Error>(())
        },
        async {
            // Wait for a short time to allow the transaction population to start
            // and fill up the txpool.
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Now, start producing blocks under load.
            for _ in 0..10 {
                // Ensure that the builder can still produce blocks under
                // heavy load of incoming transactions.
                let block = tokio::time::timeout(
                    Duration::from_secs(rbuilder.args().chain_block_time)
                        + Duration::from_millis(500),
                    driver.build_new_block_with_current_timestamp(None),
                )
                .await
                .expect("Timeout while waiting for block production")
                .expect("Failed to produce block under load");

                info!(block = ?block, "Produced a block under load");

                yield_now().await;
            }

            // we're happy with one block produced under load
            // set the done flag to true to stop the transaction population
            done.store(true, Ordering::Relaxed);
            info!("All blocks produced under load");

            Ok::<(), eyre::Error>(())
        }
    );

    populate.unwrap();

    //assert!(populate.is_ok(), "Failed to populate transactions");
    assert!(produce.is_ok(), "Failed to produce block under load");

    Ok(())
}

#[rb_test]
async fn test_no_tx_pool(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    // make sure we can build a couple of blocks first
    let _ = driver.build_new_block().await?;

    // now lets try to build a block with no transactions
    let _ = driver.build_new_block_with_no_tx_pool().await?;

    Ok(())
}

#[rb_test(args = OpRbuilderArgs {
    max_gas_per_txn: Some(25000),
    ..Default::default()
})]
async fn chain_produces_big_tx_with_gas_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    #[cfg(target_os = "linux")]
    let driver = driver
        .with_validation_node(crate::tests::ExternalNode::reth().await?)
        .await?;

    // insert valid txn under limit
    let tx = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await
        .expect("Failed to send transaction");

    // insert txn with gas usage above limit
    let tx_high_gas = driver
        .create_transaction()
        .random_big_transaction()
        .send()
        .await
        .expect("Failed to send transaction");

    let block = driver.build_new_block_with_current_timestamp(None).await?;

    // Validate builder transactions are present (must be done before moving transactions)
    block.assert_builder_tx_count(2);

    let txs = block.transactions;

    assert_eq!(txs.len(), 4, "Should have 4 transactions");

    // assert we included the tx with gas under limit
    let inclusion_result = txs.hashes().find(|hash| hash == tx.tx_hash());
    assert!(inclusion_result.is_some());

    // assert we do not include the tx with gas above limit
    let exclusion_result = txs.hashes().find(|hash| hash == tx_high_gas.tx_hash());
    assert!(exclusion_result.is_none());

    Ok(())
}

#[rb_test]
async fn chain_produces_big_tx_without_gas_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    #[cfg(target_os = "linux")]
    let driver = driver
        .with_validation_node(crate::tests::ExternalNode::reth().await?)
        .await?;

    // insert txn with gas usage but there is no limit
    let tx = driver
        .create_transaction()
        .random_big_transaction()
        .send()
        .await
        .expect("Failed to send transaction");

    let block = driver.build_new_block_with_current_timestamp(None).await?;

    // Validate builder transactions are present (must be done before moving transactions)

    block.assert_builder_tx_count(2);

    let txs = block.transactions;

    // assert we included the tx
    let inclusion_result = txs.hashes().find(|hash| hash == tx.tx_hash());
    assert!(inclusion_result.is_some());

    assert_eq!(txs.len(), 4, "Should have 4 transactions");

    Ok(())
}

/// Validates that each block contains builder transactions using the
/// BuilderTxValidation utility.
#[rb_test]
async fn block_includes_builder_transaction(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    const SAMPLE_SIZE: usize = 5;

    for _ in 0..SAMPLE_SIZE {
        let block = driver.build_new_block_with_current_timestamp(None).await?;

        // Validate that the block contains builder transactions
        assert!(
            block.has_builder_tx(),
            "Block should contain at least one builder transaction"
        );

        // 2 builder txs (fallback + flashblock number)
        block.assert_builder_tx_count(2);
    }

    Ok(())
}

#[rb_test]
async fn max_uncompressed_block_size_includes_builder_transactions(
    rbuilder: LocalInstance,
) -> eyre::Result<()> {
    let (limit, user_tx_size) = {
        let probe_driver = rbuilder.driver().await?;
        let probe_provider = rbuilder.provider().await?;

        let probe_block = probe_driver
            .build_new_block_with_current_timestamp(None)
            .await?;
        let builder_info = probe_block.find_builder_txs();
        assert_eq!(
            builder_info.count, 2,
            "probe block should include two builder txs"
        );

        let tx_hashes: Vec<_> = probe_block.transactions.hashes().collect();
        assert_eq!(
            tx_hashes.len(),
            3,
            "probe block should contain deposit + 2 builder txs"
        );

        let mut sizes = Vec::with_capacity(tx_hashes.len());
        for tx_hash in &tx_hashes {
            sizes.push(raw_tx_size_bytes(&probe_provider, *tx_hash).await?);
        }

        let first_builder_size = sizes[builder_info.indices[0]];
        let second_builder_size = sizes[builder_info.indices[1]];
        assert!(
            second_builder_size > 0,
            "second builder transaction should have non-zero encoded size"
        );

        let total_probe_size: u64 = sizes.iter().sum();
        let deposit_size = total_probe_size - first_builder_size - second_builder_size;

        let (_pending, raw_user_tx) = probe_driver
            .create_transaction()
            .random_valid_transfer()
            .send_and_get_raw_tx()
            .await?;
        let user_tx_size = raw_user_tx.len() as u64;

        // Allow: deposit + first builder + user tx. Disallow adding the final builder tx.
        let limit = deposit_size + first_builder_size + user_tx_size + (second_builder_size - 1);
        (limit, user_tx_size)
    };

    let mut args = OpRbuilderArgs::test_default();
    args.max_uncompressed_block_size = Some(limit);
    let rbuilder = LocalInstance::new(args).await?;
    let driver = rbuilder.driver().await?;
    let provider = rbuilder.provider().await?;

    let user_tx = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await?;
    let block = driver.build_new_block_with_current_timestamp(None).await?;

    assert!(
        block.transactions.hashes().any(|h| h == *user_tx.tx_hash()),
        "user tx should still fit before final builder tx is considered"
    );

    let builder_info = block.find_builder_txs();
    assert_eq!(
        builder_info.count, 1,
        "final builder tx should be skipped when it would exceed max uncompressed size"
    );

    let mut built_size = 0u64;
    for tx_hash in block.transactions.hashes() {
        built_size += raw_tx_size_bytes(&provider, tx_hash).await?;
    }

    assert!(
        built_size <= limit,
        "built block should not exceed max uncompressed size: built={built_size} limit={limit} user_tx_size={user_tx_size}"
    );

    Ok(())
}
