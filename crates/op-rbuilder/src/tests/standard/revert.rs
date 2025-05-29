use reth_transaction_pool::TransactionEvent;

use crate::{
    args::OpRbuilderArgs,
    builders::StandardBuilder,
    tests::{BlockTransactionsExt, BundleOpts, ChainDriverExt, LocalInstance, TransactionBuilderExt, ONE_ETH},
};

/// If revert protection is disabled, the transactions that revert are included in the block.
#[tokio::test]
async fn revert_protection_disabled() -> eyre::Result<()> {
    let rbuilder = LocalInstance::standard().await?;
    let driver = rbuilder.driver().await?;

    for _ in 0..10 {
        let valid_tx = driver.transaction().random_valid_transfer().send().await?;
        let reverting_tx = driver
            .transaction()
            .random_reverting_transaction()
            .send()
            .await?;
        let block = driver.build_new_block().await?;

        assert!(block
            .transactions
            .hashes()
            .any(|hash| hash == *valid_tx.tx_hash()));
        assert!(block
            .transactions
            .hashes()
            .any(|hash| hash == *reverting_tx.tx_hash()));
    }

    Ok(())
}

/// If revert protection is enabled, the transactions that revert are not included in the block.
#[tokio::test]
#[ignore = "This test is ignored for now because the revert protection logic has changed"]
async fn revert_protection_enabled() -> eyre::Result<()> {
    let rbuilder = LocalInstance::new::<StandardBuilder>(OpRbuilderArgs {
        enable_revert_protection: true,
        ..Default::default()
    })
    .await?;
    let driver = rbuilder.driver().await?;

    for _ in 0..10 {
        let valid_tx = driver.transaction().random_valid_transfer().send().await?;
        let reverting_tx = driver
            .transaction()
            .random_reverting_transaction()
            .send()
            .await?;
        let block = driver.build_new_block().await?;

        assert!(block
            .transactions
            .hashes()
            .any(|hash| hash == *valid_tx.tx_hash()));
        assert!(!block
            .transactions
            .hashes()
            .any(|hash| hash == *reverting_tx.tx_hash()));
    }

    Ok(())
}

/// If revert protection is disabled, it should not be possible to send a revert bundle
/// since the revert RPC endpoint is not available.
#[tokio::test]
async fn revert_protection_disabled_bundle_endpoint_error() -> eyre::Result<()> {
    let rbuilder = LocalInstance::standard().await?;
    let driver = rbuilder.driver().await?;

    let res = driver
        .transaction()
        .with_bundle(BundleOpts::default())
        .send()
        .await;

    assert!(
        res.is_err(),
        "Expected error because method is not available"
    );
    Ok(())
}

/// This test ensures that the transactions that get reverted and not included in the block,
/// are eventually dropped from the pool once their block range is reached.
/// This test creates N transactions with different block ranges.
#[tokio::test]
async fn revert_protection_monitor_transaction_gc() -> eyre::Result<()> {
    let rbuilder = LocalInstance::new::<StandardBuilder>(OpRbuilderArgs {
        enable_revert_protection: true,
        ..Default::default()
    })
    .await?;

    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(10, ONE_ETH).await?;
    let latest_block_number = driver.latest().await?.header.number;

    // send 10 bundles with different block ranges
    let mut pending_txn = Vec::new();

    for i in 0..accounts.len() {
        let txn = driver
            .transaction()
            .random_reverting_transaction()
            .with_signer(accounts[i].clone())
            .with_bundle(BundleOpts {
                block_number_max: Some(latest_block_number + i as u64 + 1),
            })
            .send()
            .await?;
        pending_txn.push(txn);
    }

    rbuilder.pool().print_all();

    // generate 10 blocks
    for i in 0..accounts.len() {
        let block = driver.build_new_block().await?;

        // blocks should only include two transactions (deposit + builder)
        assert_eq!(block.transactions.len(), 2);

        // since we created the 10 transactions with increasing block ranges, as we generate blocks
        // one transaction will be gc on each block.
        // transactions from [0, i] should be dropped, transactions from [i+1, 10] should be queued
        for j in 0..=i {
            assert_eq!(
                rbuilder
                    .pool()
                    .tx_status(*pending_txn[j].tx_hash())
                    .expect("tx not found in pool"),
                TransactionEvent::Discarded
            );
        }
        for j in i + 1..10 {
            assert_eq!(
                rbuilder
                    .pool()
                    .tx_status(*pending_txn[j].tx_hash())
                    .expect("tx not found in pool"),
                TransactionEvent::Pending
            );
        }
    }

    Ok(())
}

/// Test the behaviour of the revert protection bundle, if the bundle **does not** revert
/// the transaction is included in the block. If the bundle reverts, the transaction
/// is not included in the block and tried again for the next bundle range blocks
/// when it will be dropped from the pool.
#[tokio::test]
async fn revert_protection_bundle() -> eyre::Result<()> {
    let rbuilder = LocalInstance::new::<StandardBuilder>(OpRbuilderArgs {
        enable_revert_protection: true,
        ..Default::default()
    })
    .await?;

    let driver = rbuilder.driver().await?;
    let _ = driver.build_new_block().await?; // Block 1

    // Test 1: Bundle does not revert
    let valid_bundle = driver
        .transaction()
        .random_valid_transfer()
        .with_bundle(BundleOpts::default())
        .send()
        .await?;

    let block2 = driver.build_new_block().await?; // Block 2
    assert!(block2.transactions.hashes().includes(valid_bundle.tx_hash()));

    let bundle_opts = BundleOpts {
        block_number_max: Some(4),
    };

    let reverted_bundle = driver
        .transaction()
        .random_reverting_transaction()
        .with_bundle(bundle_opts)
        .send()
        .await?;

    // Test 2: Bundle reverts. It is not included in the block
    let block3 = driver.build_new_block().await?; // Block 3
    assert!(!block3.includes(reverted_bundle.tx_hash()));

    // After the block the transaction is still pending in the pool
    assert!(rbuilder.pool().is_pending(*reverted_bundle.tx_hash()));

    // Test 3: Chain progresses beyond the bundle range. The transaction is dropped from the pool
    driver.build_new_block().await?; // Block 4
    assert!(rbuilder.pool().is_dropped(*reverted_bundle.tx_hash()));

    driver.build_new_block().await?; // Block 5
    assert!(rbuilder.pool().is_dropped(*reverted_bundle.tx_hash()));
    
    Ok(())
}

// /// Test the range limits for the revert protection bundle.
// #[tokio::test]
// async fn revert_protection_bundle_range_limits() -> eyre::Result<()> {
//     let harness = TestHarnessBuilder::new("revert_protection_bundle_range_limits")
//         .with_revert_protection()
//         .build()
//         .await?;

//     let mut generator = harness.block_generator().await?;

//     // Advance two blocks and try to send a bundle with max block = 1
//     generator.generate_block().await?; // Block 1
//     generator.generate_block().await?; // Block 2

//     async fn send_bundle(
//         harness: &TestHarness,
//         block_number_max: u64,
//     ) -> eyre::Result<PendingTransactionBuilder<Optimism>> {
//         harness
//             .create_transaction()
//             .with_bundle(BundleOpts {
//                 block_number_max: Some(block_number_max),
//             })
//             .send()
//             .await
//     }

//     // Max block cannot be a past block
//     assert!(send_bundle(&harness, 1).await.is_err());

//     // Bundles are valid if their max block in in between the current block and the max block range
//     let next_valid_block = 3;

//     for i in next_valid_block..next_valid_block + MAX_BLOCK_RANGE_BLOCKS {
//         assert!(send_bundle(&harness, i).await.is_ok());
//     }

//     // A bundle with a block out of range is invalid
//     assert!(
//         send_bundle(&harness, next_valid_block + MAX_BLOCK_RANGE_BLOCKS + 1)
//             .await
//             .is_err()
//     );

//     Ok(())
// }

// /// If a transaction reverts and was sent as a normal transaction through the eth_sendRawTransaction
// /// bundle, the transaction should be included in the block.
// /// This behaviour is the same as the 'revert_protection_disabled' test.
// #[tokio::test]
// async fn revert_protection_allow_reverted_transactions_without_bundle() -> eyre::Result<()> {
//     let harness =
//         TestHarnessBuilder::new("revert_protection_allow_reverted_transactions_without_bundle")
//             .with_revert_protection()
//             .build()
//             .await?;

//     let mut generator = harness.block_generator().await?;

//     for _ in 0..10 {
//         let valid_tx = harness.send_valid_transaction().await?;
//         let reverting_tx = harness.send_revert_transaction().await?;
//         let block_generated = generator.generate_block().await?;

//         assert!(block_generated.includes(*valid_tx.tx_hash()));
//         assert!(block_generated.includes(*reverting_tx.tx_hash()));
//     }

//     Ok(())
// }
