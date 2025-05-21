use crate::tests::{BundleOpts, TestHarnessBuilder};

/// This test ensures that the transactions that get reverted an not included in the block
/// are emitted as a log on the builder.
#[tokio::test]
async fn monitor_transaction_drops() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("monitor_transaction_drops")
        .with_revert_protection()
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // send 10 reverting transactions
    let mut pending_txn = Vec::new();
    for _ in 0..10 {
        let txn = harness.send_revert_transaction().await?;
        pending_txn.push(txn);
    }

    // generate 10 blocks
    for _ in 0..10 {
        generator.generate_block().await?;
        let latest_block = harness.latest_block().await;

        // blocks should only include two transactions (deposit + builder)
        assert_eq!(latest_block.transactions.len(), 2);
    }

    // check that the builder emitted logs for the reverted transactions
    // with the monitoring logic
    // TODO: this is not ideal, lets find a different way to detect this
    // Each time a transaction is dropped, it emits a log like this
    // 'Transaction event received target="monitoring" tx_hash="<tx_hash>" kind="discarded"'
    let builder_logs = std::fs::read_to_string(harness.builder_log_path())?;

    for txn in pending_txn {
        let txn_log = format!(
            "Transaction event received target=\"monitoring\" tx_hash=\"{}\" kind=\"discarded\"",
            txn.tx_hash()
        );

        assert!(builder_logs.contains(txn_log.as_str()));
    }

    Ok(())
}

#[tokio::test]
async fn revert_protection_disabled() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("revert_protection_disabled")
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    for _ in 0..10 {
        let valid_tx = harness.send_valid_transaction().await?;
        let reverting_tx = harness.send_revert_transaction().await?;
        let block_generated = generator.generate_block().await?;

        assert!(block_generated.includes(*valid_tx.tx_hash()));
        assert!(block_generated.includes(*reverting_tx.tx_hash()));
    }

    Ok(())
}

#[tokio::test]
async fn revert_protection_disabled_bundle_endpoint_error() -> eyre::Result<()> {
    // If revert protection is disabled, it should not be possible to send a revert bundle
    // since the revert RPC endpoint is not available.
    let harness = TestHarnessBuilder::new("revert_protection_disabled_bundle_endpoint_error")
        .build()
        .await?;

    let res = harness
        .create_transaction()
        .with_bundle(BundleOpts::default())
        .send()
        .await;

    assert!(
        res.is_err(),
        "Expected error because method is not available"
    );
    Ok(())
}

#[tokio::test]
async fn revert_protection_bundle() -> eyre::Result<()> {
    // Test the behaviour of the revert protection bundle, if the bundle **does not** revert
    // the transaction is included in the block. If the bundle reverts, the transaction
    // is not included in the block and tried again for the next bundle range blocks
    // when it will be dropped from the pool.
    let harness = TestHarnessBuilder::new("revert_protection_bundle")
        .with_revert_protection()
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // Test 1: Bundle does not revert
    {
        let valid_bundle = harness
            .create_transaction()
            .with_bundle(BundleOpts::default())
            .send()
            .await?;

        let block_generated = generator.generate_block().await?;
        assert!(block_generated.includes(*valid_bundle.tx_hash()));
    }

    // Test 2: Bundle reverts. It is not included in the block
    {
        let reverted_bundle = harness
            .create_transaction()
            .with_revert()
            .with_bundle(BundleOpts::default())
            .send()
            .await?;

        let block_generated = generator.generate_block().await?;
        assert!(block_generated.not_includes(*reverted_bundle.tx_hash()));
    }

    Ok(())
}

#[tokio::test]
async fn revert_protection_bundle_range_limits() -> eyre::Result<()> {
    // Test the range limits for the revert protection bundle.
    // - It cannot have as a max block number a past block number
    // TODO: We have not decided on the limits yet.
    Ok(())
}

#[tokio::test]
async fn revert_protection_allow_reverted_transactions_without_bundle() -> eyre::Result<()> {
    // If a transaction reverts and was sent as a normal transaction through the eth_sendRawTransaction
    // bundle, the transaction should be included in the block.
    // This behaviour is the same as the 'revert_protection_disabled' test.
    let harness =
        TestHarnessBuilder::new("revert_protection_allow_reverted_transactions_without_bundle")
            .with_revert_protection()
            .build()
            .await?;

    let mut generator = harness.block_generator().await?;

    for _ in 0..10 {
        let valid_tx = harness.send_valid_transaction().await?;
        let reverting_tx = harness.send_revert_transaction().await?;
        let block_generated = generator.generate_block().await?;

        assert!(block_generated.includes(*valid_tx.tx_hash()));
        assert!(block_generated.not_includes(*reverting_tx.tx_hash()));
    }

    Ok(())
}
