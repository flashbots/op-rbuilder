use crate::{
    args::OpRbuilderArgs,
    backrun_bundle::args::BackrunBundleArgs,
    tests::{
        BlockTransactionsExt, BundleOpts, ChainDriverExt, LocalInstance, ONE_ETH,
        TransactionBuilderExt, send_backrun_bundle,
    },
};
use alloy_network::ReceiptResponse;
use alloy_provider::Provider;
use macros::rb_test;

/// Tests that a valid backrun bundle lands in the block immediately after the target transaction.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        ..Default::default()
    },
    ..Default::default()
})]
async fn basic_backrun_inclusion(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    let backrun_hash = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(10),
        BundleOpts::default(),
    )
    .await?;

    let block = driver.build_new_block().await?;

    // Verify backrun is immediately after target
    let tx_hashes: Vec<_> = block.transactions.hashes().collect();
    let target_pos = tx_hashes.iter().position(|h| *h == target_hash);
    let backrun_pos = tx_hashes.iter().position(|h| *h == backrun_hash);

    assert!(target_pos.is_some(), "Target not found in block");
    assert!(backrun_pos.is_some(), "Backrun not found in block");
    assert_eq!(
        backrun_pos.unwrap(),
        target_pos.unwrap() + 1,
        "Backrun should be immediately after target"
    );

    Ok(())
}

/// Tests that the backrun bundle RPC endpoint is not available when backruns are disabled.
#[rb_test]
async fn backrun_excluded_when_disabled(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let (_target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .send_and_get_raw_tx()
        .await?;

    let result = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_valid_transfer(),
        BundleOpts::default(),
    )
    .await;

    assert!(
        result.is_err(),
        "Expected error because backrun RPC method is not available when disabled"
    );

    Ok(())
}

/// Tests that a reverting backrun is excluded from the block while the target transaction stays.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        ..Default::default()
    },
    ..Default::default()
})]
async fn backrun_excluded_when_reverts(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    // Backrun that reverts
    let backrun_hash = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_reverting_transaction()
            .with_max_priority_fee_per_gas(10),
        BundleOpts::default(),
    )
    .await?;

    let block = driver.build_new_block().await?;

    assert!(block.includes(&target_hash), "Target tx should be in block");
    assert!(
        !block.includes(&backrun_hash),
        "Reverting backrun should not be in block"
    );

    Ok(())
}

/// Tests that a backrun with priority fee lower than the target is rejected.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        ..Default::default()
    },
    ..Default::default()
})]
async fn backrun_excluded_when_priority_fee_too_low(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(20)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    // Backrun with lower priority fee than target
    let backrun_hash = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(5),
        BundleOpts::default(),
    )
    .await?;

    let block = driver.build_new_block().await?;

    assert!(block.includes(&target_hash), "Target tx should be in block");
    assert!(
        !block.includes(&backrun_hash),
        "Backrun with low priority fee should not be in block"
    );

    Ok(())
}

/// Tests that block_number_min constraint is respected for backrun bundles.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        ..Default::default()
    },
    ..Default::default()
})]
async fn backrun_block_number_constraints(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Build a block first so we have a known block number
    let _ = driver.build_new_block().await?; // Block 1
    let latest = driver.latest().await?;
    let current_block = latest.header.number;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    // Set min_block_number to current + 2, so the backrun should NOT be included in the next block
    let backrun_hash = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(10),
        BundleOpts::default().with_block_number_min(current_block + 2),
    )
    .await?;

    // Block current+1: target should be included but backrun should NOT (min not reached)
    let block = driver.build_new_block().await?;
    assert!(block.includes(&target_hash), "Target tx should be in block");
    assert!(
        !block.includes(&backrun_hash),
        "Backrun should not be in block before min_block_number"
    );

    Ok(())
}

/// Tests that max_landed_backruns_per_target=1 limits to only one backrun per target.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        max_landed_backruns_per_target: 1,
        max_considered_backruns_per_target: 10,
        ..Default::default()
    },
    ..Default::default()
})]
async fn backrun_per_target_landing_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    // 1 target + 3 backrun signers
    let accounts = driver.fund_accounts(4, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    // Submit 3 backrun bundles for the same target
    let mut backrun_hashes = Vec::new();
    for i in 0..3 {
        let backrun_builder = driver
            .create_transaction()
            .with_signer(accounts[i + 1])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(10 + i as u128);

        let backrun_hash = send_backrun_bundle(
            target_raw_tx.clone(),
            backrun_builder,
            BundleOpts::default(),
        )
        .await?;
        backrun_hashes.push(backrun_hash);
    }

    let block = driver.build_new_block().await?;

    // Target should be included
    assert!(block.includes(&target_hash), "Target tx should be in block");

    // Only 1 backrun should land (max_landed_backruns_per_target = 1)
    let backruns_included = backrun_hashes.iter().filter(|h| block.includes(*h)).count();
    assert_eq!(
        backruns_included, 1,
        "Only 1 backrun should land per target (limit=1), but {} landed",
        backruns_included
    );

    Ok(())
}

/// Tests that max_landed_backruns_per_block=1 limits backruns across multiple targets.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        max_landed_backruns_per_block: 1,
        max_landed_backruns_per_target: 1,
        ..Default::default()
    },
    ..Default::default()
})]
async fn backrun_per_block_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    // 2 targets + 2 backrun signers
    let accounts = driver.fund_accounts(4, ONE_ETH).await?;

    let mut target_hashes = Vec::new();
    let mut backrun_hashes = Vec::new();

    // Create 2 target+backrun pairs
    for i in 0..2 {
        let (target_pending, target_raw_tx) = driver
            .create_transaction()
            .with_signer(accounts[i])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(10)
            .send_and_get_raw_tx()
            .await?;
        target_hashes.push(*target_pending.tx_hash());

        let backrun_hash = send_backrun_bundle(
            target_raw_tx,
            driver
                .create_transaction()
                .with_signer(accounts[i + 2])
                .random_valid_transfer()
                .with_max_priority_fee_per_gas(10),
            BundleOpts::default(),
        )
        .await?;
        backrun_hashes.push(backrun_hash);
    }

    let block = driver.build_new_block().await?;

    // Both targets should be included
    for target_hash in &target_hashes {
        assert!(block.includes(target_hash), "Target tx should be in block");
    }

    // Only 1 backrun total should land (max_landed_backruns_per_block = 1)
    let backruns_included = backrun_hashes.iter().filter(|h| block.includes(*h)).count();
    assert_eq!(
        backruns_included, 1,
        "Only 1 backrun should land per block (limit=1), but {} landed",
        backruns_included
    );

    Ok(())
}

/// Tests that 2 backruns can land for the same target when the limit allows it.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        max_landed_backruns_per_target: 2,
        max_considered_backruns_per_target: 10,
        ..Default::default()
    },
    ..Default::default()
})]
async fn multiple_backruns_land(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    // 1 target + 2 backrun signers
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    let mut backrun_hashes = Vec::new();
    for i in 0..2 {
        let backrun_hash = send_backrun_bundle(
            target_raw_tx.clone(),
            driver
                .create_transaction()
                .with_signer(accounts[i + 1])
                .random_valid_transfer()
                .with_max_priority_fee_per_gas(10 + i as u128),
            BundleOpts::default(),
        )
        .await?;
        backrun_hashes.push(backrun_hash);
    }

    let block = driver.build_new_block().await?;

    assert!(block.includes(&target_hash), "Target tx should be in block");

    for backrun_hash in &backrun_hashes {
        assert!(
            block.includes(backrun_hash),
            "Backrun {backrun_hash} should be in block when limit=2"
        );
    }

    Ok(())
}

/// Tests that when more backruns are submitted than the limit, the highest priority fee ones land.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        max_landed_backruns_per_target: 2,
        max_considered_backruns_per_target: 10,
        ..Default::default()
    },
    ..Default::default()
})]
async fn highest_priority_fee_backruns_land(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    // 1 target + 5 backrun signers
    let accounts = driver.fund_accounts(6, ONE_ETH).await?;

    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_valid_transfer()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    // Submit 5 backruns with priority fees: 10, 30, 20, 50, 40
    let priority_fees = [10u128, 30, 20, 50, 40];
    let mut backrun_hashes = Vec::new();
    for (i, &fee) in priority_fees.iter().enumerate() {
        let backrun_hash = send_backrun_bundle(
            target_raw_tx.clone(),
            driver
                .create_transaction()
                .with_signer(accounts[i + 1])
                .random_valid_transfer()
                .with_max_priority_fee_per_gas(fee),
            BundleOpts::default(),
        )
        .await?;
        backrun_hashes.push(backrun_hash);
    }

    let block = driver.build_new_block().await?;

    assert!(block.includes(&target_hash), "Target tx should be in block");

    // With limit=2, only the two highest priority fee backruns should land (fees 50 and 40)
    let backruns_included: Vec<_> = backrun_hashes
        .iter()
        .enumerate()
        .filter(|(_, h)| block.includes(*h))
        .map(|(i, _)| i)
        .collect();

    assert_eq!(
        backruns_included.len(),
        2,
        "Exactly 2 backruns should land (limit=2), but {} landed",
        backruns_included.len()
    );

    // The winners should be index 3 (fee=50) and index 4 (fee=40)
    assert!(
        block.includes(&backrun_hashes[3]),
        "Backrun with highest priority fee (50) should land"
    );
    assert!(
        block.includes(&backrun_hashes[4]),
        "Backrun with second highest priority fee (40) should land"
    );

    Ok(())
}

/// Tests that when the target transaction reverts, the backrun is not triggered.
#[rb_test(args = OpRbuilderArgs {
    backrun_bundle: BackrunBundleArgs {
        backruns_enabled: true,
        ..Default::default()
    },
    enable_revert_protection: true,
    ..Default::default()
})]
async fn backrun_not_triggered_when_target_reverts(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Target that reverts - sent as a bundle with revert protection
    let (target_pending, target_raw_tx) = driver
        .create_transaction()
        .with_signer(accounts[0])
        .random_reverting_transaction()
        .with_max_priority_fee_per_gas(10)
        .send_and_get_raw_tx()
        .await?;
    let target_hash = *target_pending.tx_hash();

    let backrun_hash = send_backrun_bundle(
        target_raw_tx,
        driver
            .create_transaction()
            .with_signer(accounts[1])
            .random_valid_transfer()
            .with_max_priority_fee_per_gas(10),
        BundleOpts::default(),
    )
    .await?;

    let block = driver.build_new_block().await?;

    // The target is a regular mempool tx (not a bundle), so it will be included even though it reverts
    assert!(
        block.includes(&target_hash),
        "Reverting target should be in block (no bundle revert protection)"
    );
    let receipt = driver
        .provider()
        .get_transaction_receipt(target_hash)
        .await?
        .expect("Target receipt should exist");
    assert!(!receipt.status(), "Target transaction should have reverted");
    assert!(
        !block.includes(&backrun_hash),
        "Backrun should not be in block when target reverts"
    );

    Ok(())
}
