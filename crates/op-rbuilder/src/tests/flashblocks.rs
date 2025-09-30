use alloy_provider::Provider;
use macros::rb_test;
use std::time::Duration;

use crate::{
    args::{FlashblocksArgs, OpRbuilderArgs},
    tests::{BlockTransactionsExt, BundleOpts, LocalInstance, TransactionBuilderExt},
};

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 2000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn smoke_dynamic_base(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // We align out block timestamps with current unix timestamp
    for _ in 0..10 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
        }
        let block = driver.build_new_block_with_current_timestamp(None).await?;
        assert_eq!(block.transactions.len(), 8, "Got: {:?}", block.transactions); // 5 normal txn + deposit + 2 builder txn
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(110, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn smoke_dynamic_unichain(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // We align out block timestamps with current unix timestamp
    for _ in 0..10 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
        }
        let block = driver.build_new_block_with_current_timestamp(None).await?;
        assert_eq!(block.transactions.len(), 8, "Got: {:?}", block.transactions); // 5 normal txn + deposit + 2 builder txn
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(60, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 50,
        flashblocks_fixed: true,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn smoke_classic_unichain(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // We align out block timestamps with current unix timestamp
    for _ in 0..10 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
        }
        let block = driver.build_new_block().await?;
        assert_eq!(block.transactions.len(), 8, "Got: {:?}", block.transactions); // 5 normal txn + deposit + 2 builder txn
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(60, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 2000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 50,
        flashblocks_fixed: true,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn smoke_classic_base(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // We align out block timestamps with current unix timestamp
    for _ in 0..10 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
        }
        let block = driver.build_new_block().await?;
        assert_eq!(block.transactions.len(), 8, "Got: {:?}", block.transactions); // 5 normal txn + deposit + 2 builder txn
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(110, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn unichain_dynamic_with_lag(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // We align out block timestamps with current unix timestamp
    for i in 0..9 {
        for _ in 0..5 {
            // send a valid transaction
            let _ = driver
                .create_transaction()
                .random_valid_transfer()
                .send()
                .await?;
        }
        let block = driver
            .build_new_block_with_current_timestamp(Some(Duration::from_millis(i * 100)))
            .await?;
        assert_eq!(
            block.transactions.len(),
            8,
            "Got: {:#?}",
            block.transactions
        ); // 5 normal txn + deposit + 2 builder txn
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(34, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 0,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn dynamic_with_full_block_lag(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    for _ in 0..5 {
        // send a valid transaction
        let _ = driver
            .create_transaction()
            .random_valid_transfer()
            .send()
            .await?;
    }
    let block = driver
        .build_new_block_with_current_timestamp(Some(Duration::from_millis(999)))
        .await?;
    // We could only produce block with deposits + builder tx because of short time frame
    assert_eq!(block.transactions.len(), 2);

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(1, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    enable_revert_protection: true,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn test_flashblock_min_filtering(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // Create two transactions and set their tips so that while ordinarily
    // tx2 would come before tx1 because its tip is bigger, now tx1 comes
    // first because it has a lower minimum flashblock requirement.
    let tx1 = driver
        .create_transaction()
        .random_valid_transfer()
        .with_bundle(BundleOpts::default().with_flashblock_number_min(0))
        .with_max_priority_fee_per_gas(0)
        .send()
        .await?;

    let tx2 = driver
        .create_transaction()
        .random_valid_transfer()
        .with_bundle(BundleOpts::default().with_flashblock_number_min(3))
        .with_max_priority_fee_per_gas(10)
        .send()
        .await?;

    let _block1 = driver.build_new_block_with_current_timestamp(None).await?;

    // Check that tx1 comes before tx2
    let tx1_hash = *tx1.tx_hash();
    let tx2_hash = *tx2.tx_hash();
    let tx1_pos = flashblocks_listener
        .find_transaction_flashblock(&tx1_hash)
        .unwrap();
    let tx2_pos = flashblocks_listener
        .find_transaction_flashblock(&tx2_hash)
        .unwrap();

    assert!(
        tx1_pos < tx2_pos,
        "tx {tx1_hash:?} does not come before {tx2_hash:?}"
    );

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(6, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    enable_revert_protection: true,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn test_flashblock_max_filtering(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // Since we cannot directly trigger flashblock creation in tests, we
    // instead fill up the gas of flashblocks so that our tx with the
    // flashblock_number_max parameter set is properly delayed, simulating
    // the scenario where we'd sent the tx after the flashblock max number
    // had passed.
    let call = driver
        .provider()
        .raw_request::<(i32, i32), bool>("miner_setMaxDASize".into(), (0, 100 * 3))
        .await?;
    assert!(call, "miner_setMaxDASize should be executed successfully");

    let _fit_tx_1 = driver
        .create_transaction()
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let tx1 = driver
        .create_transaction()
        .random_valid_transfer()
        .with_bundle(BundleOpts::default().with_flashblock_number_max(1))
        .send()
        .await?;

    let block = driver.build_new_block_with_current_timestamp(None).await?;
    assert!(!block.includes(tx1.tx_hash()));
    assert!(
        flashblocks_listener
            .find_transaction_flashblock(tx1.tx_hash())
            .is_none()
    );

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(6, flashblocks.len());

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    enable_revert_protection: true,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn test_flashblock_min_max_filtering(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    let tx1 = driver
        .create_transaction()
        .random_valid_transfer()
        .with_bundle(
            BundleOpts::default()
                .with_flashblock_number_max(2)
                .with_flashblock_number_min(2),
        )
        .send()
        .await?;

    let _block = driver.build_new_block_with_current_timestamp(None).await?;

    // It ends up in the 2nd flashblock
    assert_eq!(
        2,
        flashblocks_listener
            .find_transaction_flashblock(tx1.tx_hash())
            .unwrap(),
        "Transaction should be in the 2nd flashblock"
    );

    let flashblocks = flashblocks_listener.get_flashblocks();
    assert_eq!(6, flashblocks.len(), "Flashblocks length should be 6");

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: false,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 10,
    },
    ..Default::default()
})]
async fn test_flashblocks_no_state_root_calculation(rbuilder: LocalInstance) -> eyre::Result<()> {
    use alloy_primitives::B256;

    let driver = rbuilder.driver().await?;

    // Send a transaction to ensure block has some activity
    let _tx = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await?;

    // Build a block with current timestamp (not historical) and calculate_state_root: false
    let block = driver.build_new_block_with_current_timestamp(None).await?;

    // Verify that flashblocks are still produced (block should have transactions)
    assert!(
        block.transactions.len() > 2,
        "Block should contain transactions"
    ); // deposit + builder tx + user tx

    // Verify that state root is not calculated (should be zero)
    assert_eq!(
        block.header.state_root,
        B256::ZERO,
        "State root should be zero when calculate_state_root is false"
    );

    Ok(())
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 1000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 200,
        flashblocks_leeway_time: 100,
        flashblocks_fixed: true,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 3, // Cap at 3 flashblocks instead of default 5
    },
    ..Default::default()
})]
async fn test_max_flashblocks_per_block_cap(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // Send transactions to ensure blocks have activity
    for _ in 0..5 {
        let _ = driver
            .create_transaction()
            .random_valid_transfer()
            .send()
            .await?;
    }

    // Build a block - normally would produce 5 flashblocks (1000ms / 200ms = 5)
    // But with max_flashblocks_per_block: 3, it should cap at 3
    let block = driver.build_new_block().await?;
    assert_eq!(
        block.transactions.len(),
        8,
        "Block should contain all transactions"
    ); // 5 normal txn + deposit + 2 builder txn

    let flashblocks = flashblocks_listener.get_flashblocks();
    // Should produce only 3 flashblocks + 1 base flashblock = 4 total
    assert_eq!(
        4,
        flashblocks.len(),
        "Should be capped at 3 flashblocks + 1 base = 4 total"
    );

    // Verify flashblock indices are within expected range
    for fb in &flashblocks {
        assert!(
            fb.index <= 3,
            "Flashblock index should not exceed 3, got index {}",
            fb.index
        );
    }

    flashblocks_listener.stop().await
}

#[rb_test(flashblocks, args = OpRbuilderArgs {
    chain_block_time: 2000,
    flashblocks: FlashblocksArgs {
        enabled: true,
        flashblocks_port: 1239,
        flashblocks_addr: "127.0.0.1".into(),
        flashblocks_block_time: 100, // Short interval would normally create 20 flashblocks
        flashblocks_leeway_time: 50,
        flashblocks_fixed: false,
        flashblocks_calculate_state_root: true,
        flashblocks_number_contract_address: None,
        max_flashblocks_per_block: 5, // Cap at 5 flashblocks
    },
    ..Default::default()
})]
async fn test_max_flashblocks_dynamic_timing(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let flashblocks_listener = rbuilder.spawn_flashblocks_listener();

    // Send transactions
    for _ in 0..3 {
        let _ = driver
            .create_transaction()
            .random_valid_transfer()
            .send()
            .await?;
    }

    // Build block with current timestamp (dynamic timing)
    // Would normally create ~20 flashblocks (2000ms / 100ms = 20)
    // But should be capped at 5
    let block = driver.build_new_block_with_current_timestamp(None).await?;
    assert!(
        block.transactions.len() >= 5,
        "Block should contain transactions"
    );

    let flashblocks = flashblocks_listener.get_flashblocks();
    // Should be capped at 5 flashblocks + 1 base = 6 total
    assert!(
        flashblocks.len() <= 6,
        "Should be capped at 5 flashblocks + 1 base = 6 total, got {}",
        flashblocks.len()
    );

    // Verify no flashblock index exceeds the cap
    for fb in &flashblocks {
        assert!(
            fb.index <= 5,
            "Flashblock index should not exceed 5, got index {}",
            fb.index
        );
    }

    flashblocks_listener.stop().await
}
