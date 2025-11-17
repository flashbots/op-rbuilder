use crate::tests::{BlockTransactionsExt, LocalInstance};
use alloy_provider::Provider;
use macros::{if_flashblocks, if_standard, rb_test};
/// This test ensures that the miner gas limit is respected
/// We will set the limit to 60,000 and see that the builder will not include any transactions
#[rb_test]
async fn miner_gas_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let call = driver
        .provider()
        .raw_request::<(u64,), bool>("miner_setGasLimit".into(), (60000,))
        .await?;
    assert!(call, "miner_setGasLimit should be executed successfully");

    let unfit_tx = driver.create_transaction().send().await?;
    let block = driver.build_new_block().await?;

    // tx should not be included because the gas limit is less than the transaction gas
    assert!(
        !block.includes(unfit_tx.tx_hash()),
        "transaction should not be included in the block"
    );

    Ok(())
}

/// This test ensures that block will fill up to the limit, each transaction is 53,000 gas
/// We will set our limit to 1Mgas and ensure that throttling occurs
/// There is a deposit transaction for 182,706 gas, and builder transactions are 21,600 gas
///
/// Standard = (1.03 million - 182,706 - 21,600) / 53,000 = 15.57 = 15 transactions can fit
/// Flashblocks = (1.03 million - 182,706 - 21,600 - 21,600) / 53,000 = 15.17 = 15 transactions can fit
#[rb_test]
async fn block_fill(rbuilder: LocalInstance) -> eyre::Result<()> {
    if_flashblocks! {
        return Ok(());
    }

    let driver = rbuilder.driver().await?;

    let call = driver
        .provider()
        .raw_request::<(u64,), bool>("miner_setGasLimit".into(), (1_030_000,))
        .await?;
    assert!(call, "miner_setGasLimit should be executed successfully");

    let mut tx_hashes = Vec::new();
    for _ in 0..15 {
        let tx = driver
            .create_transaction()
            .with_gas_limit(53000)
            .with_max_priority_fee_per_gas(100)
            .send()
            .await?;
        tx_hashes.push(tx.tx_hash().clone());
    }
    let unfit_tx = driver
        .create_transaction()
        .with_gas_limit(53000)
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        assert!(
            block.includes(tx_hash),
            "tx i={} hash={} should be in block",
            i,
            tx_hash
        );
    }
    assert!(
        !block.includes(unfit_tx.tx_hash()),
        "unfit tx should not be in block"
    );

    if_standard! {
        assert_eq!(
            block.transactions.len(),
            17,
            "deposit + builder + 15 valid txs should be in the block"
        );
    }

    if_flashblocks! {
        assert_eq!(
            block.transactions.len(),
            18,
            "deposit + 2 builder + 15 valid txs should be in the block"
        );
    }

    Ok(())
}

/// This test ensures that the gasLimit can be reset to the default value
/// by setting it to 0
#[rb_test]
async fn reset_gas_limit(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let call = driver
        .provider()
        .raw_request::<(u64,), bool>("miner_setGasLimit".into(), (60000,))
        .await?;
    assert!(call, "miner_setGasLimit should be executed successfully");

    let unfit_tx = driver.create_transaction().send().await?;
    let block = driver.build_new_block().await?;

    // tx should not be included because the gas limit is less than the transaction gas
    assert!(
        !block.includes(unfit_tx.tx_hash()),
        "transaction should not be included in the block"
    );

    let reset_call = driver
        .provider()
        .raw_request::<(u64,), bool>("miner_setGasLimit".into(), (0,))
        .await?;
    assert!(
        reset_call,
        "miner_setGasLimit should be executed successfully"
    );

    let _ = driver.build_new_block().await?;

    let fit_tx = driver.create_transaction().send().await?;
    let block = driver.build_new_block().await?;

    // tx should be included because the gas limit is reset to the default value
    assert!(
        block.includes(fit_tx.tx_hash()),
        "transaction should be in block"
    );

    Ok(())
}
