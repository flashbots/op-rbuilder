use macros::rb_test;

use crate::{
    args::OpRbuilderArgs,
    tests::{BlockTransactionsExt, TransactionBuilderExt},
};

/// Presim alone (with revert protection disabled) should still keep
/// reverting txs out of the block — this is the load-bearing test for
/// the new feature.
#[rb_test(args = OpRbuilderArgs {
    enable_presim: true,
    presim_random_coinbase: true,
    enable_revert_protection: false,
    ..Default::default()
})]
async fn presim_filters_reverting_tx_without_revert_protection(
    rbuilder: LocalInstance,
) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let valid_tx = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await?;

    let reverting_tx = driver
        .create_transaction()
        .random_reverting_transaction()
        .send()
        .await?;

    let block = driver.build_new_block().await?;

    assert!(block.includes(valid_tx.tx_hash()));
    assert!(
        !block.includes(reverting_tx.tx_hash()),
        "presim should have excluded the reverting tx"
    );

    Ok(())
}

/// Valid txs must still land when presim is on — guards against false
/// positives from the simulation pass.
#[rb_test(args = OpRbuilderArgs {
    enable_presim: true,
    presim_random_coinbase: true,
    ..Default::default()
})]
async fn presim_keeps_valid_transactions(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let tx_a = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await?;
    let tx_b = driver
        .create_transaction()
        .random_valid_transfer()
        .send()
        .await?;

    let block = driver.build_new_block().await?;

    assert!(block.includes(tx_a.tx_hash()));
    assert!(block.includes(tx_b.tx_hash()));

    Ok(())
}

/// With presim disabled (the default), the existing behavior is unchanged:
/// reverting txs are included when revert protection is also off.
#[rb_test]
async fn presim_disabled_by_default_includes_reverts(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let reverting_tx = driver
        .create_transaction()
        .random_reverting_transaction()
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    assert!(block.includes(reverting_tx.tx_hash()));

    Ok(())
}

/// Presim should also work without random coinbase, so users who want
/// the deterministic-coinbase behavior (e.g. for traceability) can
/// opt out without losing the filter.
#[rb_test(args = OpRbuilderArgs {
    enable_presim: true,
    presim_random_coinbase: false,
    enable_revert_protection: false,
    ..Default::default()
})]
async fn presim_without_random_coinbase(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;

    let reverting_tx = driver
        .create_transaction()
        .random_reverting_transaction()
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    assert!(!block.includes(reverting_tx.tx_hash()));

    Ok(())
}
