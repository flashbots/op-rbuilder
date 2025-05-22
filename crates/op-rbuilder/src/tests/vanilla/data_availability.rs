use crate::tests::framework::TestHarnessBuilder;

/// This test ensures that the transaction size limit is respected.
/// We will set limit to 1 byte and see that the builder will not include any transactions.
#[tokio::test]
async fn data_availability_tx_size_limit() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("data_availability_tx_size_limit")
        .with_max_da_tx_size(1)
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // generate regualr tx
    let invalid_tx = harness.send_valid_transaction().await?;

    let block = generator.generate_block().await?;

    // tx should not be included because we set the tx_size_limit to 1
    assert!(
        block.not_includes(*invalid_tx.tx_hash()),
        "transaction should not be included in the block"
    );

    Ok(())
}

/// This test ensures that the block size limit is respected.
/// We will set limit to 1 byte and see that the builder will not include any transactions.
#[tokio::test]
async fn data_availability_block_size_limit() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("data_availability_block_size_limit")
        .with_max_da_block_size(1)
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // generate regualr tx
    let invalid_tx = harness.send_valid_transaction().await?;

    let block = generator.generate_block().await?;

    // tx should not be included because we set the tx_size_limit to 1
    assert!(
        block.not_includes(*invalid_tx.tx_hash()),
        "transaction should not be included in the block"
    );

    Ok(())
}

/// This test ensures that block will fill up to the limit.
/// Size of each transaction is 100000000
/// We will set limit to 3 txs and see that the builder will include 3 transactions.
/// We should not forget about builder transaction so we will spawn only 2 regular txs.
#[tokio::test]
async fn data_availability_block_fill() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("data_availability_block_fill")
        .with_max_da_block_size(100000000 * 3)
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // generate regualr tx
    let valid_tx_1 = harness.send_valid_transaction().await?;
    let valid_tx_2 = harness.send_valid_transaction().await?;
    let unfit_tx_3 = harness.send_valid_transaction().await?;

    let block = generator.generate_block().await?;

    // tx should not be included because we set the tx_size_limit to 1
    assert!(
        block.includes(*valid_tx_1.tx_hash()),
        "tx should be in block"
    );
    assert!(
        block.includes(*valid_tx_2.tx_hash()),
        "tx should be in block"
    );
    assert!(
        block.not_includes(*unfit_tx_3.tx_hash()),
        "unfit tx should not be in block"
    );
    assert!(
        harness.latest_block().await.transactions.len() == 4,
        "builder + deposit + 2 valid txs should be in the block"
    );
    Ok(())
}
