use crate::tests::framework::{TestHarnessBuilder};

/// This test ensures that the transaction size limit is respected.
/// We will set limit to 1 byte and see that the builder will not include any transactions.
#[tokio::test]
async fn data_availability_tx_size_limit() -> eyre::Result<()> {
    let harness = TestHarnessBuilder::new("integration_test_data_availability")
        .with_max_da_tx_size(1)
        .build()
        .await?;

    let mut generator = harness.block_generator().await?;

    // generate regualr tx
    let invalid_tx = harness.send_valid_transaction().await?;

    let block = generator.generate_block().await?;

    // tx should not be included because we set the tx_size_limit to 1
    assert!(block.not_includes(*invalid_tx.tx_hash()), "transaction should not be included in the block");
    
    Ok(())
}
