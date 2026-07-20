use crate::{
    args::OpRbuilderArgs,
    tests::{BlockTransactionsExt, LocalInstance, OpRbuilderArgsTestExt, karst_node_config},
};
use alloy_eips::{BlockNumberOrTag::Latest, Encodable2718, eip1559::MIN_PROTOCOL_BASE_FEE};
use alloy_network::ReceiptResponse;
use alloy_primitives::{Address, Bytes, address, bytes, hex};
use alloy_provider::{Provider, RootProvider};
use macros::rb_test;
use op_alloy_network::Optimism;
use op_alloy_rpc_types::OpTransactionRequest;
use std::time::Duration;

#[rb_test]
async fn jovian_block_parameters_set(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let tx_one = driver.create_transaction().send().await?;
    let tx_two = driver.create_transaction().send().await?;
    let block = driver.build_new_block().await?;

    assert!(block.includes(tx_one.tx_hash()));
    assert!(block.includes(tx_two.tx_hash()));

    assert!(block.header.excess_blob_gas.is_some());

    assert!(block.header.blob_gas_used.is_some());

    // Two user transactions + two builder transactions, all minimum size
    assert_eq!(block.header.blob_gas_used.unwrap(), 160_000);

    // Version byte
    assert_eq!(block.header.extra_data.slice(0..1), bytes!("0x01"));

    // Min Base Fee of zero by default
    assert_eq!(
        block.header.extra_data.slice(9..=16),
        bytes!("0x0000000000000000"),
    );

    Ok(())
}

#[rb_test]
async fn jovian_no_tx_pool_sync(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let block = driver
        .build_new_block_with_txs_timestamp(vec![], Some(true), None, None, Some(0))
        .await?;

    // Deposit transaction + user transaction
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.header.blob_gas_used, Some(0));

    let tx = driver.create_transaction().build().await;
    let block = driver
        .build_new_block_with_txs_timestamp(
            vec![tx.encoded_2718().into()],
            Some(true),
            None,
            None,
            Some(0),
        )
        .await?;

    // Deposit transaction + user transaction
    assert_eq!(block.transactions.len(), 2);
    assert_eq!(block.header.blob_gas_used, Some(40_000));

    Ok(())
}

#[rb_test]
async fn jovian_minimum_base_fee(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let genesis = driver
        .get_block(Latest)
        .await?
        .expect("must have genesis block");

    assert_eq!(genesis.header.base_fee_per_gas, Some(1));

    let min_base_fee = Some(MIN_PROTOCOL_BASE_FEE * 2);

    let block_timestamp = Duration::from_secs(genesis.header.timestamp) + Duration::from_secs(1);
    let block_one = driver
        .build_new_block_with_txs_timestamp(vec![], None, Some(block_timestamp), None, min_base_fee)
        .await?;

    assert_eq!(
        block_one.header.extra_data.slice(9..=16),
        bytes!("0x000000000000000E"),
    );

    let overpriced_tx = driver
        .create_transaction()
        .with_max_fee_per_gas(MIN_PROTOCOL_BASE_FEE as u128 * 4)
        .send()
        .await?;
    let underpriced_tx = driver
        .create_transaction()
        .with_max_fee_per_gas(MIN_PROTOCOL_BASE_FEE as u128)
        .send()
        .await?;

    let block_timestamp = Duration::from_secs(block_one.header.timestamp) + Duration::from_secs(1);
    let block_two = driver
        .build_new_block_with_txs_timestamp(vec![], None, Some(block_timestamp), None, min_base_fee)
        .await?;

    assert_eq!(
        block_two.header.extra_data.slice(9..=16),
        bytes!("0x000000000000000E"),
    );

    assert!(block_two.includes(overpriced_tx.tx_hash()));
    assert!(!block_two.includes(underpriced_tx.tx_hash()));

    Ok(())
}

#[rb_test]
async fn jovian_minimum_fee_must_be_set(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let genesis = driver
        .get_block(Latest)
        .await?
        .expect("must have genesis block");
    let block_timestamp = Duration::from_secs(genesis.header.timestamp) + Duration::from_secs(1);
    let response = driver
        .build_new_block_with_txs_timestamp(vec![], None, Some(block_timestamp), None, None)
        .await;
    assert!(response.is_err());
    Ok(())
}

/// A chain with `karstTime` set at genesis still builds and lands ordinary blocks
#[rb_test(config = karst_node_config())]
async fn karst_active_at_genesis(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let tx_one = driver.create_transaction().send().await?;
    let tx_two = driver.create_transaction().send().await?;
    let block = driver.build_new_block().await?;

    assert!(block.includes(tx_one.tx_hash()));
    assert!(block.includes(tx_two.tx_hash()));

    Ok(())
}

/// EIP-7951/RIP-7212 P256VERIFY precompile address.
const P256VERIFY_ADDRESS: Address = address!("0000000000000000000000000000000000000100");

/// secp256r1 signature-verification input (msg_hash || r || s || pubkey_x || pubkey_y)
/// See https://github.com/daimo-eth/p256-verifier/tree/master/test-vectors
const P256_VALID_SIGNATURE: [u8; 160] = hex!(
    "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"
);
const P256_INVALID_SIGNATURE: [u8; 160] = hex!(
    "3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"
);

async fn call_p256verify(
    provider: &RootProvider<Optimism>,
    input: [u8; 160],
) -> eyre::Result<Bytes> {
    let request = OpTransactionRequest::default()
        .to(P256VERIFY_ADDRESS)
        .input(Bytes::copy_from_slice(&input).into());

    Ok(provider.call(request).latest().await?)
}

/// Under Karst, P256VERIFY is correctly wired up: a valid signature returns the 32-byte
/// `0x...01`, an invalid one returns empty, per RIP-7212/EIP-7951.
#[rb_test(config = karst_node_config())]
async fn karst_p256verify_precompile_correctness(rbuilder: LocalInstance) -> eyre::Result<()> {
    let provider = rbuilder.provider().await?;

    let valid = call_p256verify(&provider, P256_VALID_SIGNATURE).await?;
    assert_eq!(
        valid,
        bytes!("0x0000000000000000000000000000000000000000000000000000000000000001")
    );

    let invalid = call_p256verify(&provider, P256_INVALID_SIGNATURE).await?;
    assert!(invalid.is_empty());

    Ok(())
}

/// P256VERIFY exists since Fjord (RIP-7212), Karst precompile set only changes its price.
/// We assert `>` rather than exact 3450-gas delta because EIP-7623's calldata gas floor can absorb part of the difference depending on byte makeup but can never flip the inequality.
#[rb_test(config = karst_node_config())]
async fn karst_p256verify_gas_repricing(rbuilder: LocalInstance) -> eyre::Result<()> {
    let karst_driver = rbuilder.driver().await?;
    let jovian = LocalInstance::new(OpRbuilderArgs::test_default()).await?;
    let jovian_driver = jovian.driver().await?;

    let karst_tx = karst_driver
        .create_transaction()
        .with_to(P256VERIFY_ADDRESS)
        .with_input(Bytes::copy_from_slice(&P256_VALID_SIGNATURE))
        .send()
        .await?;
    karst_driver.build_new_block().await?;

    let jovian_tx = jovian_driver
        .create_transaction()
        .with_to(P256VERIFY_ADDRESS)
        .with_input(Bytes::copy_from_slice(&P256_VALID_SIGNATURE))
        .send()
        .await?;
    jovian_driver.build_new_block().await?;

    let karst_receipt = karst_driver
        .provider()
        .get_transaction_receipt(*karst_tx.tx_hash())
        .await?
        .expect("karst p256verify tx not mined");
    let jovian_receipt = jovian_driver
        .provider()
        .get_transaction_receipt(*jovian_tx.tx_hash())
        .await?
        .expect("jovian p256verify tx not mined");

    assert!(karst_receipt.status(), "karst call should succeed");
    assert!(jovian_receipt.status(), "jovian call should succeed");
    assert!(
        karst_receipt.gas_used() > jovian_receipt.gas_used(),
        "karst gas_used ({}) should exceed jovian's ({}) under Osaka P256VERIFY repricing",
        karst_receipt.gas_used(),
        jovian_receipt.gas_used()
    );

    Ok(())
}
