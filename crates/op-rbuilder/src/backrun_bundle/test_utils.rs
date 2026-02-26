use super::payload_pool::StoredBackrunBundle;
use crate::tx_signer::Signer;
use alloy_consensus::TxEip1559;
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use op_alloy_consensus::OpTypedTransaction;
use std::sync::Arc;

pub(super) struct BackrunBundleBuilder<'a> {
    signer: &'a Signer,
    target: B256,
    block_range: (u64, u64),
    nonce: u64,
    max_fee_per_gas: u128,
    priority_fee: u128,
    gas_limit: u64,
    value: U256,
}

pub(super) fn make_backrun_bundle<'a>(
    signer: &'a Signer,
    target: B256,
    block_range: (u64, u64),
) -> BackrunBundleBuilder<'a> {
    BackrunBundleBuilder {
        signer,
        target,
        block_range,
        nonce: 0,
        max_fee_per_gas: 1000,
        priority_fee: 0,
        gas_limit: 21000,
        value: U256::ZERO,
    }
}

impl<'a> BackrunBundleBuilder<'a> {
    pub(super) fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    pub(super) fn with_max_fee_per_gas(mut self, max_fee_per_gas: u128) -> Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    pub(super) fn with_priority_fee(mut self, priority_fee: u128) -> Self {
        self.priority_fee = priority_fee;
        self
    }

    pub(super) fn build(self) -> StoredBackrunBundle {
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: 901,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.priority_fee,
            to: TxKind::Call(Address::ZERO),
            value: self.value,
            ..Default::default()
        });
        StoredBackrunBundle {
            target_tx_hash: self.target,
            backrun_tx: Arc::new(self.signer.sign_tx(tx).unwrap()),
            block_number_min: self.block_range.0,
            block_number_max: self.block_range.1,
            flashblock_number_min: 0,
            flashblock_number_max: u64::MAX,
            estimated_effective_priority_fee: self.priority_fee,
            estimated_da_size: 0,
            replacement_key: None,
        }
    }
}

/// Creates a raw RLP-encoded signed transaction suitable for RPC input.
pub(super) fn make_raw_tx(signer: &Signer, nonce: u64) -> Bytes {
    let tx = OpTypedTransaction::Eip1559(TxEip1559 {
        chain_id: 901,
        nonce,
        gas_limit: 21000,
        max_fee_per_gas: 1000,
        max_priority_fee_per_gas: 100,
        to: TxKind::Call(Address::ZERO),
        ..Default::default()
    });
    Bytes::from(signer.sign_tx(tx).unwrap().into_inner().encoded_2718())
}
