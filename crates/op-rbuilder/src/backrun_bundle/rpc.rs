use alloy_consensus::Transaction;
use alloy_primitives::{B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_optimism_primitives::OpTransactionSigned;
use reth_provider::BlockNumReader;
use reth_rpc_eth_types::{EthApiError, utils::recover_raw_transaction};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::primitives::bundle::BundleResult;

use super::{
    global_pool::BackrunBundleGlobalPool,
    payload_pool::{ReplacementKey, StoredBackrunBundle},
};

const MAX_BLOCK_RANGE: u64 = 10;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackrunBundleRPCArgs {
    #[serde(rename = "txs")]
    pub transactions: Vec<Bytes>,

    #[serde(rename = "blockNumber", with = "alloy_serde::quantity")]
    pub block_number: u64,

    #[serde(
        default,
        rename = "maxBlockNumber",
        with = "alloy_serde::quantity::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_number_max: Option<u64>,

    #[serde(
        default,
        rename = "minFlashblockNumber",
        with = "alloy_serde::quantity::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub flashblock_number_min: Option<u64>,

    #[serde(
        default,
        rename = "maxFlashblockNumber",
        with = "alloy_serde::quantity::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub flashblock_number_max: Option<u64>,

    #[serde(
        default,
        rename = "replacementUuid",
        skip_serializing_if = "Option::is_none"
    )]
    pub replacement_uuid: Option<Uuid>,

    /// Replacment nonce must be set if `replacement_uuid` is set
    #[serde(
        default,
        rename = "replacementNonce",
        skip_serializing_if = "Option::is_none"
    )]
    pub replacement_nonce: Option<u64>,
}

#[rpc(server, namespace = "eth")]
pub trait BackrunBundleApi {
    #[method(name = "sendBackrunBundle")]
    async fn send_backrun_bundle(&self, bundle: BackrunBundleRPCArgs) -> RpcResult<BundleResult>;
}

pub struct BackrunBundleRpc<Provider> {
    global_pool: BackrunBundleGlobalPool,
    provider: Provider,
}

impl<Provider> BackrunBundleRpc<Provider> {
    pub fn new(global_pool: BackrunBundleGlobalPool, provider: Provider) -> Self {
        Self {
            global_pool,
            provider,
        }
    }
}

#[jsonrpsee::core::async_trait]
impl<Provider> BackrunBundleApiServer for BackrunBundleRpc<Provider>
where
    Provider: BlockNumReader + Send + Sync + 'static,
{
    async fn send_backrun_bundle(&self, bundle: BackrunBundleRPCArgs) -> RpcResult<BundleResult> {
        if bundle.transactions.len() != 2 {
            return Err(EthApiError::InvalidParams(
                "backrun bundle must contain exactly 2 transactions".into(),
            )
            .into());
        }

        let block_number = bundle.block_number;
        let block_number_max = bundle.block_number_max.unwrap_or(block_number);

        if block_number_max.saturating_sub(block_number) >= MAX_BLOCK_RANGE {
            return Err(EthApiError::InvalidParams(format!(
                "block range too large: {block_number}..{block_number_max} (max range: {MAX_BLOCK_RANGE})"
            ))
            .into());
        }

        let replacement_key = match (bundle.replacement_uuid, bundle.replacement_nonce) {
            (Some(uuid), Some(nonce)) => Some(ReplacementKey { uuid, nonce }),
            (Some(_), None) => {
                return Err(EthApiError::InvalidParams(
                    "replacementNonce must be set when replacementUuid is set".into(),
                )
                .into());
            }
            _ => None,
        };

        let last_block_number = self
            .provider
            .best_block_number()
            .map_err(|_| EthApiError::InternalEthError)?;

        if block_number_max <= last_block_number {
            return Err(EthApiError::InvalidParams(format!(
                "maxBlockNumber ({block_number_max}) is in the past (current: {last_block_number})"
            ))
            .into());
        }

        let target_tx = recover_raw_transaction::<OpTransactionSigned>(&bundle.transactions[0])?;
        let backrun_tx = recover_raw_transaction::<OpTransactionSigned>(&bundle.transactions[1])?;

        let target_tx_hash = B256::from(*target_tx.tx_hash());
        let backrun_tx_hash = B256::from(*backrun_tx.tx_hash());

        let estimated_base_fee = self.global_pool.estimated_base_fee_per_gas();
        let estimated_effective_priority_fee = backrun_tx
            .effective_tip_per_gas(estimated_base_fee)
            .unwrap_or(0);
        let estimated_da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(&bundle.transactions[1]);

        let backrun_bundle = StoredBackrunBundle {
            target_tx_hash,
            backrun_tx: Arc::new(backrun_tx),
            block_number,
            block_number_max,
            flashblock_number_min: bundle.flashblock_number_min,
            flashblock_number_max: bundle.flashblock_number_max,
            estimated_effective_priority_fee,
            estimated_da_size,
            replacement_key,
        };

        self.global_pool.add_bundle(backrun_bundle);

        Ok(BundleResult {
            bundle_hash: backrun_tx_hash,
        })
    }
}
