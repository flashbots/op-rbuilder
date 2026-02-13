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

    /// Earliest flashblock index the bundle is valid for. Only enforced on the first block
    /// in the range (`blockNumber`); on later blocks all flashblocks are eligible.
    #[serde(
        default,
        rename = "minFlashblockNumber",
        with = "alloy_serde::quantity::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub flashblock_number_min: Option<u64>,

    /// Latest flashblock index the bundle is valid for. Only enforced on the last block
    /// in the range (`maxBlockNumber`); on earlier blocks all flashblocks are eligible.
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

    /// Replacement nonce must be set if `replacement_uuid` is set
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

        if block_number_max < block_number {
            return Err(EthApiError::InvalidParams(format!(
                "maxBlockNumber ({block_number_max}) must be >= blockNumber ({block_number})"
            ))
            .into());
        }

        if block_number_max.saturating_sub(block_number) > MAX_BLOCK_RANGE {
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
            flashblock_number_min: bundle.flashblock_number_min.unwrap_or(0),
            flashblock_number_max: bundle.flashblock_number_max.unwrap_or(u64::MAX),
            estimated_effective_priority_fee,
            estimated_da_size,
            replacement_key,
        };

        // Silently drop bundles rejected due to stale replacement nonce
        self.global_pool
            .add_bundle(backrun_bundle, last_block_number);

        Ok(BundleResult {
            bundle_hash: backrun_tx_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_utils::make_raw_tx, *};
    use crate::tx_signer::Signer;
    use alloy_primitives::BlockNumber;
    use reth_chainspec::ChainInfo;
    use reth_provider::ProviderResult;
    use reth_storage_api::BlockHashReader;

    /// Mock provider that returns a fixed best block number.
    struct MockProvider(u64);

    impl BlockHashReader for MockProvider {
        fn block_hash(&self, _number: BlockNumber) -> ProviderResult<Option<B256>> {
            Ok(None)
        }
        fn canonical_hashes_range(
            &self,
            _start: BlockNumber,
            _end: BlockNumber,
        ) -> ProviderResult<Vec<B256>> {
            Ok(vec![])
        }
    }

    impl BlockNumReader for MockProvider {
        fn chain_info(&self) -> ProviderResult<ChainInfo> {
            Ok(ChainInfo {
                best_number: self.0,
                best_hash: B256::ZERO,
            })
        }
        fn best_block_number(&self) -> ProviderResult<BlockNumber> {
            Ok(self.0)
        }
        fn last_block_number(&self) -> ProviderResult<BlockNumber> {
            Ok(self.0)
        }
        fn block_number(&self, _hash: B256) -> ProviderResult<Option<BlockNumber>> {
            Ok(None)
        }
    }

    fn make_rpc(best_block: u64) -> BackrunBundleRpc<MockProvider> {
        BackrunBundleRpc::new(BackrunBundleGlobalPool::default(), MockProvider(best_block))
    }

    fn valid_args(target: Bytes, backrun: Bytes, block_number: u64) -> BackrunBundleRPCArgs {
        BackrunBundleRPCArgs {
            transactions: vec![target, backrun],
            block_number,
            block_number_max: None,
            flashblock_number_min: None,
            flashblock_number_max: None,
            replacement_uuid: None,
            replacement_nonce: None,
        }
    }

    #[tokio::test]
    async fn test_rejects_wrong_tx_count() {
        let rpc = make_rpc(5);
        let s = Signer::random();
        let tx = make_raw_tx(&s, 0);

        // 1 tx
        let mut args = valid_args(tx.clone(), tx.clone(), 10);
        args.transactions = vec![tx.clone()];
        assert!(rpc.send_backrun_bundle(args).await.is_err());

        // 3 txs
        let mut args = valid_args(tx.clone(), tx.clone(), 10);
        args.transactions = vec![tx.clone(), tx.clone(), tx.clone()];
        assert!(rpc.send_backrun_bundle(args).await.is_err());

        // 0 txs
        let mut args = valid_args(tx.clone(), tx.clone(), 10);
        args.transactions = vec![];
        assert!(rpc.send_backrun_bundle(args).await.is_err());
    }

    #[tokio::test]
    async fn test_rejects_max_block_below_block_number() {
        let rpc = make_rpc(5);
        let s = Signer::random();
        let args = BackrunBundleRPCArgs {
            transactions: vec![make_raw_tx(&s, 0), make_raw_tx(&s, 1)],
            block_number: 10,
            block_number_max: Some(5),
            flashblock_number_min: None,
            flashblock_number_max: None,
            replacement_uuid: None,
            replacement_nonce: None,
        };
        assert!(rpc.send_backrun_bundle(args).await.is_err());
    }

    #[tokio::test]
    async fn test_rejects_block_range_too_large() {
        let rpc = make_rpc(5);
        let s = Signer::random();
        let args = BackrunBundleRPCArgs {
            transactions: vec![make_raw_tx(&s, 0), make_raw_tx(&s, 1)],
            block_number: 10,
            block_number_max: Some(21), // range = 11, max allowed is 10
            flashblock_number_min: None,
            flashblock_number_max: None,
            replacement_uuid: None,
            replacement_nonce: None,
        };
        assert!(rpc.send_backrun_bundle(args).await.is_err());
    }

    #[tokio::test]
    async fn test_rejects_uuid_without_nonce() {
        let rpc = make_rpc(5);
        let s = Signer::random();
        let mut args = valid_args(make_raw_tx(&s, 0), make_raw_tx(&s, 1), 10);
        args.replacement_uuid = Some(Uuid::new_v4());
        // replacement_nonce left as None
        assert!(rpc.send_backrun_bundle(args).await.is_err());
    }

    #[tokio::test]
    async fn test_rejects_past_block_number_max() {
        let rpc = make_rpc(100); // best block = 100
        let s = Signer::random();
        let args = valid_args(make_raw_tx(&s, 0), make_raw_tx(&s, 1), 99);
        // block_number_max defaults to block_number = 99 <= 100
        assert!(rpc.send_backrun_bundle(args).await.is_err());
    }

    #[tokio::test]
    async fn test_accepts_valid_bundle() {
        let rpc = make_rpc(5);
        let s = Signer::random();
        let target = make_raw_tx(&s, 0);
        let backrun = make_raw_tx(&s, 1);
        let args = valid_args(target, backrun, 10);
        let result = rpc.send_backrun_bundle(args).await;
        assert!(result.is_ok());
    }
}
