use alloy_primitives::B256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_optimism_primitives::OpTransactionSigned;
use reth_provider::BlockNumReader;
use reth_rpc_eth_types::{EthApiError, utils::recover_raw_transaction};

use crate::primitives::bundle::{Bundle, BundleResult};

use super::{
    global_pool::BackrunBundleGlobalPool,
    payload_pool::BackrunBundle,
};

#[rpc(server, namespace = "eth")]
pub trait BackrunBundleApi {
    #[method(name = "sendBackrunBundle")]
    async fn send_backrun_bundle(&self, bundle: Bundle) -> RpcResult<BundleResult>;
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
    async fn send_backrun_bundle(&self, bundle: Bundle) -> RpcResult<BundleResult> {
        if bundle.transactions.len() != 2 {
            return Err(EthApiError::InvalidParams(
                "backrun bundle must contain exactly 2 transactions".into(),
            )
            .into());
        }

        let last_block_number = self
            .provider
            .best_block_number()
            .map_err(|_| EthApiError::InternalEthError)?;

        let conditional = bundle
            .conditional(last_block_number)
            .map_err(EthApiError::from)?;

        let block_number_min = conditional
            .transaction_conditional
            .block_number_min
            .unwrap_or(last_block_number + 1);
        let block_number_max = conditional
            .transaction_conditional
            .block_number_max
            .expect("block_number_max is always set after conditional()");

        let target_tx =
            recover_raw_transaction::<OpTransactionSigned>(&bundle.transactions[0])?;
        let backrun_tx =
            recover_raw_transaction::<OpTransactionSigned>(&bundle.transactions[1])?;

        let backrun_tx_hash = B256::from(*backrun_tx.tx_hash());

        let backrun_bundle = BackrunBundle {
            target_tx: target_tx.into_inner(),
            backrun_tx: backrun_tx.into_inner(),
            block_number_min,
            block_number_max,
            flashblock_number_min: conditional.flashblock_number_min,
            flashblock_number_max: conditional.flashblock_number_max,
        };

        self.global_pool.add_bundle(backrun_bundle);

        Ok(BundleResult {
            bundle_hash: backrun_tx_hash,
        })
    }
}
