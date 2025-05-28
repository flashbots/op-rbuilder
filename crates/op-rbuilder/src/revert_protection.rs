use crate::{
    primitives::bundle::{Bundle, BundleResult, MAX_BLOCK_RANGE_BLOCKS},
    tx::{FBPooledTransaction, MaybeRevertingTransaction},
};
use alloy_json_rpc::RpcObject;
use alloy_primitives::B256;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use lru::LruCache;
use reth::rpc::api::eth::{helpers::FullEthApi, RpcReceipt};
use reth_optimism_txpool::{conditional::MaybeConditionalTransaction, OpPooledTransaction};
use reth_provider::StateProviderFactory;
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendBundle")]
    async fn send_bundle(&self, tx: Bundle) -> RpcResult<BundleResult>;
}

#[rpc(server, client, namespace = "eth")]
pub trait EthApiOverrideReplacement<R: RpcObject> {
    // Name TBD
    #[method(name = "getTransactionReceipt")]
    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<R>>;
}

pub struct RevertProtectionExt<Pool, Provider, Eth, Network = op_alloy_network::Optimism> {
    pool: Pool,
    provider: Provider,
    eth_api: Eth,
    _network: std::marker::PhantomData<Network>,
}

impl<Pool, Provider, Eth, Network> RevertProtectionExt<Pool, Provider, Eth, Network>
where
    Pool: Clone,
    Provider: Clone,
    Eth: Clone,
{
    pub fn new(pool: Pool, provider: Provider, eth_api: Eth) -> Self {
        Self {
            pool,
            provider,
            eth_api,
            _network: std::marker::PhantomData,
        }
    }

    pub fn bundle_api(&self) -> RevertProtectionBundleAPI<Pool, Provider> {
        RevertProtectionBundleAPI {
            pool: self.pool.clone(),
            provider: self.provider.clone(),
        }
    }

    pub fn eth_api(&self, reverted_cache: SharedLruCache<B256, ()>) -> RevertProtectionEthAPI<Eth> {
        RevertProtectionEthAPI {
            eth_api: self.eth_api.clone(),
            reverted_cache,
        }
    }
}

pub type SharedLruCache<K, V> = Arc<Mutex<LruCache<K, V>>>;

pub fn create_shared_cache<K, V>(capacity: usize) -> SharedLruCache<K, V>
where
    K: std::hash::Hash + Eq,
{
    let cache = LruCache::new(NonZeroUsize::new(capacity).unwrap());
    Arc::new(Mutex::new(cache))
}

pub struct RevertProtectionBundleAPI<Pool, Provider> {
    pool: Pool,
    provider: Provider,
}

#[async_trait]
impl<Pool, Provider> EthApiOverrideServer for RevertProtectionBundleAPI<Pool, Provider>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
    Provider: StateProviderFactory + Send + Sync + Clone + 'static,
{
    async fn send_bundle(&self, mut bundle: Bundle) -> RpcResult<BundleResult> {
        let last_block_number = self
            .provider
            .best_block_number()
            .map_err(|_e| EthApiError::InternalEthError)?;

        // Only one transaction in the bundle is expected
        let bundle_transaction = match bundle.transactions.len() {
            0 => {
                return Err(EthApiError::InvalidParams(
                    "bundle must contain at least one transaction".into(),
                )
                .into());
            }
            1 => bundle.transactions[0].clone(),
            _ => {
                return Err(EthApiError::InvalidParams(
                    "bundle must contain exactly one transaction".into(),
                )
                .into());
            }
        };

        if let Some(block_number_max) = bundle.block_number_max {
            // The max block cannot be a past block
            if block_number_max <= last_block_number {
                return Err(
                    EthApiError::InvalidParams("block_number_max is a past block".into()).into(),
                );
            }

            // Validate that it is not greater than the max_block_range
            if block_number_max > last_block_number + MAX_BLOCK_RANGE_BLOCKS {
                return Err(
                    EthApiError::InvalidParams("block_number_max is too high".into()).into(),
                );
            }
        } else {
            // If no upper bound is set, use the maximum block range
            bundle.block_number_max = Some(last_block_number + MAX_BLOCK_RANGE_BLOCKS);
        }

        let recovered = recover_raw_transaction(&bundle_transaction)?;
        let mut pool_transaction: FBPooledTransaction =
            OpPooledTransaction::from_pooled(recovered).into();

        pool_transaction.set_exclude_reverting_txs(true);
        pool_transaction.set_conditional(bundle.conditional());

        let hash = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(EthApiError::from)?;

        let result = BundleResult { bundle_hash: hash };
        Ok(result)
    }
}

pub struct RevertProtectionEthAPI<Eth> {
    eth_api: Eth,
    reverted_cache: SharedLruCache<B256, ()>,
}

#[async_trait]
impl<Eth> EthApiOverrideReplacementServer<RpcReceipt<Eth::NetworkTypes>>
    for RevertProtectionEthAPI<Eth>
where
    Eth: FullEthApi + Send + Sync + Clone + 'static,
{
    async fn transaction_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcReceipt<Eth::NetworkTypes>>> {
        match self.eth_api.transaction_receipt(hash).await.unwrap() {
            Some(receipt) => Ok(Some(receipt)),
            None => {
                // Try to find the transaction in the reverted cache
                let reverted_cache = self.reverted_cache.lock().unwrap();
                if reverted_cache.contains(&hash) {
                    return Err(EthApiError::InvalidParams(
                        "the transaction was reverted and dropped from the pool".into(),
                    )
                    .into());
                } else {
                    return Ok(None);
                }
            }
        }
    }
}
