use std::{sync::Arc, time::Instant};

use crate::{
    metrics::OpRBuilderMetrics,
    presim::TopOfBlockSimulator,
    primitives::bundle::{Bundle, BundleResult},
    tx::{FBPooledTransaction, MaybeFlashblockFilter},
};
use alloy_consensus::Header;
use alloy_json_rpc::RpcObject;
use alloy_primitives::B256;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use moka::future::Cache;
use op_alloy_consensus::OpTxEnvelope;
use reth::rpc::api::eth::{RpcReceipt, helpers::FullEthApi};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::OpTransactionSigned;
use reth_optimism_txpool::{OpPooledTransaction, conditional::MaybeConditionalTransaction};
use reth_primitives_traits::Recovered;
use reth_provider::{BlockReaderIdExt, ChainSpecProvider, StateProviderFactory};
use reth_rpc_eth_types::{EthApiError, utils::recover_raw_transaction};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use tracing::error;

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiExt<R: RpcObject> {
    #[method(name = "sendBundle")]
    async fn send_bundle(&self, tx: Bundle) -> RpcResult<BundleResult>;

    #[method(name = "getTransactionReceipt")]
    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<R>>;
}

pub struct RevertProtectionExt<Pool, Provider, Eth> {
    pool: Pool,
    provider: Provider,
    eth_api: Eth,
    metrics: Arc<OpRBuilderMetrics>,
    reverted_cache: Cache<B256, ()>,
    simulator: Option<Arc<TopOfBlockSimulator>>,
}

impl<Pool, Provider, Eth> RevertProtectionExt<Pool, Provider, Eth>
where
    Pool: Clone,
    Provider: Clone,
    Eth: Clone,
{
    pub(crate) fn new(
        pool: Pool,
        provider: Provider,
        eth_api: Eth,
        reverted_cache: Cache<B256, ()>,
        simulator: Option<Arc<TopOfBlockSimulator>>,
    ) -> Self {
        Self {
            pool,
            provider,
            eth_api,
            metrics: Arc::new(OpRBuilderMetrics::default()),
            reverted_cache,
            simulator,
        }
    }
}

#[async_trait]
impl<Pool, Provider, Eth> EthApiExtServer<RpcReceipt<Eth::NetworkTypes>>
    for RevertProtectionExt<Pool, Provider, Eth>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
    Provider: StateProviderFactory
        + BlockReaderIdExt<Header = Header>
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + Send
        + Sync
        + Clone
        + 'static,
    Eth: FullEthApi + Send + Sync + Clone + 'static,
{
    async fn send_bundle(&self, bundle: Bundle) -> RpcResult<BundleResult> {
        let request_start_time = Instant::now();
        self.metrics.bundle_requests.increment(1);

        let bundle_result = self
            .send_bundle_inner(bundle)
            .await
            .inspect_err(|err| error!(error = %err, "eth_sendBundle request failed"));

        if bundle_result.is_ok() {
            self.metrics.valid_bundles.increment(1);
        } else {
            self.metrics.failed_bundles.increment(1);
        }

        self.metrics
            .bundle_receive_duration
            .record(request_start_time.elapsed());

        bundle_result
    }

    async fn transaction_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcReceipt<Eth::NetworkTypes>>> {
        let upstream = self.eth_api.transaction_receipt(hash).await;
        resolve_receipt_or_reverted(upstream, hash, &self.reverted_cache).await
    }
}

impl<Pool, Provider, Eth> RevertProtectionExt<Pool, Provider, Eth>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
    Provider: StateProviderFactory
        + BlockReaderIdExt<Header = Header>
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + Send
        + Sync
        + Clone
        + 'static,
    Eth: FullEthApi + Send + Sync + Clone + 'static,
{
    async fn send_bundle_inner(&self, bundle: Bundle) -> RpcResult<BundleResult> {
        let last_block_number = self
            .provider
            .best_block_number()
            .map_err(|_e| EthApiError::InternalEthError)?;

        // Only one transaction in the bundle is expected
        let bundle_transaction = match bundle.txs.len() {
            0 => {
                return Err(EthApiError::InvalidParams(
                    "bundle must contain at least one transaction".into(),
                )
                .into());
            }
            1 => bundle.txs[0].clone(),
            _ => {
                return Err(EthApiError::InvalidParams(
                    "bundle must contain exactly one transaction".into(),
                )
                .into());
            }
        };

        let conditional = bundle
            .conditional(last_block_number)
            .map_err(EthApiError::from)?;

        let recovered: Recovered<op_alloy_consensus::OpPooledTransaction> =
            recover_raw_transaction(&bundle_transaction)?;

        let pool_transaction =
            FBPooledTransaction::from(OpPooledTransaction::from_pooled(recovered.clone()))
                .with_allowed_revert_hashes(bundle.reverting_tx_hashes.clone().unwrap_or_default())
                .with_min_flashblock_number(conditional.min_flashblock_number)
                .with_max_flashblock_number(conditional.max_flashblock_number)
                .with_conditional(conditional.transaction_conditional);

        let outcome = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(EthApiError::from)?;

        // Pre-simulate the transaction against current head state if:
        // - pre-simulation is enabled (simulator is Some)
        // - the tx is allowed to revert
        if bundle
            .reverting_tx_hashes
            .as_ref()
            .is_some_and(|hashes| !hashes.is_empty())
            && let Some(simulator) = &self.simulator
        {
            let pool = self.pool.clone();
            let metrics = self.metrics.clone();
            let simulator = simulator.clone();
            tokio::task::spawn(async move {
                let sim_start = Instant::now();
                let sim_tx: Recovered<OpTransactionSigned> = recovered
                    .clone()
                    .map(|tx| OpTransactionSigned::from(OpTxEnvelope::from(tx)));
                let sim_tx_hash = *sim_tx.hash();
                match simulator.clone().simulate_tx(sim_tx).await {
                    Ok(true) => {
                        metrics.bundle_pre_simulation_passes.increment(1);
                    }
                    Ok(false) => {
                        metrics.bundle_pre_simulation_reverts.increment(1);
                        pool.remove_transaction(sim_tx_hash);
                    }
                    Err(e) => {
                        error!(error = %e, "pre-simulation task failed");
                    }
                }
                metrics
                    .bundle_pre_simulation_duration
                    .record(sim_start.elapsed());
            });
        }

        let result = BundleResult {
            bundle_hash: outcome.hash,
        };
        Ok(result)
    }
}

/// Falls back to the reverted-cache when the upstream lookup has no receipt,
/// so revert-protected txs that got dropped surface as a clear error instead
/// of a silent `null`.
async fn resolve_receipt_or_reverted<R, E>(
    upstream: Result<Option<R>, E>,
    hash: B256,
    reverted_cache: &Cache<B256, ()>,
) -> RpcResult<Option<R>>
where
    E: Into<jsonrpsee::types::ErrorObjectOwned>,
{
    let receipt = upstream.map_err(Into::into)?;
    if let Some(receipt) = receipt {
        Ok(Some(receipt))
    } else if reverted_cache.get(&hash).await.is_some() {
        Err(EthApiError::InvalidParams("the transaction was dropped from the pool".into()).into())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::types::ErrorObjectOwned;

    fn cache() -> Cache<B256, ()> {
        Cache::builder().max_capacity(16).build()
    }

    type Upstream<R> = Result<Option<R>, ErrorObjectOwned>;

    /// Receipt from the eth_api takes precedence over the cache.
    #[tokio::test]
    async fn returns_receipt_when_present() {
        let hash = B256::repeat_byte(0xAB);
        let cache = cache();
        cache.insert(hash, ()).await;

        let upstream: Upstream<&'static str> = Ok(Some("receipt"));
        let result = resolve_receipt_or_reverted(upstream, hash, &cache).await;

        assert_eq!(result.unwrap(), Some("receipt"));
    }

    /// Missing receipt + cached as reverted -> dropped error.
    #[tokio::test]
    async fn returns_dropped_error_when_cached_reverted() {
        let hash = B256::repeat_byte(0xCD);
        let cache = cache();
        cache.insert(hash, ()).await;

        let upstream: Upstream<()> = Ok(None);
        let err = resolve_receipt_or_reverted(upstream, hash, &cache)
            .await
            .unwrap_err();

        assert!(
            err.message().contains("dropped from the pool"),
            "unexpected message: {}",
            err.message()
        );
    }

    /// Unknown tx -> Ok(None).
    #[tokio::test]
    async fn returns_none_when_unknown() {
        let hash = B256::repeat_byte(0xEF);
        let cache = cache();

        let upstream: Upstream<()> = Ok(None);
        let result = resolve_receipt_or_reverted(upstream, hash, &cache).await;

        assert_eq!(result.unwrap(), None);
    }

    /// Upstream `Err` must propagate, not panic.
    #[tokio::test]
    async fn propagates_eth_api_error_without_panicking() {
        let hash = B256::repeat_byte(0x01);
        let cache = cache();

        let upstream: Upstream<()> = Err(EthApiError::InternalEthError.into());

        let outcome = resolve_receipt_or_reverted(upstream, hash, &cache).await;

        outcome.expect_err("eth_api error must propagate, not panic");
    }
}
