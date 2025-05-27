use crate::{
    primitives::bundle::{Bundle, BundleResult, MAX_BLOCK_RANGE_BLOCKS},
    tx::{FBPooledTransaction, MaybeRevertingTransaction},
};
use alloy_primitives::B256;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use op_alloy_rpc_types::OpTransactionReceipt;
use reth::rpc::api::eth::{types::RpcTypes, RpcReceipt};
use reth_optimism_primitives::OpReceipt;
use reth_optimism_txpool::{conditional::MaybeConditionalTransaction, OpPooledTransaction};
use reth_provider::{ReceiptProvider, StateProviderFactory};
use reth_rpc_eth_types::{utils::recover_raw_transaction, EthApiError};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendBundle")]
    async fn send_bundle(&self, tx: Bundle) -> RpcResult<BundleResult>;
}

#[rpc(server, client, namespace = "eth")]
pub trait EthApiOverrideReplacement<R: RpcTypes> {
    // Name TBD
    #[method(name = "getTransactionReceipt")]
    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<RpcReceipt<R>>>;
}

pub struct RevertProtectionExt<Pool, Provider, Network = op_alloy_network::Optimism> {
    pool: Pool,
    provider: Provider,
    _network: std::marker::PhantomData<Network>,
}

impl<Pool, Provider, Network> RevertProtectionExt<Pool, Provider, Network>
where
    Pool: Clone,
    Provider: Clone,
{
    pub fn new(pool: Pool, provider: Provider) -> Self {
        Self {
            pool,
            provider,
            _network: std::marker::PhantomData,
        }
    }

    pub fn bundle_api(&self) -> RevertProtectionBundleAPI<Pool, Provider> {
        RevertProtectionBundleAPI {
            pool: self.pool.clone(),
            provider: self.provider.clone(),
        }
    }

    pub fn eth_api(&self) -> RevertProtectionEthAPI<Provider> {
        RevertProtectionEthAPI {
            provider: self.provider.clone(),
        }
    }
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

pub struct RevertProtectionEthAPI<Provider> {
    provider: Provider,
}

#[async_trait]
impl<Provider, R> EthApiOverrideReplacementServer<R> for RevertProtectionEthAPI<Provider>
where
    Provider:
        StateProviderFactory + ReceiptProvider<Receipt = OpReceipt> + Send + Sync + Clone + 'static,
    R: RpcTypes<Receipt = OpTransactionReceipt>,
{
    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<RpcReceipt<R>>> {
        println!("transaction_receipt: {:?}", hash);

        panic!("bad");

        /*
        let receipt = self
            .provider
            .receipt_by_hash(hash)
            .map_err(EthApiError::from)?;

        match receipt {
            Some(receipt) => Ok(Some(receipt)),
            None => Ok(None),
        }
        */
    }
}
