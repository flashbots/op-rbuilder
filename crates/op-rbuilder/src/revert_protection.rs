use std::num::NonZero;

use alloy_primitives::{Bytes, B256};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use lru::LruCache;
use reth_optimism_txpool::OpPooledTransaction;
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendRawTransactionRevert")]
    async fn send_raw_transaction_revert(&self, tx: Bytes) -> RpcResult<B256>;
}

struct RevertProtectionService<Pool> {
    reverted_transactions: LruCache<B256, ()>,
    pool: Pool,
}

impl<Pool> RevertProtectionService<Pool> {
    fn new(pool: Pool) -> Self {
        Self {
            reverted_transactions: LruCache::new(NonZero::new(1000).unwrap()),
            pool,
        }
    }
}

impl<Pool> RevertProtectionService<Pool> {
    pub async fn is_reverted(&self, hash: B256) -> bool {
        self.reverted_transactions.contains(&hash)
    }
}

#[async_trait]
impl<Pool> EthApiOverrideServer for RevertProtectionService<Pool>
where
    Pool: TransactionPool<Transaction = OpPooledTransaction> + Clone + 'static,
{
    async fn send_raw_transaction_revert(&self, tx: Bytes) -> RpcResult<B256> {
        let recovered = recover_raw_transaction(&tx)?;
        let pool_transaction = OpPooledTransaction::from_pooled(recovered);

        // we cannot delegate on the send_raw_transaction implementation because that one will
        // send the transactions to the sequencer if enabled, I want to avoid that footgun.
        // Since this transactions should not be executed or exist on the normal pool.
        let hash = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .unwrap(); // TODO: handle error

        Ok(hash)
    }
}
