use alloy_primitives::{Bytes, B256};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_optimism_txpool::OpPooledTransaction;
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};

use crate::tx::FBPooledTransaction;

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendRawTransactionRevert")]
    async fn send_raw_transaction_revert(&self, tx: Bytes) -> RpcResult<B256>;
}

pub struct RevertProtectionExt<Pool> {
    pool: Pool,
}

impl<Pool> RevertProtectionExt<Pool> {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<Pool> EthApiOverrideServer for RevertProtectionExt<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    async fn send_raw_transaction_revert(&self, tx: Bytes) -> RpcResult<B256> {
        let recovered = recover_raw_transaction(&tx)?;
        let pool_transaction: FBPooledTransaction =
            OpPooledTransaction::from_pooled(recovered).into();

        // TODO: Fix unwrap
        let hash = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .unwrap();

        Ok(hash)
    }
}
