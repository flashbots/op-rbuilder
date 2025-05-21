use crate::primitives::bundle::Bundle;
use crate::tx::{FBPoolTransaction, FBPooledTransaction};
use alloy_primitives::B256;
use alloy_rpc_types_eth::erc4337::TransactionConditional;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use reth_optimism_txpool::{conditional::MaybeConditionalTransaction, OpPooledTransaction};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendRawTransactionRevert")]
    async fn send_raw_transaction_revert(&self, tx: Bundle) -> RpcResult<B256>;
}

pub struct RevertProtectionExt<Pool> {
    pool: Pool,
}

impl<Pool> RevertProtectionExt<Pool> {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl Bundle {
    fn conditional(&self) -> TransactionConditional {
        TransactionConditional {
            block_number_min: self.block_number_min,
            block_number_max: self.block_number_max,
            known_accounts: Default::default(),
            timestamp_max: None,
            timestamp_min: None,
        }
    }
}

#[async_trait]
impl<Pool> EthApiOverrideServer for RevertProtectionExt<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    async fn send_raw_transaction_revert(&self, bundle: Bundle) -> RpcResult<B256> {
        let recovered = recover_raw_transaction(&bundle.transaction)?;
        let mut pool_transaction: FBPooledTransaction =
            OpPooledTransaction::from_pooled(recovered).into();

        pool_transaction.set_exclude_reverting_txs(true);
        pool_transaction.set_conditional(bundle.conditional());

        let hash = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .unwrap(); // TODO: FIX THIS

        Ok(hash)
    }
}
