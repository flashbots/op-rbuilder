use crate::tx::{FBPoolTransaction, FBPooledTransaction, RevertOptions};
use alloy_primitives::{Bytes, B256};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use op_alloy_rpc_types::OpTransactionReceipt;
use reth::tasks::pool;
use reth_optimism_txpool::{conditional::MaybeConditionalTransaction, OpPooledTransaction};
use reth_rpc_eth_api::{
    helpers::{EthState, EthTransactions, FullEthApi},
    FromEthApiError,
};
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use serde::{Deserialize, Serialize};

// Namespace overrides for revert protection support
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthApiOverride {
    #[method(name = "sendRawTransactionRevert")]
    async fn send_raw_transaction_revert(&self, tx: Bundle) -> RpcResult<B256>;

    #[method(name = "getTransactionReceipt")]
    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<OpTransactionReceipt>>;
}

pub struct RevertProtectionExt<Pool, Eth> {
    pool: Pool,
    eth_api: Eth,
}

impl<Pool, Eth> RevertProtectionExt<Pool, Eth> {
    pub fn new(pool: Pool, eth_api: Eth) -> Self {
        Self { pool, eth_api }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bundle {
    pub transaction: Bytes,
    pub block_number_min: Option<u64>,
    pub block_number_max: Option<u64>,
}

#[async_trait]
impl<Pool, Eth> EthApiOverrideServer for RevertProtectionExt<Pool, Eth>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
    Eth: FullEthApi + Send + Sync + 'static,
{
    async fn send_raw_transaction_revert(&self, bundle: Bundle) -> RpcResult<B256> {
        println!("send_raw_transaction_revert called");

        let recovered = recover_raw_transaction(&bundle.transaction)?;
        let mut pool_transaction: FBPooledTransaction =
            OpPooledTransaction::from_pooled(recovered).into();

        // TODO: I think I can remove revert options
        let opts = RevertOptions {
            block_number_min: bundle.block_number_min,
            block_number_max: bundle.block_number_max,
        };
        pool_transaction.exclude_reverting_txs = Some(opts);
        pool_transaction.set_conditional(opts.conditional());

        println!("pool_transaction: {:?}", pool_transaction);

        // pool_transaction.set_can_revert(true);

        // TODO: Fix unwrap
        let hash = self
            .pool
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .unwrap();

        Ok(hash)
    }

    async fn transaction_receipt(&self, hash: B256) -> RpcResult<Option<OpTransactionReceipt>> {
        let x = EthTransactions::transaction_receipt(&self.eth_api, hash)
            .await
            .unwrap();

        Ok(x)
    }
}
