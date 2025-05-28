use crate::tx::FBPooledTransaction;
use alloy_transport_http::reqwest;
use futures_util::StreamExt;
use jsonrpsee::{
    core::{async_trait, RpcResult, SubscriptionResult},
    proc_macros::rpc,
    PendingSubscriptionSink,
};
use reth_transaction_pool::{FullTransactionEvent, TransactionPool};
use ringbuf::{traits::Producer, HeapRb};
use serde::Serialize;
use tracing::info;

/// Ethereum pub-sub rpc interface.
#[rpc(server, namespace = "txpool")] // TODO: Change to internal namespace
pub trait EthPubSubApi {
    /// Create an ethereum subscription for the given params
    #[subscription(name = "subscribe", item = String)]
    async fn sub(&self) -> SubscriptionResult;
}

pub struct TransactionPoolMonitor<Pool> {
    pool: Pool,
    log_events: bool,
}

impl<Pool> TransactionPoolMonitor<Pool> {
    pub fn new(pool: Pool, log_events: bool) -> Self {
        Self { pool, log_events }
    }
}

impl<Pool> TransactionPoolMonitor<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    pub async fn run(self) {
        let mut buffer = HeapRb::new(1000);
        tokio::spawn(async move {});

        let mut new_transactions = self.pool.all_transactions_event_listener();

        while let Some(event) = new_transactions.next().await {
            buffer.try_push(event.clone()).unwrap();

            if self.log_events {
                transaction_event_log(event);
            }
        }
    }
}

#[async_trait]
impl<Pool> EthPubSubApiServer for TransactionPoolMonitor<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    async fn sub(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        todo!()
    }
}

fn transaction_event_log(event: FullTransactionEvent<FBPooledTransaction>) {
    match event {
        FullTransactionEvent::Pending(hash) => {
            info!(
                target = "monitoring",
                tx_hash = hash.to_string(),
                kind = "pending",
                "Transaction event received"
            )
        }
        FullTransactionEvent::Queued(hash) => {
            info!(
                target = "monitoring",
                tx_hash = hash.to_string(),
                kind = "queued",
                "Transaction event received"
            )
        }
        FullTransactionEvent::Mined {
            tx_hash,
            block_hash,
        } => info!(
            target = "monitoring",
            tx_hash = tx_hash.to_string(),
            kind = "mined",
            block_hash = block_hash.to_string(),
            "Transaction event received"
        ),
        FullTransactionEvent::Replaced {
            transaction,
            replaced_by,
        } => info!(
            target = "monitoring",
            tx_hash = transaction.hash().to_string(),
            kind = "replaced",
            replaced_by = replaced_by.to_string(),
            "Transaction event received"
        ),
        FullTransactionEvent::Discarded(hash) => {
            info!(
                target = "monitoring",
                tx_hash = hash.to_string(),
                kind = "discarded",
                "Transaction event received"
            )
        }
        FullTransactionEvent::Invalid(hash) => {
            info!(
                target = "monitoring",
                tx_hash = hash.to_string(),
                kind = "invalid",
                "Transaction event received"
            )
        }
        FullTransactionEvent::Propagated(_propagated) => {}
    }
}
