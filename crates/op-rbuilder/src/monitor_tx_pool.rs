use crate::tx::FBPooledTransaction;
use futures_util::StreamExt;
use reth_transaction_pool::{FullTransactionEvent, TransactionPool};
use tracing::info;

pub struct TransactionPoolMonitor<Pool> {
    pool: Pool,
}

impl<Pool> TransactionPoolMonitor<Pool> {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl<Pool> TransactionPoolMonitor<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    pub async fn run(self) {
        let mut new_transactions = self.pool.all_transactions_event_listener();

        while let Some(event) = new_transactions.next().await {
            transaction_event_log(event);
        }
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
