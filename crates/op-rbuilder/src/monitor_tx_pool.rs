use crate::{revert_protection::SharedLruCache, tx::FBPooledTransaction};
use alloy_primitives::B256;
use futures_util::StreamExt;
use reth_transaction_pool::{AllTransactionsEvents, FullTransactionEvent};
use tracing::info;

pub async fn monitor_tx_pool(
    mut new_transactions: AllTransactionsEvents<FBPooledTransaction>,
    reverted_cache: SharedLruCache<B256, ()>,
) {
    while let Some(event) = new_transactions.next().await {
        transaction_event_log(event, &reverted_cache);
    }
}

fn transaction_event_log(
    event: FullTransactionEvent<FBPooledTransaction>,
    reverted_cache: &SharedLruCache<B256, ()>,
) {
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
            // add the transaction hash to the reverted cache to notify the
            // eth get transaction receipt method
            reverted_cache.lock().unwrap().put(hash, ());

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
