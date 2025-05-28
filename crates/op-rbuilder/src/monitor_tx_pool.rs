use crate::tx::FBPooledTransaction;
use alloy_primitives::TxHash;
use futures_util::StreamExt;
use jsonrpsee::{
    core::{async_trait, SubscriptionResult},
    proc_macros::rpc,
    PendingSubscriptionSink, SubscriptionMessage,
};
use reth_transaction_pool::{FullTransactionEvent, TransactionEvent, TransactionPool};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::info;

#[rpc(server, namespace = "txpool")]
pub trait TxpoolExtApi {
    /// Creates a subscription that returns the txpool events.
    #[subscription(name = "subscribeEvents", item = usize)]
    fn subscribe_events(&self) -> SubscriptionResult;
}

pub struct TransactionPoolMonitor<Pool> {
    pool: Pool,
    log_events: bool,
    txpool_monitor: bool,
    event_sender: broadcast::Sender<TransactionEventData>,
    // Keep a receiver to prevent channel from closing
    _event_receiver: broadcast::Receiver<TransactionEventData>,
}

impl<Pool> TransactionPoolMonitor<Pool> {
    pub fn new(pool: Pool, log_events: bool, txpool_monitor: bool, buffer_size: usize) -> Self {
        let (event_sender, _event_receiver) = broadcast::channel(buffer_size);

        if log_events {
            info!("Logging pool transactions");
        }
        if txpool_monitor {
            info!("Monitoring txpool enabled");
        }

        Self {
            pool,
            log_events,
            txpool_monitor,
            event_sender,
            _event_receiver,
        }
    }
}

impl<Pool> TransactionPoolMonitor<Pool>
where
    Pool: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
{
    pub fn rpc(&self) -> TransactionPoolMonitorRpc {
        TransactionPoolMonitorRpc {
            event_sender: self.event_sender.clone(),
        }
    }

    pub async fn run(self) {
        let mut new_transactions = self.pool.all_transactions_event_listener();

        while let Some(event) = new_transactions.next().await {
            // Push the event to the buffer
            let event_data = TransactionEventData::from(event);
            if self.log_events {
                info!(
                    target = "monitoring",
                    tx_hash = event_data.hash.to_string(),
                    kind = event_data.kind(),
                    "Transaction event received"
                )
            }

            if self.txpool_monitor {
                println!("Sending event: {:?}", event_data);
                let _ = self.event_sender.send(event_data);
            }
        }
    }
}

pub struct TransactionPoolMonitorRpc {
    event_sender: broadcast::Sender<TransactionEventData>,
}

#[async_trait]
impl TxpoolExtApiServer for TransactionPoolMonitorRpc {
    fn subscribe_events(
        &self,
        pending_subscription_sink: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        println!("Subscribing to txpool events");
        let mut event_receiver = self.event_sender.subscribe();

        tokio::spawn(async move {
            let sink = match pending_subscription_sink.accept().await {
                Ok(sink) => sink,
                Err(e) => {
                    tracing::warn!("failed to accept subscription: {e}");
                    return;
                }
            };

            println!("Subscribed to txpool events");

            loop {
                match event_receiver.recv().await {
                    Ok(event) => {
                        println!("Received event: {:?}", event);

                        let msg = SubscriptionMessage::from(
                            serde_json::value::to_raw_value(&event)
                                .expect("Failed to serialize event"),
                        );

                        if sink.send(msg).await.is_err() {
                            tracing::debug!("Subscription closed");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("Subscription lagged, some events were dropped");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::debug!("Event channel closed");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
struct TransactionEventData {
    hash: TxHash,
    transaction_event: TransactionEvent,
}

impl TransactionEventData {
    pub fn kind(&self) -> &str {
        match self.transaction_event {
            TransactionEvent::Pending => "pending",
            TransactionEvent::Queued => "queued",
            TransactionEvent::Mined(_) => "mined",
            TransactionEvent::Replaced(_) => "replaced",
            TransactionEvent::Discarded => "discarded",
            TransactionEvent::Invalid => "invalid",
            TransactionEvent::Propagated(_) => "propagated",
        }
    }
}

impl From<FullTransactionEvent<FBPooledTransaction>> for TransactionEventData {
    fn from(event: FullTransactionEvent<FBPooledTransaction>) -> Self {
        match event {
            FullTransactionEvent::Pending(hash) => Self {
                hash,
                transaction_event: TransactionEvent::Pending,
            },
            FullTransactionEvent::Queued(hash) => Self {
                hash,
                transaction_event: TransactionEvent::Queued,
            },
            FullTransactionEvent::Mined {
                tx_hash,
                block_hash,
            } => Self {
                hash: tx_hash,
                transaction_event: TransactionEvent::Mined(block_hash),
            },
            FullTransactionEvent::Replaced {
                transaction,
                replaced_by,
            } => Self {
                hash: *transaction.hash(),
                transaction_event: TransactionEvent::Replaced(replaced_by),
            },
            FullTransactionEvent::Discarded(hash) => Self {
                hash,
                transaction_event: TransactionEvent::Discarded,
            },
            FullTransactionEvent::Invalid(hash) => Self {
                hash,
                transaction_event: TransactionEvent::Invalid,
            },
            FullTransactionEvent::Propagated(kind) => Self {
                hash: TxHash::default(),
                transaction_event: TransactionEvent::Propagated(kind),
            },
        }
    }
}
