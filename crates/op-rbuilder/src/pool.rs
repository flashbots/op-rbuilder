use std::{sync::Arc, time::Instant};

use futures::StreamExt;
use reth_tasks::Runtime;
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionPool, error::PoolError,
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::error;

use crate::{metrics::OpRBuilderMetrics, presim::TopOfBlockSimulator, tx::FBPooledTransaction};

#[derive(derive_more::Constructor)]
pub(super) struct AddBundleRequest {
    tx: FBPooledTransaction,
    respond_to: oneshot::Sender<Option<PoolError>>,
}

pub(super) async fn run_pool_insertion_task(
    runtime: Runtime,
    // TODO: Remove 'static bound
    pool: impl TransactionPool<Transaction = FBPooledTransaction> + 'static,
    mut rx: mpsc::UnboundedReceiver<AddBundleRequest>,
    simulator: Option<Arc<TopOfBlockSimulator>>,
    metrics: Arc<OpRBuilderMetrics>,
    max_concurrency: Option<usize>,
) {
    let bounded_sender = max_concurrency.map(|max| {
        let (sender, receiver) = mpsc::channel(max);
        runtime.spawn_task(async move {
            let _ = ReceiverStream::new(receiver)
                .buffer_unordered(max)
                .for_each(|_| async {})
                .await;
        });
        sender
    });

    while let Some(req) = rx.recv().await {
        let AddBundleRequest { tx, respond_to } = req;

        if let Err(e) = pool
            .add_transaction(TransactionOrigin::Local, tx.clone())
            .await
        {
            let _ = respond_to.send(Some(e));
            continue;
        } else {
            let _ = respond_to.send(None);
        }

        // Pre-simulate the transaction against current head state if:
        // - pre-simulation is enabled (simulator is Some)
        // - the tx has opted into revert protection
        if tx.revert_protected()
            && let Some(simulator) = &simulator
        {
            let pool = pool.clone();
            let metrics = metrics.clone();
            let simulator = simulator.clone();
            let fut = {
                let runtime = runtime.clone();
                async move {
                    let sim_start = Instant::now();
                    let sim_tx = tx.into_consensus();
                    let sim_tx_hash = *sim_tx.hash();
                    match simulator.clone().simulate_tx(&runtime, sim_tx).await {
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
                }
            };

            match &bounded_sender {
                Some(sender) => sender.send(fut).await.unwrap(),
                None => {
                    runtime.spawn_task(fut);
                }
            }
        }
    }
}
