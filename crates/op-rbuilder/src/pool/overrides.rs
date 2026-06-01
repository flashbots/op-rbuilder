use std::time::Instant;

use reth_transaction_pool::{
    AddedTransactionOutcome, PoolResult, PoolTransaction, TransactionOrigin, TransactionPool,
    pool::AddedTransactionState,
};
use tracing::error;

use crate::{
    pool::{Flashpool, metrics},
    tx::FBPooledTransaction,
};

impl<P: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static> Flashpool<P> {
    pub(super) async fn add_transaction_override(
        &self,
        origin: TransactionOrigin,
        transaction: FBPooledTransaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        if transaction.revert_protected()
            && let Some(ref simulator) = self.simulator
        {
            let tx_hash = *transaction.hash();
            let consensus_tx = transaction.clone_into_consensus();
            let simulator = simulator.clone();
            let inner_pool = self.inner.clone();
            let metrics = self.metrics.clone();

            self.task_executor.spawn_task(async move {
                let sim_start = Instant::now();
                let sim_result = simulator.simulate_tx(consensus_tx).await;
                metrics::increment_presim_count(&sim_result);

                match sim_result {
                    Ok(true) => {
                        let _ = inner_pool.add_transaction(origin, transaction).await;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        error!(tx_hash = %tx_hash, error = %e, "pre-simulation task failed");
                    }
                }
                metrics.presim_duration.record(sim_start.elapsed());
            });

            return Ok(AddedTransactionOutcome {
                hash: tx_hash,
                state: AddedTransactionState::Pending,
            });
        }

        self.inner.add_transaction(origin, transaction).await
    }
}
