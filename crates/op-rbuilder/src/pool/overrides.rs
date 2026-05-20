use std::time::Instant;

use reth_transaction_pool::{
    AddedTransactionOutcome, PoolResult, PoolTransaction, TransactionOrigin, TransactionPool,
    TransactionValidationOutcome, TransactionValidator, error::PoolError,
    pool::AddedTransactionState,
};
use tracing::error;

use crate::{
    pool::{Flashpool, metrics},
    tx::FBPooledTransaction,
};

impl<
    P: TransactionPool<Transaction = FBPooledTransaction> + Clone + 'static,
    V: TransactionValidator<Transaction = FBPooledTransaction> + Clone,
> Flashpool<P, V>
{
    pub(super) async fn add_transaction_override(
        &self,
        origin: TransactionOrigin,
        transaction: FBPooledTransaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        let validation_outcome = self
            .validator
            .validate_transaction(origin, transaction)
            .await;

        use TransactionValidationOutcome::*;
        let transaction = match validation_outcome {
            Valid { transaction, .. } => transaction,
            Invalid(tx, err) => return Err(PoolError::new(*tx.hash(), err)),
            Error(hash, err) => return Err(PoolError::other(hash, err)),
        };

        if transaction.transaction().revert_protected()
            && let Some(ref simulator) = self.simulator
        {
            let tx_hash = *transaction.hash();
            let consensus_tx = transaction.transaction().clone_into_consensus();
            let simulator = simulator.clone();
            let inner_pool = self.inner.clone();
            let metrics = self.metrics.clone();

            self.task_executor.spawn_task(async move {
                let sim_start = Instant::now();
                let sim_result = simulator.simulate_tx(consensus_tx).await;
                metrics::increment_presim_count(&sim_result);

                match sim_result {
                    Ok(true) => {
                        let _ = inner_pool
                            .add_transaction(origin, transaction.into_transaction())
                            .await;
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

        self.inner
            .add_transaction(origin, transaction.into_transaction())
            .await
    }
}
