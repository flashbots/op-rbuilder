mod builder;
mod delegate;
mod metrics;
mod overrides;
mod presim;

use alloy_primitives::TxHash;
pub use builder::FlashpoolBuilder;

use moka::sync::Cache;
use reth_transaction_pool::TransactionPool;
use std::sync::Arc;

use reth_tasks::TaskExecutor;

use crate::{
    pool::{metrics::PoolMetrics, presim::TopOfBlockSimulator},
    tx::FBPooledTransaction,
};

#[derive(Debug, Clone)]
pub struct Flashpool<P, V> {
    /// The reth transaction pool we're wrapping around
    inner: P,

    /// The transaction validator
    validator: V,

    /// Optional pre-simulator: when present, revert-protected txs are simulated
    /// before being added to the pool; those that would revert are rejected.
    simulator: Option<Arc<TopOfBlockSimulator>>,

    /// Task executor for spawning presim tasks
    task_executor: TaskExecutor,

    /// Cache to store reverted tx hashes
    reverted_cache: Option<Cache<TxHash, ()>>,

    /// Metrics
    metrics: Arc<PoolMetrics>,
}

/// Custom extensions on the pool where it doesn't make sense to intercept an
/// existing pool method.
pub trait FlashpoolExt {
    /// Checks if a transaction is reverted by checking if the given transaction
    /// hash is present in the reverted cache.
    fn is_tx_reverted(&self, hash: TxHash) -> bool;
}

impl<P: TransactionPool<Transaction = FBPooledTransaction>, V> FlashpoolExt for Flashpool<P, V> {
    fn is_tx_reverted(&self, hash: TxHash) -> bool {
        self.reverted_cache
            .as_ref()
            .is_some_and(|cache| cache.get(&hash).is_some())
    }
}
