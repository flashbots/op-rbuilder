mod builder;
mod delegate;

use alloy_primitives::TxHash;
pub use builder::FlashpoolBuilder;

use moka::sync::Cache;
use reth_transaction_pool::TransactionPool;

use crate::tx::FBPooledTransaction;

#[derive(Debug, Clone)]
pub struct Flashpool<P: TransactionPool<Transaction = FBPooledTransaction>> {
    inner: P,

    /// Cache to store reverted tx hashes
    reverted_cache: Option<Cache<TxHash, ()>>,
}

/// Custom extensions on the pool where it doesn't make sense to intercept an
/// existing pool method.
pub trait FlashpoolExt {
    /// Checks if a transaction is reverted by checking if the given transaction
    /// hash is present in the reverted cache.
    fn is_tx_reverted(&self, hash: TxHash) -> bool;
}

impl<P: TransactionPool<Transaction = FBPooledTransaction>> FlashpoolExt for Flashpool<P> {
    fn is_tx_reverted(&self, hash: TxHash) -> bool {
        self.reverted_cache
            .as_ref()
            .is_some_and(|cache| cache.get(&hash).is_some())
    }
}
