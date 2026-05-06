mod builder;
mod delegate;

pub use builder::FlashpoolBuilder;

use reth_transaction_pool::TransactionPool;

use crate::tx::FBPooledTransaction;

#[derive(Debug, Clone)]
pub struct Flashpool<P: TransactionPool<Transaction = FBPooledTransaction>> {
    inner: P,
}
