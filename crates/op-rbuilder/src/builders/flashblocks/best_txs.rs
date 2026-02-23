use alloy_primitives::{Address, TxHash};
use reth_payload_util::{BestPayloadTransactions, PayloadTransactions};
use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};
use std::{collections::HashSet, sync::Arc};
use tracing::debug;

use crate::tx::MaybeFlashblockFilter;

#[derive(Debug, Default)]
pub(super) struct FlashblockCommittedTxs {
    // Transactions that were already committed to the state. Using them again would cause
    // NonceTooLow, so we skip them in later flashblocks.
    committed_transactions: HashSet<TxHash>,
}

impl FlashblockCommittedTxs {
    pub(super) fn contains(&self, tx_hash: &TxHash) -> bool {
        self.committed_transactions.contains(tx_hash)
    }

    pub(super) fn mark_committed(&mut self, txs: Vec<TxHash>) {
        self.committed_transactions.extend(txs);
    }
}

pub(super) struct FlashblockPoolTxCursor<'a, T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    inner: Option<BestPayloadTransactions<T, I>>,
    current_flashblock_number: u64,
    committed_txs: &'a mut FlashblockCommittedTxs,
}

impl<'a, T, I> FlashblockPoolTxCursor<'a, T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    pub(super) fn new(committed_txs: &'a mut FlashblockCommittedTxs) -> Self {
        Self {
            inner: None,
            current_flashblock_number: 0,
            committed_txs,
        }
    }

    /// Replaces current iterator with new one. We use it on new flashblock building, to refresh
    /// priority boundaries
    pub(super) fn refresh_iterator(
        &mut self,
        inner: BestPayloadTransactions<T, I>,
        current_flashblock_number: u64,
    ) {
        self.inner = Some(inner);
        self.current_flashblock_number = current_flashblock_number;
    }

    /// Remove transaction from next iteration and it already in the state
    pub(super) fn mark_committed(&mut self, txs: Vec<TxHash>) {
        self.committed_txs.mark_committed(txs);
    }
}

impl<T, I> PayloadTransactions for FlashblockPoolTxCursor<'_, T, I>
where
    T: PoolTransaction + MaybeFlashblockFilter,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    type Transaction = T;

    fn next(&mut self, ctx: ()) -> Option<Self::Transaction> {
        let inner = self.inner.as_mut()?;
        loop {
            let tx = inner.next(ctx)?;
            // Skip transaction we already included
            if self.committed_txs.contains(tx.hash()) {
                continue;
            }

            let flashblock_number_min = tx.flashblock_number_min();
            let flashblock_number_max = tx.flashblock_number_max();

            // Check min flashblock requirement
            if let Some(min) = flashblock_number_min
                && self.current_flashblock_number < min
            {
                continue;
            }

            // Check max flashblock requirement
            if let Some(max) = flashblock_number_max
                && self.current_flashblock_number > max
            {
                debug!(
                    target: "payload_builder",
                    tx_hash = ?tx.hash(),
                    sender = ?tx.sender(),
                    nonce = tx.nonce(),
                    current_flashblock = self.current_flashblock_number,
                    max_flashblock = max,
                    "Bundle flashblock max exceeded"
                );
                inner.mark_invalid(tx.sender(), tx.nonce());
                continue;
            }

            return Some(tx);
        }
    }

    /// Proxy to inner iterator
    fn mark_invalid(&mut self, sender: Address, nonce: u64) {
        if let Some(inner) = self.inner.as_mut() {
            inner.mark_invalid(sender, nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        builders::flashblocks::best_txs::{FlashblockCommittedTxs, FlashblockPoolTxCursor},
        mock_tx::{MockFbTransaction, MockFbTransactionFactory},
    };
    use alloy_consensus::Transaction;
    use reth_payload_util::{BestPayloadTransactions, PayloadTransactions};
    use reth_transaction_pool::{CoinbaseTipOrdering, PoolTransaction, pool::PendingPool};
    use std::sync::Arc;

    #[test]
    fn test_simple_case() {
        let mut pool = PendingPool::new(CoinbaseTipOrdering::<MockFbTransaction>::default());
        let mut f = MockFbTransactionFactory::default();

        // Add 3 regular transaction
        let tx_1 = f.create_eip1559();
        let tx_2 = f.create_eip1559();
        let tx_3 = f.create_eip1559();
        pool.add_transaction(Arc::new(tx_1), 0);
        pool.add_transaction(Arc::new(tx_2), 0);
        pool.add_transaction(Arc::new(tx_3), 0);

        let mut committed = FlashblockCommittedTxs::default();
        // ### First flashblock
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);
            // Accept first tx
            let tx1 = cursor.next(()).unwrap();
            // Invalidate second tx
            let tx2 = cursor.next(()).unwrap();
            cursor.mark_invalid(tx2.sender(), tx2.nonce());
            // Accept third tx
            let tx3 = cursor.next(()).unwrap();
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
            // Mark transaction as committed
            cursor.mark_committed(vec![*tx1.hash(), *tx3.hash()]);
        }

        // ### Second flashblock
        // It should not return txs 1 and 3, but should return 2
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 1);
            let tx2 = cursor.next(()).unwrap();
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
            // Mark transaction as committed
            cursor.mark_committed(vec![*tx2.hash()]);
        }

        // ### Third flashblock
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 2);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }
    }

    /// Test bundle cases
    /// We won't mark transactions as commited to test that boundaries are respected
    #[test]
    fn test_bundle_case() {
        let mut pool = PendingPool::new(CoinbaseTipOrdering::<MockFbTransaction>::default());
        let mut f = MockFbTransactionFactory::default();

        // Add 4 fb transaction
        let tx_1 = f.create_legacy_fb(None, None);
        let tx_1_hash = *tx_1.hash();
        let tx_2 = f.create_legacy_fb(None, Some(1));
        let tx_2_hash = *tx_2.hash();
        let tx_3 = f.create_legacy_fb(Some(1), None);
        let tx_3_hash = *tx_3.hash();
        let tx_4 = f.create_legacy_fb(Some(2), Some(3));
        let tx_4_hash = *tx_4.hash();
        pool.add_transaction(Arc::new(tx_1), 0);
        pool.add_transaction(Arc::new(tx_2), 0);
        pool.add_transaction(Arc::new(tx_3), 0);
        pool.add_transaction(Arc::new(tx_4), 0);

        let mut committed = FlashblockCommittedTxs::default();
        // ### First flashblock
        // should contain txs 1 and 2
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);
            let tx1 = cursor.next(()).unwrap();
            assert_eq!(tx1.hash(), &tx_1_hash);
            let tx2 = cursor.next(()).unwrap();
            assert_eq!(tx2.hash(), &tx_2_hash);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }

        // ### Second flashblock
        // should contain txs 1, 2, and 3
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 1);
            let tx1 = cursor.next(()).unwrap();
            assert_eq!(tx1.hash(), &tx_1_hash);
            let tx2 = cursor.next(()).unwrap();
            assert_eq!(tx2.hash(), &tx_2_hash);
            let tx3 = cursor.next(()).unwrap();
            assert_eq!(tx3.hash(), &tx_3_hash);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }

        // ### Third flashblock
        // should contain txs 1, 3, and 4
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 2);
            let tx1 = cursor.next(()).unwrap();
            assert_eq!(tx1.hash(), &tx_1_hash);
            let tx3 = cursor.next(()).unwrap();
            assert_eq!(tx3.hash(), &tx_3_hash);
            let tx4 = cursor.next(()).unwrap();
            assert_eq!(tx4.hash(), &tx_4_hash);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }

        // ### Forth flashblock
        // should contain txs 1, 3, and 4
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 3);
            let tx1 = cursor.next(()).unwrap();
            assert_eq!(tx1.hash(), &tx_1_hash);
            let tx3 = cursor.next(()).unwrap();
            assert_eq!(tx3.hash(), &tx_3_hash);
            let tx4 = cursor.next(()).unwrap();
            assert_eq!(tx4.hash(), &tx_4_hash);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }

        // ### Fifth flashblock
        // should contain txs 1 and 3
        {
            let mut cursor = FlashblockPoolTxCursor::new(&mut committed);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 4);
            let tx1 = cursor.next(()).unwrap();
            assert_eq!(tx1.hash(), &tx_1_hash);
            let tx3 = cursor.next(()).unwrap();
            assert_eq!(tx3.hash(), &tx_3_hash);
            // Check that it's empty
            assert!(cursor.next(()).is_none(), "Iterator should be empty");
        }
    }
}
