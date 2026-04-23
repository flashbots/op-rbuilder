use alloy_primitives::{Address, TxHash};
use reth_payload_util::{BestPayloadTransactions, PayloadTransactions};
use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};
use std::{collections::HashSet, sync::Arc};
use tracing::debug;

use crate::tx::MaybeFlashblockFilter;

/// Per-block cache of transactions that should be skipped in subsequent flashblocks.
///
/// This is threaded across flashblocks within the same block so that:
/// - Committed txs aren't re-fetched from the pool (would cause `NonceTooLow`).
/// - Reverted txs aren't re-simulated (would waste work).
///
/// A fresh instance is created per block, so exclusions do not leak between blocks.
#[derive(Debug, Default)]
pub(super) struct FlashblockTxCache {
    /// Transactions already committed to state.
    committed: HashSet<TxHash>,
    /// Transactions that reverted and were excluded from inclusion.
    excluded: HashSet<TxHash>,
}

impl FlashblockTxCache {
    pub(super) fn is_committed(&self, tx_hash: &TxHash) -> bool {
        self.committed.contains(tx_hash)
    }

    pub(super) fn is_excluded(&self, tx_hash: &TxHash) -> bool {
        self.excluded.contains(tx_hash)
    }

    pub(super) fn mark_committed(&mut self, txs: Vec<TxHash>) {
        self.committed.extend(txs);
    }

    pub(super) fn mark_excluded(&mut self, tx_hash: TxHash) {
        self.excluded.insert(tx_hash);
    }
}

pub(super) struct FlashblockPoolTxCursor<'a, T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    inner: Option<BestPayloadTransactions<T, I>>,
    current_flashblock_number: u64,
    tx_cache: &'a mut FlashblockTxCache,
}

impl<'a, T, I> FlashblockPoolTxCursor<'a, T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    pub(super) fn new(tx_cache: &'a mut FlashblockTxCache) -> Self {
        Self {
            inner: None,
            current_flashblock_number: 0,
            tx_cache,
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
        self.tx_cache.mark_committed(txs);
    }

    /// Exclude a transaction hash so it is skipped in subsequent flashblocks.
    pub(super) fn mark_excluded(&mut self, tx_hash: TxHash) {
        self.tx_cache.mark_excluded(tx_hash);
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
            if self.tx_cache.is_committed(tx.hash()) {
                continue;
            }

            // Skip transactions that reverted in a previous flashblock
            if self.tx_cache.is_excluded(tx.hash()) {
                continue;
            }

            let min_flashblock_number = tx.min_flashblock_number();
            let max_flashblock_number = tx.max_flashblock_number();

            // Check min flashblock requirement
            if let Some(min) = min_flashblock_number
                && self.current_flashblock_number < min
            {
                continue;
            }

            // Check max flashblock requirement
            if let Some(max) = max_flashblock_number
                && self.current_flashblock_number > max
            {
                debug!(
                    target: "payload_builder",
                    tx_hash = %tx.hash(),
                    sender = %tx.sender(),
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

impl<I> crate::traits::PayloadTxsBounds
    for FlashblockPoolTxCursor<'_, crate::tx::FBPooledTransaction, I>
where
    I: Iterator<Item = Arc<ValidPoolTransaction<crate::tx::FBPooledTransaction>>>,
{
    fn mark_excluded(&mut self, hash: TxHash) {
        Self::mark_excluded(self, hash);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        builder::best_txs::{FlashblockPoolTxCursor, FlashblockTxCache},
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

        let mut committed = FlashblockTxCache::default();
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

        let mut committed = FlashblockTxCache::default();
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

    /// Excluded txs persist across flashblocks (refresh_iterator) within the same block,
    /// but a new iterator (new block) starts with a clean excluded set.
    #[test]
    fn test_excluded_txs_persist_within_block_cleared_between_blocks() {
        let mut pool = PendingPool::new(CoinbaseTipOrdering::<MockFbTransaction>::default());
        let mut f = MockFbTransactionFactory::default();

        let tx_1 = f.create_eip1559();
        let tx_1_hash = *tx_1.hash();
        let tx_2 = f.create_eip1559();
        let tx_2_hash = *tx_2.hash();
        let tx_3 = f.create_eip1559();
        let tx_3_hash = *tx_3.hash();
        pool.add_transaction(Arc::new(tx_1), 0);
        pool.add_transaction(Arc::new(tx_2), 0);
        pool.add_transaction(Arc::new(tx_3), 0);

        // === Block 1 ===
        // Fresh cache per block — exclusions are tracked here so they persist across
        // flashblocks but not across blocks.
        {
            let mut tx_cache = FlashblockTxCache::default();
            let mut cursor = FlashblockPoolTxCursor::new(&mut tx_cache);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);

            // Flashblock 0: all 3 returned, tx_2 reverts so we exclude it
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);
            let got_1 = cursor.next(()).unwrap();
            assert_eq!(got_1.hash(), &tx_1_hash);
            let got_2 = cursor.next(()).unwrap();
            assert_eq!(got_2.hash(), &tx_2_hash);
            // tx_2 reverted — exclude it
            cursor.mark_excluded(tx_2_hash);
            let got_3 = cursor.next(()).unwrap();
            assert_eq!(got_3.hash(), &tx_3_hash);
            assert!(cursor.next(()).is_none());
            // Commit successful txs
            cursor.mark_committed(vec![tx_1_hash, tx_3_hash]);

            // Flashblock 1: tx_1/tx_3 committed, tx_2 excluded — nothing returned
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 1);
            assert!(cursor.next(()).is_none(), "tx_2 should be excluded");

            // Flashblock 2: tx_2 still excluded
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 2);
            assert!(cursor.next(()).is_none(), "tx_2 should still be excluded");
        }

        // === Block 2: fresh cache, exclusions cleared ===
        {
            let mut tx_cache = FlashblockTxCache::default();
            let mut cursor = FlashblockPoolTxCursor::new(&mut tx_cache);
            cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);

            let mut count = 0;
            while cursor.next(()).is_some() {
                count += 1;
            }
            assert_eq!(
                count, 3,
                "New block should see all 3 txs — exclusions not inherited"
            );
        }
    }

    /// Only the excluded tx is skipped — other txs in the pool are unaffected.
    #[test]
    fn test_excluded_tx_does_not_affect_other_txs() {
        let mut pool = PendingPool::new(CoinbaseTipOrdering::<MockFbTransaction>::default());
        let mut f = MockFbTransactionFactory::default();

        let tx_1 = f.create_eip1559();
        let tx_1_hash = *tx_1.hash();
        let tx_2 = f.create_eip1559();
        let tx_2_hash = *tx_2.hash();
        let tx_3 = f.create_eip1559();
        let tx_3_hash = *tx_3.hash();
        pool.add_transaction(Arc::new(tx_1), 0);
        pool.add_transaction(Arc::new(tx_2), 0);
        pool.add_transaction(Arc::new(tx_3), 0);

        let mut committed = FlashblockTxCache::default();
        let mut cursor = FlashblockPoolTxCursor::new(&mut committed);

        // Flashblock 0: exclude tx_1 only
        cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);
        let got_1 = cursor.next(()).unwrap();
        assert_eq!(got_1.hash(), &tx_1_hash);
        cursor.mark_excluded(tx_1_hash);
        // tx_2 and tx_3 should still be returned
        let got_2 = cursor.next(()).unwrap();
        assert_eq!(got_2.hash(), &tx_2_hash);
        let got_3 = cursor.next(()).unwrap();
        assert_eq!(got_3.hash(), &tx_3_hash);
        assert!(cursor.next(()).is_none());

        // Flashblock 1: tx_1 excluded, tx_2 and tx_3 available
        cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 1);
        let got = cursor.next(()).unwrap();
        assert_eq!(got.hash(), &tx_2_hash);
        let got = cursor.next(()).unwrap();
        assert_eq!(got.hash(), &tx_3_hash);
        assert!(cursor.next(()).is_none(), "only tx_1 should be excluded");
    }

    /// Multiple txs can be excluded independently.
    #[test]
    fn test_multiple_excluded_txs() {
        let mut pool = PendingPool::new(CoinbaseTipOrdering::<MockFbTransaction>::default());
        let mut f = MockFbTransactionFactory::default();

        let tx_1 = f.create_eip1559();
        let tx_1_hash = *tx_1.hash();
        let tx_2 = f.create_eip1559();
        let tx_2_hash = *tx_2.hash();
        let tx_3 = f.create_eip1559();
        let tx_3_hash = *tx_3.hash();
        pool.add_transaction(Arc::new(tx_1), 0);
        pool.add_transaction(Arc::new(tx_2), 0);
        pool.add_transaction(Arc::new(tx_3), 0);

        let mut committed = FlashblockTxCache::default();
        let mut cursor = FlashblockPoolTxCursor::new(&mut committed);

        // Flashblock 0: exclude tx_1 and tx_3
        cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 0);
        cursor.next(()).unwrap(); // tx_1
        cursor.mark_excluded(tx_1_hash);
        cursor.next(()).unwrap(); // tx_2
        cursor.next(()).unwrap(); // tx_3
        cursor.mark_excluded(tx_3_hash);

        // Flashblock 1: only tx_2 should be returned
        cursor.refresh_iterator(BestPayloadTransactions::new(pool.best()), 1);
        let got = cursor.next(()).unwrap();
        assert_eq!(got.hash(), &tx_2_hash);
        assert!(
            cursor.next(()).is_none(),
            "tx_1 and tx_3 should both be excluded"
        );
    }
}
