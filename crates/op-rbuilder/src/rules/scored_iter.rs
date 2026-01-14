//! Score-ordered transaction iterator for O(k) block building.
//!
//! This module provides iterators that yield transactions in rule-score order
//! by using the pre-computed score index populated at validation time.

use alloy_primitives::{Address, B256};
use reth_payload_util::PayloadTransactions;
use reth_transaction_pool::TransactionPool;
use std::collections::HashSet;
use tracing::trace;

use super::score_index::SharedScoreIndex;

/// Iterator that yields transactions in rule-score order using the pre-computed score index.
///
/// This achieves O(n) + O(k) complexity instead of O(n log n) eager sorting:
/// - O(n) to build the pending transaction hash set
/// - O(k) to iterate and return k transactions
///
/// # Usage
///
/// ```ignore
/// let iter = ScoreOrderedTransactions::new(&pool, score_index);
/// while let Some(tx) = iter.next(()) {
///     // Process transaction in score order
/// }
/// ```
pub struct ScoreOrderedTransactions<Pool>
where
    Pool: TransactionPool,
{
    /// Reference to the transaction pool
    pool: Pool,
    /// Currently pending transaction hashes (filter for stale entries in score index).
    pending_hashes: HashSet<B256>,
    /// Transaction hashes in score order (snapshot from shared index, may contain stale entries).
    score_ordered_hashes: Vec<B256>,
    /// Current position in score_ordered_hashes (O(1) vs O(n) for Vec removal).
    position: usize,
    /// Senders marked as invalid (their transactions should be skipped)
    invalid_senders: HashSet<Address>,
}

impl<Pool> ScoreOrderedTransactions<Pool>
where
    Pool: TransactionPool,
{
    /// Create a new score-ordered iterator.
    ///
    /// This constructor:
    /// 1. Gets all pending transactions from the pool to build a hash set: O(n)
    /// 2. Gets score-ordered hashes from the shared index: O(m) where m = index size
    pub fn new(pool: Pool, score_index: &SharedScoreIndex) -> Self {
        // Get pending (executable) transaction hashes - O(n)
        let pending_hashes: HashSet<B256> = pool
            .pending_transactions()
            .iter()
            .map(|tx| *tx.hash())
            .collect();

        // Get score-ordered hashes from shared index (take a snapshot)
        let score_ordered_hashes: Vec<B256> = score_index.read().iter_hashes().collect();

        Self {
            pool,
            pending_hashes,
            score_ordered_hashes,
            position: 0,
            invalid_senders: HashSet::new(),
        }
    }

    /// Check if there are more transactions to process.
    pub fn has_more(&self) -> bool {
        self.position < self.score_ordered_hashes.len()
    }

    /// Get the number of entries in the score index.
    pub fn index_size(&self) -> usize {
        self.score_ordered_hashes.len()
    }

    /// Get the number of pending transactions.
    pub fn pending_count(&self) -> usize {
        self.pending_hashes.len()
    }
}

impl<Pool> PayloadTransactions for ScoreOrderedTransactions<Pool>
where
    Pool: TransactionPool,
    Pool::Transaction: Clone,
{
    type Transaction = Pool::Transaction;

    fn next(&mut self, _ctx: ()) -> Option<Self::Transaction> {
        while self.position < self.score_ordered_hashes.len() {
            let tx_hash = self.score_ordered_hashes[self.position];
            self.position += 1;

            // Skip if not in pending set (transaction may have been included/evicted)
            if !self.pending_hashes.contains(&tx_hash) {
                trace!(
                    target: "score_ordered_iter",
                    %tx_hash,
                    "Skipping transaction: not in pending set (may have been included or evicted)"
                );
                continue;
            }

            // Try to get the transaction from pool
            let Some(pooled_tx) = self.pool.get(&tx_hash) else {
                trace!(
                    target: "score_ordered_iter",
                    %tx_hash,
                    "Skipping transaction: no longer in pool"
                );
                continue;
            };

            // Check if sender is marked invalid
            let sender = pooled_tx.sender();
            if self.invalid_senders.contains(&sender) {
                trace!(
                    target: "score_ordered_iter",
                    %tx_hash,
                    %sender,
                    "Skipping transaction: sender marked invalid"
                );
                continue;
            }

            // Remove from pending set so we don't return it again
            self.pending_hashes.remove(&tx_hash);

            // Return the transaction
            // Note: We need to extract the inner transaction from ValidPoolTransaction
            return Some(pooled_tx.transaction.clone());
        }

        None
    }

    fn mark_invalid(&mut self, sender: Address, _nonce: u64) {
        // Mark this sender as invalid - skip all their remaining transactions
        self.invalid_senders.insert(sender);
    }
}

/// Transaction iterator that uses score-based ordering when available.
///
/// This iterator checks the score index at construction time:
/// - If the score index has entries, transactions are returned in score order
/// - Otherwise, falls back to the inner iterator (typically gas-price ordering)
pub struct BestTransactionsWithScores<Pool, Inner>
where
    Pool: TransactionPool,
    Inner: PayloadTransactions,
{
    /// Score-ordered iterator (used when score index has entries)
    score_ordered: Option<ScoreOrderedTransactions<Pool>>,
    /// Fallback inner iterator (used when score index is empty)
    inner: Inner,
}

impl<Pool, Inner> BestTransactionsWithScores<Pool, Inner>
where
    Pool: TransactionPool,
    Pool::Transaction: Clone,
    Inner: PayloadTransactions<Transaction = Pool::Transaction>,
{
    /// Create a new transaction iterator that uses score ordering when available.
    ///
    /// The decision to use score ordering is based solely on whether the score
    /// index has entries.
    /// - No scoring rules configured → index empty → use gas-price ordering
    /// - Scoring rules exist → index populated → use score ordering
    /// - Rules added at runtime → new txs scored → next block uses score ordering
    ///
    /// # Arguments
    ///
    /// * `pool` - The transaction pool
    /// * `inner` - Fallback iterator for gas-price ordering
    /// * `score_index` - Optional shared score index
    pub fn new(pool: Pool, inner: Inner, score_index: Option<&SharedScoreIndex>) -> Self {
        let has_scored_transactions = score_index
            .map(|idx| !idx.read().is_empty())
            .unwrap_or(false);

        if let (true, Some(idx)) = (has_scored_transactions, score_index) {
            Self {
                score_ordered: Some(ScoreOrderedTransactions::new(pool, idx)),
                inner,
            }
        } else {
            Self {
                score_ordered: None,
                inner,
            }
        }
    }

    /// Check if we're using score-based ordering.
    pub fn is_using_score_order(&self) -> bool {
        self.score_ordered.is_some()
    }
}

impl<Pool, Inner> PayloadTransactions for BestTransactionsWithScores<Pool, Inner>
where
    Pool: TransactionPool,
    Pool::Transaction: Clone,
    Inner: PayloadTransactions<Transaction = Pool::Transaction>,
{
    type Transaction = Pool::Transaction;

    fn next(&mut self, ctx: ()) -> Option<Self::Transaction> {
        if let Some(ref mut score_ordered) = self.score_ordered {
            score_ordered.next(ctx)
        } else {
            self.inner.next(ctx)
        }
    }

    fn mark_invalid(&mut self, sender: Address, nonce: u64) {
        if let Some(ref mut score_ordered) = self.score_ordered {
            score_ordered.mark_invalid(sender, nonce);
        }
        // Also mark in inner iterator for consistency
        self.inner.mark_invalid(sender, nonce);
    }
}