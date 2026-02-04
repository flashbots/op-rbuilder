//! Score index for O(k) block building.
//!
//! This module maintains a parallel index of transaction scores computed at ingress time.
//! Instead of sorting all transactions at block building time (O(n log n)), we:

use alloy_primitives::{Address, B256};
use parking_lot::RwLock;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

/// Key for ordering transactions by score in the index.
///
/// Transactions are ordered by:
/// 1. Score (descending - higher scores first)
/// 2. Max priority fee (descending - higher fees first for tiebreaking)
/// 3. Transaction hash (ascending - for uniqueness/stability)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScoreKey {
    /// Rule-based boost score
    pub score: i64,
    /// Max priority fee per gas (for tiebreaking)
    pub max_priority_fee: u128,
    /// Transaction hash (for uniqueness)
    pub tx_hash: B256,
}

impl Ord for ScoreKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher score first (descending)
        other
            .score
            .cmp(&self.score)
            // Higher max priority fee first (descending, tiebreaker)
            .then_with(|| other.max_priority_fee.cmp(&self.max_priority_fee))
            // Hash for uniqueness (ascending)
            .then_with(|| self.tx_hash.cmp(&other.tx_hash))
    }
}

impl PartialOrd for ScoreKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Entry storing score metadata for a transaction.
#[derive(Clone, Copy, Debug)]
pub struct ScoreEntry {
    /// The ordering key
    pub key: ScoreKey,
    /// Transaction sender (for filtering invalid senders)
    pub sender: Address,
}

/// Index that tracks transaction scores for efficient block building.
///
/// Maintains transactions ordered by (score DESC, tip DESC) for iteration,
/// plus a lookup map for O(1) access by transaction hash.
#[derive(Default, Debug)]
pub struct ScoreIndex {
    /// Transactions ordered by score (highest first)
    ordered: BTreeSet<ScoreKey>,
    /// Lookup from tx_hash to full entry for O(1) access
    lookup: HashMap<B256, ScoreEntry>,
}

impl ScoreIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a transaction's score.
    ///
    /// If the transaction already exists, it will be updated with the new score.
    pub fn upsert(&mut self, tx_hash: B256, sender: Address, score: i64, max_priority_fee: u128) {
        // If entry exists, we only need to remove from ordered set since lookup.insert() overwrites.
        // This is slightly more efficient than calling self.remove() which does both.
        if let Some(old_entry) = self.lookup.get(&tx_hash) {
            self.ordered.remove(&old_entry.key);
        }

        let key = ScoreKey {
            score,
            max_priority_fee,
            tx_hash,
        };
        let entry = ScoreEntry { key, sender };

        self.ordered.insert(key);
        self.lookup.insert(tx_hash, entry);

        // Invariant: ordered and lookup must always have the same size
        debug_assert_eq!(
            self.ordered.len(),
            self.lookup.len(),
            "ScoreIndex invariant violated: ordered and lookup are out of sync"
        );
    }

    /// Remove a transaction from the index.
    ///
    /// Returns true if the transaction was present and removed.
    pub fn remove(&mut self, tx_hash: &B256) -> bool {
        if let Some(entry) = self.lookup.remove(tx_hash) {
            self.ordered.remove(&entry.key);
            debug_assert_eq!(
                self.ordered.len(),
                self.lookup.len(),
                "ScoreIndex invariant violated: ordered and lookup are out of sync after remove"
            );
            true
        } else {
            false
        }
    }

    /// Check that internal data structures are in sync.
    ///
    /// Returns true if `ordered` and `lookup` have the same size.
    /// This is useful for testing invariant maintenance.
    #[cfg(test)]
    pub fn is_in_sync(&self) -> bool {
        self.ordered.len() == self.lookup.len()
    }

    /// Get the score entry for a transaction.
    pub fn get(&self, tx_hash: &B256) -> Option<&ScoreEntry> {
        self.lookup.get(tx_hash)
    }

    /// Get just the score for a transaction.
    pub fn get_score(&self, tx_hash: &B256) -> Option<i64> {
        self.lookup.get(tx_hash).map(|e| e.key.score)
    }

    /// Iterate transaction hashes in score order (highest first).
    pub fn iter_hashes(&self) -> impl Iterator<Item = B256> + '_ {
        self.ordered.iter().map(|k| k.tx_hash)
    }

    /// Iterate full entries in score order (highest first).
    pub fn iter_entries(&self) -> impl Iterator<Item = &ScoreEntry> + '_ {
        self.ordered
            .iter()
            .filter_map(|k| self.lookup.get(&k.tx_hash))
    }

    /// Number of entries in the index.
    pub fn len(&self) -> usize {
        self.lookup.len()
    }

    /// Check if index is empty.
    pub fn is_empty(&self) -> bool {
        self.lookup.is_empty()
    }

    /// Remove entries for transactions not in the given set.
    ///
    /// This is used for periodic cleanup of stale entries.
    pub fn retain(&mut self, valid_hashes: &HashSet<B256>) {
        let to_remove: Vec<_> = self
            .lookup
            .keys()
            .filter(|h| !valid_hashes.contains(*h))
            .copied()
            .collect();

        for hash in to_remove {
            self.remove(&hash);
        }
    }

    /// Clear all entries from the index.
    pub fn clear(&mut self) {
        self.ordered.clear();
        self.lookup.clear();
    }
}

/// Thread-safe shared score index.
///
/// This type is created at startup and passed to components that need to
/// read or write transaction scores:
/// - [`RuleBasedValidator`]: Inserts scores when transactions pass validation
/// - [`monitor_tx_pool`]: Removes scores when transactions leave the pool
/// - [`ScoreOrderedTransactions`]: Reads scores in order during block building
pub type SharedScoreIndex = Arc<RwLock<ScoreIndex>>;

/// Create a new shared score index.
///
/// Call this once at startup and pass the result to all components that need it.
pub fn new_shared_score_index() -> SharedScoreIndex {
    Arc::new(RwLock::new(ScoreIndex::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn make_hash(n: u8) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        B256::from(bytes)
    }

    #[test]
    fn test_score_ordering() {
        let mut index = ScoreIndex::new();
        let sender = address!("0000000000000000000000000000000000000001");

        // Insert transactions with different scores
        index.upsert(make_hash(1), sender, 100, 50); // High score
        index.upsert(make_hash(2), sender, 50, 100); // Medium score, high fee
        index.upsert(make_hash(3), sender, 50, 50); // Medium score, medium fee
        index.upsert(make_hash(4), sender, 10, 1000); // Low score, very high fee

        // Verify internal sync after all inserts
        assert!(index.is_in_sync());

        // Verify ordering: should be by score DESC, then max_priority_fee DESC
        let hashes: Vec<_> = index.iter_hashes().collect();
        assert_eq!(hashes[0], make_hash(1)); // score=100
        assert_eq!(hashes[1], make_hash(2)); // score=50, fee=100
        assert_eq!(hashes[2], make_hash(3)); // score=50, fee=50
        assert_eq!(hashes[3], make_hash(4)); // score=10
    }

    #[test]
    fn test_upsert_update() {
        let mut index = ScoreIndex::new();
        let sender = address!("0000000000000000000000000000000000000001");
        let hash = make_hash(1);

        // Insert
        index.upsert(hash, sender, 50, 100);
        assert_eq!(index.get_score(&hash), Some(50));
        assert_eq!(index.len(), 1);
        assert!(index.is_in_sync());

        // Update (same hash, different score)
        index.upsert(hash, sender, 100, 200);
        assert_eq!(index.get_score(&hash), Some(100));
        assert_eq!(index.len(), 1); // Still only one entry
        assert!(index.is_in_sync()); // Verify sync after update
    }

    #[test]
    fn test_remove() {
        let mut index = ScoreIndex::new();
        let sender = address!("0000000000000000000000000000000000000001");
        let hash = make_hash(1);

        index.upsert(hash, sender, 50, 100);
        assert_eq!(index.len(), 1);
        assert!(index.is_in_sync());

        assert!(index.remove(&hash));
        assert_eq!(index.len(), 0);
        assert_eq!(index.get_score(&hash), None);
        assert!(index.is_in_sync()); // Verify sync after remove

        // Remove non-existent
        assert!(!index.remove(&hash));
        assert!(index.is_in_sync());
    }

    #[test]
    fn test_retain() {
        let mut index = ScoreIndex::new();
        let sender = address!("0000000000000000000000000000000000000001");

        index.upsert(make_hash(1), sender, 100, 50);
        index.upsert(make_hash(2), sender, 50, 100);
        index.upsert(make_hash(3), sender, 10, 50);
        assert!(index.is_in_sync());

        // Keep only hash 1 and 3
        let valid: HashSet<_> = [make_hash(1), make_hash(3)].into_iter().collect();
        index.retain(&valid);

        assert_eq!(index.len(), 2);
        assert!(index.get(&make_hash(1)).is_some());
        assert!(index.get(&make_hash(2)).is_none()); // Removed
        assert!(index.get(&make_hash(3)).is_some());
        assert!(index.is_in_sync()); // Verify sync after retain
    }

    #[test]
    fn test_ordered_lookup_sync() {
        // Dedicated test for verifying ordered and lookup stay in sync
        let mut index = ScoreIndex::new();
        let sender = address!("0000000000000000000000000000000000000001");

        // Start empty - should be in sync
        assert!(index.is_in_sync());
        assert_eq!(index.len(), 0);

        // Insert multiple entries
        for i in 0..10 {
            index.upsert(make_hash(i), sender, i as i64 * 10, i as u128);
            assert!(index.is_in_sync());
        }
        assert_eq!(index.len(), 10);

        // Update some entries (replacement)
        for i in 0..5 {
            index.upsert(make_hash(i), sender, i as i64 * 100, i as u128 * 2);
            assert!(index.is_in_sync());
        }
        assert_eq!(index.len(), 10); // Same count after updates

        // Remove some entries
        for i in 5..8 {
            index.remove(&make_hash(i));
            assert!(index.is_in_sync());
        }
        assert_eq!(index.len(), 7);

        // Clear
        index.clear();
        assert!(index.is_in_sync());
        assert_eq!(index.len(), 0);
    }
}
