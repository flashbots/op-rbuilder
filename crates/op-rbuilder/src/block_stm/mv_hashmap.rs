//! Multi-Version Hash Map for Block-STM
//!
//! The MVHashMap is the central data structure for parallel execution. It stores
//! versioned writes from transactions, allowing concurrent reads while tracking
//! dependencies for conflict detection.
//!
//! # Key Features
//!
//! - **Versioned Storage**: Each key can have multiple versions (one per transaction)
//! - **Dependency Tracking**: Readers register dependencies on writers for push-based invalidation
//! - **Concurrent Access**: Uses fine-grained locking for parallel read/write

use crate::block_stm::types::{
    EvmStateKey, EvmStateValue, Incarnation, ReadResult, TxnIndex, Version,
};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::trace;

/// Entry for a single transaction's write to a key.
#[derive(Debug)]
struct WriteEntry {
    /// The incarnation that wrote this value
    incarnation: Incarnation,
    /// The written value
    value: EvmStateValue,
    /// Whether this entry has been marked as aborted
    aborted: AtomicBool,
}

impl WriteEntry {
    fn new(incarnation: Incarnation, value: EvmStateValue) -> Self {
        Self {
            incarnation,
            value,
            aborted: AtomicBool::new(false),
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    fn mark_aborted(&self) {
        self.aborted.store(true, Ordering::Release);
    }
}

/// Versioned data for a single key.
/// Maps transaction index to the write entry.
#[derive(Debug, Default)]
struct VersionedValue {
    /// Map from txn_idx to write entry.
    /// BTreeMap keeps entries sorted by txn_idx for efficient "latest before" queries.
    writes: BTreeMap<TxnIndex, WriteEntry>,
    /// Set of transactions that have read this key (for dependency tracking).
    /// Maps reader txn_idx to the version they observed.
    readers: HashMap<TxnIndex, Option<Version>>,
}

impl VersionedValue {
    /// Write a value at the given version.
    fn write(&mut self, txn_idx: TxnIndex, incarnation: Incarnation, value: EvmStateValue) {
        self.writes.insert(txn_idx, WriteEntry::new(incarnation, value));
    }

    /// Read the latest value written by a transaction with index < reader_txn_idx.
    /// Returns the value and version, or NotFound if no such write exists.
    fn read(&mut self, reader_txn_idx: TxnIndex) -> ReadResult {
        // Find the latest write with txn_idx < reader_txn_idx
        let maybe_entry = self
            .writes
            .range(..reader_txn_idx)
            .next_back();

        match maybe_entry {
            Some((&writer_txn_idx, entry)) => {
                if entry.is_aborted() {
                    // Track that we tried to read from an aborted transaction
                    self.readers.insert(reader_txn_idx, None);
                    ReadResult::Aborted { txn_idx: writer_txn_idx }
                } else {
                    let version = Version::new(writer_txn_idx, entry.incarnation);
                    // Track the dependency
                    self.readers.insert(reader_txn_idx, Some(version));
                    ReadResult::Value {
                        value: entry.value.clone(),
                        version,
                    }
                }
            }
            None => {
                // No write found, reader depends on base state
                self.readers.insert(reader_txn_idx, None);
                ReadResult::NotFound
            }
        }
    }

    /// Mark a transaction's write as aborted.
    /// Returns the set of reader transactions that need to be invalidated.
    fn mark_aborted(&mut self, txn_idx: TxnIndex) -> HashSet<TxnIndex> {
        if let Some(entry) = self.writes.get(&txn_idx) {
            entry.mark_aborted();
        }

        // Find all readers that read from this transaction or later
        // (they may have been affected by this write)
        let version = self.writes.get(&txn_idx).map(|e| Version::new(txn_idx, e.incarnation));
        
        self.readers
            .iter()
            .filter_map(|(&reader_idx, &observed_version)| {
                // Reader is affected if:
                // 1. They read from the aborted transaction
                // 2. They read from base state but the aborted tx is before them
                //    (they should have seen the write)
                if reader_idx > txn_idx {
                    if observed_version == version || observed_version.is_none() {
                        Some(reader_idx)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Clear the read tracking for a transaction (when it's re-executed).
    fn clear_reader(&mut self, txn_idx: TxnIndex) {
        self.readers.remove(&txn_idx);
    }

    /// Delete a transaction's write (when the transaction is re-executed with new incarnation).
    fn delete_write(&mut self, txn_idx: TxnIndex) {
        self.writes.remove(&txn_idx);
    }
}

/// Multi-Version Hash Map for Block-STM parallel execution.
///
/// Stores versioned writes per key and tracks read dependencies for push-based invalidation.
#[derive(Debug)]
pub struct MVHashMap {
    /// Map from state key to versioned values.
    data: RwLock<HashMap<EvmStateKey, RwLock<VersionedValue>>>,
    /// Number of transactions in the block (reserved for future use).
    #[allow(dead_code)]
    num_txns: usize,
}

impl MVHashMap {
    /// Create a new MVHashMap for a block with the given number of transactions.
    pub fn new(num_txns: usize) -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            num_txns,
        }
    }

    /// Write a value at the given version.
    pub fn write(&self, txn_idx: TxnIndex, incarnation: Incarnation, key: EvmStateKey, value: EvmStateValue) {
        trace!(
            txn_idx = txn_idx,
            incarnation = incarnation,
            key = %key,
            "MVHashMap write"
        );

        // Get or create the versioned value entry for this key
        {
            let data = self.data.read();
            if let Some(versioned) = data.get(&key) {
                versioned.write().write(txn_idx, incarnation, value);
                return;
            }
        }

        // Key doesn't exist, need to create it
        let mut data = self.data.write();
        let versioned = data.entry(key.clone()).or_insert_with(|| RwLock::new(VersionedValue::default()));
        versioned.write().write(txn_idx, incarnation, value);
    }

    /// Read the latest value for a key that was written by a transaction before reader_txn_idx.
    pub fn read(&self, reader_txn_idx: TxnIndex, key: &EvmStateKey) -> ReadResult {
        let data = self.data.read();
        
        match data.get(key) {
            Some(versioned) => {
                let result = versioned.write().read(reader_txn_idx);
                trace!(
                    reader_txn_idx = reader_txn_idx,
                    key = %key,
                    result = ?result,
                    "MVHashMap read"
                );
                result
            }
            None => {
                trace!(
                    reader_txn_idx = reader_txn_idx,
                    key = %key,
                    "MVHashMap read - key not in map"
                );
                ReadResult::NotFound
            }
        }
    }

    /// Mark a transaction as aborted and return the set of dependent transactions
    /// that need to be invalidated.
    pub fn mark_aborted(&self, txn_idx: TxnIndex) -> HashSet<TxnIndex> {
        trace!(txn_idx = txn_idx, "MVHashMap marking transaction as aborted");

        let mut dependents = HashSet::new();
        let data = self.data.read();
        
        for versioned in data.values() {
            let affected = versioned.write().mark_aborted(txn_idx);
            dependents.extend(affected);
        }

        trace!(
            txn_idx = txn_idx,
            num_dependents = dependents.len(),
            "MVHashMap found dependent transactions"
        );

        dependents
    }

    /// Clear all read tracking for a transaction (called before re-execution).
    pub fn clear_reads(&self, txn_idx: TxnIndex) {
        let data = self.data.read();
        for versioned in data.values() {
            versioned.write().clear_reader(txn_idx);
        }
    }

    /// Delete all writes from a transaction (called before re-execution with new incarnation).
    pub fn delete_writes(&self, txn_idx: TxnIndex) {
        let data = self.data.read();
        for versioned in data.values() {
            versioned.write().delete_write(txn_idx);
        }
    }

    /// Apply multiple writes from a transaction.
    pub fn apply_writes(&self, txn_idx: TxnIndex, incarnation: Incarnation, writes: Vec<(EvmStateKey, EvmStateValue)>) {
        for (key, value) in writes {
            self.write(txn_idx, incarnation, key, value);
        }
    }

    /// Get the final committed value for a key.
    /// Should only be called after all transactions are committed.
    pub fn get_committed_value(&self, key: &EvmStateKey) -> Option<EvmStateValue> {
        let data = self.data.read();
        data.get(key).and_then(|versioned| {
            let v = versioned.read();
            v.writes
                .iter()
                .next_back()
                .map(|(_, entry)| entry.value.clone())
        })
    }

    /// Get all keys that have been written to.
    pub fn get_written_keys(&self) -> Vec<EvmStateKey> {
        self.data.read().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    fn test_key(slot: u64) -> EvmStateKey {
        EvmStateKey::Storage(Address::ZERO, U256::from(slot))
    }

    fn test_value(v: u64) -> EvmStateValue {
        EvmStateValue::Storage(U256::from(v))
    }

    #[test]
    fn test_simple_write_read() {
        let mv = MVHashMap::new(10);
        let key = test_key(1);
        let value = test_value(42);

        // Transaction 0 writes
        mv.write(0, 0, key.clone(), value.clone());

        // Transaction 1 reads -> should see tx0's write
        match mv.read(1, &key) {
            ReadResult::Value { value: v, version } => {
                assert_eq!(v, value);
                assert_eq!(version.txn_idx, 0);
                assert_eq!(version.incarnation, 0);
            }
            _ => panic!("Expected Value result"),
        }

        // Transaction 0 reads -> should not see its own write
        match mv.read(0, &key) {
            ReadResult::NotFound => {}
            _ => panic!("Expected NotFound result"),
        }
    }

    #[test]
    fn test_read_latest_before() {
        let mv = MVHashMap::new(10);
        let key = test_key(1);

        // tx0 writes 100
        mv.write(0, 0, key.clone(), test_value(100));
        // tx2 writes 200
        mv.write(2, 0, key.clone(), test_value(200));
        // tx5 writes 500
        mv.write(5, 0, key.clone(), test_value(500));

        // tx1 should see tx0's write (100)
        match mv.read(1, &key) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(100));
                assert_eq!(version.txn_idx, 0);
            }
            _ => panic!("Expected Value"),
        }

        // tx3 should see tx2's write (200)
        match mv.read(3, &key) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(200));
                assert_eq!(version.txn_idx, 2);
            }
            _ => panic!("Expected Value"),
        }

        // tx6 should see tx5's write (500)
        match mv.read(6, &key) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(500));
                assert_eq!(version.txn_idx, 5);
            }
            _ => panic!("Expected Value"),
        }
    }

    #[test]
    fn test_incarnation_overwrite() {
        let mv = MVHashMap::new(10);
        let key = test_key(1);

        // tx0 incarnation 0 writes 100
        mv.write(0, 0, key.clone(), test_value(100));

        // tx1 reads, should see 100
        match mv.read(1, &key) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(100));
                assert_eq!(version.incarnation, 0);
            }
            _ => panic!("Expected Value"),
        }

        // tx0 gets re-executed (incarnation 1), writes 200
        mv.delete_writes(0);
        mv.write(0, 1, key.clone(), test_value(200));

        // tx1 reads again, should see 200 with incarnation 1
        match mv.read(1, &key) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(200));
                assert_eq!(version.incarnation, 1);
            }
            _ => panic!("Expected Value"),
        }
    }

    #[test]
    fn test_abort_tracking() {
        let mv = MVHashMap::new(10);
        let key = test_key(1);

        // tx0 writes
        mv.write(0, 0, key.clone(), test_value(100));

        // tx1, tx2, tx3 all read from tx0
        let _ = mv.read(1, &key);
        let _ = mv.read(2, &key);
        let _ = mv.read(3, &key);

        // Mark tx0 as aborted
        let dependents = mv.mark_aborted(0);

        // All readers should be in the dependent set
        assert!(dependents.contains(&1));
        assert!(dependents.contains(&2));
        assert!(dependents.contains(&3));
    }

    #[test]
    fn test_multiple_keys() {
        let mv = MVHashMap::new(10);
        let key1 = test_key(1);
        let key2 = test_key(2);

        // tx0 writes to key1
        mv.write(0, 0, key1.clone(), test_value(100));
        // tx1 writes to key2
        mv.write(1, 0, key2.clone(), test_value(200));

        // tx2 reads both
        match mv.read(2, &key1) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(100));
                assert_eq!(version.txn_idx, 0);
            }
            _ => panic!("Expected Value for key1"),
        }

        match mv.read(2, &key2) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, test_value(200));
                assert_eq!(version.txn_idx, 1);
            }
            _ => panic!("Expected Value for key2"),
        }
    }

    #[test]
    fn test_not_found() {
        let mv = MVHashMap::new(10);
        let key = test_key(1);

        // No writes yet
        match mv.read(0, &key) {
            ReadResult::NotFound => {}
            _ => panic!("Expected NotFound"),
        }

        // tx5 writes
        mv.write(5, 0, key.clone(), test_value(500));

        // tx3 still shouldn't see it (tx5 > tx3)
        match mv.read(3, &key) {
            ReadResult::NotFound => {}
            _ => panic!("Expected NotFound"),
        }
    }
}

