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
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

pub type WriteSet = HashSet<(EvmStateKey, EvmStateValue)>;

pub type ReadSet = HashSet<(EvmStateKey, Option<Version>)>;

/// Validation result with conflict details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Conflict {
        key: EvmStateKey,
        expected_version: Option<Version>,
        actual_version: Option<Version>,
    },
}

#[derive(Eq, PartialEq, Debug, Hash, Clone)]
pub enum MVHashMapValue {
    // This is a write of an executed tx that was performed.
    Write(Incarnation, EvmStateValue),

    // This is an estimate marker for an aborted tx.
    Estimate,
}

/// Multi-Version Hash Map for Block-STM parallel execution.
///
/// Stores versioned writes per key and tracks read dependencies for push-based invalidation.
/// Also stores balance deltas separately for commutative fee accumulation.
#[derive(Debug)]
pub struct MVHashMap {
    /// Map from state key to versioned values.
    data: DashMap<EvmStateKey, RwLock<HashMap<TxnIndex, MVHashMapValue>>>,
    last_written_locations: Vec<RwLock<HashSet<EvmStateKey>>>,
    last_read_set: Vec<RwLock<HashSet<(EvmStateKey, Option<Version>)>>>,
}

impl MVHashMap {
    /// Create a new MVHashMap for a block with the given number of transactions.
    pub fn new(num_txns: usize) -> Self {
        let last_written_locations = std::iter::repeat_with(|| RwLock::new(HashSet::new()))
            .take(num_txns)
            .collect();
        let last_read_set = std::iter::repeat_with(|| RwLock::new(HashSet::new()))
            .take(num_txns)
            .collect();

        Self {
            data: DashMap::new(),
            last_written_locations,
            last_read_set,
        }
    }

    /// Apply a write set to the MVHashMap.
    pub fn apply_write_set(
        &self,
        txn_idx: TxnIndex,
        incarnation_number: Incarnation,
        write_set: &WriteSet,
    ) {
        for (key, value) in write_set {
            match self.data.get_mut(key) {
                Some(version_map) => {
                    version_map.write().insert(
                        txn_idx,
                        MVHashMapValue::Write(incarnation_number, value.clone()),
                    );
                }
                None => {
                    let mut new_map = HashMap::new();
                    new_map.insert(
                        txn_idx,
                        MVHashMapValue::Write(incarnation_number, value.clone()),
                    );
                    self.data.insert(key.clone(), RwLock::new(new_map));
                }
            }
        }
    }

    /// Update last_written_locations for the given txn_idx and return if there were any changes.
    pub fn rcu_update_last_written_locations(
        &self,
        txn_idx: TxnIndex,
        new_locations: HashSet<EvmStateKey>,
    ) -> bool {
        let mut last_written_locations = self.last_written_locations[txn_idx as usize].write();
        let unwritten_locations = new_locations.difference(&last_written_locations).count();
        if unwritten_locations == 0 {
            return false;
        }
        *last_written_locations = new_locations;
        true
    }

    pub fn record(&self, version: Version, read_set: &ReadSet, write_set: &WriteSet) -> bool {
        let Version {
            txn_idx,
            incarnation,
        } = version;
        self.apply_write_set(txn_idx, incarnation, write_set);
        let new_locations = write_set.iter().map(|(key, _)| key.clone()).collect();
        let wrote_new_location = self.rcu_update_last_written_locations(txn_idx, new_locations);
        *self.last_read_set[txn_idx as usize].write() = read_set.clone();
        wrote_new_location
    }

    pub fn read(&self, location: &EvmStateKey, reader_idx: TxnIndex) -> ReadResult {
        let Some(version_map) = self.data.get(location) else {
            return ReadResult::NotFound;
        };
        let version_map = version_map.read();
        MVHashMap::read_internal(&version_map, reader_idx)
    }

    fn read_internal(
        version_map: &HashMap<TxnIndex, MVHashMapValue>,
        reader_idx: TxnIndex,
    ) -> ReadResult {
        let lower_reads = version_map
            .iter()
            .filter(|(idx, _)| **idx < reader_idx)
            .collect::<HashSet<(&u32, &MVHashMapValue)>>();
        if lower_reads.is_empty() {
            return ReadResult::NotFound;
        }
        let highest_read = lower_reads.iter().max_by_key(|(idx, _)| *idx).unwrap();
        match *highest_read {
            (txn_idx, MVHashMapValue::Estimate) => ReadResult::Aborted { txn_idx: *txn_idx },
            (txn_idx, MVHashMapValue::Write(incarnation, value)) => ReadResult::Value {
                value: value.clone(),
                version: Version {
                    txn_idx: *txn_idx,
                    incarnation: *incarnation,
                },
            },
        }
    }

    pub fn validate_read_set(&self, txn_idx: TxnIndex) -> bool {
        let prior_reads = self.last_read_set[txn_idx as usize].read();
        for (location, version) in prior_reads.iter() {
            let cur_read = self.read(location, txn_idx);
            match cur_read {
                ReadResult::Aborted { .. } => return false,
                ReadResult::NotFound if version.is_some() => return false,
                ReadResult::Value {
                    version: read_version,
                    ..
                } if Some(read_version) != *version => return false,
                _ => continue,
            }
        }
        true
    }

    /// Validate read set and return detailed conflict information if validation fails.
    pub fn validate_read_set_detailed(&self, txn_idx: TxnIndex) -> ValidationResult {
        let prior_reads = self.last_read_set[txn_idx as usize].read();
        for (location, version) in prior_reads.iter() {
            let cur_read = self.read(location, txn_idx);
            match cur_read {
                ReadResult::Aborted {
                    txn_idx: aborted_txn,
                } => {
                    return ValidationResult::Conflict {
                        key: location.clone(),
                        expected_version: *version,
                        actual_version: Some(Version::new(aborted_txn, 0)),
                    };
                }
                ReadResult::NotFound if version.is_some() => {
                    return ValidationResult::Conflict {
                        key: location.clone(),
                        expected_version: *version,
                        actual_version: None,
                    };
                }
                ReadResult::Value {
                    version: read_version,
                    ..
                } if Some(read_version) != *version => {
                    return ValidationResult::Conflict {
                        key: location.clone(),
                        expected_version: *version,
                        actual_version: Some(read_version),
                    };
                }
                _ => continue,
            }
        }
        ValidationResult::Valid
    }

    pub fn convert_writes_to_estimates(&self, txn_idx: TxnIndex) {
        let prev_locations = self.last_written_locations[txn_idx as usize].read();
        for location in prev_locations.iter() {
            let version_map = self.data.get_mut(location);
            debug_assert!(
                version_map.is_some(),
                "last_written_locations should only contain locations that have been written to"
            );
            if let Some(version_map) = version_map {
                version_map
                    .write()
                    .insert(txn_idx, MVHashMapValue::Estimate);
            }
        }
    }

    pub fn into_snapshot(self) -> HashMap<EvmStateKey, EvmStateValue> {
        let data = self.data.into_iter();
        let mut snapshot = HashMap::new();
        for (key, version_map) in data {
            if let ReadResult::Value { value, .. } =
                MVHashMap::read_internal(&version_map.read(), self.last_read_set.len() as u32)
            {
                snapshot.insert(key.clone(), value);
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use std::{sync::Arc, thread};

    fn make_storage_key(slot: u64) -> EvmStateKey {
        EvmStateKey::Storage(Address::ZERO, U256::from(slot))
    }

    fn make_storage_value(val: u64) -> EvmStateValue {
        EvmStateValue::Storage(U256::from(val))
    }

    #[test]
    fn test_basic_write_and_read() {
        let mv = MVHashMap::new(3);
        let key = make_storage_key(0);
        let value = make_storage_value(100);

        let mut write_set = WriteSet::new();
        write_set.insert((key.clone(), value.clone()));

        mv.apply_write_set(0, 0, &write_set);

        // Transaction 1 should see tx 0's write
        match mv.read(&key, 1) {
            ReadResult::Value {
                value: v,
                version: ver,
            } => {
                assert_eq!(v, value);
                assert_eq!(ver.txn_idx, 0);
            }
            _ => panic!("Expected Value result"),
        }

        // Transaction 0 should not see its own write
        assert!(matches!(mv.read(&key, 0), ReadResult::NotFound));
    }

    #[test]
    fn test_read_highest_lower_version() {
        let mv = MVHashMap::new(5);
        let key = make_storage_key(0);

        // Tx 0 writes value 100
        let mut ws0 = WriteSet::new();
        ws0.insert((key.clone(), make_storage_value(100)));
        mv.apply_write_set(0, 0, &ws0);

        // Tx 2 writes value 200
        let mut ws2 = WriteSet::new();
        ws2.insert((key.clone(), make_storage_value(200)));
        mv.apply_write_set(2, 0, &ws2);

        // Tx 4 should see tx 2's write (highest < 4)
        match mv.read(&key, 4) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, make_storage_value(200));
                assert_eq!(version.txn_idx, 2);
            }
            _ => panic!("Expected Value result"),
        }

        // Tx 1 should see tx 0's write
        match mv.read(&key, 1) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, make_storage_value(100));
                assert_eq!(version.txn_idx, 0);
            }
            _ => panic!("Expected Value result"),
        }
    }

    #[test]
    fn test_convert_to_estimate() {
        let mv = MVHashMap::new(3);
        let key = make_storage_key(0);

        let mut write_set = WriteSet::new();
        write_set.insert((key.clone(), make_storage_value(100)));

        let read_set = ReadSet::new();
        mv.record(Version::new(0, 0), &read_set, &write_set);

        // Convert tx 0's writes to estimates (simulating abort)
        mv.convert_writes_to_estimates(0);

        // Tx 1 should now see Aborted
        match mv.read(&key, 1) {
            ReadResult::Aborted { txn_idx } => assert_eq!(txn_idx, 0),
            _ => panic!("Expected Aborted result"),
        }
    }

    #[test]
    fn test_validation_detects_changed_version() {
        let mv = MVHashMap::new(3);
        let key = make_storage_key(0);

        // Tx 0 writes
        let mut ws0 = WriteSet::new();
        ws0.insert((key.clone(), make_storage_value(100)));
        mv.record(Version::new(0, 0), &ReadSet::new(), &ws0);

        // Tx 1 reads from tx 0's write
        let mut rs1 = ReadSet::new();
        rs1.insert((key.clone(), Some(Version::new(0, 0))));
        mv.record(Version::new(1, 0), &rs1, &WriteSet::new());

        // Validation should pass
        assert!(mv.validate_read_set(1));

        // Now tx 0 re-executes with incarnation 1 and writes different value
        let mut ws0_new = WriteSet::new();
        ws0_new.insert((key.clone(), make_storage_value(200)));
        mv.record(Version::new(0, 1), &ReadSet::new(), &ws0_new);

        // Tx 1's validation should fail (version changed from (0,0) to (0,1))
        assert!(!mv.validate_read_set(1));
    }

    #[test]
    fn test_validation_detects_aborted_dependency() {
        let mv = MVHashMap::new(3);
        let key = make_storage_key(0);

        // Tx 0 writes
        let mut ws0 = WriteSet::new();
        ws0.insert((key.clone(), make_storage_value(100)));
        mv.record(Version::new(0, 0), &ReadSet::new(), &ws0);

        // Tx 1 reads from tx 0
        let mut rs1 = ReadSet::new();
        rs1.insert((key.clone(), Some(Version::new(0, 0))));
        mv.record(Version::new(1, 0), &rs1, &WriteSet::new());

        // Convert tx 0 to estimate (abort)
        mv.convert_writes_to_estimates(0);

        // Tx 1's validation should fail
        assert!(!mv.validate_read_set(1));
    }

    #[test]
    fn test_into_snapshot() {
        let mv = MVHashMap::new(3);

        // Each tx writes to a different slot
        for i in 0..3 {
            let mut ws = WriteSet::new();
            ws.insert((make_storage_key(i), make_storage_value(i * 100)));
            mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
        }

        let snapshot = mv.into_snapshot();
        assert_eq!(snapshot.len(), 3);
        assert_eq!(
            snapshot.get(&make_storage_key(0)),
            Some(&make_storage_value(0))
        );
        assert_eq!(
            snapshot.get(&make_storage_key(1)),
            Some(&make_storage_value(100))
        );
        assert_eq!(
            snapshot.get(&make_storage_key(2)),
            Some(&make_storage_value(200))
        );
    }

    // ==================== STRESS TESTS ====================

    #[test]
    fn stress_test_non_conflicting_writes() {
        // Many transactions each writing to disjoint keys
        let num_txns = 100;
        let mv = Arc::new(MVHashMap::new(num_txns));

        // Each transaction writes to its own unique slot
        let handles: Vec<_> = (0..num_txns)
            .map(|i| {
                let mv = Arc::clone(&mv);
                thread::spawn(move || {
                    let mut ws = WriteSet::new();
                    ws.insert((make_storage_key(i as u64), make_storage_value(i as u64)));
                    mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All validations should pass (no conflicts)
        for i in 0..num_txns {
            assert!(
                mv.validate_read_set(i as u32),
                "Validation failed for tx {}",
                i
            );
        }
    }

    #[test]
    fn stress_test_all_conflicting_writes() {
        // Many transactions all writing to the SAME key
        let num_txns = 50;
        let mv = Arc::new(MVHashMap::new(num_txns));
        let shared_key = make_storage_key(0);

        // All transactions write to the same slot
        let handles: Vec<_> = (0..num_txns)
            .map(|i| {
                let mv = Arc::clone(&mv);
                let key = shared_key.clone();
                thread::spawn(move || {
                    let mut ws = WriteSet::new();
                    ws.insert((key, make_storage_value(i as u64)));
                    mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Higher transactions should see lower transactions' writes
        for i in 1..num_txns {
            match mv.read(&shared_key, i as u32) {
                ReadResult::Value { version, .. } => {
                    assert!(
                        version.txn_idx < i as u32,
                        "Tx {} should read from lower tx, got {}",
                        i,
                        version.txn_idx
                    );
                }
                _ => panic!("Expected Value for tx {}", i),
            }
        }
    }

    #[test]
    fn stress_test_concurrent_reads_and_writes() {
        let num_txns = 100;
        let mv = Arc::new(MVHashMap::new(num_txns));

        // First, write all values
        for i in 0..num_txns {
            let mut ws = WriteSet::new();
            ws.insert((make_storage_key(i as u64), make_storage_value(i as u64)));
            mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
        }

        // Concurrent reads from multiple threads
        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let mv = Arc::clone(&mv);
                thread::spawn(move || {
                    for i in 0..num_txns {
                        let key = make_storage_key(i as u64);
                        // Read from a higher tx index to see the write
                        let result = mv.read(&key, (i + 1) as u32);
                        assert!(
                            matches!(result, ReadResult::Value { .. }),
                            "Thread {} failed to read key {} from tx {}",
                            thread_id,
                            i,
                            i + 1
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn stress_test_mixed_read_write_patterns() {
        use rand::prelude::*;

        let num_txns = 50;
        let num_keys = 10;
        let mv = Arc::new(MVHashMap::new(num_txns));

        // Each transaction writes to a random subset of keys
        let handles: Vec<_> = (0..num_txns)
            .map(|i| {
                let mv = Arc::clone(&mv);
                thread::spawn(move || {
                    let mut rng = rand::rng();
                    let mut ws = WriteSet::new();

                    // Write to 1-3 random keys
                    let num_writes = rng.random_range(1..=3);
                    for _ in 0..num_writes {
                        let key_idx = rng.random_range(0..num_keys);
                        ws.insert((make_storage_key(key_idx), make_storage_value(i as u64)));
                    }

                    mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Verify the map is in consistent state
        for key_idx in 0..num_keys {
            let key = make_storage_key(key_idx);
            let result = mv.read(&key, num_txns as u32);
            // Either found or not found is valid
            assert!(matches!(
                result,
                ReadResult::Value { .. } | ReadResult::NotFound
            ));
        }
    }

    #[test]
    fn stress_test_validation_after_reexecution() {
        // Simulate re-execution scenario with increasing incarnations
        let num_txns = 20;
        let mv = MVHashMap::new(num_txns);
        let shared_key = make_storage_key(0);

        // All txs write to same key initially
        for i in 0..num_txns {
            let mut ws = WriteSet::new();
            ws.insert((shared_key.clone(), make_storage_value(i as u64)));
            mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
        }

        // Tx 5 reads from tx 4
        let mut rs5 = ReadSet::new();
        rs5.insert((shared_key.clone(), Some(Version::new(4, 0))));
        *mv.last_read_set[5].write() = rs5;

        // Validation should pass
        assert!(mv.validate_read_set(5));

        // Now tx 4 re-executes with incarnation 1
        let mut ws4 = WriteSet::new();
        ws4.insert((shared_key.clone(), make_storage_value(400)));
        mv.record(Version::new(4, 1), &ReadSet::new(), &ws4);

        // Tx 5's validation should fail (dependency changed)
        assert!(!mv.validate_read_set(5));

        // Update tx 5's read set to reflect new version
        let mut rs5_updated = ReadSet::new();
        rs5_updated.insert((shared_key.clone(), Some(Version::new(4, 1))));
        *mv.last_read_set[5].write() = rs5_updated;

        // Now validation should pass
        assert!(mv.validate_read_set(5));
    }

    // ==================== BALANCE INCREMENT TESTS ====================

    fn make_balance_key(addr_byte: u8) -> EvmStateKey {
        EvmStateKey::Balance(Address::repeat_byte(addr_byte))
    }

    fn make_balance_value(val: u64) -> EvmStateValue {
        EvmStateValue::Balance(U256::from(val))
    }

    fn make_balance_increment(val: u64) -> EvmStateValue {
        EvmStateValue::BalanceIncrement(U256::from(val))
    }

    #[test]
    fn test_balance_increment_recorded_as_write() {
        let mv = MVHashMap::new(3);
        let key = make_balance_key(1);

        // Tx 0 writes a balance increment (fee payment)
        let mut write_set = WriteSet::new();
        write_set.insert((key.clone(), make_balance_increment(100)));

        mv.apply_write_set(0, 0, &write_set);

        // Tx 1 should see the balance increment write
        match mv.read(&key, 1) {
            ReadResult::Value { value, version } => {
                assert_eq!(value, make_balance_increment(100));
                assert_eq!(version.txn_idx, 0);
            }
            _ => panic!("Expected Value result with BalanceIncrement"),
        }
    }

    #[test]
    fn test_balance_read_conflicts_with_increment_write() {
        let mv = MVHashMap::new(3);
        let key = make_balance_key(1);

        // Tx 0 writes an absolute balance value
        let mut ws0 = WriteSet::new();
        ws0.insert((key.clone(), make_balance_value(1000)));
        mv.record(Version::new(0, 0), &ReadSet::new(), &ws0);

        // Tx 1 reads the balance (sees tx 0's write)
        let mut rs1 = ReadSet::new();
        rs1.insert((key.clone(), Some(Version::new(0, 0))));
        mv.record(Version::new(1, 0), &rs1, &WriteSet::new());

        // Validation should pass initially
        assert!(mv.validate_read_set(1));

        // Now tx 0 re-executes and writes a balance increment instead
        let mut ws0_new = WriteSet::new();
        ws0_new.insert((key.clone(), make_balance_increment(50)));
        mv.record(Version::new(0, 1), &ReadSet::new(), &ws0_new);

        // Tx 1's validation should fail (version changed from (0,0) to (0,1))
        assert!(!mv.validate_read_set(1));
    }

    #[test]
    fn test_parallel_balance_increments_no_read_conflict() {
        // Multiple transactions writing balance increments to the same address
        // without reading. Since Block-STM doesn't validate writes against writes,
        // these should all be valid as long as no transaction reads the balance.
        let mv = MVHashMap::new(4);
        let key = make_balance_key(1);

        // All transactions write balance increments (blind writes)
        for i in 0..4 {
            let mut ws = WriteSet::new();
            ws.insert((key.clone(), make_balance_increment((i + 1) * 100)));
            // Empty read set - no reads of this balance
            mv.record(Version::new(i as u32, 0), &ReadSet::new(), &ws);
        }

        // All validations should pass (no reads to conflict with)
        for i in 0..4 {
            assert!(
                mv.validate_read_set(i as u32),
                "Tx {} should validate (blind write)",
                i
            );
        }
    }

    #[test]
    fn test_balance_increment_after_balance_read_causes_conflict() {
        let mv = MVHashMap::new(3);
        let key = make_balance_key(1);

        // Tx 0 writes a balance value
        let mut ws0 = WriteSet::new();
        ws0.insert((key.clone(), make_balance_value(1000)));
        mv.record(Version::new(0, 0), &ReadSet::new(), &ws0);

        // Tx 2 reads the balance from base state (NotFound, since tx 0 hasn't been seen yet)
        // Then tx 1 writes a balance increment
        let mut rs2 = ReadSet::new();
        rs2.insert((key.clone(), Some(Version::new(0, 0))));
        mv.record(Version::new(2, 0), &rs2, &WriteSet::new());

        // Initially tx 2 validation passes
        assert!(mv.validate_read_set(2));

        // Tx 1 writes a balance increment
        let mut ws1 = WriteSet::new();
        ws1.insert((key.clone(), make_balance_increment(50)));
        mv.record(Version::new(1, 0), &ReadSet::new(), &ws1);

        // Tx 2's validation should now fail because tx 1's write changed the value
        assert!(!mv.validate_read_set(2));
    }
}
