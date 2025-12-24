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
