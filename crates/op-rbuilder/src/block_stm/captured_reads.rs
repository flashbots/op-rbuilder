//! Captured Reads - Read Set Tracking for Block-STM
//!
//! During transaction execution, we need to track all state reads to:
//! 1. Detect conflicts when validating
//! 2. Enable push-based invalidation when a dependency is aborted
//!
//! The `CapturedReads` struct records all reads performed during execution,
//! including the version (which transaction wrote the value) for validation.

use crate::block_stm::types::{EvmStateKey, EvmStateValue, Version};
use std::collections::HashMap;

/// A single captured read operation.
#[derive(Debug, Clone)]
pub struct CapturedRead {
    /// The version from which the value was read.
    /// None means the value was read from base state (not from any transaction).
    pub version: Option<Version>,
    /// The value that was observed.
    pub value: EvmStateValue,
}

impl CapturedRead {
    /// Create a new captured read from a transaction's write.
    pub fn from_version(version: Version, value: EvmStateValue) -> Self {
        Self {
            version: Some(version),
            value,
        }
    }

    /// Create a new captured read from base state.
    pub fn from_base_state(value: EvmStateValue) -> Self {
        Self {
            version: None,
            value,
        }
    }
}

/// Tracks all reads performed during a transaction's execution.
///
/// Used for:
/// - Validation: checking if any reads have become stale
/// - Dependency tracking: knowing which transactions this one depends on
#[derive(Debug, Default)]
pub struct CapturedReads {
    /// Map from state key to the read that was performed.
    reads: HashMap<EvmStateKey, CapturedRead>,
}

impl CapturedReads {
    /// Create a new empty CapturedReads.
    pub fn new() -> Self {
        Self {
            reads: HashMap::new(),
        }
    }

    /// Record a read from a transaction's write.
    pub fn capture_read(&mut self, key: EvmStateKey, version: Version, value: EvmStateValue) {
        self.reads
            .insert(key, CapturedRead::from_version(version, value));
    }

    /// Record a read from base state.
    pub fn capture_base_read(&mut self, key: EvmStateKey, value: EvmStateValue) {
        self.reads.insert(key, CapturedRead::from_base_state(value));
    }

    /// Get all captured reads.
    pub fn reads(&self) -> &HashMap<EvmStateKey, CapturedRead> {
        &self.reads
    }

    /// Get the set of transaction indices that this transaction depends on.
    pub fn dependencies(&self) -> impl Iterator<Item = u32> + '_ {
        self.reads
            .values()
            .filter_map(|read| read.version.map(|v| v.txn_idx))
    }

    /// Check if any read depends on the given transaction index.
    pub fn depends_on(&self, txn_idx: u32) -> bool {
        self.reads
            .values()
            .any(|read| read.version.map(|v| v.txn_idx) == Some(txn_idx))
    }

    /// Clear all captured reads (for re-execution).
    pub fn clear(&mut self) {
        self.reads.clear();
    }

    /// Get the number of reads captured.
    pub fn len(&self) -> usize {
        self.reads.len()
    }

    /// Check if no reads have been captured.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
    }
}

/// Result of validating a transaction's read set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// All reads are still valid.
    Valid,
    /// A read has become invalid due to a conflicting write.
    Invalid {
        /// The key that has a conflict.
        key: EvmStateKey,
        /// The version we originally read from.
        original_version: Option<Version>,
        /// The new version that invalidates our read.
        new_version: Option<Version>,
    },
    /// A read from an aborted transaction was detected.
    ReadFromAborted {
        /// The key that was read from an aborted transaction.
        key: EvmStateKey,
        /// The aborted transaction index.
        aborted_txn_idx: u32,
    },
}

impl ValidationResult {
    /// Returns true if the validation passed.
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
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
    fn test_capture_read() {
        let mut reads = CapturedReads::new();
        let key = test_key(1);
        let version = Version::new(0, 0);
        let value = test_value(42);

        reads.capture_read(key.clone(), version, value.clone());

        assert_eq!(reads.len(), 1);
        let captured = reads.reads().get(&key).unwrap();
        assert_eq!(captured.version, Some(version));
        assert_eq!(captured.value, value);
    }

    #[test]
    fn test_capture_base_read() {
        let mut reads = CapturedReads::new();
        let key = test_key(1);
        let value = test_value(42);

        reads.capture_base_read(key.clone(), value.clone());

        let captured = reads.reads().get(&key).unwrap();
        assert_eq!(captured.version, None);
        assert_eq!(captured.value, value);
    }

    #[test]
    fn test_dependencies() {
        let mut reads = CapturedReads::new();

        // Read from tx0
        reads.capture_read(test_key(1), Version::new(0, 0), test_value(100));
        // Read from tx2
        reads.capture_read(test_key(2), Version::new(2, 0), test_value(200));
        // Read from base state
        reads.capture_base_read(test_key(3), test_value(300));

        let deps: Vec<_> = reads.dependencies().collect();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&0));
        assert!(deps.contains(&2));
    }

    #[test]
    fn test_depends_on() {
        let mut reads = CapturedReads::new();
        reads.capture_read(test_key(1), Version::new(0, 0), test_value(100));

        assert!(reads.depends_on(0));
        assert!(!reads.depends_on(1));
        assert!(!reads.depends_on(2));
    }

    #[test]
    fn test_clear() {
        let mut reads = CapturedReads::new();
        reads.capture_read(test_key(1), Version::new(0, 0), test_value(100));
        reads.capture_base_read(test_key(2), test_value(200));

        assert_eq!(reads.len(), 2);

        reads.clear();

        assert!(reads.is_empty());
    }
}

