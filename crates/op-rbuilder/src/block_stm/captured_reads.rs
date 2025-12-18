//! Captured Reads - Read Set Tracking for Block-STM
//!
//! During transaction execution, we need to track all state reads to:
//! 1. Detect conflicts when validating
//! 2. Enable push-based invalidation when a dependency is aborted
//!
//! The `CapturedReads` struct records all reads performed during execution,
//! including the version (which transaction wrote the value) for validation.

use crate::block_stm::types::{EvmStateKey, EvmStateValue, ResolvedBalance, Version};
use alloy_primitives::{Address, U256};
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

/// A captured resolved balance read (with deltas applied).
#[derive(Debug, Clone)]
pub struct CapturedResolvedBalance {
    /// The address whose balance was resolved
    pub address: Address,
    /// The base value before deltas
    pub base_value: U256,
    /// The version of the base value (None if from storage)
    pub base_version: Option<Version>,
    /// The total delta that was applied
    pub total_delta: U256,
    /// The final resolved value
    pub resolved_value: U256,
    /// All versions that contributed deltas
    pub contributors: Vec<Version>,
}

impl CapturedResolvedBalance {
    /// Create from a ResolvedBalance.
    pub fn from_resolved(address: Address, resolved: ResolvedBalance) -> Self {
        Self {
            address,
            base_value: resolved.base_value,
            base_version: resolved.base_version,
            total_delta: resolved.total_delta,
            resolved_value: resolved.resolved_value,
            contributors: resolved.contributors,
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
    /// Resolved balance reads (balance reads that included deltas).
    /// These are tracked separately because they depend on multiple transactions.
    resolved_balances: HashMap<Address, CapturedResolvedBalance>,
}

impl CapturedReads {
    /// Create a new empty CapturedReads.
    pub fn new() -> Self {
        Self {
            reads: HashMap::new(),
            resolved_balances: HashMap::new(),
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

    /// Record a resolved balance read (balance with deltas applied).
    pub fn capture_resolved_balance(&mut self, address: Address, resolved: ResolvedBalance) {
        self.resolved_balances
            .insert(address, CapturedResolvedBalance::from_resolved(address, resolved));
    }

    /// Get all captured reads.
    pub fn reads(&self) -> &HashMap<EvmStateKey, CapturedRead> {
        &self.reads
    }

    /// Get all captured resolved balances.
    pub fn resolved_balances(&self) -> &HashMap<Address, CapturedResolvedBalance> {
        &self.resolved_balances
    }

    /// Get the set of transaction indices that this transaction depends on.
    /// Includes dependencies from both regular reads and resolved balance reads.
    pub fn dependencies(&self) -> impl Iterator<Item = u32> + '_ {
        // Dependencies from regular reads
        let read_deps = self
            .reads
            .values()
            .filter_map(|read| read.version.map(|v| v.txn_idx));

        // Dependencies from resolved balances (all contributors)
        let balance_deps = self
            .resolved_balances
            .values()
            .flat_map(|rb| {
                rb.base_version
                    .iter()
                    .map(|v| v.txn_idx)
                    .chain(rb.contributors.iter().map(|v| v.txn_idx))
            });

        read_deps.chain(balance_deps)
    }

    /// Check if any read depends on the given transaction index.
    pub fn depends_on(&self, txn_idx: u32) -> bool {
        // Check regular reads
        let has_read_dep = self
            .reads
            .values()
            .any(|read| read.version.map(|v| v.txn_idx) == Some(txn_idx));

        if has_read_dep {
            return true;
        }

        // Check resolved balances (base version + contributors)
        self.resolved_balances.values().any(|rb| {
            rb.base_version.map(|v| v.txn_idx) == Some(txn_idx)
                || rb.contributors.iter().any(|v| v.txn_idx == txn_idx)
        })
    }

    /// Clear all captured reads (for re-execution).
    pub fn clear(&mut self) {
        self.reads.clear();
        self.resolved_balances.clear();
    }

    /// Get the number of reads captured (regular reads + resolved balances).
    pub fn len(&self) -> usize {
        self.reads.len() + self.resolved_balances.len()
    }

    /// Check if no reads have been captured.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty() && self.resolved_balances.is_empty()
    }

    /// Get the original balance for an address (if it was read).
    /// Returns None if the balance was never read.
    pub fn get_balance(&self, address: Address) -> Option<U256> {
        let key = EvmStateKey::Balance(address);
        self.reads.get(&key).and_then(|read| {
            if let EvmStateValue::Balance(balance) = read.value {
                Some(balance)
            } else {
                None
            }
        })
    }

    /// Get the original nonce for an address (if it was read).
    /// Returns None if the nonce was never read.
    pub fn get_nonce(&self, address: Address) -> Option<u64> {
        let key = EvmStateKey::Nonce(address);
        self.reads.get(&key).and_then(|read| {
            if let EvmStateValue::Nonce(nonce) = read.value {
                Some(nonce)
            } else {
                None
            }
        })
    }

    /// Get the original code hash for an address (if it was read).
    /// Returns None if the code hash was never read.
    pub fn get_code_hash(&self, address: Address) -> Option<alloy_primitives::B256> {
        let key = EvmStateKey::CodeHash(address);
        self.reads.get(&key).and_then(|read| {
            if let EvmStateValue::CodeHash(hash) = read.value {
                Some(hash)
            } else {
                None
            }
        })
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

