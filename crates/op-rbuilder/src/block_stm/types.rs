//! Core types for Block-STM parallel execution engine.
//!
//! This module defines the fundamental types used throughout the Block-STM implementation:
//! - Transaction indexing and versioning
//! - EVM state key abstraction
//! - Read/write tracking types

use alloy_primitives::{Address, Bytes, B256, U256};
use std::fmt;

/// Index of a transaction within a block (0-based).
pub type TxnIndex = u32;

/// Incarnation number - incremented each time a transaction is re-executed.
/// Starts at 0 for the first execution.
pub type Incarnation = u32;

/// A version uniquely identifies a specific execution of a transaction.
/// Consists of (transaction index, incarnation number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    pub txn_idx: TxnIndex,
    pub incarnation: Incarnation,
}

impl Version {
    pub fn new(txn_idx: TxnIndex, incarnation: Incarnation) -> Self {
        Self { txn_idx, incarnation }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(txn={}, inc={})", self.txn_idx, self.incarnation)
    }
}

/// Represents a key in the EVM state that can be read or written.
/// This abstracts over the different types of state in the EVM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvmStateKey {
    /// Account balance: key is the address
    Balance(Address),
    /// Account nonce: key is the address
    Nonce(Address),
    /// Account code hash: key is the address
    CodeHash(Address),
    /// Account code: key is the address
    Code(Address),
    /// Storage slot: key is (address, slot)
    Storage(Address, U256),
}

impl fmt::Display for EvmStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmStateKey::Balance(addr) => write!(f, "Balance({})", addr),
            EvmStateKey::Nonce(addr) => write!(f, "Nonce({})", addr),
            EvmStateKey::CodeHash(addr) => write!(f, "CodeHash({})", addr),
            EvmStateKey::Code(addr) => write!(f, "Code({})", addr),
            EvmStateKey::Storage(addr, slot) => write!(f, "Storage({}, {})", addr, slot),
        }
    }
}

/// Represents a value in the EVM state.
/// Encapsulates all possible value types that can be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmStateValue {
    /// Balance value (U256)
    Balance(U256),
    /// Nonce value (u64)
    Nonce(u64),
    /// Code hash
    CodeHash(B256),
    /// Contract bytecode
    Code(Bytes),
    /// Storage slot value
    Storage(U256),
    /// Account does not exist (for distinguishing "not found" from "zero")
    NotFound,
}

impl EvmStateValue {
    /// Returns true if this represents a non-existent account/value
    pub fn is_not_found(&self) -> bool {
        matches!(self, EvmStateValue::NotFound)
    }
}

/// Result of reading from the MVHashMap.
#[derive(Debug, Clone)]
pub enum ReadResult {
    /// Value was written by a previous transaction at this version
    Value {
        value: EvmStateValue,
        version: Version,
    },
    /// Value is not in MVHashMap, should read from base state.
    /// The reader should register itself as dependent on this key.
    NotFound,
    /// A previous transaction wrote to this key but was aborted.
    /// Reader should wait or abort.
    Aborted {
        /// The transaction that aborted
        txn_idx: TxnIndex,
    },
}

/// Represents a read operation recorded during transaction execution.
#[derive(Debug, Clone)]
pub struct RecordedRead {
    /// The key that was read
    pub key: EvmStateKey,
    /// The version from which the value was read (None if from base state)
    pub version: Option<Version>,
    /// The value that was observed
    pub value: EvmStateValue,
}

/// Represents a write operation to be committed.
#[derive(Debug, Clone)]
pub struct WriteOp {
    /// The key being written
    pub key: EvmStateKey,
    /// The new value
    pub value: EvmStateValue,
}

/// Status of a transaction in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Transaction is waiting to be scheduled for execution
    PendingScheduling,
    /// Transaction is currently being executed
    Executing(Incarnation),
    /// Transaction finished execution successfully
    Executed(Incarnation),
    /// Transaction was aborted and needs re-execution
    Aborted(Incarnation),
    /// Transaction has been committed (finalized)
    Committed,
}

impl ExecutionStatus {
    /// Returns the incarnation if the status has one
    pub fn incarnation(&self) -> Option<Incarnation> {
        match self {
            ExecutionStatus::Executing(inc)
            | ExecutionStatus::Executed(inc)
            | ExecutionStatus::Aborted(inc) => Some(*inc),
            ExecutionStatus::PendingScheduling | ExecutionStatus::Committed => None,
        }
    }
}

/// Task type for worker threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// Execute transaction at given index with given incarnation
    Execute { txn_idx: TxnIndex, incarnation: Incarnation },
    /// Validate transaction at given index
    Validate { txn_idx: TxnIndex },
    /// No more tasks available (workers should check for completion)
    NoTask,
    /// All work is done
    Done,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(0, 0);
        let v2 = Version::new(0, 1);
        let v3 = Version::new(1, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_evm_state_key_display() {
        let addr = Address::ZERO;
        let key = EvmStateKey::Balance(addr);
        assert!(key.to_string().contains("Balance"));

        let storage_key = EvmStateKey::Storage(addr, U256::from(42));
        assert!(storage_key.to_string().contains("Storage"));
    }

    #[test]
    fn test_execution_status_incarnation() {
        assert_eq!(ExecutionStatus::PendingScheduling.incarnation(), None);
        assert_eq!(ExecutionStatus::Executing(5).incarnation(), Some(5));
        assert_eq!(ExecutionStatus::Executed(3).incarnation(), Some(3));
        assert_eq!(ExecutionStatus::Aborted(2).incarnation(), Some(2));
        assert_eq!(ExecutionStatus::Committed.incarnation(), None);
    }
}

