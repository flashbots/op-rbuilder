//! Core types for Block-STM parallel execution engine.
//!
//! This module defines the fundamental types used throughout the Block-STM implementation:
//! - Transaction indexing and versioning
//! - EVM state key abstraction
//! - Read/write tracking types

use alloy_primitives::{Address, B256, Bytes, U256};
use derive_more::Display;
use std::fmt;

/// Types of block resources tracked during parallel execution.
/// Resources are cumulative values that accumulate across transactions (e.g., gas usage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockResourceType {
    /// Cumulative gas used by transactions
    Gas,
    /// Cumulative data availability bytes used by transactions
    DABytes,
    // Future: AccountCreates, etc.
}

impl fmt::Display for BlockResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockResourceType::Gas => write!(f, "Gas"),
            BlockResourceType::DABytes => write!(f, "DABytes"),
        }
    }
}

/// Index of a transaction within a block (0-based).
pub type TxnIndex = u32;

/// Incarnation number - incremented each time a transaction is re-executed.
/// Starts at 0 for the first execution.
pub type Incarnation = u32;

/// Status of a transaction in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    Validate { version: Version },
    Execute { version: Version },
}

/// A version uniquely identifies a specific execution of a transaction.
/// Consists of (transaction index, incarnation number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version {
    pub txn_idx: TxnIndex,
    pub incarnation: Incarnation,
}

impl Version {
    pub fn new(txn_idx: TxnIndex, incarnation: Incarnation) -> Self {
        Self {
            txn_idx,
            incarnation,
        }
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
    /// Block resource usage tracking (e.g., cumulative gas)
    BlockResourceUsed(BlockResourceType),
}

impl fmt::Display for EvmStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmStateKey::Balance(addr) => write!(f, "Balance({})", addr),
            EvmStateKey::Nonce(addr) => write!(f, "Nonce({})", addr),
            EvmStateKey::CodeHash(addr) => write!(f, "CodeHash({})", addr),
            EvmStateKey::Code(addr) => write!(f, "Code({})", addr),
            EvmStateKey::Storage(addr, slot) => write!(f, "Storage({}, {})", addr, slot),
            EvmStateKey::BlockResourceUsed(resource_type) => {
                write!(f, "BlockResourceUsed({})", resource_type)
            }
        }
    }
}

/// Represents a value in the EVM state.
/// Encapsulates all possible value types that can be stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
pub enum EvmStateValue {
    /// Balance value (U256) - absolute value
    Balance(U256),
    /// Balance increment (U256) - delta to add, used for fee payments.
    /// Distinct from Balance to prevent accidentally overwriting balance with a delta.
    BalanceIncrement(U256),
    /// Nonce value (u64)
    Nonce(u64),
    /// Code hash
    CodeHash(B256),
    /// Contract bytecode
    Code(Bytes),
    /// Storage slot value
    Storage(U256),
    /// Block resource usage (u64) - cumulative counter
    BlockResourceUsed(u64),
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

/// A balance delta (fee increment) that can be accumulated without conflicts.
///
/// Balance deltas are commutative operations - they can be applied in any order
/// with the same result. This enables parallel fee accumulation to coinbase
/// without creating read-write conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceDelta {
    /// The address receiving the balance increment
    pub address: Address,
    /// The amount to add to the balance
    pub delta: U256,
}

impl BalanceDelta {
    /// Create a new balance delta.
    pub fn new(address: Address, delta: U256) -> Self {
        Self { address, delta }
    }
}

/// Entry for a balance delta with version tracking.
#[derive(Debug, Clone)]
pub struct VersionedDelta {
    /// The version (txn_idx, incarnation) that wrote this delta
    pub version: Version,
    /// The delta amount
    pub delta: U256,
}

impl VersionedDelta {
    /// Create a new versioned delta.
    pub fn new(version: Version, delta: U256) -> Self {
        Self { version, delta }
    }
}

/// Result of resolving a balance with pending deltas.
#[derive(Debug, Clone)]
pub struct ResolvedBalance {
    /// The base value (from storage or earlier write)
    pub base_value: U256,
    /// The version of the base value (None if from storage)
    pub base_version: Option<Version>,
    /// Sum of all deltas applied
    pub total_delta: U256,
    /// The final resolved value (base + total_delta)
    pub resolved_value: U256,
    /// All versions that contributed deltas (for dependency tracking)
    pub contributors: Vec<Version>,
}

/// Represents a write operation to be committed.
#[derive(Debug, Clone)]
pub struct WriteOp {
    /// The key being written
    pub key: EvmStateKey,
    /// The new value
    pub value: EvmStateValue,
}
