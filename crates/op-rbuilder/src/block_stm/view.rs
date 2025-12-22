//! Versioned State View for Block-STM
//!
//! The `LatestView` provides a versioned view of state for a specific transaction.
//! It wraps the MVHashMap and base database, routing reads through the multi-version
//! data structure while tracking dependencies.
//!
//! # Read Resolution
//!
//! When reading state:
//! 1. Check MVHashMap for writes from earlier transactions
//! 2. If found, record the dependency and return the value
//! 3. If not found, read from base state and record as base dependency

use crate::block_stm::{
    captured_reads::CapturedReads,
    mv_hashmap::MVHashMap,
    types::{EvmStateKey, EvmStateValue, Incarnation, ReadResult, TxnIndex, Version},
};
use alloy_primitives::{Address, B256, Bytes, U256};
use parking_lot::Mutex;
use tracing::instrument;

/// Error returned when a read encounters an aborted transaction.
#[derive(Debug, Clone)]
pub struct ReadAbortedError {
    /// The transaction that was aborted
    pub aborted_txn_idx: TxnIndex,
}

/// Result type for view operations.
pub type ViewResult<T> = Result<T, ReadAbortedError>;

/// A versioned view of state for a specific transaction.
///
/// Provides read access to state, checking the MVHashMap first for writes
/// from earlier transactions, then falling back to base state.
pub struct LatestView<'a, BaseDB> {
    /// The transaction index this view is for
    txn_idx: TxnIndex,
    /// The incarnation of this execution
    incarnation: Incarnation,
    /// The multi-version hash map with concurrent writes
    mv_hashmap: &'a MVHashMap,
    /// The base database for reads not in MVHashMap
    base_db: &'a BaseDB,
    /// Captured reads for this transaction (interior mutability for tracking)
    captured_reads: Mutex<CapturedReads>,
}

impl<'a, BaseDB> LatestView<'a, BaseDB> {
    /// Create a new view for a transaction.
    pub fn new(
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        mv_hashmap: &'a MVHashMap,
        base_db: &'a BaseDB,
    ) -> Self {
        Self {
            txn_idx,
            incarnation,
            mv_hashmap,
            base_db,
            captured_reads: Mutex::new(CapturedReads::new()),
        }
    }

    /// Get the transaction index.
    pub fn txn_idx(&self) -> TxnIndex {
        self.txn_idx
    }

    /// Get the incarnation.
    pub fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// Take the captured reads (consumes the internal state).
    pub fn take_captured_reads(&self) -> CapturedReads {
        std::mem::take(&mut *self.captured_reads.lock())
    }

    /// Get a reference to the base database.
    pub fn base_db(&self) -> &'a BaseDB {
        self.base_db
    }

    /// Read a value from the versioned state.
    ///
    /// Returns the value if found, or an error if an aborted transaction was encountered.
    /// If the key is not in MVHashMap, the caller should read from base state
    /// and call `record_base_read` with the result.
    #[instrument(level = "trace", skip(self), fields(txn_idx = self.txn_idx, key = %key))]
    pub fn read_from_mvhashmap(
        &self,
        key: &EvmStateKey,
    ) -> ViewResult<Option<(EvmStateValue, Version)>> {
        match self.mv_hashmap.read(self.txn_idx, key) {
            ReadResult::Value { value, version } => {
                // Record the read
                self.captured_reads
                    .lock()
                    .capture_read(key.clone(), version, value.clone());

                Ok(Some((value, version)))
            }
            ReadResult::NotFound => Ok(None),
            ReadResult::Aborted {
                txn_idx: aborted_txn_idx,
            } => Err(ReadAbortedError { aborted_txn_idx }),
        }
    }

    /// Record a read from base state (when MVHashMap doesn't have the value).
    pub fn record_base_read(&self, key: EvmStateKey, value: EvmStateValue) {
        self.captured_reads.lock().capture_base_read(key, value);
    }
}

/// Write set collected during transaction execution.
#[derive(Debug, Default)]
pub struct WriteSet {
    /// The writes to be applied (regular state changes)
    writes: Vec<(EvmStateKey, EvmStateValue)>,
    /// Balance deltas (commutative fee increments)
    /// These are handled separately to allow parallel accumulation
    balance_deltas: Vec<(Address, U256)>,
}

impl WriteSet {
    /// Create a new empty write set.
    pub fn new() -> Self {
        Self {
            writes: Vec::new(),
            balance_deltas: Vec::new(),
        }
    }

    /// Add a write to the set.
    pub fn write(&mut self, key: EvmStateKey, value: EvmStateValue) {
        self.writes.push((key, value));
    }

    /// Record a balance write.
    pub fn write_balance(&mut self, address: Address, balance: U256) {
        self.write(
            EvmStateKey::Balance(address),
            EvmStateValue::Balance(balance),
        );
    }

    /// Record a nonce write.
    pub fn write_nonce(&mut self, address: Address, nonce: u64) {
        self.write(EvmStateKey::Nonce(address), EvmStateValue::Nonce(nonce));
    }

    /// Record a code write.
    pub fn write_code(&mut self, address: Address, code: Bytes) {
        self.write(EvmStateKey::Code(address), EvmStateValue::Code(code));
    }

    /// Record a code hash write.
    pub fn write_code_hash(&mut self, address: Address, hash: B256) {
        self.write(
            EvmStateKey::CodeHash(address),
            EvmStateValue::CodeHash(hash),
        );
    }

    /// Record a storage write.
    pub fn write_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.write(
            EvmStateKey::Storage(address, slot),
            EvmStateValue::Storage(value),
        );
    }

    /// Add a balance delta (commutative fee increment).
    ///
    /// Balance deltas are different from regular writes - they can be
    /// accumulated in parallel without conflicts. Only when the balance
    /// is read do they need to be resolved.
    pub fn add_balance_delta(&mut self, address: Address, delta: U256) {
        self.balance_deltas.push((address, delta));
    }

    /// Consume the write set and return the regular writes.
    pub fn into_writes(self) -> Vec<(EvmStateKey, EvmStateValue)> {
        self.writes
    }

    /// Consume the write set and return both regular writes and balance deltas.
    #[expect(clippy::type_complexity)]
    pub fn into_parts(self) -> (Vec<(EvmStateKey, EvmStateValue)>, Vec<(Address, U256)>) {
        (self.writes, self.balance_deltas)
    }

    /// Get the balance deltas.
    pub fn balance_deltas(&self) -> &[(Address, U256)] {
        &self.balance_deltas
    }

    /// Get the number of regular writes.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Get the number of balance deltas.
    pub fn num_deltas(&self) -> usize {
        self.balance_deltas.len()
    }

    /// Check if empty (no writes or deltas).
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.balance_deltas.is_empty()
    }
}

/// Execution output from a single transaction.
#[derive(Debug)]
pub struct TxnOutput {
    /// The read set (dependencies)
    pub reads: CapturedReads,
    /// The write set
    pub writes: WriteSet,
    /// Gas used
    pub gas_used: u64,
    /// Whether the transaction succeeded
    pub success: bool,
}

impl TxnOutput {
    /// Create a new transaction output.
    pub fn new(reads: CapturedReads, writes: WriteSet, gas_used: u64, success: bool) -> Self {
        Self {
            reads,
            writes,
            gas_used,
            success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_stm::mv_hashmap::MVHashMap;

    struct MockBaseDb;

    fn test_key(slot: u64) -> EvmStateKey {
        EvmStateKey::Storage(Address::ZERO, U256::from(slot))
    }

    fn test_value(v: u64) -> EvmStateValue {
        EvmStateValue::Storage(U256::from(v))
    }

    #[test]
    fn test_view_read_from_mvhashmap() {
        let mv = MVHashMap::new(10);
        let base = MockBaseDb;
        let key = test_key(1);
        let value = test_value(42);

        // Transaction 0 writes
        mv.write(0, 0, key.clone(), value.clone());

        // Transaction 1's view reads
        let view = LatestView::new(1, 0, &mv, &base);
        let result = view.read_from_mvhashmap(&key).unwrap();

        assert!(result.is_some());
        let (read_value, version) = result.unwrap();
        assert_eq!(read_value, value);
        assert_eq!(version.txn_idx, 0);
    }

    #[test]
    fn test_view_read_not_found() {
        let mv = MVHashMap::new(10);
        let base = MockBaseDb;
        let key = test_key(1);

        // No writes yet
        let view = LatestView::new(1, 0, &mv, &base);
        let result = view.read_from_mvhashmap(&key).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_view_captures_reads() {
        let mv = MVHashMap::new(10);
        let base = MockBaseDb;
        let key1 = test_key(1);
        let key2 = test_key(2);
        let value1 = test_value(100);

        // tx0 writes to key1
        mv.write(0, 0, key1.clone(), value1.clone());

        // tx2's view
        let view = LatestView::new(2, 0, &mv, &base);

        // Read from MVHashMap
        let _ = view.read_from_mvhashmap(&key1);

        // Record a base read
        view.record_base_read(key2.clone(), test_value(200));

        // Check captured reads
        let reads = view.take_captured_reads();
        assert_eq!(reads.len(), 2);
        assert!(reads.depends_on(0)); // Depends on tx0 for key1
    }

    #[test]
    fn test_write_set() {
        let mut ws = WriteSet::new();

        ws.write_balance(Address::ZERO, U256::from(1000));
        ws.write_nonce(Address::ZERO, 5);
        ws.write_storage(Address::ZERO, U256::from(1), U256::from(42));

        assert_eq!(ws.len(), 3);

        let writes = ws.into_writes();
        assert_eq!(writes.len(), 3);
    }
}
