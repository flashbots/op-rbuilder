//! Database Adapter for Block-STM Parallel Execution
//!
//! This module provides a `VersionedDatabase` that implements the revm `Database` trait
//! while routing reads through the MVHashMap for versioned state access.
//!
//! # How It Works
//!
//! 1. For each read operation, first check MVHashMap for writes from earlier transactions
//! 2. If found, return the versioned value and track the dependency
//! 3. If not found, read from base state and track as a base dependency
//! 4. All writes go to a local WriteSet (committed to MVHashMap after execution)

use crate::block_stm::{
    captured_reads::CapturedReads,
    mv_hashmap::{MVHashMap},
    types::{EvmStateKey, EvmStateValue, Incarnation, ReadResult, TxnIndex, Version},
    view::WriteSet,
};
use alloy_primitives::{Address, B256, U256};
use derive_more::Debug;
use revm::{Database, DatabaseRef, bytecode::Bytecode};
use revm::database_interface::DBErrorMarker;
use revm::state::AccountInfo;
use std::{collections::HashMap};
use std::sync::Mutex;
use tracing::trace;

/// Error type for versioned database operations.
#[derive(Debug, Clone)]
pub enum VersionedDbError {
    /// Read encountered an aborted transaction - need to abort and retry
    ReadAborted { aborted_txn_idx: TxnIndex },
    /// Base database error
    BaseDbError(String),
}

impl std::fmt::Display for VersionedDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionedDbError::ReadAborted { aborted_txn_idx } => {
                write!(f, "Read from aborted transaction {}", aborted_txn_idx)
            }
            VersionedDbError::BaseDbError(e) => write!(f, "Base DB error: {}", e),
        }
    }
}

impl std::error::Error for VersionedDbError {}

impl DBErrorMarker for VersionedDbError {}

/// Account state cached during execution.
#[derive(Debug, Clone, Default)]
struct CachedAccount {
    /// Account info (balance, nonce, code_hash)
    info: Option<AccountInfo>,
}

/// A versioned database that routes reads through MVHashMap.
///
/// This implements the revm `Database` trait, allowing it to be used
/// directly with the EVM for parallel execution.
#[derive(Debug)]
pub struct VersionedDatabase<'a, BaseDB> {
    /// Transaction index this database is for
    txn_idx: TxnIndex,
    /// Incarnation of this execution
    incarnation: Incarnation,
    /// The multi-version hash map
    mv_hashmap: &'a MVHashMap,
    /// The base database for reads not in MVHashMap
    base_db: &'a BaseDB,
    /// Captured reads for dependency tracking
    captured_reads: Mutex<CapturedReads>,
    /// Local write buffer (applied to MVHashMap after execution)
    writes: Mutex<WriteSet>,
    /// Cached account data to avoid re-reading
    account_cache: Mutex<HashMap<Address, CachedAccount>>,
    /// Whether an abort condition was encountered
    aborted: Mutex<Option<TxnIndex>>,
}

impl<'a, BaseDB> VersionedDatabase<'a, BaseDB> {
    /// Create a new versioned database for a transaction.
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
            writes: Mutex::new(WriteSet::new()),
            account_cache: Mutex::new(HashMap::new()),
            aborted: Mutex::new(None),
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

    /// Check if execution was aborted due to reading from an aborted transaction.
    pub fn was_aborted(&self) -> Option<TxnIndex> {
        *self.aborted.lock().unwrap()
    }

    /// Take the captured reads (consumes internal state).
    pub fn take_captured_reads(&self) -> CapturedReads {
        std::mem::take(&mut *self.captured_reads.lock().unwrap())
    }

    /// Take the write set (consumes internal state).
    pub fn take_writes(&self) -> WriteSet {
        std::mem::take(&mut *self.writes.lock().unwrap())
    }

    /// Record a read from MVHashMap.
    fn record_versioned_read(&self, key: EvmStateKey, version: Version, value: EvmStateValue) {
        self.captured_reads.lock().unwrap().capture_read(key, version, value);
    }

    /// Record a read from base state.
    fn record_base_read(&self, key: EvmStateKey, value: EvmStateValue) {
        self.captured_reads.lock().unwrap().capture_base_read(key, value);
    }

    /// Mark execution as aborted.
    fn mark_aborted(&self, aborted_txn_idx: TxnIndex) {
        *self.aborted.lock().unwrap() = Some(aborted_txn_idx);
    }
}

impl<'a, BaseDB> Database for VersionedDatabase<'a, BaseDB>
where
    BaseDB: revm::DatabaseRef,
    <BaseDB as revm::DatabaseRef>::Error: std::fmt::Display,
{
    type Error = VersionedDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, VersionedDbError> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, VersionedDbError> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, VersionedDbError> {
        self.storage_ref(address, slot)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, VersionedDbError> {
        self.block_hash_ref(number)
    }
}

/// Implementation for base databases that implement DatabaseRef.
impl<'a, BaseDB> DatabaseRef for VersionedDatabase<'a, BaseDB>
where
    BaseDB: revm::DatabaseRef,
    <BaseDB as revm::DatabaseRef>::Error: std::fmt::Display,
{
    type Error = VersionedDbError;

    /// Read account info (balance, nonce, code_hash).
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, VersionedDbError> {
        // Check cache first
        {
            let cache = self.account_cache.lock().unwrap();
            if let Some(cached) = cache.get(&address) {
                if cached.info.is_some() {
                    return Ok(cached.info.clone());
                }
            }
        }

        // Check MVHashMap for balance
        let balance_key = EvmStateKey::Balance(address);
        let balance_result = self.mv_hashmap.read(self.txn_idx, &balance_key);

        // Check MVHashMap for nonce
        let nonce_key = EvmStateKey::Nonce(address);
        let nonce_result = self.mv_hashmap.read(self.txn_idx, &nonce_key);

        // Check MVHashMap for code hash
        let code_hash_key = EvmStateKey::CodeHash(address);
        let code_hash_result = self.mv_hashmap.read(self.txn_idx, &code_hash_key);

        // Check for aborts
        if let ReadResult::Aborted { txn_idx } = &balance_result {
            self.mark_aborted(*txn_idx);
            return Err(VersionedDbError::ReadAborted { aborted_txn_idx: *txn_idx });
        }
        if let ReadResult::Aborted { txn_idx } = &nonce_result {
            self.mark_aborted(*txn_idx);
            return Err(VersionedDbError::ReadAborted { aborted_txn_idx: *txn_idx });
        }
        if let ReadResult::Aborted { txn_idx } = &code_hash_result {
            self.mark_aborted(*txn_idx);
            return Err(VersionedDbError::ReadAborted { aborted_txn_idx: *txn_idx });
        }

        // Read base account if needed
        let base_account = self.base_db.basic_ref(address)
            .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))?;

        let base_info = base_account.unwrap_or_default();

        // Merge MVHashMap values with base state
        let balance = match &balance_result {
            ReadResult::Value { value: EvmStateValue::Balance(b), version } => {
                self.record_versioned_read(balance_key, *version, EvmStateValue::Balance(*b));
                *b
            }
            _ => {
                self.record_base_read(balance_key, EvmStateValue::Balance(base_info.balance));
                base_info.balance
            }
        };

        let nonce = match &nonce_result {
            ReadResult::Value { value: EvmStateValue::Nonce(n), version } => {
                self.record_versioned_read(nonce_key, *version, EvmStateValue::Nonce(*n));
                *n
            }
            _ => {
                self.record_base_read(nonce_key, EvmStateValue::Nonce(base_info.nonce));
                base_info.nonce
            }
        };

        let code_hash = match &code_hash_result {
            ReadResult::Value { value: EvmStateValue::CodeHash(h), version } => {
                self.record_versioned_read(code_hash_key, *version, EvmStateValue::CodeHash(*h));
                *h
            }
            _ => {
                self.record_base_read(code_hash_key, EvmStateValue::CodeHash(base_info.code_hash));
                base_info.code_hash
            }
        };

        let account_info = AccountInfo {
            balance,
            nonce,
            code_hash,
            code: base_info.code.clone(),
        };

        trace!(
            txn_idx = self.txn_idx,
            address = %address,
            balance = %balance,
            nonce = nonce,
            "Read account info"
        );

        // Cache the result
        {
            let mut cache = self.account_cache.lock().unwrap();
            let entry = cache.entry(address).or_default();
            entry.info = Some(account_info.clone());
        }

        Ok(Some(account_info))
    }

    /// Read a storage slot.
    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, VersionedDbError> {
        let key = EvmStateKey::Storage(address, slot);

        match self.mv_hashmap.read(self.txn_idx, &key) {
            ReadResult::Value { value: EvmStateValue::Storage(v), version } => {
                trace!(
                    txn_idx = self.txn_idx,
                    address = %address,
                    slot = %slot,
                    value = %v,
                    source_txn = version.txn_idx,
                    "Read storage from MVHashMap"
                );
                self.record_versioned_read(key, version, EvmStateValue::Storage(v));
                Ok(v)
            }
            ReadResult::Value { .. } => {
                // Unexpected value type
                Ok(U256::ZERO)
            }
            ReadResult::NotFound => {
                // Read from base state
                let value = self.base_db.storage_ref(address, slot)
                    .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))?;
                trace!(
                    txn_idx = self.txn_idx,
                    address = %address,
                    slot = %slot,
                    value = %value,
                    "Read storage from base state"
                );
                self.record_base_read(key, EvmStateValue::Storage(value));
                Ok(value)
            }
            ReadResult::Aborted { txn_idx: aborted_txn_idx } => {
                trace!(
                    txn_idx = self.txn_idx,
                    address = %address,
                    slot = %slot,
                    aborted_txn = aborted_txn_idx,
                    "Read storage from aborted transaction"
                );
                self.mark_aborted(aborted_txn_idx);
                Err(VersionedDbError::ReadAborted { aborted_txn_idx })
            }
        }
    }

    /// Read a block hash.
    /// Block hashes are immutable within a block, so we don't track them as dependencies.
    fn block_hash_ref(&self, number: u64) -> Result<B256, VersionedDbError> {
        self.base_db.block_hash_ref(number)
            .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))
    }

    /// Read contract code by hash.
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, VersionedDbError> {
        // Code is usually immutable, read directly from base
        self.base_db.code_by_hash_ref(code_hash)
            .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_stm::mv_hashmap::MVHashMap;

    /// Mock base database for testing.
    struct MockBaseDb {
        accounts: HashMap<Address, AccountInfo>,
        storage: HashMap<(Address, U256), U256>,
    }

    impl MockBaseDb {
        fn new() -> Self {
            Self {
                accounts: HashMap::new(),
                storage: HashMap::new(),
            }
        }

        fn with_account(mut self, address: Address, balance: U256, nonce: u64) -> Self {
            self.accounts.insert(address, AccountInfo {
                balance,
                nonce,
                code_hash: B256::ZERO,
                code: None,
            });
            self
        }

        fn with_storage(mut self, address: Address, slot: U256, value: U256) -> Self {
            self.storage.insert((address, slot), value);
            self
        }
    }

    impl revm::DatabaseRef for MockBaseDb {
        type Error = std::convert::Infallible;

        fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.accounts.get(&address).cloned())
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::default())
        }

        fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
            Ok(self.storage.get(&(address, index)).copied().unwrap_or(U256::ZERO))
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn test_read_from_base_state() {
        let mv = MVHashMap::new(10);
        let addr = Address::from([1u8; 20]);
        let mut base = MockBaseDb::new()
            .with_account(addr, U256::from(1000), 5);

        let db = VersionedDatabase::new(0, 0, &mv, &mut base);

        let info = db.basic_ref(addr).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(1000));
        assert_eq!(info.nonce, 5);

        // Check that reads were captured
        let reads = db.take_captured_reads();
        assert!(!reads.is_empty());
    }

    #[test]
    fn test_read_from_mvhashmap() {
        let mv = MVHashMap::new(10);
        let addr = Address::from([1u8; 20]);
        
        // Tx0 writes a balance
        mv.write(0, 0, EvmStateKey::Balance(addr), EvmStateValue::Balance(U256::from(2000)));
        mv.write(0, 0, EvmStateKey::Nonce(addr), EvmStateValue::Nonce(10));

        let mut base = MockBaseDb::new()
            .with_account(addr, U256::from(1000), 5);

        // Tx1 reads - should see tx0's writes
        let db = VersionedDatabase::new(1, 0, &mv, &mut base);

        let info = db.basic_ref(addr).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(2000)); // From MVHashMap
        assert_eq!(info.nonce, 10); // From MVHashMap
    }

    #[test]
    fn test_storage_read() {
        let mv = MVHashMap::new(10);
        let addr = Address::from([1u8; 20]);
        let slot = U256::from(42);
        
        // Tx0 writes to storage
        mv.write(0, 0, EvmStateKey::Storage(addr, slot), EvmStateValue::Storage(U256::from(999)));

        let mut base = MockBaseDb::new()
            .with_storage(addr, slot, U256::from(100));

        // Tx1 should see tx0's write
        let db = VersionedDatabase::new(1, 0, &mv, &mut base);
        let value = db.storage_ref(addr, slot).unwrap();
        assert_eq!(value, U256::from(999));

        // Tx0 should see base state (can't see own writes)
        let db0 = VersionedDatabase::new(0, 0, &mv, &mut base);
        let value0 = db0.storage_ref(addr, slot).unwrap();
        assert_eq!(value0, U256::from(100));
    }

    #[test]
    fn test_aborted_read_detection() {
        let mv = MVHashMap::new(10);
        let addr = Address::from([1u8; 20]);
        
        // Tx0 writes and is marked as aborted
        mv.write(0, 0, EvmStateKey::Balance(addr), EvmStateValue::Balance(U256::from(2000)));
        mv.mark_aborted(0);

        let mut base = MockBaseDb::new();

        // Tx1 tries to read - should get abort error
        let db = VersionedDatabase::new(1, 0, &mv, &mut base);
        let result = db.basic_ref(addr);
        
        assert!(result.is_err());
        assert!(db.was_aborted().is_some());
    }
}

