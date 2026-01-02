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
    mv_hashmap::{MVHashMap, ReadSet},
    types::{EvmStateKey, EvmStateValue, ReadResult, TxnIndex, Version},
};
use alloy_primitives::{Address, B256, U256};
use dashmap::DashMap;
use derive_more::Debug;
use revm::{
    Database, bytecode::Bytecode, database_interface::DBErrorMarker, primitives::HashMap,
    state::AccountInfo,
};
use std::{cmp::min, sync::Arc};

/// Shared cache for contract bytecode.
/// Maps code_hash -> bytecode for contracts deployed within the same block.
/// This is thread-safe and shared across all parallel transactions.
pub type SharedCodeCache = Arc<DashMap<B256, Bytecode>>;

/// Error type for versioned database operations.
#[derive(Debug, Clone)]
pub enum VersionedDbError {
    /// Read encountered an aborted transaction - need to abort and retry
    ReadAborted { aborted_txn_idx: TxnIndex },

    /// Read encountered an invalid value for a key (should not happen)
    InvalidValue {
        key: EvmStateKey,
        value: EvmStateValue,
        version: Version,
    },
    /// Base database error
    BaseDbError(String),
}

impl std::fmt::Display for VersionedDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionedDbError::ReadAborted { aborted_txn_idx } => {
                write!(f, "Read from aborted transaction {}", aborted_txn_idx)
            }
            VersionedDbError::InvalidValue {
                key,
                value,
                version,
            } => {
                write!(
                    f,
                    "Invalid value for key {}: {} at version {}",
                    key, value, version
                )
            }
            VersionedDbError::BaseDbError(e) => write!(f, "Base DB error: {}", e),
        }
    }
}

impl std::error::Error for VersionedDbError {}

impl DBErrorMarker for VersionedDbError {}

/// A versioned database that routes reads through MVHashMap.
///
/// This implements the revm `Database` trait, allowing it to be used
/// directly with the EVM for parallel execution.
#[derive(Debug)]
pub struct VersionedDatabase<'a, BaseDB> {
    /// Transaction index this database is for
    txn_idx: TxnIndex,
    /// The multi-version hash map
    mv_hashmap: &'a MVHashMap,
    /// The base database for reads not in MVHashMap
    base_db: &'a BaseDB,
    /// Shared cache for contract bytecode deployed within this block
    #[debug(skip)]
    code_cache: SharedCodeCache,
    /// Read set for dependency tracking
    read_set: ReadSet,
    /// Captured reads for change tracking
    captured_reads: HashMap<EvmStateKey, EvmStateValue>,
    /// Captured writes for block resources (gas, DA bytes)
    pub captured_writes: HashMap<EvmStateKey, EvmStateValue>,
}

impl<'a, BaseDB> VersionedDatabase<'a, BaseDB> {
    /// Create a new versioned database for a transaction.
    pub fn new(
        txn_idx: TxnIndex,
        mv_hashmap: &'a MVHashMap,
        base_db: &'a BaseDB,
        code_cache: SharedCodeCache,
    ) -> Self {
        Self {
            txn_idx,
            mv_hashmap,
            base_db,
            code_cache,
            read_set: ReadSet::new(),
            captured_reads: HashMap::default(),
            captured_writes: HashMap::default(),
        }
    }

    /// Get the transaction index.
    pub fn txn_idx(&self) -> TxnIndex {
        self.txn_idx
    }

    /// Take the captured reads (consumes internal state).
    pub fn take_read_set(&mut self) -> ReadSet {
        std::mem::take(&mut self.read_set)
    }

    pub fn take_captured_reads(&mut self) -> HashMap<EvmStateKey, EvmStateValue> {
        std::mem::take(&mut self.captured_reads)
    }

    fn add_to_reads(&mut self, key: EvmStateKey, value: EvmStateValue, version: Option<Version>) {
        self.read_set.insert((key.clone(), version));
        self.captured_reads.insert(key, value);
    }

    /// Read a block resource value from MVHashMap.
    /// Called BEFORE EVM execution to create dependency and enable early conflict detection.
    pub fn read_block_resource(
        &mut self,
        resource_type: crate::block_stm::types::BlockResourceType,
    ) -> Result<u64, VersionedDbError> {
        use crate::block_stm::types::{EvmStateKey, EvmStateValue};

        let key = EvmStateKey::BlockResourceUsed(resource_type);
        match self.mv_hashmap.read(&key, self.txn_idx) {
            ReadResult::Value {
                value: EvmStateValue::BlockResourceUsed(val),
                version,
            } => {
                self.add_to_reads(key, EvmStateValue::BlockResourceUsed(val), Some(version));
                Ok(val)
            }
            ReadResult::NotFound => {
                // Resource not written yet, defaults to 0
                self.add_to_reads(key, EvmStateValue::BlockResourceUsed(0), None);
                Ok(0)
            }
            ReadResult::Aborted { txn_idx } => {
                Err(VersionedDbError::ReadAborted {
                    aborted_txn_idx: txn_idx,
                })
            }
            ReadResult::Value { value, version } => {
                // Wrong value type - should never happen
                Err(VersionedDbError::InvalidValue {
                    key,
                    value,
                    version,
                })
            }
        }
    }

    /// Write a block resource value.
    /// This will be captured in the write set automatically.
    pub fn write_block_resource(
        &mut self,
        resource_type: crate::block_stm::types::BlockResourceType,
        value: u64,
    ) -> Result<(), VersionedDbError> {
        use crate::block_stm::types::{EvmStateKey, EvmStateValue};

        let key = EvmStateKey::BlockResourceUsed(resource_type);
        // Add to captured writes - will be added to write set when transaction completes
        self.captured_writes.insert(key, EvmStateValue::BlockResourceUsed(value));
        Ok(())
    }

    /// Read address gas usage from MVHashMap.
    /// Called BEFORE EVM execution to create dependency and check gas limits.
    pub fn read_address_gas_used(
        &mut self,
        address: Address,
    ) -> Result<u64, VersionedDbError> {
        use crate::block_stm::types::{EvmStateKey, EvmStateValue};

        let key = EvmStateKey::AddressGasUsed(address);
        match self.mv_hashmap.read(&key, self.txn_idx) {
            ReadResult::Value {
                value: EvmStateValue::AddressGasUsed(val),
                version,
            } => {
                self.add_to_reads(key, EvmStateValue::AddressGasUsed(val), Some(version));
                Ok(val)
            }
            ReadResult::NotFound => {
                // No gas used yet for this address in this block
                self.add_to_reads(key, EvmStateValue::AddressGasUsed(0), None);
                Ok(0)
            }
            ReadResult::Aborted { txn_idx } => {
                Err(VersionedDbError::ReadAborted {
                    aborted_txn_idx: txn_idx,
                })
            }
            ReadResult::Value { value, version } => {
                // Wrong value type - should never happen
                Err(VersionedDbError::InvalidValue {
                    key,
                    value,
                    version,
                })
            }
        }
    }

    /// Write address gas usage value.
    /// This will be captured in the write set automatically.
    pub fn write_address_gas_used(
        &mut self,
        address: Address,
        value: u64,
    ) -> Result<(), VersionedDbError> {
        use crate::block_stm::types::{EvmStateKey, EvmStateValue};

        let key = EvmStateKey::AddressGasUsed(address);
        // Add to captured writes - will be added to write set when transaction completes
        self.captured_writes.insert(key, EvmStateValue::AddressGasUsed(value));
        Ok(())
    }

    // /// Record a resolved balance read (balance with deltas applied).
    // fn record_resolved_balance(
    //     &self,
    //     address: Address,
    //     resolved: crate::block_stm::types::ResolvedBalance,
    // ) {
    //     self.captured_reads
    //         .lock()
    //         .unwrap()
    //         .capture_resolved_balance(address, resolved);
    // }

    // /// Resolve a balance including any pending deltas.
    // ///
    // /// This handles the case where earlier transactions have written balance deltas
    // /// (e.g., fee increments) that need to be applied to the balance.
    // #[instrument(level = "trace", skip(self), fields(txn_idx = self.txn_idx, address = %address))]
    // fn resolve_balance_with_deltas(
    //     &self,
    //     address: Address,
    //     base_value: U256,
    //     base_version: Option<Version>,
    // ) -> Result<U256, VersionedDbError> {
    //     // Check if there are pending deltas for this address
    //     if !self.mv_hashmap.has_pending_deltas(&address, self.txn_idx) {
    //         // No deltas, just return the base value (already recorded)
    //         return Ok(base_value);
    //     }

    //     // Resolve deltas
    //     match self
    //         .mv_hashmap
    //         .resolve_balance(address, self.txn_idx, base_value, base_version)
    //     {
    //         Ok(resolved) => {
    //             let final_value = resolved.resolved_value;

    //             // Record the resolved balance read (tracks all contributors)
    //             self.record_resolved_balance(address, resolved);

    //             Ok(final_value)
    //         }
    //         Err(aborted_txn_idx) => {
    //             self.mark_aborted(aborted_txn_idx);
    //             Err(VersionedDbError::ReadAborted { aborted_txn_idx })
    //         }
    //     }
    // }
}

impl<'a, BaseDB> Database for VersionedDatabase<'a, BaseDB>
where
    BaseDB: revm::DatabaseRef,
    <BaseDB as revm::DatabaseRef>::Error: std::fmt::Display,
{
    type Error = VersionedDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, VersionedDbError> {
        // Check MVHashMap for balance
        let balance_key = EvmStateKey::Balance(address);
        let balance_result = self.mv_hashmap.read(&balance_key, self.txn_idx);

        // Check MVHashMap for nonce
        let nonce_key = EvmStateKey::Nonce(address);
        let nonce_result = self.mv_hashmap.read(&nonce_key, self.txn_idx);

        // Check MVHashMap for code hash
        let code_hash_key = EvmStateKey::CodeHash(address);
        let code_hash_result = self.mv_hashmap.read(&code_hash_key, self.txn_idx);

        // Check for aborts (get minimum aborted txn index)
        let mut aborted_txn_idx = None;
        if let ReadResult::Aborted { txn_idx } = &balance_result {
            aborted_txn_idx = Some(
                aborted_txn_idx
                    .map(|idx| min(idx, *txn_idx))
                    .unwrap_or(*txn_idx),
            );
        }
        if let ReadResult::Aborted { txn_idx } = &nonce_result {
            aborted_txn_idx = Some(
                aborted_txn_idx
                    .map(|idx| min(idx, *txn_idx))
                    .unwrap_or(*txn_idx),
            );
        }
        if let ReadResult::Aborted { txn_idx } = &code_hash_result {
            aborted_txn_idx = Some(
                aborted_txn_idx
                    .map(|idx| min(idx, *txn_idx))
                    .unwrap_or(*txn_idx),
            );
        }

        if aborted_txn_idx.is_some() {
            return Err(VersionedDbError::ReadAborted {
                aborted_txn_idx: aborted_txn_idx.unwrap(),
            });
        }

        if let (
            &ReadResult::Value {
                value: EvmStateValue::Balance(b),
                version: balance_version,
            },
            &ReadResult::Value {
                value: EvmStateValue::Nonce(n),
                version: nonce_version,
            },
            &ReadResult::Value {
                value: EvmStateValue::CodeHash(h),
                version: code_hash_version,
            },
        ) = (&balance_result, &nonce_result, &code_hash_result)
        {
            self.add_to_reads(
                balance_key,
                EvmStateValue::Balance(b),
                Some(balance_version),
            );
            self.add_to_reads(nonce_key, EvmStateValue::Nonce(n), Some(nonce_version));
            self.add_to_reads(
                code_hash_key,
                EvmStateValue::CodeHash(h),
                Some(code_hash_version),
            );
            Ok(Some(AccountInfo {
                balance: b,
                nonce: n,
                code_hash: h,
                code: self.code_cache.get(&h).map(|c| c.clone()),
            }))
        } else {
            // Read base account if needed
            let base_account = self
                .base_db
                .basic_ref(address)
                .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))?;

            let mut did_exist = base_account.is_some();
            let mut base_info = base_account.unwrap_or_default();

            match balance_result {
                ReadResult::Value {
                    value: EvmStateValue::Balance(value),
                    version,
                } => {
                    self.add_to_reads(balance_key, EvmStateValue::Balance(value), Some(version));
                    base_info.balance = value;
                    did_exist = true;
                }
                ReadResult::Value {
                    value: EvmStateValue::BalanceIncrement(increment),
                    version,
                } => {
                    // BalanceIncrement is a delta that should be added to the base balance.
                    // We read the base balance and add the increment.
                    // Track dependency on the increment write for conflict detection.
                    self.add_to_reads(
                        balance_key.clone(),
                        EvmStateValue::BalanceIncrement(increment),
                        Some(version),
                    );
                    base_info.balance = base_info.balance.saturating_add(increment);
                    did_exist = true;
                }
                ReadResult::Value { value, version } => {
                    return Err(VersionedDbError::InvalidValue {
                        key: EvmStateKey::Balance(address),
                        value: value,
                        version: version,
                    });
                }
                ReadResult::NotFound => {
                    self.add_to_reads(balance_key, EvmStateValue::Balance(base_info.balance), None);
                }
                ReadResult::Aborted { .. } => {
                    unreachable!();
                }
            }

            match nonce_result {
                ReadResult::Value {
                    value: EvmStateValue::Nonce(value),
                    version,
                } => {
                    self.add_to_reads(nonce_key, EvmStateValue::Nonce(value), Some(version));
                    base_info.nonce = value;
                    did_exist = true;
                }
                ReadResult::Value { value, version } => {
                    return Err(VersionedDbError::InvalidValue {
                        key: EvmStateKey::Nonce(address),
                        value: value,
                        version: version,
                    });
                }
                ReadResult::NotFound => {
                    self.add_to_reads(nonce_key, EvmStateValue::Nonce(base_info.nonce), None);
                }
                ReadResult::Aborted { .. } => {
                    unreachable!();
                }
            }

            match code_hash_result {
                ReadResult::Value {
                    value: EvmStateValue::CodeHash(value),
                    version,
                } => {
                    self.add_to_reads(code_hash_key, EvmStateValue::CodeHash(value), Some(version));
                    base_info.code_hash = value;
                    // CRITICAL: Also populate code from cache to match the new code_hash
                    // Without this, AccountInfo has correct code_hash but code=None,
                    // causing contract calls to fail silently
                    base_info.code = self.code_cache.get(&value).map(|c| c.clone());
                    did_exist = true;
                }
                ReadResult::Value { value, version } => {
                    return Err(VersionedDbError::InvalidValue {
                        key: EvmStateKey::Balance(address),
                        value: value,
                        version: version,
                    });
                }
                ReadResult::NotFound => {
                    self.add_to_reads(
                        code_hash_key,
                        EvmStateValue::CodeHash(base_info.code_hash),
                        None,
                    );
                }
                ReadResult::Aborted { .. } => {
                    unreachable!();
                }
            }

            if did_exist {
                Ok(Some(base_info))
            } else {
                Ok(None)
            }
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, VersionedDbError> {
        // First check the shared code cache for contracts deployed within this block
        if let Some(code) = self.code_cache.get(&code_hash) {
            return Ok(code.clone());
        }

        // Fall back to base database
        self.base_db
            .code_by_hash_ref(code_hash)
            .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, VersionedDbError> {
        match self
            .mv_hashmap
            .read(&EvmStateKey::Storage(address, slot), self.txn_idx)
        {
            ReadResult::Value {
                value: EvmStateValue::Storage(v),
                version,
            } => {
                self.read_set
                    .insert((EvmStateKey::Storage(address, slot), Some(version)));
                Ok(v)
            }
            ReadResult::Value { value, version } => Err(VersionedDbError::InvalidValue {
                key: EvmStateKey::Storage(address, slot),
                value: value,
                version: version,
            }),
            ReadResult::NotFound => {
                self.read_set
                    .insert((EvmStateKey::Storage(address, slot), None));
                self.base_db
                    .storage_ref(address, slot)
                    .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))
            }
            ReadResult::Aborted { txn_idx } => Err(VersionedDbError::ReadAborted {
                aborted_txn_idx: txn_idx,
            }),
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, VersionedDbError> {
        self.base_db
            .block_hash_ref(number)
            .map_err(|e| VersionedDbError::BaseDbError(e.to_string()))
    }
}
