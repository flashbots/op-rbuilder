//! Lazy Database Wrapper
//!
//! This module provides a database wrapper that tracks balance increments lazily,
//! deferring balance updates until the account is read. This is useful for
//! parallel execution where multiple fee recipients need balance updates
//! that don't conflict with transaction execution.

use alloy_primitives::{Address, B256, U256, map::HashMap};
use revm::{
    bytecode::Bytecode,
    state::AccountInfo,
    Database, DatabaseRef,
};
use auto_impl::auto_impl;

/// Trait for databases that support lazy balance increments.
///
/// This allows deferring balance updates (e.g., coinbase rewards, L1 fees)
/// until the account is actually read, avoiding write conflicts in parallel execution.
#[auto_impl(&mut)]
pub trait LazyDatabase {
    /// Record a pending balance increment for an address.
    ///
    /// The increment will be applied when the account is next read via `basic()`.
    fn lazily_increment_balance(&mut self, address: Address, amount: U256);

    /// Get pending balance increments.
    fn pending_increments(&mut self) -> HashMap<Address, U256>;
}

/// A database wrapper that tracks balance increments lazily.
///
/// When `lazily_increment_balance` is called, the increment is stored but not
/// immediately applied. When `basic()` is called for an account with pending
/// increments, the increment is added to the returned balance.
#[derive(Debug)]
pub struct LazyDatabaseWrapper<DB> {
    /// The inner database
    inner: DB,
    /// Pending balance increments by address
    pending_increments: HashMap<Address, U256>,
}

impl<DB> LazyDatabaseWrapper<DB> {
    /// Create a new lazy database wrapper.
    pub fn new(inner: DB) -> Self {
        Self {
            inner,
            pending_increments: HashMap::default(),
        }
    }

    /// Unwrap and return the inner database along with pending increments.
    pub fn into_inner(self) -> (DB, HashMap<Address, U256>) {
        (self.inner, self.pending_increments)
    }

    /// Get a reference to the inner database.
    pub fn inner(&self) -> &DB {
        &self.inner
    }

    /// Get a mutable reference to the inner database.
    pub fn inner_mut(&mut self) -> &mut DB {
        &mut self.inner
    }
}

impl<DB> LazyDatabase for LazyDatabaseWrapper<DB> {
    fn lazily_increment_balance(&mut self, address: Address, amount: U256) {
        if amount.is_zero() {
            return;
        }
        *self.pending_increments.entry(address).or_insert(U256::ZERO) += amount;
    }

    fn pending_increments(&mut self) -> HashMap<Address, U256> {
        self.pending_increments.clone()
    }
}

impl<DB: Database> Database for LazyDatabaseWrapper<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let mut account = self.inner.basic(address)?;

        // Apply any pending balance increment
        if let Some(increment) = self.pending_increments.get(&address) {
            if let Some(ref mut info) = account {
                info.balance = info.balance.saturating_add(*increment);
            } else {
                // Account doesn't exist yet but has pending increment
                // Create a new account with just the balance
                account = Some(AccountInfo {
                    balance: *increment,
                    nonce: 0,
                    code_hash: B256::ZERO,
                    code: None,
                });
            }
        }

        Ok(account)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.inner.storage(address, slot)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

impl<DB: DatabaseRef> DatabaseRef for LazyDatabaseWrapper<DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let mut account = self.inner.basic_ref(address)?;

        // Apply any pending balance increment
        if let Some(increment) = self.pending_increments.get(&address) {
            if let Some(ref mut info) = account {
                info.balance = info.balance.saturating_add(*increment);
            } else {
                // Account doesn't exist yet but has pending increment
                account = Some(AccountInfo {
                    balance: *increment,
                    nonce: 0,
                    code_hash: B256::ZERO,
                    code: None,
                });
            }
        }

        Ok(account)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.inner.storage_ref(address, slot)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }
}

