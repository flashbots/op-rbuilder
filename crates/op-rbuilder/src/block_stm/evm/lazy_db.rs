//! Lazy Database Wrapper
//!
//! This module provides a database wrapper that tracks balance increments lazily,
//! deferring balance updates until the account is read. This is useful for
//! parallel execution where multiple fee recipients need balance updates
//! that don't conflict with transaction execution.

use alloy_primitives::{Address, B256, U256, map::HashMap};
use auto_impl::auto_impl;
use revm::{Database, DatabaseRef, bytecode::Bytecode, state::AccountInfo};

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

/// Implementation of LazyDatabase for reth_revm::State that forwards to the inner database.
/// This allows State<LazyDatabaseWrapper<...>> to be used with OpLazyEvmFactory.
impl<DB: LazyDatabase> LazyDatabase for reth_revm::State<DB> {
    fn lazily_increment_balance(&mut self, address: Address, amount: U256) {
        self.database.lazily_increment_balance(address, amount);
    }

    fn pending_increments(&mut self) -> HashMap<Address, U256> {
        self.database.pending_increments()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    /// Mock database for testing that returns configurable account info
    #[derive(Debug, Default)]
    struct MockDb {
        accounts: HashMap<Address, AccountInfo>,
    }

    impl MockDb {
        fn with_account(mut self, addr: Address, balance: U256, nonce: u64) -> Self {
            self.accounts.insert(
                addr,
                AccountInfo {
                    balance,
                    nonce,
                    code_hash: B256::ZERO,
                    code: None,
                },
            );
            self
        }
    }

    impl Database for MockDb {
        type Error = Infallible;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.accounts.get(&address).cloned())
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::default())
        }

        fn storage(&mut self, _address: Address, _slot: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn test_lazy_increment_accumulates() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr = Address::repeat_byte(1);

        // Increment once
        lazy_db.lazily_increment_balance(addr, U256::from(100));
        assert_eq!(
            lazy_db.pending_increments().get(&addr),
            Some(&U256::from(100))
        );

        // Increment again - should accumulate
        lazy_db.lazily_increment_balance(addr, U256::from(50));
        assert_eq!(
            lazy_db.pending_increments().get(&addr),
            Some(&U256::from(150))
        );
    }

    #[test]
    fn test_lazy_increment_zero_is_ignored() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr = Address::repeat_byte(1);

        // Zero increment should be ignored
        lazy_db.lazily_increment_balance(addr, U256::ZERO);
        assert!(lazy_db.pending_increments().is_empty());
    }

    #[test]
    fn test_lazy_increment_multiple_addresses() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr1 = Address::repeat_byte(1);
        let addr2 = Address::repeat_byte(2);

        lazy_db.lazily_increment_balance(addr1, U256::from(100));
        lazy_db.lazily_increment_balance(addr2, U256::from(200));

        let increments = lazy_db.pending_increments();
        assert_eq!(increments.get(&addr1), Some(&U256::from(100)));
        assert_eq!(increments.get(&addr2), Some(&U256::from(200)));
    }

    #[test]
    fn test_basic_applies_pending_increment_to_existing_account() {
        let addr = Address::repeat_byte(1);
        let db = MockDb::default().with_account(addr, U256::from(1000), 5);
        let mut lazy_db = LazyDatabaseWrapper::new(db);

        // Add pending increment
        lazy_db.lazily_increment_balance(addr, U256::from(250));

        // Read account - should have increment applied
        let account = lazy_db.basic(addr).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(1250)); // 1000 + 250
        assert_eq!(account.nonce, 5); // nonce unchanged
    }

    #[test]
    fn test_basic_creates_account_for_nonexistent_with_increment() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr = Address::repeat_byte(1);

        // Add pending increment for non-existent account
        lazy_db.lazily_increment_balance(addr, U256::from(500));

        // Read account - should create new account with just the increment
        let account = lazy_db.basic(addr).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(500));
        assert_eq!(account.nonce, 0);
        assert_eq!(account.code_hash, B256::ZERO);
    }

    #[test]
    fn test_basic_returns_none_for_nonexistent_without_increment() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr = Address::repeat_byte(1);

        // No increment, account doesn't exist
        let account = lazy_db.basic(addr).unwrap();
        assert!(account.is_none());
    }

    #[test]
    fn test_into_inner_returns_pending_increments() {
        let db = MockDb::default();
        let mut lazy_db = LazyDatabaseWrapper::new(db);
        let addr = Address::repeat_byte(1);

        lazy_db.lazily_increment_balance(addr, U256::from(100));

        let (_inner_db, increments) = lazy_db.into_inner();
        assert_eq!(increments.get(&addr), Some(&U256::from(100)));
    }
}
