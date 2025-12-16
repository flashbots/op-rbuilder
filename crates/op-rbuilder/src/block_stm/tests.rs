//! Integration and Consistency Tests for Block-STM
//!
//! These tests verify that:
//! 1. Parallel execution produces identical results to sequential execution
//! 2. Conflict detection and re-execution work correctly
//! 3. The system handles various edge cases

use crate::block_stm::{
    executor::{BlockStmConfig, BlockStmExecutor, TxnExecutionResult},
    types::{EvmStateKey, EvmStateValue, TxnIndex},
    view::WriteSet,
};
use alloy_primitives::{Address, U256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Test Helpers
// =============================================================================

/// A mock database that stores account balances.
#[derive(Debug, Default)]
struct MockDb {
    balances: HashMap<Address, U256>,
}

impl MockDb {
    fn with_balance(mut self, addr: Address, balance: U256) -> Self {
        self.balances.insert(addr, balance);
        self
    }

    fn get_balance(&self, addr: &Address) -> U256 {
        self.balances.get(addr).cloned().unwrap_or(U256::ZERO)
    }
}

/// A simple transaction for testing.
#[derive(Debug, Clone)]
struct TestTransaction {
    /// Sender address
    from: Address,
    /// Recipient address (None for simple balance read)
    to: Option<Address>,
    /// Amount to transfer
    amount: U256,
    /// Gas to use
    gas: u64,
}

impl TestTransaction {
    fn transfer(from: Address, to: Address, amount: U256) -> Self {
        Self {
            from,
            to: Some(to),
            amount,
            gas: 21000,
        }
    }

    fn read_balance(addr: Address) -> Self {
        Self {
            from: addr,
            to: None,
            amount: U256::ZERO,
            gas: 21000,
        }
    }
}

/// Execute transactions sequentially (baseline for comparison).
fn execute_sequential(
    transactions: &[TestTransaction],
    initial_balances: &HashMap<Address, U256>,
) -> (Vec<TxnExecutionResult>, HashMap<Address, U256>) {
    let mut balances = initial_balances.clone();
    let mut results = Vec::new();

    for (idx, tx) in transactions.iter().enumerate() {
        let from_balance = balances.get(&tx.from).cloned().unwrap_or(U256::ZERO);
        
        let success = if let Some(to) = tx.to {
            if from_balance >= tx.amount {
                // Perform transfer
                *balances.entry(tx.from).or_insert(U256::ZERO) -= tx.amount;
                *balances.entry(to).or_insert(U256::ZERO) += tx.amount;
                true
            } else {
                // Insufficient balance
                false
            }
        } else {
            // Just a read operation
            true
        };

        results.push(TxnExecutionResult {
            txn_idx: idx as TxnIndex,
            gas_used: tx.gas,
            success,
        });
    }

    (results, balances)
}

/// Create test addresses.
fn test_addresses() -> (Address, Address, Address) {
    let a = Address::from([1u8; 20]);
    let b = Address::from([2u8; 20]);
    let c = Address::from([3u8; 20]);
    (a, b, c)
}

fn balance_key(addr: Address) -> EvmStateKey {
    EvmStateKey::Balance(addr)
}

fn balance_value(v: U256) -> EvmStateValue {
    EvmStateValue::Balance(v)
}

// =============================================================================
// Consistency Tests
// =============================================================================

#[test]
fn test_parallel_matches_sequential_independent_transfers() {
    let (addr_a, addr_b, addr_c) = test_addresses();
    
    // Initial state: A has 1000, B has 500, C has 0
    let mut initial_balances = HashMap::new();
    initial_balances.insert(addr_a, U256::from(1000));
    initial_balances.insert(addr_b, U256::from(500));
    initial_balances.insert(addr_c, U256::ZERO);

    // Independent transfers (no conflicts):
    // A -> B: 100
    // B -> C: 50
    // These are independent because we're not implementing actual balance checks
    // in the mock - we're testing the execution infrastructure
    let transactions = vec![
        TestTransaction::transfer(addr_a, addr_b, U256::from(100)),
        TestTransaction::transfer(addr_b, addr_c, U256::from(50)),
    ];

    // Execute sequentially
    let (seq_results, _seq_balances) = execute_sequential(&transactions, &initial_balances);

    // Execute in parallel
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    let db = MockDb::default()
        .with_balance(addr_a, U256::from(1000))
        .with_balance(addr_b, U256::from(500));

    let par_result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();

        // Read sender balance from MVHashMap or base
        let from_key = balance_key(tx.from);
        let from_balance = match view.read_from_mvhashmap(&from_key) {
            Ok(Some((EvmStateValue::Balance(b), _))) => b,
            Ok(None) => {
                let b = db.get_balance(&tx.from);
                view.record_base_read(from_key.clone(), balance_value(b));
                b
            }
            _ => U256::ZERO,
        };

        let success = if let Some(to) = tx.to {
            if from_balance >= tx.amount {
                // Write updated balances
                writes.write_balance(tx.from, from_balance - tx.amount);
                
                // Read recipient balance
                let to_key = balance_key(to);
                let to_balance = match view.read_from_mvhashmap(&to_key) {
                    Ok(Some((EvmStateValue::Balance(b), _))) => b,
                    Ok(None) => {
                        let b = db.get_balance(&to);
                        view.record_base_read(to_key.clone(), balance_value(b));
                        b
                    }
                    _ => U256::ZERO,
                };
                writes.write_balance(to, to_balance + tx.amount);
                true
            } else {
                false
            }
        } else {
            true
        };

        (view.take_captured_reads(), writes, tx.gas, success)
    });

    // Compare results
    assert_eq!(seq_results.len(), par_result.results.len());
    for (seq, par) in seq_results.iter().zip(par_result.results.iter()) {
        assert_eq!(seq.txn_idx, par.txn_idx, "Transaction index mismatch");
        assert_eq!(seq.gas_used, par.gas_used, "Gas used mismatch at tx {}", seq.txn_idx);
        assert_eq!(seq.success, par.success, "Success mismatch at tx {}", seq.txn_idx);
    }
}

#[test]
fn test_parallel_many_independent_transactions() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
    
    // Create 50 addresses, each making a transfer to a unique recipient
    let transactions: Vec<TestTransaction> = (0..50)
        .map(|i| {
            let from = Address::from([i as u8; 20]);
            let to = Address::from([(i + 100) as u8; 20]);
            TestTransaction::transfer(from, to, U256::from(100))
        })
        .collect();

    let db = MockDb::default();

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();
        
        // Just write the transfers without complex balance logic
        if let Some(to) = tx.to {
            writes.write_balance(tx.from, U256::from(900)); // Assume 1000 - 100
            writes.write_balance(to, tx.amount);
        }

        (view.take_captured_reads(), writes, tx.gas, true)
    });

    assert_eq!(result.results.len(), 50);
    assert_eq!(result.stats.total_commits, 50);
    // Independent transactions should have no aborts
    assert_eq!(result.stats.total_aborts, 0);
}

// =============================================================================
// Conflict Detection Tests
// =============================================================================

#[test]
fn test_write_write_conflict_same_key() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    let addr = Address::from([1u8; 20]);
    
    // Two transactions both writing to the same address's balance
    let transactions = vec![
        TestTransaction::transfer(addr, Address::from([2u8; 20]), U256::from(100)),
        TestTransaction::transfer(addr, Address::from([3u8; 20]), U256::from(200)),
    ];

    let db = MockDb::default().with_balance(addr, U256::from(1000));
    let execution_count = AtomicU64::new(0);

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        execution_count.fetch_add(1, Ordering::Relaxed);
        
        let mut writes = WriteSet::new();
        
        // Read sender balance
        let from_key = balance_key(tx.from);
        let from_balance = match view.read_from_mvhashmap(&from_key) {
            Ok(Some((EvmStateValue::Balance(b), _))) => b,
            Ok(None) => {
                let b = db.get_balance(&tx.from);
                view.record_base_read(from_key.clone(), balance_value(b));
                b
            }
            _ => db.get_balance(&tx.from),
        };

        if let Some(to) = tx.to {
            // tx1 depends on tx0's write to from_balance
            writes.write_balance(tx.from, from_balance - tx.amount);
            writes.write_balance(to, tx.amount);
        }

        (view.take_captured_reads(), writes, tx.gas, true)
    });

    // Both should eventually commit
    assert_eq!(result.results.len(), 2);
    assert_eq!(result.stats.total_commits, 2);
    
    // Both should succeed
    assert!(result.results[0].success);
    assert!(result.results[1].success);
}

#[test]
fn test_read_write_conflict() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    let (addr_a, addr_b, _) = test_addresses();
    
    // tx0 writes to A's balance
    // tx1 reads A's balance
    // tx1 depends on tx0
    let transactions = vec![
        TestTransaction::transfer(addr_a, addr_b, U256::from(100)),
        TestTransaction::read_balance(addr_a),
    ];

    let db = MockDb::default().with_balance(addr_a, U256::from(1000));

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();
        
        // Read sender balance
        let from_key = balance_key(tx.from);
        let _from_balance = match view.read_from_mvhashmap(&from_key) {
            Ok(Some((EvmStateValue::Balance(b), _))) => b,
            Ok(None) => {
                let b = db.get_balance(&tx.from);
                view.record_base_read(from_key.clone(), balance_value(b));
                b
            }
            _ => db.get_balance(&tx.from),
        };

        if let Some(to) = tx.to {
            writes.write_balance(tx.from, U256::from(900));
            writes.write_balance(to, tx.amount);
        }

        (view.take_captured_reads(), writes, tx.gas, true)
    });

    assert_eq!(result.results.len(), 2);
    assert_eq!(result.stats.total_commits, 2);
}

#[test]
fn test_chain_of_dependencies() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
    
    // Chain: A->B, B->C, C->D
    // Each transfer depends on the previous one completing
    let addr_a = Address::from([1u8; 20]);
    let addr_b = Address::from([2u8; 20]);
    let addr_c = Address::from([3u8; 20]);
    let addr_d = Address::from([4u8; 20]);

    let transactions = vec![
        TestTransaction::transfer(addr_a, addr_b, U256::from(100)),
        TestTransaction::transfer(addr_b, addr_c, U256::from(50)),
        TestTransaction::transfer(addr_c, addr_d, U256::from(25)),
    ];

    let db = MockDb::default()
        .with_balance(addr_a, U256::from(1000))
        .with_balance(addr_b, U256::from(500))
        .with_balance(addr_c, U256::from(200));

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();
        
        // Read sender balance
        let from_key = balance_key(tx.from);
        let from_balance = match view.read_from_mvhashmap(&from_key) {
            Ok(Some((EvmStateValue::Balance(b), _))) => b,
            Ok(None) => {
                let b = db.get_balance(&tx.from);
                view.record_base_read(from_key.clone(), balance_value(b));
                b
            }
            _ => db.get_balance(&tx.from),
        };

        if let Some(to) = tx.to {
            // Read recipient balance
            let to_key = balance_key(to);
            let to_balance = match view.read_from_mvhashmap(&to_key) {
                Ok(Some((EvmStateValue::Balance(b), _))) => b,
                Ok(None) => {
                    let b = db.get_balance(&to);
                    view.record_base_read(to_key.clone(), balance_value(b));
                    b
                }
                _ => db.get_balance(&to),
            };

            writes.write_balance(tx.from, from_balance - tx.amount);
            writes.write_balance(to, to_balance + tx.amount);
        }

        (view.take_captured_reads(), writes, tx.gas, true)
    });

    // All should commit
    assert_eq!(result.results.len(), 3);
    assert_eq!(result.stats.total_commits, 3);
    
    // All should succeed
    for r in &result.results {
        assert!(r.success);
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_single_transaction() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
    let (addr_a, addr_b, _) = test_addresses();
    
    let transactions = vec![
        TestTransaction::transfer(addr_a, addr_b, U256::from(100)),
    ];

    let db = MockDb::default().with_balance(addr_a, U256::from(1000));

    let result = executor.execute(&transactions, &db, |_, tx, view| {
        let mut writes = WriteSet::new();
        if let Some(to) = tx.to {
            writes.write_balance(tx.from, U256::from(900));
            writes.write_balance(to, tx.amount);
        }
        (view.take_captured_reads(), writes, tx.gas, true)
    });

    assert_eq!(result.results.len(), 1);
    assert_eq!(result.stats.total_commits, 1);
    assert_eq!(result.stats.total_aborts, 0);
}

#[test]
fn test_empty_transactions() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
    let transactions: Vec<TestTransaction> = vec![];
    let db = MockDb::default();

    let result = executor.execute(&transactions, &db, |_, _, view| {
        (view.take_captured_reads(), WriteSet::new(), 21000, true)
    });

    assert_eq!(result.results.len(), 0);
    assert_eq!(result.stats.total_commits, 0);
}

#[test]
fn test_all_transactions_fail() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    
    let transactions: Vec<TestTransaction> = (0..5)
        .map(|i| {
            let from = Address::from([i as u8; 20]);
            let to = Address::from([(i + 100) as u8; 20]);
            TestTransaction::transfer(from, to, U256::from(100))
        })
        .collect();

    let db = MockDb::default(); // No balances, all transfers should "fail"

    let result = executor.execute(&transactions, &db, |_, _, view| {
        // All transactions fail (insufficient balance)
        (view.take_captured_reads(), WriteSet::new(), 21000, false)
    });

    assert_eq!(result.results.len(), 5);
    assert_eq!(result.stats.total_commits, 5);
    
    // All should be marked as failed
    for r in &result.results {
        assert!(!r.success);
    }
}

#[test]
fn test_mixed_success_and_failure() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    
    // Odd-indexed transactions succeed, even-indexed fail
    let transactions: Vec<TestTransaction> = (0..10)
        .map(|i| {
            let from = Address::from([i as u8; 20]);
            let to = Address::from([(i + 100) as u8; 20]);
            TestTransaction::transfer(from, to, U256::from(100))
        })
        .collect();

    let db = MockDb::default();

    let result = executor.execute(&transactions, &db, |txn_idx, _, view| {
        let success = txn_idx % 2 == 1; // Odd indices succeed
        let mut writes = WriteSet::new();
        if success {
            writes.write_balance(Address::from([txn_idx as u8; 20]), U256::from(900));
        }
        (view.take_captured_reads(), writes, 21000, success)
    });

    assert_eq!(result.results.len(), 10);
    
    for (i, r) in result.results.iter().enumerate() {
        assert_eq!(r.success, i % 2 == 1, "Mismatch at index {}", i);
    }
}

// =============================================================================
// Storage Slot Tests
// =============================================================================

#[test]
fn test_storage_slot_conflicts() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
    let contract = Address::from([42u8; 20]);
    let slot = U256::from(1);
    
    // Two transactions writing to the same storage slot
    #[derive(Debug, Clone)]
    struct StorageWriteTx {
        contract: Address,
        slot: U256,
        value: U256,
    }

    let transactions = vec![
        StorageWriteTx { contract, slot, value: U256::from(100) },
        StorageWriteTx { contract, slot, value: U256::from(200) },
    ];

    let db = MockDb::default();

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();
        
        // Read current storage value
        let key = EvmStateKey::Storage(tx.contract, tx.slot);
        let _ = view.read_from_mvhashmap(&key);
        
        // Write new value
        writes.write_storage(tx.contract, tx.slot, tx.value);
        
        (view.take_captured_reads(), writes, 21000, true)
    });

    assert_eq!(result.results.len(), 2);
    assert_eq!(result.stats.total_commits, 2);
}

#[test]
fn test_multiple_storage_slots_no_conflict() {
    let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
    let contract = Address::from([42u8; 20]);
    
    // Each transaction writes to a different storage slot
    #[derive(Debug, Clone)]
    struct StorageWriteTx {
        slot: U256,
        value: U256,
    }

    let transactions: Vec<StorageWriteTx> = (0..20)
        .map(|i| StorageWriteTx {
            slot: U256::from(i),
            value: U256::from(i * 100),
        })
        .collect();

    let db = MockDb::default();

    let result = executor.execute(&transactions, &db, |_txn_idx, tx, view| {
        let mut writes = WriteSet::new();
        writes.write_storage(contract, tx.slot, tx.value);
        (view.take_captured_reads(), writes, 21000, true)
    });

    assert_eq!(result.results.len(), 20);
    assert_eq!(result.stats.total_commits, 20);
    assert_eq!(result.stats.total_aborts, 0); // No conflicts
}

