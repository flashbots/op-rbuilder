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

// =============================================================================
// Balance Delta Tests (Fee Accumulation)
// =============================================================================

/// Test that many transactions can add deltas to the same address without conflicts.
/// This simulates parallel fee accumulation to coinbase.
#[test]
fn test_balance_delta_parallel_accumulation_no_conflicts() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    use crate::block_stm::scheduler::Scheduler;
    use crate::block_stm::captured_reads::CapturedReads;
    
    let num_txns = 100;
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(num_txns);
    let scheduler = Scheduler::new(num_txns);
    
    // Each transaction adds a fee delta - NO reads of coinbase balance
    for i in 0..num_txns {
        let txn_idx = i as TxnIndex;
        scheduler.start_execution(txn_idx, 0);
        
        let mut writes = WriteSet::new();
        // Add a fee delta (commutative operation)
        writes.add_balance_delta(coinbase, U256::from(100 + i));
        
        // No reads captured - just delta writes
        let reads = CapturedReads::new();
        
        scheduler.finish_execution(txn_idx, 0, reads, writes, 21000, true, &mv);
    }
    
    // All transactions should commit with NO aborts
    let stats = scheduler.get_stats();
    assert_eq!(stats.total_commits, num_txns);
    assert_eq!(stats.total_aborts, 0, "Balance deltas should NOT cause conflicts");
    
    // Verify total delta sum
    let total = mv.get_committed_delta_sum(&coinbase);
    let expected: u64 = (0..num_txns).map(|i| 100 + i as u64).sum();
    assert_eq!(total, U256::from(expected));
}

/// Test that regular balance writes still cause conflicts (deltas are separate).
#[test]
fn test_balance_regular_writes_still_conflict() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(10);
    
    // Tx0 writes a regular balance (NOT a delta)
    mv.write(0, 0, EvmStateKey::Balance(coinbase), EvmStateValue::Balance(U256::from(1000)));
    
    // Tx1 reads the balance - should see Tx0's write
    let result = mv.read(1, &EvmStateKey::Balance(coinbase));
    
    match result {
        crate::block_stm::types::ReadResult::Value { version, .. } => {
            assert_eq!(version.txn_idx, 0);
        }
        _ => panic!("Expected to read from Tx0"),
    }
}

/// Test that delta resolution correctly sums all prior deltas.
#[test]
fn test_balance_delta_resolution_correctness() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(100);
    
    // Many transactions add deltas
    let num_deltas = 50;
    for i in 0..num_deltas {
        mv.write_balance_delta(coinbase, i as TxnIndex, 0, U256::from(i + 1));
    }
    
    // Each reader at different positions should see correct cumulative sum
    for reader_idx in 1..=num_deltas {
        let result = mv.resolve_balance(coinbase, reader_idx as TxnIndex, U256::ZERO, None).unwrap();
        
        // Expected sum: 1 + 2 + ... + (reader_idx - 1) = (reader_idx - 1) * reader_idx / 2
        // But we're summing (i+1) for i in 0..(reader_idx), so it's reader_idx * (reader_idx + 1) / 2
        // Actually: sum of (1, 2, ..., reader_idx) where each is from tx i-1
        // For reader_idx = 5, we see deltas from tx0=1, tx1=2, tx2=3, tx3=4, tx4=5 -> but tx4 is NOT visible to reader 5
        // Reader sees tx0..tx(reader_idx-1), so deltas 1..reader_idx
        let expected: u64 = (1..reader_idx as u64 + 1).sum();
        assert_eq!(
            result.total_delta, 
            U256::from(expected),
            "Reader {} should see delta sum {}",
            reader_idx,
            expected
        );
    }
}

/// Test mixed scenario: some txns write deltas, one reads balance.
/// Only the reader should have dependencies, delta writers should not conflict.
#[test]
fn test_balance_delta_mixed_read_and_delta_writes() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    use crate::block_stm::scheduler::Scheduler;
    use crate::block_stm::captured_reads::CapturedReads;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(10);
    let scheduler = Scheduler::new(10);
    
    // Tx0-4: Just write deltas (no reads)
    for i in 0..5 {
        scheduler.start_execution(i, 0);
        
        let mut writes = WriteSet::new();
        writes.add_balance_delta(coinbase, U256::from(100));
        
        let reads = CapturedReads::new();
        scheduler.finish_execution(i, 0, reads, writes, 21000, true, &mv);
    }
    
    // Tx5: Reads the balance (triggers resolution)
    scheduler.start_execution(5, 0);
    
    let base_value = U256::from(1000);
    let resolved = mv.resolve_balance(coinbase, 5, base_value, None).unwrap();
    
    let mut reads = CapturedReads::new();
    reads.capture_resolved_balance(coinbase, resolved.clone());
    
    let writes = WriteSet::new();
    scheduler.finish_execution(5, 0, reads, writes, 21000, true, &mv);
    
    // Tx6-9: More delta writes after the reader
    for i in 6..10 {
        scheduler.start_execution(i, 0);
        
        let mut writes = WriteSet::new();
        writes.add_balance_delta(coinbase, U256::from(50));
        
        let reads = CapturedReads::new();
        scheduler.finish_execution(i, 0, reads, writes, 21000, true, &mv);
    }
    
    // All should commit
    let stats = scheduler.get_stats();
    assert_eq!(stats.total_commits, 10);
    assert_eq!(stats.total_aborts, 0);
    
    // Verify the reader saw the correct resolved value
    assert_eq!(resolved.resolved_value, U256::from(1500)); // 1000 + 5*100
    assert_eq!(resolved.contributors.len(), 5);
}

/// Stress test: Parallel execution with many delta writes and occasional reads.
#[test]
fn test_balance_delta_stress_parallel() {
    use std::sync::Arc;
    use std::thread;
    
    use crate::block_stm::mv_hashmap::MVHashMap;
    use crate::block_stm::scheduler::Scheduler;
    use crate::block_stm::captured_reads::CapturedReads;
    
    let num_txns = 100;
    let coinbase = Address::from([0xCB; 20]);
    let mv = Arc::new(MVHashMap::new(num_txns));
    let scheduler = Arc::new(Scheduler::new(num_txns));
    
    let num_threads = 4;
    let mut handles = Vec::new();
    
    for _thread_id in 0..num_threads {
        let mv = Arc::clone(&mv);
        let scheduler = Arc::clone(&scheduler);
        
        handles.push(thread::spawn(move || {
            loop {
                let task = scheduler.next_task();
                match task {
                    crate::block_stm::types::Task::Execute { txn_idx, incarnation } => {
                        scheduler.start_execution(txn_idx, incarnation);
                        
                        let mut writes = WriteSet::new();
                        let mut reads = CapturedReads::new();
                        
                        // Every 10th transaction reads the balance
                        if txn_idx % 10 == 9 {
                            let base = U256::from(1000);
                            match mv.resolve_balance(coinbase, txn_idx, base, None) {
                                Ok(resolved) => {
                                    reads.capture_resolved_balance(coinbase, resolved);
                                }
                                Err(_aborted) => {
                                    // Aborted, will be rescheduled
                                    continue;
                                }
                            }
                        } else {
                            // Most transactions just add deltas
                            writes.add_balance_delta(coinbase, U256::from(txn_idx as u64 + 1));
                        }
                        
                        scheduler.finish_execution(txn_idx, incarnation, reads, writes, 21000, true, &mv);
                    }
                    crate::block_stm::types::Task::Done => break,
                    crate::block_stm::types::Task::NoTask => {
                        thread::yield_now();
                    }
                    _ => {}
                }
            }
        }));
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let stats = scheduler.get_stats();
    assert_eq!(stats.total_commits, num_txns);
    
    // Delta writers (90 of them) should have no aborts
    // Readers (10 of them) might have some aborts due to re-execution
    // But the total should be reasonable
    println!(
        "Stress test: {} commits, {} aborts, {} executions",
        stats.total_commits, stats.total_aborts, stats.total_executions
    );
}

/// Test that delta contributor re-execution properly invalidates readers.
#[test]
fn test_balance_delta_contributor_reexecution_invalidates_reader() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    use crate::block_stm::scheduler::Scheduler;
    use crate::block_stm::captured_reads::CapturedReads;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(10);
    let scheduler = Scheduler::new(10);
    
    // Tx0: Writes delta +100
    scheduler.start_execution(0, 0);
    let mut writes0 = WriteSet::new();
    writes0.add_balance_delta(coinbase, U256::from(100));
    let reads0 = CapturedReads::new();
    scheduler.finish_execution(0, 0, reads0, writes0, 21000, true, &mv);
    
    // Tx1: Reads and resolves balance
    scheduler.start_execution(1, 0);
    let resolved = mv.resolve_balance(coinbase, 1, U256::from(1000), None).unwrap();
    assert_eq!(resolved.resolved_value, U256::from(1100));
    
    let mut reads1 = CapturedReads::new();
    reads1.capture_resolved_balance(coinbase, resolved);
    let writes1 = WriteSet::new();
    scheduler.finish_execution(1, 0, reads1, writes1, 21000, true, &mv);
    
    // Now abort Tx0 and re-execute with different delta
    scheduler.abort(0, &mv);
    
    // Tx0 incarnation 1: Writes delta +200 instead
    scheduler.start_execution(0, 1);
    let mut writes0_new = WriteSet::new();
    writes0_new.add_balance_delta(coinbase, U256::from(200));
    let reads0_new = CapturedReads::new();
    scheduler.finish_execution(0, 1, reads0_new, writes0_new, 21000, true, &mv);
    
    // Check that Tx1 was marked for re-execution
    let tx1_status = scheduler.get_status(1);
    assert!(
        matches!(tx1_status, crate::block_stm::types::ExecutionStatus::Aborted(_)),
        "Tx1 should be aborted because its contributor Tx0 re-executed"
    );
}

/// Test validation correctly detects when resolved balance changes.
#[test]
fn test_balance_delta_validation_detects_changes() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(10);
    
    // Tx0 writes delta +100
    mv.write_balance_delta(coinbase, 0, 0, U256::from(100));
    
    // Tx1 resolves
    let resolved_v1 = mv.resolve_balance(coinbase, 1, U256::from(1000), None).unwrap();
    assert_eq!(resolved_v1.resolved_value, U256::from(1100));
    
    // Now Tx0 re-executes with different delta
    mv.delete_deltas(0);
    mv.write_balance_delta(coinbase, 0, 1, U256::from(200)); // incarnation 1
    
    // Tx1 tries to validate - should detect the change
    let resolved_v2 = mv.resolve_balance(coinbase, 1, U256::from(1000), None).unwrap();
    
    // The new resolution is different
    assert_ne!(resolved_v1.resolved_value, resolved_v2.resolved_value);
    assert_eq!(resolved_v2.resolved_value, U256::from(1200)); // 1000 + 200
    
    // The contributor version also changed
    assert_ne!(resolved_v1.contributors[0].incarnation, resolved_v2.contributors[0].incarnation);
}

/// Test multiple addresses receiving deltas independently.
#[test]
fn test_balance_delta_multiple_addresses() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    
    let addr1 = Address::from([1u8; 20]);
    let addr2 = Address::from([2u8; 20]);
    let addr3 = Address::from([3u8; 20]);
    let mv = MVHashMap::new(30);
    
    // 10 txns add to addr1, 10 to addr2, 10 to addr3
    for i in 0..10 {
        mv.write_balance_delta(addr1, i as TxnIndex, 0, U256::from(100));
    }
    for i in 10..20 {
        mv.write_balance_delta(addr2, i as TxnIndex, 0, U256::from(200));
    }
    for i in 20..30 {
        mv.write_balance_delta(addr3, i as TxnIndex, 0, U256::from(300));
    }
    
    // Verify sums are independent
    assert_eq!(mv.get_committed_delta_sum(&addr1), U256::from(1000)); // 10 * 100
    assert_eq!(mv.get_committed_delta_sum(&addr2), U256::from(2000)); // 10 * 200
    assert_eq!(mv.get_committed_delta_sum(&addr3), U256::from(3000)); // 10 * 300
}

/// Test that aborted delta shows up as error during resolution.
#[test]
fn test_balance_delta_aborted_contributor_fails_resolution() {
    use crate::block_stm::mv_hashmap::MVHashMap;
    
    let coinbase = Address::from([0xCB; 20]);
    let mv = MVHashMap::new(10);
    
    // Tx0 writes delta
    mv.write_balance_delta(coinbase, 0, 0, U256::from(100));
    
    // Mark Tx0 as aborted
    mv.mark_aborted(0);
    
    // Tx1 tries to resolve - should fail
    let result = mv.resolve_balance(coinbase, 1, U256::from(1000), None);
    
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), 0); // Aborted txn idx
}

