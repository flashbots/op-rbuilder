//! Block-STM Executor
//!
//! The main executor that orchestrates parallel transaction execution using Block-STM.
//!
//! # Execution Flow
//!
//! 1. Collect all transactions to execute
//! 2. Initialize MVHashMap and Scheduler
//! 3. Spawn worker threads
//! 4. Workers execute transactions speculatively
//! 5. Handle conflicts via abort/re-execute
//! 6. Commit in order
//! 7. Collect results

use crate::block_stm::{
    captured_reads::CapturedReads,
    mv_hashmap::MVHashMap,
    scheduler::{Scheduler, SchedulerStats},
    types::{Task, TxnIndex},
    view::{LatestView, WriteSet},
};
use std::sync::Arc;
use std::thread;
use tracing::{info, trace};

/// Configuration for the Block-STM executor.
#[derive(Debug, Clone)]
pub struct BlockStmConfig {
    /// Number of worker threads
    pub num_threads: usize,
}

impl Default for BlockStmConfig {
    fn default() -> Self {
        Self {
            num_threads: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
        }
    }
}

impl BlockStmConfig {
    /// Create a config with a specific number of threads.
    pub fn with_threads(num_threads: usize) -> Self {
        Self { num_threads }
    }
}

/// Result of executing a single transaction.
#[derive(Debug, Clone)]
pub struct TxnExecutionResult {
    /// Transaction index
    pub txn_idx: TxnIndex,
    /// Gas used
    pub gas_used: u64,
    /// Whether the transaction succeeded
    pub success: bool,
}

/// Result of parallel execution.
#[derive(Debug)]
pub struct ParallelExecutionResult {
    /// Results for each transaction, in order
    pub results: Vec<TxnExecutionResult>,
    /// Execution statistics
    pub stats: SchedulerStats,
}

/// The Block-STM parallel executor.
pub struct BlockStmExecutor {
    config: BlockStmConfig,
}

impl BlockStmExecutor {
    /// Create a new executor with the given configuration.
    pub fn new(config: BlockStmConfig) -> Self {
        Self { config }
    }

    /// Create a new executor with default configuration.
    pub fn default_executor() -> Self {
        Self::new(BlockStmConfig::default())
    }

    /// Execute transactions in parallel.
    ///
    /// # Type Parameters
    /// - `Tx`: Transaction type
    /// - `BaseDB`: Base database type for state reads
    /// - `ExecFn`: Function to execute a single transaction
    ///
    /// # Arguments
    /// - `transactions`: The transactions to execute
    /// - `base_db`: The base database for reading initial state
    /// - `exec_fn`: Function that executes a single transaction given a view
    ///
    /// The `exec_fn` receives:
    /// - Transaction index
    /// - Reference to the transaction
    /// - A `LatestView` for reading state (which tracks dependencies)
    ///
    /// It should return:
    /// - `CapturedReads`: The reads performed (from view.take_captured_reads())
    /// - `WriteSet`: The writes to apply
    /// - `u64`: Gas used
    /// - `bool`: Whether the transaction succeeded
    pub fn execute<Tx, BaseDB, ExecFn>(
        &self,
        transactions: &[Tx],
        base_db: &BaseDB,
        exec_fn: ExecFn,
    ) -> ParallelExecutionResult
    where
        Tx: Sync,
        BaseDB: Sync,
        ExecFn: Fn(TxnIndex, &Tx, &LatestView<'_, BaseDB>) -> (CapturedReads, WriteSet, u64, bool)
            + Sync
            + Send,
    {
        let num_txns = transactions.len();
        if num_txns == 0 {
            return ParallelExecutionResult {
                results: vec![],
                stats: SchedulerStats::default(),
            };
        }

        info!(
            num_txns = num_txns,
            num_threads = self.config.num_threads,
            "Starting Block-STM parallel execution"
        );

        // Initialize shared state
        let mv_hashmap = Arc::new(MVHashMap::new(num_txns));
        let scheduler = Arc::new(Scheduler::new(num_txns));

        // Use scoped threads so we can borrow transactions and base_db
        // Reference to exec_fn for sharing across threads
        let exec_fn_ref = &exec_fn;
        
        thread::scope(|s| {
            // Spawn worker threads
            let num_threads = self.config.num_threads.min(num_txns);
            
            for thread_id in 0..num_threads {
                let mv_hashmap = Arc::clone(&mv_hashmap);
                let scheduler = Arc::clone(&scheduler);
                
                s.spawn(move || {
                    scheduler.worker_start();
                    
                    trace!(
                        thread_id = thread_id,
                        "Block-STM worker started"
                    );

                    loop {
                        let task = scheduler.next_task();
                        
                        match task {
                            Task::Execute { txn_idx, incarnation } => {
                                trace!(
                                    thread_id = thread_id,
                                    txn_idx = txn_idx,
                                    incarnation = incarnation,
                                    "Worker executing transaction"
                                );

                                scheduler.start_execution(txn_idx, incarnation);

                                // Create the view for this transaction
                                let view = LatestView::new(
                                    txn_idx,
                                    incarnation,
                                    &mv_hashmap,
                                    base_db,
                                );

                                // Execute the transaction
                                let tx = &transactions[txn_idx as usize];
                                let (reads, writes, gas_used, success) = exec_fn_ref(txn_idx, tx, &view);

                                trace!(
                                    thread_id = thread_id,
                                    txn_idx = txn_idx,
                                    incarnation = incarnation,
                                    gas_used = gas_used,
                                    success = success,
                                    num_reads = reads.len(),
                                    num_writes = writes.len(),
                                    "Worker finished executing transaction"
                                );

                                // Notify scheduler of completion
                                scheduler.finish_execution(
                                    txn_idx,
                                    incarnation,
                                    reads,
                                    writes,
                                    gas_used,
                                    success,
                                    &mv_hashmap,
                                );
                            }
                            Task::Validate { txn_idx } => {
                                trace!(
                                    thread_id = thread_id,
                                    txn_idx = txn_idx,
                                    "Worker validating transaction"
                                );
                                // Validation is handled in try_commit for now
                            }
                            Task::NoTask => {
                                // No work available, check if we should wait or exit
                                if scheduler.is_done() {
                                    break;
                                }
                                scheduler.wait_for_work();
                            }
                            Task::Done => {
                                break;
                            }
                        }
                    }

                    scheduler.worker_done();
                    
                    trace!(
                        thread_id = thread_id,
                        "Block-STM worker finished"
                    );
                });
            }
        });

        // Collect results
        let stats = scheduler.get_stats();
        let results: Vec<_> = (0..num_txns as TxnIndex)
            .map(|txn_idx| TxnExecutionResult {
                txn_idx,
                gas_used: scheduler.get_gas_used(txn_idx),
                success: scheduler.was_successful(txn_idx),
            })
            .collect();

        info!(
            num_txns = num_txns,
            total_executions = stats.total_executions,
            total_aborts = stats.total_aborts,
            "Block-STM parallel execution complete"
        );

        ParallelExecutionResult { results, stats }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_stm::types::{EvmStateKey, EvmStateValue};
    use alloy_primitives::{Address, U256};

    /// A simple mock transaction for testing.
    #[derive(Debug, Clone)]
    struct MockTransaction {
        /// Keys this transaction reads
        pub reads: Vec<EvmStateKey>,
        /// Keys and values this transaction writes
        pub writes: Vec<(EvmStateKey, EvmStateValue)>,
        /// Gas to use
        pub gas: u64,
    }

    struct MockDb;

    fn test_key(slot: u64) -> EvmStateKey {
        EvmStateKey::Storage(Address::ZERO, U256::from(slot))
    }

    fn test_value(v: u64) -> EvmStateValue {
        EvmStateValue::Storage(U256::from(v))
    }

    #[test]
    fn test_executor_empty() {
        let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
        let transactions: Vec<MockTransaction> = vec![];
        let db = MockDb;

        let result = executor.execute(&transactions, &db, |_, _, _| {
            (CapturedReads::new(), WriteSet::new(), 21000, true)
        });

        assert_eq!(result.results.len(), 0);
    }

    #[test]
    fn test_executor_single_transaction() {
        let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(1));
        let transactions = vec![MockTransaction {
            reads: vec![],
            writes: vec![(test_key(1), test_value(100))],
            gas: 21000,
        }];
        let db = MockDb;

        let result = executor.execute(&transactions, &db, |_, tx, view| {
            // Simulate reads
            for key in &tx.reads {
                let _ = view.read_from_mvhashmap(key);
            }

            // Build write set
            let mut writes = WriteSet::new();
            for (key, value) in &tx.writes {
                writes.write(key.clone(), value.clone());
            }

            (view.take_captured_reads(), writes, tx.gas, true)
        });

        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].gas_used, 21000);
        assert!(result.results[0].success);
        assert_eq!(result.stats.total_commits, 1);
    }

    #[test]
    fn test_executor_multiple_independent_transactions() {
        let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(4));
        
        // 10 transactions that don't conflict (each writes to different key)
        let transactions: Vec<MockTransaction> = (0..10)
            .map(|i| MockTransaction {
                reads: vec![],
                writes: vec![(test_key(i), test_value(i * 100))],
                gas: 21000,
            })
            .collect();
        
        let db = MockDb;

        let result = executor.execute(&transactions, &db, |_, tx, view| {
            let mut writes = WriteSet::new();
            for (key, value) in &tx.writes {
                writes.write(key.clone(), value.clone());
            }
            (view.take_captured_reads(), writes, tx.gas, true)
        });

        assert_eq!(result.results.len(), 10);
        assert_eq!(result.stats.total_commits, 10);
        // No conflicts, so no aborts
        assert_eq!(result.stats.total_aborts, 0);
        
        // All should succeed
        for r in &result.results {
            assert!(r.success);
            assert_eq!(r.gas_used, 21000);
        }
    }

    #[test]
    fn test_executor_dependent_transactions() {
        let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(2));
        
        // tx0 writes to key 1
        // tx1 reads key 1, writes to key 2
        // This creates a dependency: tx1 depends on tx0
        let key1 = test_key(1);
        let key2 = test_key(2);
        
        let transactions = vec![
            MockTransaction {
                reads: vec![],
                writes: vec![(key1.clone(), test_value(100))],
                gas: 21000,
            },
            MockTransaction {
                reads: vec![key1.clone()],
                writes: vec![(key2.clone(), test_value(200))],
                gas: 21000,
            },
        ];
        
        let db = MockDb;

        let result = executor.execute(&transactions, &db, |txn_idx, tx, view| {
            // Simulate reads
            for key in &tx.reads {
                match view.read_from_mvhashmap(key) {
                    Ok(Some((_value, version))) => {
                        trace!(
                            txn_idx = txn_idx,
                            key = %key,
                            source_txn = version.txn_idx,
                            "Read value from MVHashMap"
                        );
                    }
                    Ok(None) => {
                        // Would read from base, record it
                        view.record_base_read(key.clone(), EvmStateValue::NotFound);
                    }
                    Err(_) => {
                        // Read from aborted transaction - in real impl would need to handle
                    }
                }
            }

            let mut writes = WriteSet::new();
            for (key, value) in &tx.writes {
                writes.write(key.clone(), value.clone());
            }

            (view.take_captured_reads(), writes, tx.gas, true)
        });

        assert_eq!(result.results.len(), 2);
        assert_eq!(result.stats.total_commits, 2);
        
        // Both should succeed
        assert!(result.results[0].success);
        assert!(result.results[1].success);
    }

    #[test]
    fn test_executor_with_many_threads() {
        let executor = BlockStmExecutor::new(BlockStmConfig::with_threads(8));
        
        // 100 independent transactions
        let transactions: Vec<MockTransaction> = (0..100)
            .map(|i| MockTransaction {
                reads: vec![],
                writes: vec![(test_key(i), test_value(i * 100))],
                gas: 21000,
            })
            .collect();
        
        let db = MockDb;

        let result = executor.execute(&transactions, &db, |_, tx, view| {
            let mut writes = WriteSet::new();
            for (key, value) in &tx.writes {
                writes.write(key.clone(), value.clone());
            }
            (view.take_captured_reads(), writes, tx.gas, true)
        });

        assert_eq!(result.results.len(), 100);
        assert_eq!(result.stats.total_commits, 100);
    }
}

