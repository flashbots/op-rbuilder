//! Scheduler for Block-STM Parallel Execution
//!
//! The Scheduler coordinates parallel transaction execution, handling:
//! - Task distribution to worker threads
//! - Abort management and push-based invalidation
//! - In-order commit sequencing
//!
//! # Execution Flow
//!
//! 1. All transactions start in `PendingScheduling` state
//! 2. Workers request tasks and execute transactions speculatively
//! 3. When conflicts are detected, dependent transactions are aborted
//! 4. Transactions are committed in order (tx0 must commit before tx1)

use crate::block_stm::{
    captured_reads::CapturedReads,
    mv_hashmap::MVHashMap,
    types::{ExecutionStatus, Incarnation, Task, TxnIndex},
    view::WriteSet,
};
use alloy_primitives::Address;
use parking_lot::{Condvar, Mutex, RwLock};
use std::{
    collections::{HashSet, VecDeque},
    sync::atomic::{AtomicUsize, Ordering},
};
use tracing::instrument;

/// Per-transaction execution state.
#[derive(Debug)]
struct TxnState {
    /// Current execution status
    status: ExecutionStatus,
    /// Number of times this transaction has been executed
    incarnation: Incarnation,
    /// The read set from the latest execution (for validation)
    reads: Option<CapturedReads>,
    /// The write set from the latest execution
    writes: Option<WriteSet>,
    /// Gas used in the latest execution
    gas_used: u64,
    /// Whether the latest execution was successful
    success: bool,
    /// DA size of the transaction (for limit checking)
    tx_da_size: u64,
}

impl TxnState {
    fn new() -> Self {
        Self {
            status: ExecutionStatus::PendingScheduling,
            incarnation: 0,
            reads: None,
            writes: None,
            gas_used: 0,
            success: false,
            tx_da_size: 0,
        }
    }
}

/// Statistics about the execution.
#[derive(Debug, Default)]
pub struct SchedulerStats {
    /// Total number of executions (including re-executions)
    pub total_executions: usize,
    /// Number of aborts
    pub total_aborts: usize,
    /// Number of successful commits
    pub total_commits: usize,
}

/// The Block-STM Scheduler.
///
/// Manages task distribution, abort handling, and commit ordering.
pub struct Scheduler {
    /// Number of transactions in the block
    num_txns: usize,
    /// Transaction senders (for handling nonce dependencies)
    tx_senders: Vec<Address>,
    /// Per-transaction state
    txn_states: Vec<RwLock<TxnState>>,
    /// Initial gas used (from builder tx, etc.)
    initial_gas_used: u64,
    /// Initial DA bytes used (from builder tx, etc.)
    initial_da_used: u64,
    /// Block gas limit
    block_gas_limit: u64,
    /// Block DA limit (None means no limit)
    block_da_limit: Option<u64>,
    /// Per-transaction DA limit (None means no limit)
    tx_da_limit: Option<u64>,
    /// Committed gas values per transaction (written before commit_idx advances)
    /// This ensures race-free reading of gas values when checking limits
    committed_gas: Vec<std::sync::atomic::AtomicU64>,
    /// Committed DA values per transaction (written before commit_idx advances)
    committed_da: Vec<std::sync::atomic::AtomicU64>,
    /// Queue of transactions ready for execution
    execution_queue: Mutex<VecDeque<TxnIndex>>,
    /// Set of transactions that need validation
    validation_queue: Mutex<HashSet<TxnIndex>>,
    /// Index of the next transaction to commit (commits must be in order)
    commit_idx: AtomicUsize,
    /// Condition variable for waking up workers
    work_available: Condvar,
    /// Lock for condition variable
    work_lock: Mutex<()>,
    /// Number of active workers
    active_workers: AtomicUsize,
    /// Whether execution is complete
    done: RwLock<bool>,
    /// Execution statistics
    stats: Mutex<SchedulerStats>,
}

impl Scheduler {
    /// Create a new scheduler for a block with the given number of transactions.
    pub fn new(
        num_txns: usize,
        tx_senders: Vec<Address>,
        initial_gas_used: u64,
        initial_da_used: u64,
        block_gas_limit: u64,
        block_da_limit: Option<u64>,
        tx_da_limit: Option<u64>,
    ) -> Self {
        assert_eq!(
            tx_senders.len(),
            num_txns,
            "tx_senders length must match num_txns"
        );

        // Initialize all transactions as pending
        let txn_states: Vec<_> = (0..num_txns)
            .map(|_| RwLock::new(TxnState::new()))
            .collect();

        // Initialize committed gas/da vectors (written before commit_idx advances)
        let committed_gas: Vec<_> = (0..num_txns)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();
        let committed_da: Vec<_> = (0..num_txns)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();

        // Queue all transactions for initial execution
        let execution_queue: VecDeque<_> = (0..num_txns as TxnIndex).collect();

        Self {
            num_txns,
            tx_senders,
            txn_states,
            initial_gas_used,
            initial_da_used,
            block_gas_limit,
            block_da_limit,
            tx_da_limit,
            committed_gas,
            committed_da,
            execution_queue: Mutex::new(execution_queue),
            validation_queue: Mutex::new(HashSet::new()),
            commit_idx: AtomicUsize::new(0),
            work_available: Condvar::new(),
            work_lock: Mutex::new(()),
            active_workers: AtomicUsize::new(0),
            done: RwLock::new(false),
            stats: Mutex::new(SchedulerStats::default()),
        }
    }

    pub fn get_commit_idx(&self) -> usize {
        self.commit_idx.load(Ordering::SeqCst)
    }

    /// Get the number of transactions.
    pub fn num_txns(&self) -> usize {
        self.num_txns
    }

    /// Register a worker starting work.
    pub fn worker_start(&self) {
        self.active_workers.fetch_add(1, Ordering::SeqCst);
    }

    /// Register a worker finishing work.
    pub fn worker_done(&self) {
        let prev = self.active_workers.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            // Last worker, wake up anyone waiting
            self.work_available.notify_all();
        }
    }

    /// Check if all work is done.
    pub fn is_done(&self) -> bool {
        *self.done.read()
    }

    /// Get the next task for a worker.
    pub fn next_task(&self) -> Task {
        // Check if we're done
        if *self.done.read() {
            return Task::Done;
        }

        // Try to get a transaction to execute
        if let Some(txn_idx) = self.execution_queue.lock().pop_front() {
            let state = self.txn_states[txn_idx as usize].read();
            let incarnation = state.incarnation;
            return Task::Execute {
                txn_idx,
                incarnation,
            };
        }

        // Try to get a transaction to validate
        if let Some(&txn_idx) = self.validation_queue.lock().iter().next() {
            self.validation_queue.lock().remove(&txn_idx);
            return Task::Validate { txn_idx };
        }

        // No work available
        Task::NoTask
    }

    /// Wait for work to become available.
    pub fn wait_for_work(&self) {
        let mut lock = self.work_lock.lock();
        // Check one more time if there's work or we're done
        if !self.execution_queue.lock().is_empty()
            || !self.validation_queue.lock().is_empty()
            || *self.done.read()
        {
            return;
        }
        // Wait with timeout to avoid deadlocks
        self.work_available
            .wait_for(&mut lock, std::time::Duration::from_millis(10));
    }

    /// Notify that work is available.
    fn notify_work(&self) {
        self.work_available.notify_all();
    }

    /// Mark a transaction as starting execution.
    pub fn start_execution(&self, txn_idx: TxnIndex, incarnation: Incarnation) {
        let mut state = self.txn_states[txn_idx as usize].write();
        state.status = ExecutionStatus::Executing(incarnation);
        self.stats.lock().total_executions += 1;
    }

    /// Record execution completion for a transaction.
    #[expect(clippy::too_many_arguments)]
    pub fn finish_execution(
        &self,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        reads: CapturedReads,
        writes: WriteSet,
        gas_used: u64,
        success: bool,
        mv_hashmap: &MVHashMap,
        tx_da_size: u64,
    ) {
        // Separate regular writes and balance deltas
        let (regular_writes, balance_deltas) = writes.into_parts();

        // Apply regular writes to MVHashMap
        mv_hashmap.apply_writes(txn_idx, incarnation, regular_writes);

        // Apply balance deltas to MVHashMap
        // These are tracked separately for commutative accumulation
        mv_hashmap.apply_balance_deltas(txn_idx, incarnation, balance_deltas);

        // Update transaction state
        {
            let mut state = self.txn_states[txn_idx as usize].write();
            state.status = ExecutionStatus::Executed(incarnation);
            state.reads = Some(reads);
            state.writes = None; // Already applied to MVHashMap
            state.gas_used = gas_used;
            state.success = success;
            state.tx_da_size = tx_da_size;
        }

        // Try to commit if this is the next transaction to commit
        self.try_commit(mv_hashmap);
    }

    /// Abort a transaction due to a conflict.
    #[instrument(
        level = "info",
        name = "block_stm_tx_abort",
        skip(self, mv_hashmap),
        fields(txn_idx)
    )]
    pub fn abort(&self, txn_idx: TxnIndex, mv_hashmap: &MVHashMap) {
        let mut state = self.txn_states[txn_idx as usize].write();

        // Increment incarnation for re-execution
        state.incarnation += 1;
        state.status = ExecutionStatus::Aborted(state.incarnation - 1);
        state.reads = None;
        state.writes = None;

        self.stats.lock().total_aborts += 1;

        // Clear MVHashMap entries and get dependents to abort
        mv_hashmap.delete_writes(txn_idx);
        let dependents = mv_hashmap.mark_aborted(txn_idx);

        drop(state);

        // Schedule re-execution at the FRONT of the queue.
        // Aborted transactions block commits, so they should be prioritized.
        self.execution_queue.lock().push_front(txn_idx);

        // Abort dependent transactions
        for dep_idx in dependents {
            if dep_idx > txn_idx {
                self.abort(dep_idx, mv_hashmap);
            }
        }

        self.notify_work();
    }

    /// Recursively mark a transaction and its same-sender dependents as LimitExceeded.
    ///
    /// Different-sender dependents are aborted for retry.
    fn mark_limit_exceeded_recursive(&self, txn_idx: TxnIndex, mv_hashmap: &MVHashMap) {
        let sender = self.tx_senders[txn_idx as usize];

        // Clean up MVHashMap
        mv_hashmap.delete_writes(txn_idx);
        let dependents = mv_hashmap.mark_aborted(txn_idx);

        // Mark as LimitExceeded
        {
            let mut state = self.txn_states[txn_idx as usize].write();
            state.status = ExecutionStatus::LimitExceeded;
        }

        // Cascade: same sender → LimitExceeded, different sender → abort for retry
        for dep_idx in dependents {
            if dep_idx > txn_idx {
                let dep_sender = self.tx_senders[dep_idx as usize];
                if dep_sender == sender {
                    self.mark_limit_exceeded_recursive(dep_idx, mv_hashmap);
                } else {
                    self.abort(dep_idx, mv_hashmap);
                }
            }
        }
    }

    /// Try to commit transactions in order.
    ///
    /// Uses compare_exchange on commit_idx to ensure exactly one thread
    /// commits each transaction, preventing race conditions in stats tracking.
    fn try_commit(&self, mv_hashmap: &MVHashMap) {
        loop {
            let commit_idx = self.commit_idx.load(Ordering::SeqCst);
            if commit_idx >= self.num_txns {
                // All transactions committed
                *self.done.write() = true;
                self.notify_work();
                return;
            }

            let state = self.txn_states[commit_idx].read();

            // Check if the transaction at commit_idx is ready to commit
            match state.status {
                ExecutionStatus::Executed(_incarnation) => {
                    // Validate the transaction
                    if self.validate_transaction(commit_idx as TxnIndex, &state, mv_hashmap) {
                        drop(state);

                        // Check if this transaction would exceed block limits
                        // Sum from committed_gas/committed_da vectors which are written BEFORE
                        // commit_idx advances, ensuring race-free reading
                        let mut cumulative_gas = self.initial_gas_used;
                        let mut cumulative_da = self.initial_da_used;

                        for i in 0..commit_idx {
                            // Read from atomic vectors - these are written before commit_idx advances
                            // LimitExceeded transactions have 0 in these vectors
                            cumulative_gas += self.committed_gas[i].load(Ordering::SeqCst);
                            cumulative_da += self.committed_da[i].load(Ordering::SeqCst);
                        }

                        // Check if current transaction would exceed limits
                        let state = self.txn_states[commit_idx].read();
                        let tx_gas = state.gas_used;
                        let tx_da = state.tx_da_size;
                        let would_exceed_gas = cumulative_gas + tx_gas > self.block_gas_limit;
                        let would_exceed_tx_da =
                            self.tx_da_limit.is_some_and(|limit| tx_da > limit);
                        let would_exceed_block_da = self
                            .block_da_limit
                            .is_some_and(|limit| cumulative_da + tx_da > limit);

                        if would_exceed_gas || would_exceed_tx_da || would_exceed_block_da {
                            // Transaction exceeds limits - mark as LimitExceeded and cascade
                            let current_sender = self.tx_senders[commit_idx];
                            drop(state);

                            // Clean up MVHashMap (like abort does)
                            mv_hashmap.delete_writes(commit_idx as TxnIndex);
                            let dependents = mv_hashmap.mark_aborted(commit_idx as TxnIndex);

                            // Mark this transaction as LimitExceeded
                            {
                                let mut state = self.txn_states[commit_idx].write();
                                state.status = ExecutionStatus::LimitExceeded;
                            }

                            // Handle dependents:
                            // - Same sender: Mark LimitExceeded (nonce dependency, permanent)
                            // - Different sender: Abort for retry (data dependency only)
                            for dep_idx in dependents {
                                if dep_idx > commit_idx as TxnIndex {
                                    let dep_sender = self.tx_senders[dep_idx as usize];
                                    if dep_sender == current_sender {
                                        self.mark_limit_exceeded_recursive(dep_idx, mv_hashmap);
                                    } else {
                                        self.abort(dep_idx, mv_hashmap);
                                    }
                                }
                            }

                            // Write 0 to committed vectors BEFORE advancing commit_idx
                            // (LimitExceeded transactions don't count toward cumulative limits)
                            self.committed_gas[commit_idx].store(0, Ordering::SeqCst);
                            self.committed_da[commit_idx].store(0, Ordering::SeqCst);

                            // Advance commit_idx past this transaction
                            // If compare_exchange fails, another thread already handled this transaction
                            let _ = self.commit_idx.compare_exchange(
                                commit_idx,
                                commit_idx + 1,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            );
                            // Continue regardless - either we advanced or another thread did
                            continue;
                        }

                        drop(state);

                        // Write gas/da to committed vectors BEFORE advancing commit_idx
                        // This ensures any thread reading [0, new_commit_idx) sees correct values
                        self.committed_gas[commit_idx].store(tx_gas, Ordering::SeqCst);
                        self.committed_da[commit_idx].store(tx_da, Ordering::SeqCst);

                        // Atomically claim this commit slot using compare_exchange.
                        // Only the thread that successfully advances commit_idx is
                        // responsible for updating the status and incrementing stats.
                        match self.commit_idx.compare_exchange(
                            commit_idx,
                            commit_idx + 1,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_) => {
                                // We successfully claimed this commit slot
                                let _commit_span = tracing::info_span!(
                                    "block_stm_tx_commit",
                                    txn_idx = commit_idx
                                )
                                .entered();

                                {
                                    let mut state = self.txn_states[commit_idx].write();
                                    state.status = ExecutionStatus::Committed;
                                }

                                self.stats.lock().total_commits += 1;

                                // Continue to try committing the next transaction
                                continue;
                            }
                            Err(_) => {
                                // Another thread already claimed this slot,
                                // loop to check the next transaction
                                continue;
                            }
                        }
                    } else {
                        // Validation failed, abort and re-execute
                        drop(state);
                        self.abort(commit_idx as TxnIndex, mv_hashmap);
                        return;
                    }
                }
                _ => {
                    // Transaction not ready yet
                    return;
                }
            }
        }
    }

    /// Validate a transaction's read set.
    fn validate_transaction(
        &self,
        txn_idx: TxnIndex,
        state: &TxnState,
        mv_hashmap: &MVHashMap,
    ) -> bool {
        let validate_span = tracing::info_span!(
            "block_stm_tx_validate",
            txn_idx = txn_idx,
            error = tracing::field::Empty
        );
        let _entered = validate_span.enter();

        let reads = match &state.reads {
            Some(r) => r,
            None => return true, // No reads to validate
        };

        // Check each regular read to see if it's still valid
        for (key, captured) in reads.reads() {
            // Re-read from MVHashMap
            let current = mv_hashmap.read(txn_idx, key);

            match (captured.version, &current) {
                // Both read from same version - valid
                (Some(v1), crate::block_stm::types::ReadResult::Value { version: v2, .. })
                    if v1 == *v2 =>
                {
                    continue;
                }
                // Both read from base state - valid
                (None, crate::block_stm::types::ReadResult::NotFound) => continue,
                // Mismatch - invalid
                _ => {
                    validate_span.record("error", "read_version_mismatch");
                    return false;
                }
            }
        }

        // Check resolved balance reads (balance reads with deltas applied)
        for (address, resolved) in reads.resolved_balances() {
            // Re-resolve the balance with current deltas
            let current_result = mv_hashmap.resolve_balance(
                *address,
                txn_idx,
                resolved.base_value,
                resolved.base_version,
            );

            match current_result {
                Ok(current) => {
                    // Check if the resolved value is the same
                    if current.resolved_value != resolved.resolved_value {
                        validate_span.record("error", "balance_value_mismatch");
                        return false;
                    }

                    // Check if contributors are the same (versions match)
                    if current.contributors.len() != resolved.contributors.len() {
                        validate_span.record("error", "contributor_count_mismatch");
                        return false;
                    }

                    // Verify each contributor version matches
                    for (orig, curr) in resolved
                        .contributors
                        .iter()
                        .zip(current.contributors.iter())
                    {
                        if orig != curr {
                            validate_span.record("error", "contributor_version_mismatch");
                            return false;
                        }
                    }
                }
                Err(_aborted_txn_idx) => {
                    // One of the contributors was aborted
                    validate_span.record("error", "contributor_aborted");
                    return false;
                }
            }
        }

        true
    }

    /// Get the current execution statistics.
    pub fn get_stats(&self) -> SchedulerStats {
        let stats = self.stats.lock();
        SchedulerStats {
            total_executions: stats.total_executions,
            total_aborts: stats.total_aborts,
            total_commits: stats.total_commits,
        }
    }

    /// Get the status of a transaction.
    pub fn get_status(&self, txn_idx: TxnIndex) -> ExecutionStatus {
        self.txn_states[txn_idx as usize].read().status
    }

    /// Check if a transaction was committed (race-free using committed_gas vector).
    /// Returns true if the transaction contributed gas to the block (committed, not LimitExceeded).
    /// This is race-free because committed_gas is written BEFORE commit_idx advances.
    pub fn is_committed(&self, txn_idx: TxnIndex) -> bool {
        let idx = txn_idx as usize;
        if idx >= self.num_txns {
            return false;
        }
        // committed_gas > 0 means committed (LimitExceeded has 0)
        // But also check commit_idx to ensure we're looking at processed transactions
        idx < self.commit_idx.load(Ordering::SeqCst)
            && self.committed_gas[idx].load(Ordering::SeqCst) > 0
    }

    /// Get the gas used by a committed transaction.
    pub fn get_gas_used(&self, txn_idx: TxnIndex) -> u64 {
        self.txn_states[txn_idx as usize].read().gas_used
    }

    /// Check if a transaction was successful.
    pub fn was_successful(&self, txn_idx: TxnIndex) -> bool {
        self.txn_states[txn_idx as usize].read().success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_initial_state() {
        let scheduler = Scheduler::new(5, vec![Address::ZERO; 5], 0, 0, u64::MAX, None, None);

        assert_eq!(scheduler.num_txns(), 5);
        assert!(!scheduler.is_done());

        // All transactions should be queued for execution
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Task::Execute {
                txn_idx: 0,
                incarnation: 0
            }
        ));
    }

    #[test]
    fn test_scheduler_task_ordering() {
        let scheduler = Scheduler::new(3, vec![Address::ZERO; 3], 0, 0, u64::MAX, None, None);

        // Should get transactions in order
        assert!(matches!(
            scheduler.next_task(),
            Task::Execute { txn_idx: 0, .. }
        ));
        assert!(matches!(
            scheduler.next_task(),
            Task::Execute { txn_idx: 1, .. }
        ));
        assert!(matches!(
            scheduler.next_task(),
            Task::Execute { txn_idx: 2, .. }
        ));

        // No more tasks
        assert!(matches!(scheduler.next_task(), Task::NoTask));
    }

    #[test]
    fn test_scheduler_execution_flow() {
        let scheduler = Scheduler::new(2, vec![Address::ZERO; 2], 0, 0, u64::MAX, None, None);
        let mv = MVHashMap::new(2);

        // Execute tx0
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Task::Execute {
                txn_idx: 0,
                incarnation: 0
            }
        ));
        scheduler.start_execution(0, 0);

        let reads = CapturedReads::new();
        let writes = WriteSet::new();
        scheduler.finish_execution(0, 0, reads, writes, 21000, true, &mv, 100);

        // tx0 should now be committed
        assert!(matches!(
            scheduler.get_status(0),
            ExecutionStatus::Committed
        ));

        // Execute tx1
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Task::Execute {
                txn_idx: 1,
                incarnation: 0
            }
        ));
        scheduler.start_execution(1, 0);

        let reads = CapturedReads::new();
        let writes = WriteSet::new();
        scheduler.finish_execution(1, 0, reads, writes, 21000, true, &mv, 100);

        // tx1 should now be committed
        assert!(matches!(
            scheduler.get_status(1),
            ExecutionStatus::Committed
        ));

        // Should be done
        assert!(scheduler.is_done());
    }

    #[test]
    fn test_scheduler_abort_reschedules() {
        let scheduler = Scheduler::new(3, vec![Address::ZERO; 3], 0, 0, u64::MAX, None, None);
        let mv = MVHashMap::new(3);

        // Get all initial tasks
        let _ = scheduler.next_task(); // tx0
        let _ = scheduler.next_task(); // tx1
        let _ = scheduler.next_task(); // tx2

        // Abort tx1
        scheduler.start_execution(1, 0);
        scheduler.abort(1, &mv);

        // tx1 should be re-queued with incremented incarnation
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Task::Execute {
                txn_idx: 1,
                incarnation: 1
            }
        ));
    }

    #[test]
    fn test_scheduler_stats() {
        let scheduler = Scheduler::new(2, vec![Address::ZERO; 2], 0, 0, u64::MAX, None, None);
        let mv = MVHashMap::new(2);

        // Execute both transactions
        scheduler.start_execution(0, 0);
        scheduler.finish_execution(
            0,
            0,
            CapturedReads::new(),
            WriteSet::new(),
            21000,
            true,
            &mv,
            100,
        );

        scheduler.start_execution(1, 0);
        scheduler.finish_execution(
            1,
            0,
            CapturedReads::new(),
            WriteSet::new(),
            21000,
            true,
            &mv,
            100,
        );

        let stats = scheduler.get_stats();
        assert_eq!(stats.total_executions, 2);
        assert_eq!(stats.total_commits, 2);
        assert_eq!(stats.total_aborts, 0);
    }
}
