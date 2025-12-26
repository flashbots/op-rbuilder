use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::block_stm::{
    ExecutionStatus, Task, Version,
    types::{Incarnation, TxnIndex},
};
use std::{collections::HashSet, sync::Mutex};

pub struct Scheduler {
    execution_idx: AtomicUsize,
    validation_idx: AtomicUsize,
    decrease_cnt: AtomicUsize,
    num_active_tasks: AtomicUsize,
    done_marker: AtomicBool,
    txn_dependency: Vec<Mutex<HashSet<TxnIndex>>>,
    txn_status: Vec<Mutex<(Incarnation, ExecutionStatus)>>,
    num_txns: u32,
}

impl Scheduler {
    pub fn new(num_txns: usize) -> Self {
        Self {
            execution_idx: AtomicUsize::new(0),
            validation_idx: AtomicUsize::new(0),
            decrease_cnt: AtomicUsize::new(0),
            num_active_tasks: AtomicUsize::new(0),
            done_marker: AtomicBool::new(false),
            txn_dependency: std::iter::repeat_with(|| Mutex::new(HashSet::new()))
                .take(num_txns)
                .collect(),
            txn_status: std::iter::repeat_with(|| Mutex::new((0, ExecutionStatus::ReadyToExecute)))
                .take(num_txns)
                .collect(),
            num_txns: num_txns as u32,
        }
    }

    fn decrease_execution_idx(&self, target_idx: usize) {
        // set to min of target_idx and current execution_idx
        self.execution_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_cnt.fetch_add(1, Ordering::SeqCst);
    }

    pub fn done(&self) -> bool {
        self.done_marker.load(Ordering::SeqCst)
    }

    /// Get the current execution status of a transaction.
    pub fn get_status(&self, txn_idx: TxnIndex) -> ExecutionStatus {
        self.txn_status[txn_idx as usize].lock().unwrap().1
    }

    /// Get the total number of transactions.
    pub fn num_txns(&self) -> usize {
        self.num_txns as usize
    }

    fn decrease_validation_idx(&self, target_idx: usize) {
        // set to min of target_idx and current validation_idx
        self.validation_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_cnt.fetch_add(1, Ordering::SeqCst);
    }

    fn check_done(&self) {
        let observed_cnt = self.decrease_cnt.load(Ordering::SeqCst);
        if std::cmp::min(
            self.execution_idx.load(Ordering::SeqCst),
            self.validation_idx.load(Ordering::SeqCst),
        ) >= self.num_txns as usize
            && self.num_active_tasks.load(Ordering::SeqCst) == 0
            && observed_cnt == self.decrease_cnt.load(Ordering::SeqCst)
        {
            self.done_marker.store(true, Ordering::SeqCst);
        }
    }

    fn try_incarnate(&self, txn_idx: TxnIndex) -> Option<(TxnIndex, Incarnation)> {
        if txn_idx < self.num_txns {
            let mut status = self.txn_status[txn_idx as usize].lock().unwrap();
            if status.1 == ExecutionStatus::ReadyToExecute {
                status.1 = ExecutionStatus::Executing;
            }
            return Some((txn_idx, status.0));
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_execute(&self) -> Option<(TxnIndex, Incarnation)> {
        if self.execution_idx.load(Ordering::SeqCst) >= self.num_txns as usize {
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_execute = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        return self.try_incarnate(idx_to_execute as TxnIndex);
    }

    fn next_version_to_validate(&self) -> Option<(TxnIndex, Incarnation)> {
        if self.validation_idx.load(Ordering::SeqCst) >= self.num_txns as usize {
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx_to_validate < self.num_txns as usize {
            let (incarnation, status) = *self.txn_status[idx_to_validate as usize].lock().unwrap();
            if status == ExecutionStatus::Executed {
                return Some((idx_to_validate as TxnIndex, incarnation));
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    pub fn next_task(&self) -> Option<Task> {
        if self.validation_idx.load(Ordering::SeqCst) < self.execution_idx.load(Ordering::SeqCst) {
            if let Some((txn_idx, incarnation)) = self.next_version_to_validate() {
                return Some(Task::Validate {
                    version: Version::new(txn_idx, incarnation),
                });
            }
        } else {
            if let Some((txn_idx, incarnation)) = self.next_version_to_execute() {
                return Some(Task::Execute {
                    version: Version::new(txn_idx, incarnation),
                });
            }
        }
        None
    }

    pub fn add_dependency(&self, txn_idx: TxnIndex, dependency: TxnIndex) -> bool {
        {
            let mut dependencies = self.txn_dependency[txn_idx as usize].lock().unwrap();
            if self.txn_status[dependency as usize].lock().unwrap().1 == ExecutionStatus::Executed {
                return false;
            }

            self.txn_status[txn_idx as usize].lock().unwrap().1 = ExecutionStatus::Aborting;
            dependencies.insert(dependency);
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        true
    }

    fn set_ready_status(&self, txn_idx: TxnIndex) {
        let mut status = self.txn_status[txn_idx as usize].lock().unwrap();
        status.0 = status.0 + 1;
        status.1 = ExecutionStatus::ReadyToExecute;
    }

    fn resume_dependencies(&self, dependent_tx_idxs: &[TxnIndex]) {
        for txn_idx in dependent_tx_idxs.iter() {
            self.set_ready_status(*txn_idx);
        }
        let min_idx = dependent_tx_idxs.iter().min();
        if let Some(min_idx) = min_idx {
            self.decrease_execution_idx(*min_idx as usize);
        }
    }

    pub fn finish_execution(
        &self,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        wrote_new_path: bool,
    ) -> Option<Task> {
        {
            let mut txn_status = self.txn_status[txn_idx as usize].lock().unwrap();
            txn_status.1 = ExecutionStatus::Executed;
        }
        let mut deps = HashSet::new();
        std::mem::swap(
            &mut *self.txn_dependency[txn_idx as usize].lock().unwrap(),
            &mut deps,
        );
        self.resume_dependencies(&deps.iter().map(|&x| x as TxnIndex).collect::<Vec<_>>());
        if self.validation_idx.load(Ordering::SeqCst) > txn_idx as usize {
            if wrote_new_path {
                self.decrease_validation_idx(txn_idx as usize);
            } else {
                return Some(Task::Validate {
                    version: Version::new(txn_idx, incarnation),
                });
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    pub fn try_validation_abort(&self, txn_idx: TxnIndex, incarnation: Incarnation) -> bool {
        let mut txn_status = self.txn_status[txn_idx as usize].lock().unwrap();
        if *txn_status == (incarnation, ExecutionStatus::Executed) {
            txn_status.1 = ExecutionStatus::Aborting;
            return true;
        }
        false
    }

    pub fn finish_validation(&self, txn_idx: TxnIndex, aborted: bool) -> Option<Task> {
        if aborted {
            self.set_ready_status(txn_idx);
            self.decrease_validation_idx((txn_idx + 1) as usize);
            if self.execution_idx.load(Ordering::SeqCst) > txn_idx as usize {
                let new_version = self.try_incarnate(txn_idx as TxnIndex);
                if let Some(new_version) = new_version {
                    return Some(Task::Execute {
                        version: Version::new(new_version.0, new_version.1),
                    });
                }
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_new() {
        let scheduler = Scheduler::new(5);
        assert_eq!(scheduler.num_txns(), 5);
        assert!(!scheduler.done());
    }

    #[test]
    fn test_initial_status_is_ready_to_execute() {
        let scheduler = Scheduler::new(3);
        for i in 0..3 {
            assert_eq!(scheduler.get_status(i), ExecutionStatus::ReadyToExecute);
        }
    }

    #[test]
    fn test_first_task_is_execute() {
        let scheduler = Scheduler::new(3);
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Some(Task::Execute {
                version: Version {
                    txn_idx: 0,
                    incarnation: 0
                }
            })
        ));
    }

    #[test]
    fn test_execution_changes_status_to_executing() {
        let scheduler = Scheduler::new(3);
        let _ = scheduler.next_task(); // Get execute task for tx 0
        assert_eq!(scheduler.get_status(0), ExecutionStatus::Executing);
    }

    #[test]
    fn test_finish_execution_changes_status_to_executed() {
        let scheduler = Scheduler::new(3);
        let _ = scheduler.next_task(); // Execute tx 0
        scheduler.finish_execution(0, 0, false);
        assert_eq!(scheduler.get_status(0), ExecutionStatus::Executed);
    }

    #[test]
    fn test_validation_after_execution() {
        let scheduler = Scheduler::new(3);

        // Execute tx 0
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Execute { .. })));
        scheduler.finish_execution(0, 0, false);

        // Next task should be validation (validation_idx=0 < execution_idx=1)
        let task = scheduler.next_task();
        assert!(matches!(
            task,
            Some(Task::Validate {
                version: Version {
                    txn_idx: 0,
                    incarnation: 0
                }
            })
        ));

        // Finish validation (not aborted)
        scheduler.finish_validation(0, false);

        // Status should still be Executed after successful validation
        assert_eq!(scheduler.get_status(0), ExecutionStatus::Executed);
    }

    #[test]
    fn test_validation_abort_triggers_reexecution() {
        let scheduler = Scheduler::new(3);

        // Execute tx 0
        let _ = scheduler.next_task();
        scheduler.finish_execution(0, 0, false);

        // Get validation task
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Validate { .. })));

        // Try to abort validation
        let aborted = scheduler.try_validation_abort(0, 0);
        assert!(aborted);
        assert_eq!(scheduler.get_status(0), ExecutionStatus::Aborting);

        // Finish validation with abort=true
        let next_task = scheduler.finish_validation(0, true);

        // Should get re-execute task with incremented incarnation
        assert!(matches!(
            next_task,
            Some(Task::Execute {
                version: Version {
                    txn_idx: 0,
                    incarnation: 1
                }
            })
        ));
    }

    /// Helper to execute and validate a transaction through the scheduler.
    fn execute_and_validate(scheduler: &Scheduler, txn_idx: u32) {
        // Get execute task
        let task = scheduler.next_task();
        assert!(
            matches!(task, Some(Task::Execute { version }) if version.txn_idx == txn_idx),
            "Expected Execute task for tx {}, got {:?}",
            txn_idx,
            task
        );

        // Finish execution
        scheduler.finish_execution(txn_idx, 0, false);

        // Get validation task
        let task = scheduler.next_task();
        assert!(
            matches!(task, Some(Task::Validate { version }) if version.txn_idx == txn_idx),
            "Expected Validate task for tx {}, got {:?}",
            txn_idx,
            task
        );

        // Finish validation (success)
        scheduler.finish_validation(txn_idx, false);
    }

    #[test]
    fn test_safe_commit_point_all_executed() {
        let scheduler = Scheduler::new(3);

        // Execute and validate all transactions
        for i in 0..3 {
            execute_and_validate(&scheduler, i);
        }

        // All should be in Executed state
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, 3);
    }

    #[test]
    fn test_safe_commit_point_partial() {
        let scheduler = Scheduler::new(5);

        // Execute and validate tx 0, 1, 2
        for i in 0..3 {
            execute_and_validate(&scheduler, i);
        }

        // tx 3 starts executing but doesn't finish
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Execute { version }) if version.txn_idx == 3));

        // Safe commit point should be 3 (tx 0, 1, 2 are Executed and validated)
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, 3);
    }

    #[test]
    fn test_safe_commit_point_with_gap() {
        let scheduler = Scheduler::new(5);

        // Execute and validate tx 0
        execute_and_validate(&scheduler, 0);

        // Start tx 1 but don't finish
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Execute { version }) if version.txn_idx == 1));

        // Safe commit point should be 1 (only tx 0 is Executed)
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, 1);
    }

    #[test]
    fn test_safe_commit_point_none_executed() {
        let scheduler = Scheduler::new(3);

        // Start executing tx 0 but don't finish
        let _ = scheduler.next_task();

        // Safe commit point should be 0 (no transactions fully executed)
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, 0);
    }

    #[test]
    fn test_safe_commit_point_after_abort() {
        let scheduler = Scheduler::new(3);

        // Execute and validate tx 0
        execute_and_validate(&scheduler, 0);

        // Execute tx 1
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Execute { version }) if version.txn_idx == 1));
        scheduler.finish_execution(1, 0, false);

        // Get validation task for tx 1
        let task = scheduler.next_task();
        assert!(matches!(task, Some(Task::Validate { version }) if version.txn_idx == 1));

        // Abort tx 1 (simulating validation failure)
        scheduler.try_validation_abort(1, 0);
        scheduler.finish_validation(1, true);

        // tx 1 is now ReadyToExecute, not Executed
        // Safe commit point should be 1 (only tx 0)
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, 1);
    }

    // ==================== STRESS TESTS ====================

    use std::{sync::Arc, thread};

    /// Helper to run scheduler to completion, processing any task that comes up.
    fn run_scheduler_to_completion(scheduler: &Scheduler, max_iterations: usize) -> usize {
        let mut iterations = 0;
        while !scheduler.done() && iterations < max_iterations {
            iterations += 1;
            let task = scheduler.next_task();
            match task {
                Some(Task::Execute { version }) => {
                    scheduler.finish_execution(version.txn_idx, version.incarnation, false);
                }
                Some(Task::Validate { version }) => {
                    scheduler.finish_validation(version.txn_idx, false);
                }
                None => {
                    // No task available, yield and retry
                    thread::yield_now();
                }
            }
        }
        iterations
    }

    #[test]
    fn stress_test_sequential_execution_many_txns() {
        // Test that we can process many transactions
        let num_txns = 100;
        let scheduler = Scheduler::new(num_txns);

        let iterations = run_scheduler_to_completion(&scheduler, num_txns * 3);

        // Should complete within reasonable iterations
        assert!(
            iterations < num_txns * 3,
            "Took too many iterations: {}",
            iterations
        );

        // All transactions should be executed
        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, num_txns);
        assert!(scheduler.done());
    }

    #[test]
    fn stress_test_concurrent_task_fetching() {
        // Multiple threads competing to get tasks
        let num_txns = 50;
        let scheduler = Arc::new(Scheduler::new(num_txns));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let scheduler = Arc::clone(&scheduler);
                thread::spawn(move || {
                    let mut executed = Vec::new();
                    let mut iterations = 0;
                    while !scheduler.done() && iterations < 500 {
                        iterations += 1;
                        let task = scheduler.next_task();
                        match task {
                            Some(Task::Execute { version }) => {
                                // Simulate execution
                                scheduler.finish_execution(
                                    version.txn_idx,
                                    version.incarnation,
                                    false,
                                );
                                executed.push(version.txn_idx);
                            }
                            Some(Task::Validate { version }) => {
                                // Simulate validation (always passes)
                                scheduler.finish_validation(version.txn_idx, false);
                            }
                            None => {
                                // No task available, yield and retry
                                thread::yield_now();
                            }
                        }
                    }
                    executed
                })
            })
            .collect();

        let mut all_executed: Vec<u32> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        all_executed.sort();
        all_executed.dedup();

        // All transactions should have been executed exactly once
        assert_eq!(all_executed.len(), num_txns);
        for i in 0..num_txns {
            assert!(all_executed.contains(&(i as u32)));
        }
    }

    #[test]
    fn stress_test_with_random_aborts() {
        use rand::prelude::*;

        let num_txns = 30;
        let scheduler = Arc::new(Scheduler::new(num_txns));

        let handles: Vec<_> = (0..4)
            .map(|_thread_id| {
                let scheduler = Arc::clone(&scheduler);
                thread::spawn(move || {
                    let mut rng = rand::rng();
                    let mut iterations = 0;
                    let max_iterations = 2000;
                    let mut pending_task: Option<Task> = None;

                    while !scheduler.done() && iterations < max_iterations {
                        iterations += 1;

                        // Get next task (either pending or from scheduler)
                        let task = pending_task.take().or_else(|| scheduler.next_task());

                        match task {
                            Some(Task::Execute { version }) => {
                                let next = scheduler.finish_execution(
                                    version.txn_idx,
                                    version.incarnation,
                                    false,
                                );
                                if let Some(Task::Validate { version: v }) = next {
                                    // Randomly abort 5% of validations
                                    if rng.random_ratio(1, 20) {
                                        let aborted = scheduler
                                            .try_validation_abort(v.txn_idx, v.incarnation);
                                        // Keep returned task (may be re-execute)
                                        pending_task =
                                            scheduler.finish_validation(v.txn_idx, aborted);
                                    } else {
                                        scheduler.finish_validation(v.txn_idx, false);
                                    }
                                }
                            }
                            Some(Task::Validate { version }) => {
                                // Randomly abort 5% of validations
                                if rng.random_ratio(1, 20) {
                                    let aborted = scheduler
                                        .try_validation_abort(version.txn_idx, version.incarnation);
                                    // Keep returned task (may be re-execute)
                                    pending_task =
                                        scheduler.finish_validation(version.txn_idx, aborted);
                                } else {
                                    scheduler.finish_validation(version.txn_idx, false);
                                }
                            }
                            None => {
                                thread::yield_now();
                            }
                        }
                    }
                    iterations
                })
            })
            .collect();

        for h in handles {
            let iterations = h.join().unwrap();
            assert!(
                iterations < 2000,
                "Thread hit max iterations: {}",
                iterations
            );
        }

        // Eventually all transactions should be executed
        assert!(scheduler.done(), "Scheduler did not complete");
    }

    #[test]
    fn stress_test_dependency_chains_debug() {
        // Test scheduler with selective aborts - debug version
        let num_txns = 20;
        let scheduler = Scheduler::new(num_txns);

        let mut abort_count = 0;
        let mut execution_count = vec![0u32; num_txns];
        let mut iterations = 0;
        let max_iterations = 500;
        let mut pending_task: Option<Task> = None;

        while !scheduler.done() && iterations < max_iterations {
            iterations += 1;

            // Get next task (either pending or from scheduler)
            let task = pending_task.take().or_else(|| scheduler.next_task());

            match task {
                Some(Task::Execute { version }) => {
                    execution_count[version.txn_idx as usize] += 1;
                    if iterations < 100 || iterations % 50 == 0 {
                        println!(
                            "Iter {}: Execute tx={} inc={}",
                            iterations, version.txn_idx, version.incarnation
                        );
                    }

                    let next =
                        scheduler.finish_execution(version.txn_idx, version.incarnation, false);
                    if let Some(Task::Validate { version: v }) = next {
                        // Abort every 3rd transaction on first incarnation only
                        if v.txn_idx % 3 == 0 && v.incarnation == 0 {
                            let aborted = scheduler.try_validation_abort(v.txn_idx, v.incarnation);
                            if aborted {
                                abort_count += 1;
                                println!(
                                    "Iter {}: ABORTED tx={} inc={} (inline)",
                                    iterations, v.txn_idx, v.incarnation
                                );
                            }
                            // finish_validation may return a re-execute task - keep it for next iteration
                            pending_task = scheduler.finish_validation(v.txn_idx, aborted);
                            if let Some(Task::Execute { version: next_v }) = pending_task {
                                println!(
                                    "Iter {}: finish_validation returned Execute tx={} inc={}",
                                    iterations, next_v.txn_idx, next_v.incarnation
                                );
                            }
                        } else {
                            scheduler.finish_validation(v.txn_idx, false);
                        }
                    }
                }
                Some(Task::Validate { version }) => {
                    if iterations < 100 || iterations % 50 == 0 {
                        println!(
                            "Iter {}: Validate tx={} inc={}",
                            iterations, version.txn_idx, version.incarnation
                        );
                    }

                    // Abort every 3rd transaction on first incarnation only
                    if version.txn_idx % 3 == 0 && version.incarnation == 0 {
                        let aborted =
                            scheduler.try_validation_abort(version.txn_idx, version.incarnation);
                        if aborted {
                            abort_count += 1;
                            println!(
                                "Iter {}: ABORTED tx={} inc={}",
                                iterations, version.txn_idx, version.incarnation
                            );
                        }
                        // finish_validation may return a re-execute task - keep it for next iteration
                        pending_task = scheduler.finish_validation(version.txn_idx, aborted);
                        if let Some(Task::Execute { version: next_v }) = pending_task {
                            println!(
                                "Iter {}: finish_validation returned Execute tx={} inc={}",
                                iterations, next_v.txn_idx, next_v.incarnation
                            );
                        }
                    } else {
                        scheduler.finish_validation(version.txn_idx, false);
                    }
                }
                None => {
                    if iterations % 100 == 0 {
                        println!("Iter {}: No task available", iterations);
                    }
                    thread::yield_now();
                }
            }
        }

        println!("\n=== Test Results ===");
        println!("Total iterations: {}", iterations);
        println!("Total aborts: {}", abort_count);
        println!("Scheduler done: {}", scheduler.done());
        println!("Execution counts: {:?}", execution_count);

        // Print final status
        for i in 0..num_txns {
            let status = scheduler.get_status(i as u32);
            if status != ExecutionStatus::Executed {
                println!("Tx {}: {:?}", i, status);
            }
        }

        assert!(scheduler.done(), "Scheduler should be done");
        assert!(
            iterations < 500,
            "Took too many iterations: {} (aborts: {})",
            iterations,
            abort_count
        );

        let safe_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(safe_commit_point, num_txns);
    }

    #[test]
    fn stress_test_rapid_abort_reexecute_cycle() {
        // Test that scheduler completes correctly even with aborts
        let num_txns = 10;
        let scheduler = Scheduler::new(num_txns);

        // Just run to completion with occasional random aborts
        use rand::prelude::*;
        let mut rng = rand::rng();
        let mut abort_count = 0;

        let iterations = run_scheduler_to_completion_with_aborts(&scheduler, 1000, |_version| {
            // Randomly abort 10% of validations
            if rng.random_ratio(1, 10) {
                abort_count += 1;
                true
            } else {
                false
            }
        });

        assert!(scheduler.done(), "Scheduler should complete");
        assert!(
            iterations < 1000,
            "Should complete within iteration limit, took {}",
            iterations
        );

        // All transactions should be executed
        for i in 0..num_txns {
            assert_eq!(
                scheduler.get_status(i as u32),
                ExecutionStatus::Executed,
                "Transaction {} should be executed",
                i
            );
        }
    }

    /// Helper that runs scheduler to completion with an abort callback.
    /// KEY: Always processes returned tasks from finish_validation/finish_execution.
    fn run_scheduler_to_completion_with_aborts<F>(
        scheduler: &Scheduler,
        max_iterations: usize,
        mut should_abort: F,
    ) -> usize
    where
        F: FnMut(Version) -> bool,
    {
        let mut iterations = 0;
        let mut pending_task: Option<Task> = None;

        while !scheduler.done() && iterations < max_iterations {
            iterations += 1;

            // Get next task (either pending or from scheduler)
            let task = pending_task.take().or_else(|| scheduler.next_task());

            match task {
                Some(Task::Execute { version }) => {
                    let next =
                        scheduler.finish_execution(version.txn_idx, version.incarnation, false);
                    if let Some(Task::Validate { version: v }) = next {
                        if should_abort(v) {
                            let aborted = scheduler.try_validation_abort(v.txn_idx, v.incarnation);
                            // Keep returned task (may be re-execute)
                            pending_task = scheduler.finish_validation(v.txn_idx, aborted);
                        } else {
                            scheduler.finish_validation(v.txn_idx, false);
                        }
                    }
                }
                Some(Task::Validate { version }) => {
                    if should_abort(version) {
                        let aborted =
                            scheduler.try_validation_abort(version.txn_idx, version.incarnation);
                        // Keep returned task (may be re-execute)
                        pending_task = scheduler.finish_validation(version.txn_idx, aborted);
                    } else {
                        scheduler.finish_validation(version.txn_idx, false);
                    }
                }
                None => {
                    thread::yield_now();
                }
            }
        }
        iterations
    }

    #[test]
    fn stress_test_safe_commit_point_under_contention() {
        // Simulate a scenario where we check safe commit point while execution is ongoing
        let num_txns = 20;
        let scheduler = Arc::new(Scheduler::new(num_txns));

        // Start a worker thread
        let scheduler_clone = Arc::clone(&scheduler);
        let worker = thread::spawn(move || {
            let mut iterations = 0;
            while !scheduler_clone.done() && iterations < 500 {
                iterations += 1;
                let task = scheduler_clone.next_task();
                match task {
                    Some(Task::Execute { version }) => {
                        // Small delay to simulate work
                        thread::yield_now();
                        scheduler_clone.finish_execution(
                            version.txn_idx,
                            version.incarnation,
                            false,
                        );
                    }
                    Some(Task::Validate { version }) => {
                        scheduler_clone.finish_validation(version.txn_idx, false);
                    }
                    None => {
                        thread::yield_now();
                    }
                }
            }
        });

        // Meanwhile, repeatedly check the safe commit point
        let mut max_commit_point = 0;
        for _ in 0..100 {
            let commit_point = (0..scheduler.num_txns())
                .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
                .count();

            // Commit point should only increase (or stay same)
            assert!(
                commit_point >= max_commit_point,
                "Commit point went backwards: {} -> {}",
                max_commit_point,
                commit_point
            );
            max_commit_point = commit_point;

            thread::yield_now();
        }

        worker.join().unwrap();

        // Final commit point should be all transactions
        let final_commit_point = (0..scheduler.num_txns())
            .take_while(|&i| scheduler.get_status(i as u32) == ExecutionStatus::Executed)
            .count();

        assert_eq!(final_commit_point, num_txns);
    }
}
