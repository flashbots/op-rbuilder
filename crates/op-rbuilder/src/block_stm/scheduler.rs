use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracing::info;

use crate::block_stm::{
    Version,
    types::{Incarnation, TxnIndex},
};
use std::{collections::HashSet, sync::Mutex};

/// Status of a transaction in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    Validate { version: Version },
    Execute { version: Version },
}

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

    fn decrease_validation_idx(&self, target_idx: usize) {
        // set to min of target_idx and current validation_idx
        self.validation_idx.fetch_min(target_idx, Ordering::SeqCst);
        self.decrease_cnt.fetch_add(1, Ordering::SeqCst);
    }

    fn check_done(&self) {
        let observed_cnt = self.decrease_cnt.load(Ordering::SeqCst);
        info!(
            "estimate done condition: {}, {}, {}, {}",
            self.execution_idx.load(Ordering::SeqCst),
            self.validation_idx.load(Ordering::SeqCst),
            self.num_active_tasks.load(Ordering::SeqCst),
            observed_cnt
        );
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
        info!("try to incarnate: {}", txn_idx);
        if txn_idx < self.num_txns {
            let mut status = self.txn_status[txn_idx as usize].lock().unwrap();
            if status.1 == ExecutionStatus::ReadyToExecute {
                status.1 = ExecutionStatus::Executing;
            }
            info!("incarnated: {}", txn_idx);
            return Some((txn_idx, status.0));
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_version_to_execute(&self) -> Option<(TxnIndex, Incarnation)> {
        info!(
            "next version to execute: {}",
            self.execution_idx.load(Ordering::SeqCst)
        );
        if self.execution_idx.load(Ordering::SeqCst) >= self.num_txns as usize {
            info!("next version to execute: done");
            info!(
                "execution_idx: {}",
                self.execution_idx.load(Ordering::SeqCst)
            );
            info!("num_txns: {}", self.num_txns);
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_execute = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        info!("next version to execute: {}", idx_to_execute);
        return self.try_incarnate(idx_to_execute as TxnIndex);
    }

    fn next_version_to_validate(&self) -> Option<(TxnIndex, Incarnation)> {
        info!(
            "next version to validate: {}",
            self.validation_idx.load(Ordering::SeqCst)
        );
        if self.validation_idx.load(Ordering::SeqCst) >= self.num_txns as usize {
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx_to_validate = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        info!("next version to validate: {}", idx_to_validate);
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
        info!(
            "next task: validation_idx: {}, execution_idx: {}",
            self.validation_idx.load(Ordering::SeqCst),
            self.execution_idx.load(Ordering::SeqCst)
        );
        if self.validation_idx.load(Ordering::SeqCst) < self.execution_idx.load(Ordering::SeqCst) {
            info!("next task: validation_idx < execution_idx");
            if let Some((txn_idx, incarnation)) = self.next_version_to_validate() {
                return Some(Task::Validate {
                    version: Version::new(txn_idx, incarnation),
                });
            }
        } else {
            info!("next task: execution_idx < validation_idx");
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
            debug_assert_eq!(txn_status.1, ExecutionStatus::Executing);
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
        info!("try to validate abort: {}", txn_idx);
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
