use std::{
    collections::hash_map::Entry,
    sync::{Arc, Mutex},
    thread,
};

use alloy_consensus::Transaction;
use alloy_primitives::{Address, U256};
use op_revm::{OpHaltReason, OpTransactionError};
use reth_node_api::PayloadBuilderError;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use reth_revm::State;
use revm::{
    Database, DatabaseRef,
    context::result::{EVMError, ResultAndState},
    primitives::HashMap,
    state::{Account, EvmState},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn, Span};

use crate::{
    block_stm::{
        EvmStateKey, EvmStateValue, ExecutionStatus, MVHashMap, Scheduler, SharedCodeCache, Task,
        ValidationResult, Version, VersionedDatabase, VersionedDbError,
        mv_hashmap::{ReadSet, WriteSet},
    },
    tx::FBPoolTransaction,
};

/// Result of executing a single transaction in parallel.
/// Stored for deferred commit during the commit phase.
#[derive(Clone)]
pub struct TxExecutionResult {
    /// The transaction that was executed
    pub tx: Recovered<op_alloy_consensus::OpTxEnvelope>,
    /// State changes from execution (using alloy's HashMap for compatibility)
    pub state: StateWithIncrements,
    /// Whether execution succeeded
    pub success: bool,
    /// Logs from execution (needed for receipt building)
    pub logs: Vec<alloy_primitives::Log>,
    /// Gas used
    pub gas_used: u64,
    /// DA size
    pub tx_da_size: u64,
    pub miner_fee: u128,
}

#[derive(Clone)]
pub struct StateWithIncrements {
    pub loaded_state: EvmState,
    pub pending_balance_increments: HashMap<Address, U256>,
}

impl StateWithIncrements {
    pub fn resolve_state<DB: Database>(self, db: &mut DB) -> Result<EvmState, DB::Error> {
        let mut state = self.loaded_state;
        for (addr, delta) in self.pending_balance_increments.iter() {
            match state.entry(*addr) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().info.balance = entry.get().info.balance.saturating_add(*delta);
                }
                Entry::Vacant(entry) => {
                    let mut account = db.basic(*addr)?.unwrap_or_default();
                    account.balance = account.balance.saturating_add(*delta);
                    let mut account: Account = account.into();
                    account.mark_touch();
                    entry.insert(account);
                }
            }
        }
        Ok(state)
    }
}

pub struct Executor<
    Tx: FBPoolTransaction<Consensus = OpTransactionSigned>,
    DB: Database + DatabaseRef,
> {
    execution_results: Arc<Mutex<Vec<Option<TxExecutionResult>>>>,
    scheduler: Arc<Scheduler>,
    mv_hashmap: Arc<MVHashMap>,
    pub shared_code_cache: SharedCodeCache,

    num_threads: usize,
    transactions: Vec<Tx>,
    base_db: DB,
}

impl<
    Tx: FBPoolTransaction<Consensus = OpTransactionSigned>,
    DB: Database + DatabaseRef + Send + Sync,
> Executor<Tx, DB>
{
    pub fn new(num_threads: usize, transactions: Vec<Tx>, base_db: DB) -> Self {
        Executor {
            num_threads,
            execution_results: Arc::new(Mutex::new(vec![None; transactions.len()])),
            scheduler: Arc::new(Scheduler::new(transactions.len())),
            mv_hashmap: Arc::new(MVHashMap::new(transactions.len())),
            transactions,
            shared_code_cache: SharedCodeCache::default(),
            base_db,
        }
    }

    pub fn execute_single_tx<
        ExecuteTxFn: (Fn(
                &Recovered<op_alloy_consensus::OpTxEnvelope>,
                &mut State<VersionedDatabase<'_, DB>>,
            ) -> Result<
                ResultAndState<OpHaltReason>,
                EVMError<VersionedDbError, OpTransactionError>,
            >) + Send
            + Sync,
    >(
        &self,
        version: Version,
        base_fee: u64,
        execute_tx: &Arc<ExecuteTxFn>,
    ) -> (ReadSet, WriteSet, TxExecutionResult) {
        let Version {
            txn_idx,
            incarnation,
        } = version;

        let pool_tx = &self.transactions[txn_idx as usize];
        let tx_da_size = pool_tx.estimated_da_size();
        let tx = pool_tx.clone().into_consensus();

        // Routes reads through MVHashMap, falls back to base state
        let versioned_db = VersionedDatabase::new(
            txn_idx,
            &self.mv_hashmap,
            &self.base_db,
            Arc::clone(&self.shared_code_cache),
        );

        // Create State wrapper for EVM execution
        let mut tx_state = State::builder().with_database(versioned_db).build();

        // // Wrap State with LazyDatabaseWrapper to support lazy balance increments
        // let mut lazy_state =
        //     crate::block_stm::evm::LazyDatabaseWrapper::new(tx_state);

        // Execute transaction with versioned state
        let (read_set, write_set, exec_result) = match execute_tx(&tx, &mut tx_state) {
            Ok(result) => {
                let ResultAndState { result, state } = result;
                let gas_used = result.gas_used();

                // Build write set from state changes
                let mut write_set = WriteSet::new();
                let db_mut = &mut tx_state.database;
                let read_set = db_mut.take_read_set();
                let captured_reads = db_mut.take_captured_reads();

                // Add writes only for values that actually changed
                for (addr, account) in state.iter() {
                    debug!("Account touched: {}", addr);
                    if account.is_touched() {
                        // Get original values from captured reads (if available)
                        let original_balance = captured_reads.get(&EvmStateKey::Balance(*addr));
                        let original_nonce = captured_reads.get(&EvmStateKey::Nonce(*addr));
                        let original_code_hash = captured_reads.get(&EvmStateKey::CodeHash(*addr));

                        // Only write balance if it changed
                        if original_balance != Some(&EvmStateValue::Balance(account.info.balance)) {
                            write_set.insert((
                                EvmStateKey::Balance(*addr),
                                EvmStateValue::Balance(account.info.balance),
                            ));
                        }

                        // Only write nonce if it changed
                        if original_nonce != Some(&EvmStateValue::Nonce(account.info.nonce)) {
                            write_set.insert((
                                EvmStateKey::Nonce(*addr),
                                EvmStateValue::Nonce(account.info.nonce),
                            ));
                        }

                        // Only write code hash if it changed
                        if original_code_hash
                            != Some(&EvmStateValue::CodeHash(account.info.code_hash))
                        {
                            write_set.insert((
                                EvmStateKey::CodeHash(*addr),
                                EvmStateValue::CodeHash(account.info.code_hash),
                            ));

                            // Store bytecode in shared cache for lookup by later transactions
                            // This is critical: when a contract is deployed, its bytecode must be
                            // accessible to subsequent transactions via code_by_hash_ref()
                            if let Some(ref code) = account.info.code {
                                self.shared_code_cache
                                    .insert(account.info.code_hash, code.clone());
                            }
                        }

                        // Storage slots already have is_changed() check
                        for (slot, value) in account.storage.iter() {
                            if value.is_changed() {
                                write_set.insert((
                                    EvmStateKey::Storage(*addr, *slot),
                                    EvmStateValue::Storage(value.present_value),
                                ));
                            }
                        }
                    }
                }

                // // Add pending balance increments as deltas (commutative fee accumulation)
                // // These are tracked separately to allow parallel accumulation
                // for (addr, delta) in pending_balance_increments.iter() {
                //     write_set.add_balance_delta(*addr, *delta);
                // }

                // Get captured reads for validation

                // Extract success and logs from result
                let success = result.is_success();

                if !success {
                    warn!(
                        target: "block_stm",
                        txn_idx = txn_idx,
                        incarnation = incarnation,
                        result = ?result,
                        "Transaction reverted"
                    );
                }
                let logs = result.into_logs();

                let miner_fee = tx
                    .effective_tip_per_gas(base_fee)
                    .expect("fee is always valid");

                (
                    read_set,
                    write_set,
                    TxExecutionResult {
                        tx,
                        state: StateWithIncrements {
                            loaded_state: state,
                            pending_balance_increments: Default::default(),
                        },
                        success,
                        logs,
                        gas_used,
                        tx_da_size,
                        miner_fee: miner_fee,
                    },
                )
            }
            Err(EVMError::Database(VersionedDbError::ReadAborted { aborted_txn_idx })) => {
                if !self.scheduler.add_dependency(txn_idx, aborted_txn_idx) {
                    return self.execute_single_tx(version, base_fee, execute_tx);
                }
                let db_mut = &mut tx_state.database;

                warn!(
                    target: "block_stm",
                    txn_idx = txn_idx,
                    incarnation = incarnation,
                    aborted_txn_idx = aborted_txn_idx,
                    "Read aborted for transaction"
                );

                let read_set = db_mut.take_read_set();
                (
                    read_set,
                    Default::default(),
                    TxExecutionResult {
                        tx,
                        state: StateWithIncrements {
                            loaded_state: EvmState::default(),
                            pending_balance_increments: Default::default(),
                        },
                        success: false,
                        logs: vec![],
                        gas_used: 0,
                        tx_da_size: 0,
                        miner_fee: 0,
                    },
                )
            }
            Err(err) => {
                let db_mut = &mut tx_state.database;

                let read_set = db_mut.take_read_set();

                warn!(
                    target: "block_stm",
                    txn_idx = txn_idx,
                    incarnation = incarnation,
                    error = %err,
                    "Error executing transaction"
                );
                (
                    read_set,
                    Default::default(),
                    TxExecutionResult {
                        tx,
                        state: StateWithIncrements {
                            loaded_state: EvmState::default(),
                            pending_balance_increments: Default::default(),
                        },
                        success: false,
                        logs: vec![],
                        gas_used: 0,
                        tx_da_size: 0,
                        miner_fee: 0,
                    },
                )
            }
        };

        (read_set, write_set, exec_result)
    }

    pub fn execute_transactions_parallel<
        ExecuteTxFn: (Fn(
                &Recovered<op_alloy_consensus::OpTxEnvelope>,
                &mut State<VersionedDatabase<'_, DB>>,
            ) -> Result<
                ResultAndState<OpHaltReason>,
                EVMError<VersionedDbError, OpTransactionError>,
            >) + Send
            + Sync,
    >(
        &mut self,
        base_fee: u64,
        cancellation_token: CancellationToken,
        execute_tx: ExecuteTxFn,
        parent_span: Span,
    ) {
        let num_candidates = self.transactions.len();
        let num_threads = self.num_threads.min(num_candidates);

        let this = Arc::new(self);
        let cancellation_token = Arc::new(cancellation_token);
        let execute_tx = Arc::new(execute_tx);

        thread::scope(|s: &thread::Scope<'_, '_>| {
            for worker_id in 0..num_threads {
                let this = Arc::clone(&this);
                let cancellation_token = Arc::clone(&cancellation_token);
                let execute_tx = Arc::clone(&execute_tx);
                let worker_span = tracing::info_span!(
                    parent: &parent_span,
                    "block_stm_worker",
                    worker_id = worker_id
                );
                s.spawn(move || {
                    let _worker_guard = worker_span.entered();
                    debug!("Spawning worker thread {}", worker_id);

                    let mut task = None;

                    while !this.scheduler.done() {
                        let is_cancelled = cancellation_token.is_cancelled();

                        // Finish validation tasks only if cancelled.
                        if is_cancelled && !matches!(task, Some(Task::Validate { version })) {
                            break;
                        }
                        task = if let Some(Task::Execute { version }) = task {
                            let Version {
                                txn_idx,
                                incarnation,
                            } = version;
                            
                            let tx_execute_span = tracing::info_span!(
                                parent: Span::current(),
                                "block_stm_tx_execute",
                                txn_idx = txn_idx,
                                incarnation = incarnation
                            );
                            let _tx_execute_guard = tx_execute_span.entered();
                            
                            debug!(
                                worker_id = worker_id,
                                txn_idx = txn_idx,
                                incarnation = incarnation,
                                "Starting execution task"
                            );
                            
                            let (read_set, write_set, exec_result) = this.execute_single_tx(version, base_fee, &execute_tx);

                            {
                                let mut results = this.execution_results.lock().unwrap();
                                results[txn_idx as usize] = Some(exec_result);
                            }

                            let wrote_new_path = this.mv_hashmap.record(version, &read_set, &write_set);

                            let next_task = this
                                .scheduler
                                .finish_execution(txn_idx, incarnation, wrote_new_path);
                            debug!(
                                worker_id = worker_id,
                                txn_idx = txn_idx,
                                incarnation = incarnation,
                                wrote_new_path = wrote_new_path,
                                "Finished execution task"
                            );
                            next_task
                        } else {
                            task
                        };
                        task = if let Some(Task::Validate {
                            version:
                                Version {
                                    txn_idx,
                                    incarnation,
                                },
                        }) = task
                        {
                            let tx_validate_span = tracing::info_span!(
                                parent: Span::current(),
                                "block_stm_tx_validate",
                                txn_idx = txn_idx,
                                incarnation = incarnation
                            );
                            let _tx_validate_guard = tx_validate_span.entered();
                            
                            debug!(
                                worker_id = worker_id,
                                txn_idx = txn_idx,
                                incarnation = incarnation,
                                "Starting validation task"
                            );

                            let validation_result = this.mv_hashmap.validate_read_set_detailed(txn_idx);
                            let read_set_valid = matches!(validation_result, ValidationResult::Valid);

                            let aborted = !read_set_valid
                                && this.scheduler.try_validation_abort(txn_idx, incarnation);

                            if aborted {
                                // Log conflict details at warn level
                                if let ValidationResult::Conflict {
                                    key,
                                    expected_version,
                                    actual_version,
                                } = validation_result
                                {
                                    warn!(
                                        worker_id = worker_id,
                                        txn_idx = txn_idx,
                                        incarnation = incarnation,
                                        key = %key,
                                        expected_version = ?expected_version,
                                        actual_version = ?actual_version,
                                        "Block-STM conflict detected: transaction aborted due to stale read"
                                    );
                                }
                                this.mv_hashmap.convert_writes_to_estimates(txn_idx);
                            }
                            
                            let next_task = this.scheduler.finish_validation(txn_idx, aborted);
                            debug!(
                                worker_id = worker_id,
                                txn_idx = txn_idx,
                                incarnation = incarnation,
                                aborted = aborted,
                                read_set_valid = read_set_valid,
                                "Finished validation task"
                            );
                            next_task
                        } else {
                            task
                        };
                        if task.is_none() {
                            // Get next task from Block-STM scheduler
                            task = this.scheduler.next_task();
                            if task.is_none() {
                                std::thread::yield_now();
                            }
                        }
                    }
                    
                    debug!(
                        worker_id = worker_id,
                        scheduler_done = this.scheduler.done(),
                        cancelled = cancellation_token.is_cancelled(),
                        "Worker thread exiting"
                    );
                });
            }
        });
        
        debug!(
            "All worker threads completed. Scheduler done: {}, Execution idx: {}, Validation idx: {}",
            this.scheduler.done(),
            this.scheduler.execution_idx(),
            this.scheduler.validation_idx()
        );
    }

    pub fn try_into_committed_results(
        self,
    ) -> Result<(Vec<TxExecutionResult>, SharedCodeCache), PayloadBuilderError> {
        // Calculate the safe commit point: longest prefix of fully validated transactions.
        // A transaction is safe to commit only if:
        // 1. It has ExecutionStatus::Executed (not Aborting/ReadyToExecute/Executing)
        // 2. Validation has passed this transaction (validation_idx > i)
        // Note: validation_idx indicates how far validation has progressed, not just how far
        // execution has progressed.
        let validation_idx = self.scheduler.validation_idx();
        let safe_commit_point = (0..self.scheduler.num_txns())
            .take_while(|&i| {
                self.scheduler.get_status(i as u32) == ExecutionStatus::Executed
                    && validation_idx > i
            })
            .count();

        // Commit phase: apply results in order
        let results = Arc::try_unwrap(self.execution_results)
            .map_err(|_| PayloadBuilderError::Other("Failed to unwrap execution results".into()))?
            .into_inner()
            .unwrap();

        Ok((
            results
                .into_iter()
                .take(safe_commit_point)
                .filter_map(|r| r)
                .collect(),
            self.shared_code_cache,
        ))
    }
}
