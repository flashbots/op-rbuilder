# Block-STM Parallel Transaction Execution

This module implements Block-STM style parallel transaction execution for the OP Stack payload builder. It enables speculative parallel execution of transactions with automatic conflict detection and resolution.

## Overview

Block-STM (Software Transactional Memory) is a parallel execution engine that:
1. **Speculatively executes** all transactions in parallel
2. **Tracks read/write sets** during execution for conflict detection
3. **Detects conflicts** via validation of read sets
4. **Re-executes** conflicting transactions with updated state
5. **Commits in order** to maintain sequential semantics

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Payload Builder                              │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    execute_best_transactions_parallel           │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                  │                                   │
│                                  ▼                                   │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                         Scheduler                               │ │
│  │  - Dispatches tasks to worker threads                          │ │
│  │  - Manages abort/re-execution on conflicts                     │ │
│  │  - Ensures in-order commits                                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                  │                                   │
│         ┌────────────────────────┼────────────────────────┐         │
│         ▼                        ▼                        ▼         │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐  │
│  │  Worker 0   │          │  Worker 1   │          │  Worker N   │  │
│  │             │          │             │          │             │  │
│  │ ┌─────────┐ │          │ ┌─────────┐ │          │ ┌─────────┐ │  │
│  │ │Versioned│ │          │ │Versioned│ │          │ │Versioned│ │  │
│  │ │Database │ │          │ │Database │ │          │ │Database │ │  │
│  │ └────┬────┘ │          │ └────┬────┘ │          │ └────┬────┘ │  │
│  └──────┼──────┘          └──────┼──────┘          └──────┼──────┘  │
│         │                        │                        │         │
│         └────────────────────────┼────────────────────────┘         │
│                                  ▼                                   │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                        MVHashMap                                │ │
│  │  - Multi-version data structure for all state keys             │ │
│  │  - Tracks writes per (txn_idx, incarnation)                    │ │
│  │  - Enables reads of earlier transactions' writes               │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                  │                                   │
│                                  ▼                                   │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                     Base State (Read-Only)                      │ │
│  │  - Shared reference to State<DB>                                │ │
│  │  - Fallback for keys not in MVHashMap                          │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### Types (`types.rs`)

Core type definitions:

| Type | Description |
|------|-------------|
| `TxnIndex` | Transaction index in the block (u32) |
| `Incarnation` | Execution attempt number (u32) |
| `Version` | Tuple of (TxnIndex, Incarnation) identifying a specific execution |
| `ExecutionStatus` | State machine: PendingScheduling → Executing → Executed → Committed |
| `Task` | Work unit: Execute, Validate, NoTask, Done |
| `EvmStateKey` | EVM state identifier (Balance, Nonce, Code, Storage, BlockHash) |
| `EvmStateValue` | Corresponding state values |
| `ReadResult` | Result of reading from MVHashMap (Value, NotFound, Aborted) |

### MVHashMap (`mv_hashmap.rs`)

Multi-version data structure that stores versioned writes:

```rust
// Structure (conceptual)
HashMap<EvmStateKey, BTreeMap<TxnIndex, VersionedEntry>>

struct VersionedEntry {
    incarnation: Incarnation,
    value: EvmStateValue,
    dependents: HashSet<TxnIndex>,  // For push-based invalidation
}
```

**Key Operations:**
- `read(txn_idx, key)` → Returns the latest write from txn < txn_idx
- `apply_writes(txn_idx, incarnation, writes)` → Records transaction's writes
- `delete_writes(txn_idx)` → Removes writes on abort
- `mark_aborted(txn_idx)` → Returns dependent transactions to abort

### CapturedReads (`captured_reads.rs`)

Tracks what each transaction read during execution:

```rust
struct CapturedReads {
    reads: HashMap<EvmStateKey, CapturedRead>,
}

struct CapturedRead {
    version: Option<Version>,  // None = read from base state
    value: EvmStateValue,
}
```

Used during validation to check if reads are still valid (no conflicting writes occurred).

### VersionedDatabase (`db_adapter.rs`)

Implements `revm::Database` for use with the EVM:

```rust
struct VersionedDatabase<'a, BaseDB> {
    txn_idx: TxnIndex,
    incarnation: Incarnation,
    mv_hashmap: &'a MVHashMap,
    base_db: &'a BaseDB,
    captured_reads: Mutex<CapturedReads>,
    aborted: Mutex<Option<TxnIndex>>,
}
```

**Read Flow:**
1. Check MVHashMap for writes from earlier transactions
2. If found and not aborted → return value, record read
3. If aborted → mark self as aborted (will re-execute)
4. If not found → read from base_db, record read

### Scheduler (`scheduler.rs`)

Coordinates parallel execution:

```rust
struct Scheduler {
    num_txns: usize,
    txn_states: Vec<RwLock<TxnState>>,
    execution_queue: Mutex<VecDeque<TxnIndex>>,
    commit_idx: AtomicUsize,  // Next transaction to commit
    // ...
}
```

**Task Flow:**
1. Workers call `next_task()` to get work
2. Execute transaction with `VersionedDatabase`
3. Call `finish_execution()` with read/write sets
4. Scheduler validates and commits in order
5. On conflict → abort and re-schedule

### WriteSet (`view.rs`)

Collects writes during transaction execution:

```rust
struct WriteSet {
    writes: HashMap<EvmStateKey, EvmStateValue>,
}
```

## Execution Flow

### 1. Initialization

```rust
let scheduler = Scheduler::new(num_candidates);
let mv_hashmap = MVHashMap::new(num_candidates);
let execution_results = vec![None; num_candidates];
```

### 2. Parallel Execution Phase

Each worker thread:

```rust
loop {
    match scheduler.next_task() {
        Task::Execute { txn_idx, incarnation } => {
            // Create versioned database for this transaction
            let versioned_db = VersionedDatabase::new(
                txn_idx, incarnation, &mv_hashmap, &base_db
            );
            
            // Wrap in State for EVM
            let mut tx_state = State::builder()
                .with_database(versioned_db)
                .build();
            
            // Execute transaction
            let result = evm.transact(&tx);
            
            // Check for abort condition
            if tx_state.database.was_aborted() {
                // Will be re-scheduled
                scheduler.finish_execution(..., success=false);
                continue;
            }
            
            // Build write set from state changes
            let write_set = build_write_set(&state);
            let captured_reads = tx_state.database.take_captured_reads();
            
            // Report to scheduler (may trigger commit)
            scheduler.finish_execution(
                txn_idx, incarnation,
                captured_reads, write_set,
                gas_used, success, &mv_hashmap
            );
        }
        Task::Done => break,
        // ...
    }
}
```

### 3. Validation & Commit

The scheduler's `try_commit()` validates transactions in order:

```rust
fn try_commit(&self, mv_hashmap: &MVHashMap) {
    loop {
        let commit_idx = self.commit_idx.load();
        let state = self.txn_states[commit_idx].read();
        
        match state.status {
            ExecutionStatus::Executed(incarnation) => {
                // Validate read set
                if self.validate_transaction(commit_idx, &state, mv_hashmap) {
                    // Commit!
                    state.status = ExecutionStatus::Committed;
                    self.commit_idx.fetch_add(1);
                } else {
                    // Conflict detected, abort and re-execute
                    self.abort(commit_idx, mv_hashmap);
                    return;
                }
            }
            _ => return, // Not ready yet
        }
    }
}
```

### 4. Sequential Commit Phase

After all workers complete, process results in order:

```rust
for (txn_idx, result) in execution_results.iter().enumerate() {
    if let Some(tx_result) = result {
        // Update cumulative gas
        info.cumulative_gas_used += tx_result.gas_used;
        
        // Build receipt with correct cumulative gas
        let receipt = build_receipt(tx_result, info.cumulative_gas_used);
        info.receipts.push(receipt);
        
        // Load accounts into cache and commit state
        for address in tx_result.state.keys() {
            db.load_cache_account(*address);
        }
        db.commit(tx_result.state);
    }
}
```

## Conflict Detection

A conflict occurs when:
1. Transaction A reads key K at version V
2. Transaction B (where B < A) writes to key K at version V' > V
3. Transaction A's read is now stale

**Detection via Read Set Validation:**
```rust
fn validate_transaction(&self, txn_idx: TxnIndex, state: &TxnState) -> bool {
    for (key, captured_read) in state.reads.iter() {
        let current = mv_hashmap.read(txn_idx, key);
        
        // Check if read version matches current version
        if captured_read.version != current.version {
            return false;  // Conflict!
        }
    }
    true
}
```

## EVM State Mapping

| EVM State | EvmStateKey | EvmStateValue |
|-----------|-------------|---------------|
| Account balance | `Balance(Address)` | `Balance(U256)` |
| Account nonce | `Nonce(Address)` | `Nonce(u64)` |
| Contract code | `Code(Address)` | `Code(Bytes)` |
| Code hash | `CodeHash(Address)` | `CodeHash(B256)` |
| Storage slot | `Storage(Address, U256)` | `Storage(U256)` |
| Block hash | `BlockHash(u64)` | `BlockHash(B256)` |

## Performance Considerations

1. **Thread Count**: Currently hardcoded to 4. Should be tuned based on:
   - Number of CPU cores
   - Transaction complexity
   - Contention patterns

2. **Conflict Rate**: High conflict rates reduce parallelism benefit
   - Common patterns: DEX swaps to same pool, token transfers
   - Low-conflict blocks benefit most

3. **Overhead**: Parallel execution adds overhead from:
   - MVHashMap lookups
   - Read set tracking
   - Validation and potential re-execution

4. **Optimal Scenarios**:
   - Many independent transactions
   - Low state contention
   - Complex transactions (amortizes overhead)

## Future Improvements

- [ ] Configurable thread count
- [ ] Metrics for conflict rate and re-execution count
- [ ] Adaptive parallelism based on conflict patterns
- [ ] Pre-execution dependency analysis
- [ ] Resource group optimization (batch related storage slots)

