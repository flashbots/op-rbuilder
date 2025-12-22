//! Block-STM: Parallel Transaction Execution Engine for EVM
//!
//! This module implements a parallel execution engine for EVM transactions based on
//! the Block-STM algorithm. Block-STM enables speculative parallel execution by:
//!
//! 1. Executing all transactions in parallel speculatively
//! 2. Tracking read/write sets during execution
//! 3. Detecting conflicts via push-based invalidation
//! 4. Re-executing conflicting transactions
//! 5. Committing results in transaction order
//!
//! # Architecture
//!
//! - [`types`]: Core types (TxnIndex, Version, EvmStateKey)
//! - [`mv_hashmap`]: Multi-version data structure for concurrent state access
//! - [`captured_reads`]: Read set tracking during execution
//! - [`view`]: Versioned state view implementing revm's Database trait
//! - [`scheduler`]: Transaction scheduling and abort management
//! - [`executor`]: Main parallel execution orchestrator

pub mod captured_reads;
pub mod db_adapter;
pub mod evm;
pub mod executor;
pub mod mv_hashmap;
pub mod scheduler;
pub mod types;
pub mod view;

#[cfg(test)]
mod tests;

// Re-export commonly used types
pub use captured_reads::CapturedReads;
pub use db_adapter::{VersionedDatabase, VersionedDbError};
pub use executor::BlockStmExecutor;
pub use mv_hashmap::MVHashMap;
pub use scheduler::Scheduler;
pub use types::{
    EvmStateKey, EvmStateValue, ExecutionStatus, Incarnation, ReadResult, Task, TxnIndex, Version,
};
