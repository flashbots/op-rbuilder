//! Backrun bundle support for op-rbuilder.
//!
//! A backrun bundle pairs a **target transaction** (already in the mempool) with a
//! single **backrun transaction** that is executed immediately after the target lands
//! in a block. Searchers submit bundles via the [`rpc`] module's
//! `eth_sendBackrunBundle` RPC method.
//!
//!
//! # Bundle commit semantics
//!
//! During block building, after each successfully committed pool transaction the
//! builder checks whether any backrun bundles target that transaction. Candidates
//! are retrieved from the per-block [`payload_pool::BackrunBundlePayloadPool`],
//! ordered by descending effective priority fee, and filtered by:
//!
//! 1. **Block & flashblock validity** — the bundle must be valid for the current
//!    block number and flashblock index (`StoredBackrunBundle::is_valid`).
//! 2. **Priority fee floor** — the backrun's effective priority fee must be at
//!    least as high as the target transaction's miner fee.
//! 3. **EVM execution** — the backrun transaction is executed against the
//!    post-target state. If it reverts it is excluded.
//! 4. **Gas & DA limits** — standard per-transaction and per-block gas/DA limits
//!    apply, as well as per-address gas limits.
//!
//! A successfully committed backrun is appended to the block right after its
//! target transaction. Its fees contribute to `total_fees` and it counts
//! toward the shared `num_txs_considered` / `num_txs_simulated` counters just
//! like any other transaction.
//!
//! # Metrics
//!
//! **Pool metrics** (`op_rbuilder.backrun_pool.*`):
//! - `bundle_count` — current number of bundles across all payload pools.
//! - `backruns_per_tx` — distribution of backrun candidates per tx
//!
//! **Builder metrics** (`op_rbuilder.*`):
//! - `payload_num_backruns_considered` / `_gauge` — how many backrun candidates
//!   were evaluated during a single payload build.
//! - `payload_num_backruns_successful` / `_gauge` — how many were included.
//! - `backrun_transaction_processing_duration` / `_gauge` — wall-clock time spent
//!   processing backruns.
//!
//! Backrun transactions also increment the shared builder counters
//! (`num_txs_considered`, `num_txs_simulated_success`, `num_bundles_reverted`,
//! etc.) so they are reflected in overall payload build statistics.

mod args;
mod global_pool;
mod maintain;
mod metrics;
mod payload_pool;
mod rpc;
#[cfg(test)]
mod test_utils;

pub use args::BackrunBundleArgs;
pub use global_pool::BackrunBundleGlobalPool;
pub use maintain::maintain_backrun_bundle_pool_future;
pub use payload_pool::{BackrunBundlePayloadPool, ReplacementKey, StoredBackrunBundle};
pub use rpc::{BackrunBundleApiServer, BackrunBundleRpc, BackrunBundleRpcArgs};

#[derive(Debug, Clone)]
pub struct BackrunBundlesPayloadCtx {
    pub pool: BackrunBundlePayloadPool,
    pub args: BackrunBundleArgs,
}
