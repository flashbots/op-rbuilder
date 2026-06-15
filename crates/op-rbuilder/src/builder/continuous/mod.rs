//! Continuous flashblock build mode.
//!
//! In continuous mode the builder produces sealed flashblock candidates back-to-back
//! within each flashblock interval, keeping only the highest-fee one in a shared
//! slot. When the scheduler signals end-of-interval, the main loop publishes the
//! pretaken candidate immediately without awaiting the current build task, so
//! trigger -> publish latency is fast (bounded by serialization + WS send), rather
//! than by one full build pass.

mod candidate_loop;
mod interval;
mod publish;
mod shared_best;
mod transition;
mod types;

/// Test-only knobs for continuous build mode.
///
/// Threaded through [`BuilderConfig`](crate::builder::BuilderConfig) because the
/// builder is constructed inside the node and is otherwise unreachable from a
/// test. Always default (empty) outside `#[cfg(test)]`.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ContinuousTestHooks {
    /// Number of `SharedBest::take()` calls to force to miss, consumed once
    /// across this builder's `SharedBest` instances. Deterministically
    /// exercises the trigger-miss fallback path.
    pub force_take_miss_count: u64,
}
