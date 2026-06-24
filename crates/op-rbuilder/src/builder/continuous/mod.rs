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

#[cfg(test)]
pub(crate) mod test_hooks {
    pub(crate) use super::shared_best::test_hooks::force_next_take_misses;
}
