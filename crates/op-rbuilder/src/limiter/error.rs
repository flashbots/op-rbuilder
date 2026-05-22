use thiserror::Error;

/// Errors returned when committing an [`AddressLimiterGuard`] back to its
/// canonical [`AddressLimiter`].
///
/// [`AddressLimiterGuard`]: super::AddressLimiterGuard
/// [`AddressLimiter`]: super::AddressLimiter
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommitError {
    /// The canonical limiter advanced (via `refill_buckets` or a sibling
    /// commit) since this guard began, so the guard's deltas are no longer
    /// safe to apply.
    #[error("guard is stale: guard_epoch={guard_epoch}, canonical_epoch={canonical_epoch}")]
    StaleEpoch {
        guard_epoch: u64,
        canonical_epoch: u64,
    },
}
