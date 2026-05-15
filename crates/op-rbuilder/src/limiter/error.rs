use thiserror::Error;

/// Errors returned when committing an [`AddressLimiterOverlay`] back to its
/// canonical [`AddressLimiter`].
///
/// [`AddressLimiterOverlay`]: super::AddressLimiterOverlay
/// [`AddressLimiter`]: super::AddressLimiter
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommitError {
    /// The canonical limiter advanced (via refresh or a sibling commit) since
    /// this overlay was forked, so the overlay's deltas are no longer safe to
    /// apply.
    #[error("overlay is stale: overlay_epoch={overlay_epoch}, canonical_epoch={canonical_epoch}")]
    StaleEpoch {
        overlay_epoch: u64,
        canonical_epoch: u64,
    },
}
