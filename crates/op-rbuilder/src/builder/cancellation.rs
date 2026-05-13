use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

/// Why a payload job was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CancellationReason {
    Resolved,
    NewFcu,
    Deadline,
}

/// Structured cancellation for a single payload building job.
///
/// A `CancellationToken` with an atomic reason that records *why* the job was stopped:
/// - `Resolved`: `getPayload` was called. Stop building, don't publish new flashblocks.
/// - `NewFcu`: A new FCU arrived (`ensure_only_one_payload`). Abandon all work.
/// - `Deadline`: The payload job deadline was reached. Stop all work.
///
/// Use `cancel_resolved()`, `cancel_new_fcu()`, `cancel_deadline()` to fire the token with specific reason.
#[derive(Clone)]
pub(crate) struct PayloadJobCancellation {
    token: CancellationToken,
    reason: Arc<OnceLock<CancellationReason>>,
}

impl PayloadJobCancellation {
    /// Creates a new `PayloadJobCancellation` with the token uncancelled.
    pub(crate) fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            reason: Arc::new(OnceLock::new()),
        }
    }

    fn cancel_with(&self, reason: CancellationReason) {
        // OnceLock ensures that the first writer wins. If already set, the
        // original reason is preserved.
        let _ = self.reason.set(reason);
        self.token.cancel();
    }

    /// Cancel with `NewFcu` reason.
    pub(crate) fn cancel_new_fcu(&self) {
        self.cancel_with(CancellationReason::NewFcu);
    }

    /// Cancel with `Resolved` reason.
    pub(crate) fn cancel_resolved(&self) {
        self.cancel_with(CancellationReason::Resolved);
    }

    /// Cancel with `Deadline` reason.
    pub(crate) fn cancel_deadline(&self) {
        self.cancel_with(CancellationReason::Deadline);
    }

    /// Returns true if cancelled with `Resolved` reason.
    pub(crate) fn is_resolved(&self) -> bool {
        self.reason() == Some(CancellationReason::Resolved)
    }

    /// Returns true if cancelled with `NewFcu` reason.
    pub(crate) fn is_new_fcu(&self) -> bool {
        self.reason() == Some(CancellationReason::NewFcu)
    }

    /// Future that resolves when cancelled (any reason).
    pub(crate) fn cancelled(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.token.cancelled()
    }

    /// Returns the underlying token.
    /// Passed to blocking tasks and the scheduler.
    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Creates a child token.
    /// Useful for per-flashblock cancellation.
    pub(crate) fn child_token(&self) -> CancellationToken {
        self.token.child_token()
    }

    /// Returns the reason this job was cancelled, or `None` if not cancelled.
    pub(crate) fn reason(&self) -> Option<CancellationReason> {
        self.reason.get().copied()
    }
}

impl Default for PayloadJobCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PayloadJobCancellation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayloadJobCancellation")
            .field("cancelled", &self.token.is_cancelled())
            .field("reason", &self.reason())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_cancel_new_fcu() {
        let cancel = PayloadJobCancellation::new();
        assert!(!cancel.token().is_cancelled());

        cancel.cancel_new_fcu();
        assert!(cancel.token().is_cancelled());
        assert!(cancel.is_new_fcu());
        assert!(!cancel.is_resolved());
        assert_eq!(cancel.reason(), Some(CancellationReason::NewFcu));
    }

    #[tokio::test]
    async fn test_cancel_resolved() {
        let cancel = PayloadJobCancellation::new();
        cancel.cancel_resolved();
        assert!(cancel.token().is_cancelled());
        assert!(cancel.is_resolved());
        assert!(!cancel.is_new_fcu());
        assert_eq!(cancel.reason(), Some(CancellationReason::Resolved));
    }

    #[tokio::test]
    async fn test_cancel_deadline() {
        let cancel = PayloadJobCancellation::new();
        cancel.cancel_deadline();
        assert!(cancel.token().is_cancelled());
        assert!(!cancel.is_new_fcu());
        assert!(!cancel.is_resolved());
        assert_eq!(cancel.reason(), Some(CancellationReason::Deadline));
    }

    #[tokio::test]
    async fn test_awaitable() {
        let cancel = PayloadJobCancellation::new();
        let token = cancel.token();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel_resolved();
        });

        timeout(Duration::from_millis(100), token.cancelled())
            .await
            .expect("token should fire when resolved fires");
    }

    #[tokio::test]
    async fn test_child_token_cancelled() {
        let cancel = PayloadJobCancellation::new();
        let child = cancel.child_token();
        assert!(!child.is_cancelled());

        cancel.cancel_resolved();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn test_reason_none_when_not_cancelled() {
        let cancel = PayloadJobCancellation::new();
        assert_eq!(cancel.reason(), None);
    }

    #[tokio::test]
    async fn test_first_reason_wins() {
        let cancel = PayloadJobCancellation::new();
        cancel.cancel_resolved();
        cancel.cancel_new_fcu();
        assert_eq!(cancel.reason(), Some(CancellationReason::Resolved));
    }
}
