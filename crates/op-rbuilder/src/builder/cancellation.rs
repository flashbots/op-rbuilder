use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

/// Structured cancellation for a single payload building job.
///
/// Three distinct tokens that can distinguish *why* building was stopped:
/// - `new_fcu`: A new FCU arrived (`ensure_only_one_payload`). Abandon all work.
/// - `resolved`: `getPayload` was called. Stop building, don't publish new flashblocks.
/// - `deadline`: The payload job deadline was reached. Stop all work.
///
/// `any` fires when ANY of the above fires. It is used for tasks that should stop regardless of cancellation reason.
///
/// Use `cancel_new_fcu()`, `cancel_resolved()`, `cancel_deadline()` to fire
/// a specific source, these also cancel `any` automatically.
///
/// These fields must remains private to enforce the invariant that `any` is always canceled
/// alongside any specific token. Use accessor methods to read token state.
#[derive(Clone)]
pub(crate) struct PayloadJobCancellation {
    new_fcu: CancellationToken,
    resolved: CancellationToken,
    deadline: CancellationToken,
    any: CancellationToken,
}

/// Why a payload job was canceled.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CancellationReason {
    Resolved,
    NewFcu,
    Deadline,
    /// Job completed normally (all scheduled flashblocks built before resolve/fcu).
    Complete,
}

impl CancellationReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NewFcu => "new_fcu",
            Self::Deadline => "deadline",
            Self::Complete => "complete",
        }
    }
}

impl PayloadJobCancellation {
    /// Creates a new `PayloadJobCancellation` with all tokens uncancelled.
    pub(crate) fn new() -> Self {
        Self {
            new_fcu: CancellationToken::new(),
            resolved: CancellationToken::new(),
            deadline: CancellationToken::new(),
            any: CancellationToken::new(),
        }
    }

    /// Fires `new_fcu` token and `any`.
    pub(crate) fn cancel_new_fcu(&self) {
        self.new_fcu.cancel();
        self.any.cancel();
    }

    /// Fires `resolved` token and `any`.
    pub(crate) fn cancel_resolved(&self) {
        self.resolved.cancel();
        self.any.cancel();
    }

    /// Fires `deadline` token and `any`.
    pub(crate) fn cancel_deadline(&self) {
        self.deadline.cancel();
        self.any.cancel();
    }

    /// Returns true if any cancellation source has fired.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.any.is_cancelled()
    }

    /// Returns true if `resolved` specifically was cancelled.
    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.is_cancelled()
    }

    /// Returns true if `new_fcu` specifically was cancelled.
    pub(crate) fn is_new_fcu(&self) -> bool {
        self.new_fcu.is_cancelled()
    }

    /// Future that resolves when `resolved` is cancelled.
    pub(crate) fn resolved_cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.resolved.cancelled()
    }

    /// Future that resolves when `new_fcu` is cancelled.
    pub(crate) fn new_fcu_cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.new_fcu.cancelled()
    }

    /// Returns the `any` token.
    /// Passed to blocking tasks and the scheduler.
    pub(crate) fn any_token(&self) -> CancellationToken {
        self.any.clone()
    }

    /// Creates a child token of `any`.
    /// Useful for per-flashblock cancellation.
    #[allow(dead_code)]
    pub(crate) fn child_token(&self) -> CancellationToken {
        self.any.child_token()
    }

    /// Returns the reason this job was canceled, or `Complete` if not canceled.
    pub(crate) fn reason(&self) -> CancellationReason {
        if self.resolved.is_cancelled() {
            CancellationReason::Resolved
        } else if self.new_fcu.is_cancelled() {
            CancellationReason::NewFcu
        } else if self.deadline.is_cancelled() {
            CancellationReason::Deadline
        } else {
            CancellationReason::Complete
        }
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
            .field("new_fcu", &self.new_fcu.is_cancelled())
            .field("resolved", &self.resolved.is_cancelled())
            .field("deadline", &self.deadline.is_cancelled())
            .field("any", &self.any.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_cancel_new_fcu_fires_any() {
        let cancel = PayloadJobCancellation::new();
        assert!(!cancel.is_cancelled());

        cancel.cancel_new_fcu();
        assert!(cancel.is_cancelled());
        assert!(cancel.is_new_fcu());
        assert!(!cancel.is_resolved());
        assert!(matches!(cancel.reason(), CancellationReason::NewFcu));
    }

    #[tokio::test]
    async fn test_cancel_resolved_fires_any() {
        let cancel = PayloadJobCancellation::new();
        cancel.cancel_resolved();
        assert!(cancel.is_cancelled());
        assert!(cancel.is_resolved());
        assert!(!cancel.is_new_fcu());
        assert!(matches!(cancel.reason(), CancellationReason::Resolved));
    }

    #[tokio::test]
    async fn test_cancel_deadline_fires_any() {
        let cancel = PayloadJobCancellation::new();
        cancel.cancel_deadline();
        assert!(cancel.is_cancelled());
        assert!(!cancel.is_new_fcu());
        assert!(!cancel.is_resolved());
        assert!(matches!(cancel.reason(), CancellationReason::Deadline));
    }

    #[tokio::test]
    async fn test_any_awaitable() {
        let cancel = PayloadJobCancellation::new();
        let any = cancel.any_token();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel_resolved();
        });

        timeout(Duration::from_millis(100), any.cancelled())
            .await
            .expect("any should fire when resolved fires");
    }

    #[tokio::test]
    async fn test_child_token_cancelled_by_any() {
        let cancel = PayloadJobCancellation::new();
        let child = cancel.child_token();
        assert!(!child.is_cancelled());

        cancel.cancel_resolved();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn test_reason_complete_when_not_cancelled() {
        let cancel = PayloadJobCancellation::new();
        assert!(matches!(cancel.reason(), CancellationReason::Complete));
    }
}
