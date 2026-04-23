use reth_node_api::PayloadBuilderError;
use reth_tasks::Runtime;

/// Extension trait for [`Runtime`] that adds a helper for awaiting the result of
/// a blocking closure from async code.
pub(crate) trait RuntimeExt {
    /// Spawn a blocking closure on the runtime and await its result.
    ///
    /// The closure runs on a blocking thread (via [`Runtime::spawn_blocking`]).
    /// The returned future resolves with whatever the closure returned, or an
    /// error if the blocking task was cancelled or panicked.
    fn run_blocking_task<T, F>(
        &self,
        task: F,
    ) -> impl std::future::Future<Output = Result<T, PayloadBuilderError>> + Send
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, PayloadBuilderError> + Send + 'static;
}

impl RuntimeExt for Runtime {
    fn run_blocking_task<T, F>(
        &self,
        task: F,
    ) -> impl std::future::Future<Output = Result<T, PayloadBuilderError>> + Send
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, PayloadBuilderError> + Send + 'static,
    {
        let handle = self.spawn_blocking(task);
        async move {
            handle
                .await
                .map_err(|e| PayloadBuilderError::Other(Box::new(e)))?
        }
    }
}
