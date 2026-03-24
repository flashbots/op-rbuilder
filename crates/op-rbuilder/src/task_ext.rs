use reth::tasks::TaskSpawner;
use reth_node_api::PayloadBuilderError;
use tokio::sync::oneshot;

/// Extension trait for [`TaskSpawner`] that adds a blocking task helper
/// returning the result via a oneshot channel.
pub(crate) trait TaskSpawnerExt: TaskSpawner {
    /// Spawns a blocking task and awaits its result.
    ///
    /// The closure runs on a blocking thread. The result is sent back via a
    /// oneshot channel so the caller can `.await` it from an async context.
    fn run_blocking_task<T, F>(
        &self,
        task: F,
    ) -> impl std::future::Future<Output = Result<T, PayloadBuilderError>>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, PayloadBuilderError> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.spawn_blocking_task(Box::pin(async move {
            let _ = tx.send(task());
        }));

        async {
            rx.await
                .map_err(|_| PayloadBuilderError::Other("blocking task dropped".into()))?
        }
    }
}

impl<T: TaskSpawner> TaskSpawnerExt for T {}
