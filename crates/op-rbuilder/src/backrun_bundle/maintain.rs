use super::global_pool::BackrunBundleGlobalPool;
use futures_util::{FutureExt, Stream, StreamExt, future::BoxFuture};
use reth_chain_state::CanonStateNotification;
use reth_primitives_traits::NodePrimitives;
use reth_tasks::TaskExecutor;

pub fn maintain_backrun_bundle_pool_future<N, St>(
    pool: BackrunBundleGlobalPool,
    events: St,
    task_executor: TaskExecutor,
) -> BoxFuture<'static, ()>
where
    N: NodePrimitives,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    async move {
        maintain_backrun_bundle_pool(pool, events, task_executor).await;
    }
    .boxed()
}

async fn maintain_backrun_bundle_pool<N, St>(
    pool: BackrunBundleGlobalPool,
    mut events: St,
    task_executor: TaskExecutor,
) where
    N: NodePrimitives,
    St: Stream<Item = CanonStateNotification<N>> + Send + Unpin + 'static,
{
    loop {
        let Some(event) = events.next().await else {
            tracing::debug!(target: "op-rbuilder::backrun_bundle", "canonical state stream ended");
            break;
        };
        let pool = pool.clone();
        task_executor.spawn_blocking(async move {
            pool.on_canonical_state_change(event.tip());
        });
    }
}
