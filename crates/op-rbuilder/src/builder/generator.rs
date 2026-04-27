use alloy_primitives::B256;
use futures_util::{Future, FutureExt};
use reth::providers::{BlockReaderIdExt, StateProviderFactory};
use reth_basic_payload_builder::{HeaderForPayload, PayloadConfig, PrecachedState};
use reth_node_api::{NodePrimitives, PayloadKind};
use reth_payload_builder::{
    BuildNewPayload, KeepPayloadJobAlive, PayloadBuilderError, PayloadId, PayloadJob,
    PayloadJobGenerator,
};
use reth_payload_primitives::{BuiltPayload, PayloadAttributes};
use reth_primitives_traits::HeaderTy;
use reth_provider::CanonStateNotification;
use reth_revm::cached::CachedReads;
use reth_tasks::Runtime;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::watch,
    time::{Duration, Sleep},
};
use tracing::info;

use super::cancellation::PayloadJobCancellation;

/// A trait for building payloads that encapsulate Ethereum transactions.
///
/// This trait provides the `try_build` method to construct a transaction payload
/// using `BuildArguments`. It returns a `Result` indicating success or a
/// `PayloadBuilderError` if building fails.
#[async_trait::async_trait]
pub(super) trait PayloadBuilder: Send + Sync + Clone {
    /// The RPC-level payload attributes (what the engine API sends).
    type RpcAttributes: PayloadAttributes + Clone + Unpin;
    /// The builder-level payload attributes (used internally during building).
    type Attributes: PayloadAttributes + Clone + Send + Sync + 'static;
    /// The type of the built payload.
    type BuiltPayload: BuiltPayload;

    /// Convert RPC attributes to builder attributes.
    fn from_rpc_attrs(
        parent: B256,
        id: PayloadId,
        attrs: Self::RpcAttributes,
    ) -> Result<Self::Attributes, PayloadBuilderError>;

    /// Tries to build a transaction payload using provided arguments.
    async fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
        best_payload_tx: watch::Sender<Option<Self::BuiltPayload>>,
    ) -> Result<(), PayloadBuilderError>;
}

pub(super) struct BuildArguments<Attributes, Payload: BuiltPayload> {
    /// Previously cached disk reads
    pub cached_reads: CachedReads,
    /// How to configure the payload.
    pub config: PayloadConfig<Attributes, HeaderTy<Payload::Primitives>>,
    /// Structured cancellation.
    pub cancel: PayloadJobCancellation,
}

/// The generator type that creates new payload jobs.
#[derive(Debug)]
pub(super) struct BlockPayloadJobGenerator<Client, Builder> {
    /// The client that can interact with the chain.
    client: Client,
    /// How to spawn building tasks
    executor: Runtime,
    /// The type responsible for building payloads.
    /// See [PayloadBuilder]
    builder: Builder,
    /// The last payload's cancellation.
    /// `cancel_new_fcu()` is called when a new FCU arrives
    last_payload_cancel: Arc<Mutex<PayloadJobCancellation>>,
    /// The extra block deadline in seconds
    extra_block_deadline: Duration,
    /// Stored `cached_reads` for new payload jobs.
    pre_cached: Option<PrecachedState>,
    /// The configured block time
    block_time: Duration,
    /// Metrics for recording telemetry
    metrics: Arc<crate::metrics::OpRBuilderMetrics>,
}

impl<Client, Builder> BlockPayloadJobGenerator<Client, Builder> {
    /// Creates a new [BlockPayloadJobGenerator] with a custom [PayloadBuilder].
    pub(super) fn with_builder(
        client: Client,
        executor: Runtime,
        builder: Builder,
        extra_block_deadline: Duration,
        block_time: Duration,
        metrics: Arc<crate::metrics::OpRBuilderMetrics>,
    ) -> Self {
        Self {
            client,
            executor,
            builder,
            last_payload_cancel: Arc::new(Mutex::new(PayloadJobCancellation::new())),
            extra_block_deadline,
            pre_cached: None,
            block_time,
            metrics,
        }
    }

    /// Returns the pre-cached reads for the given parent header if it matches the cached state's
    /// block.
    fn maybe_pre_cached(&self, parent: B256) -> Option<CachedReads> {
        self.pre_cached
            .as_ref()
            .filter(|pc| pc.block == parent)
            .map(|pc| pc.cached.clone())
    }
}

impl<Client, Builder> PayloadJobGenerator for BlockPayloadJobGenerator<Client, Builder>
where
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = HeaderForPayload<Builder::BuiltPayload>>
        + Clone
        + Unpin
        + 'static,
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type Job = BlockPayloadJob<Builder>;

    /// This is invoked when the node receives payload attributes from the beacon node via
    /// `engine_forkchoiceUpdatedVX`
    fn new_payload_job(
        &self,
        build: BuildNewPayload<<Builder as PayloadBuilder>::RpcAttributes>,
        id: PayloadId,
    ) -> Result<Self::Job, PayloadBuilderError> {
        let rpc_attributes = build.attributes.clone();
        let parent_hash = build.parent_hash;

        // Convert RPC attributes to builder attributes
        let builder_attributes = Builder::from_rpc_attrs(parent_hash, id, build.attributes)?;

        // Calculate and record FCU arrival delay metric in milliseconds
        // Expected: FCU should arrive at (payload_timestamp - block_time)
        // Positive delay = FCU arrived late, Negative = FCU arrived early
        let timestamp = rpc_attributes.timestamp();
        let now = SystemTime::now();
        let expected_fcu_arrival =
            SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp) - self.block_time;
        let fcu_arrival_delay_ms = now
            .duration_since(expected_fcu_arrival)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_else(|e| -(e.duration().as_millis() as i64));
        self.metrics
            .fcu_arrival_delay
            .record(fcu_arrival_delay_ms as f64);

        let cancellation = {
            // Cancel existing payload via new_fcu
            {
                let last_cancel = self.last_payload_cancel.lock().unwrap();
                last_cancel.cancel_new_fcu();
            }

            // Create new PayloadJobCancellation and store it
            let cancellation = PayloadJobCancellation::new();
            {
                let mut last_cancel = self.last_payload_cancel.lock().unwrap();
                *last_cancel = cancellation.clone();
            }
            cancellation
        };

        let parent_header = if parent_hash.is_zero() {
            // use latest block if parent is zero: genesis block
            self.client
                .latest_header()?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(parent_hash))?
        } else {
            self.client
                .sealed_header_by_hash(parent_hash)?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(parent_hash))?
        };

        info!(
            target: "payload_builder",
            id = %id,
            "Spawn block building job",
        );

        let deadline = job_deadline(rpc_attributes.timestamp()) + self.extra_block_deadline;

        let deadline = Box::pin(tokio::time::sleep(deadline));
        let config = PayloadConfig::new(Arc::new(parent_header.clone()), builder_attributes, id);

        let mut job = BlockPayloadJob {
            executor: self.executor.clone(),
            builder: self.builder.clone(),
            config,
            rpc_attributes,
            payload_rx: None,
            cancel: cancellation,
            deadline,
            cached_reads: self
                .maybe_pre_cached(parent_header.hash())
                .unwrap_or_default(),
        };

        job.spawn_build_job();

        Ok(job)
    }

    fn on_new_state<N: NodePrimitives>(&mut self, new_state: CanonStateNotification<N>) {
        let mut cached = CachedReads::default();

        // extract the state from the notification and put it into the cache
        let committed = new_state.committed();
        let new_execution_outcome = committed.execution_outcome();
        for (addr, acc) in new_execution_outcome.bundle_accounts_iter() {
            if let Some(info) = acc.info.clone() {
                // we want pre cache existing accounts and their storage
                // this only includes changed accounts and storage but is better than nothing
                let storage = acc
                    .storage
                    .iter()
                    .map(|(key, slot)| (*key, slot.present_value))
                    .collect();
                cached.insert_account(addr, info, storage);
            }
        }

        self.pre_cached = Some(PrecachedState {
            block: committed.tip().hash(),
            cached,
        });
    }
}

/// A [PayloadJob] that builds blocks.
pub(super) struct BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder,
{
    /// The configuration for how the payload will be created.
    config: PayloadConfig<Builder::Attributes, HeaderForPayload<Builder::BuiltPayload>>,
    /// The original RPC-level attributes (returned by payload_attributes())
    rpc_attributes: Builder::RpcAttributes,
    /// How to spawn building tasks
    executor: Runtime,
    /// The type responsible for building payloads.
    ///
    /// See [PayloadBuilder]
    builder: Builder,
    /// Receiver for the latest payload from the builder task.
    payload_rx: Option<watch::Receiver<Option<Builder::BuiltPayload>>>,
    /// Structured cancellation for the running job
    cancel: PayloadJobCancellation,
    /// Deadline at which the job is forcibly cancelled.
    deadline: Pin<Box<Sleep>>,
    /// Caches all disk reads for the state the new payloads builds on.
    cached_reads: CachedReads,
}

impl<Builder> PayloadJob for BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone + Send + Sync + 'static,
{
    type PayloadAttributes = Builder::RpcAttributes;
    type ResolvePayloadFuture = ResolvePayload<Self::BuiltPayload>;
    type BuiltPayload = Builder::BuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        unimplemented!()
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        Ok(self.rpc_attributes.clone())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        info!(target: "payload_builder", payload_kind = ?kind, "Resolve payload job");

        let rx = self.payload_rx.take();
        let cancellation = self.cancel.clone();
        (
            ResolvePayload::new(rx, cancellation),
            KeepPayloadJobAlive::No,
        )
    }
}

impl<Builder> BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    fn spawn_build_job(&mut self) {
        let builder = self.builder.clone();
        let payload_config = self.config.clone();
        let cancellation = self.cancel.clone();

        let (watch_tx, watch_rx) = watch::channel(None);
        self.payload_rx = Some(watch_rx);
        let cached_reads = std::mem::take(&mut self.cached_reads);
        // try_build is not in a blocking task!
        // We have to make sure any blocking work is handled individually within payload builder
        self.executor.spawn_task(Box::pin(async move {
            let args = BuildArguments {
                cached_reads,
                config: payload_config,
                cancel: cancellation,
            };

            let payload_id = args.config.payload_id;
            if let Err(e) = builder.try_build(args, watch_tx).await {
                tracing::error!(id = %payload_id, "build task failed: {:?}", e);
            }
        }));
    }
}

/// Polled by `PayloadBuilderService` to drive the job to completion or cancellation.
impl<Builder> Future for BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        tracing::trace!("Polling job");
        let this = self.get_mut();

        // Check if deadline is reached
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.cancel.cancel_deadline();
            tracing::debug!("Deadline reached");
            return Poll::Ready(Ok(()));
        }

        // If canceled via any source
        if this.cancel.is_cancelled() {
            tracing::debug!("Job cancelled");
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

/// A future that resolves with the latest payload value, waiting for the first publish if needed.
/// We wrap the inner future in this one to have a concrete type we can easily instantiate it.
pub(super) struct ResolvePayload<T> {
    future: futures_util::future::BoxFuture<'static, Result<T, PayloadBuilderError>>,
}

impl<T: Clone + Send + Sync + 'static> ResolvePayload<T> {
    fn new(
        payload_rx: Option<watch::Receiver<Option<T>>>,
        cancellation: PayloadJobCancellation,
    ) -> Self {
        let future = async move {
            let Some(mut rx) = payload_rx else {
                return Err(PayloadBuilderError::Other(
                    "payload receiver missing".into(),
                ));
            };

            loop {
                if let Some(payload) = rx.borrow().clone() {
                    cancellation.cancel_resolved();
                    return Ok(payload);
                }

                rx.changed().await.map_err(|_| {
                    PayloadBuilderError::Other("builder exited before producing payload".into())
                })?;
            }
        }
        .boxed();

        Self { future }
    }
}

impl<T> Future for ResolvePayload<T> {
    type Output = Result<T, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(cx)
    }
}

fn job_deadline(unix_timestamp_secs: u64) -> Duration {
    let unix_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Safe subtraction that handles the case where timestamp is in the past
    let duration_until = unix_timestamp_secs.saturating_sub(unix_now);

    if duration_until == 0 {
        // Enforce a minimum block time of 1 second by rounding up any duration less than 1 second
        Duration::from_secs(1)
    } else {
        Duration::from_secs(duration_until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep, timeout};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockPayload(u64);

    #[tokio::test]
    async fn test_job_deadline() {
        // Test future deadline
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let future_timestamp = now + Duration::from_secs(2);
        // 2 seconds from now
        let deadline = job_deadline(future_timestamp.as_secs());
        assert!(deadline <= Duration::from_secs(2));
        assert!(deadline > Duration::from_secs(0));

        // Test past deadline
        let past_timestamp = now - Duration::from_secs(10);
        let deadline = job_deadline(past_timestamp.as_secs());
        // Should default to 1 second when timestamp is in the past
        assert_eq!(deadline, Duration::from_secs(1));

        // Test current timestamp
        let deadline = job_deadline(now.as_secs());
        // Should use 1 second when timestamp is current
        assert_eq!(deadline, Duration::from_secs(1));
    }

    // TODO: Re-enable after adapting to reth 2.0 APIs (reth_testing_utils removed,
    // new_payload_job signature changed to take BuildNewPayload<RpcAttributes>).
    // #[tokio::test]
    // async fn test_payload_generator() { ... }

    // TODO: Re-enable after adapting to reth 2.0 APIs (reth_testing_utils removed,
    // executor is now a concrete `Runtime` so CountingTaskExecutor can no longer be plugged in).
    // #[tokio::test]
    // async fn test_spawn_build_job_uses_async_executor() { ... }

    #[tokio::test]
    async fn test_resolve_payload_waits_for_first_value() {
        let (tx, rx) = watch::channel::<Option<MockPayload>>(None);
        let cancel = PayloadJobCancellation::new();
        let resolve = ResolvePayload::new(Some(rx), cancel.clone());

        tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            tx.send_replace(Some(MockPayload(7)));
        });

        let payload = timeout(Duration::from_secs(1), resolve)
            .await
            .expect("resolve should complete")
            .expect("resolve should return payload");
        assert_eq!(payload, MockPayload(7));
        assert!(cancel.is_resolved());
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_resolve_payload_returns_latest_value() {
        let (tx, rx) = watch::channel::<Option<MockPayload>>(None);
        tx.send_replace(Some(MockPayload(1)));
        tx.send_replace(Some(MockPayload(2)));

        let cancel = PayloadJobCancellation::new();
        let payload = ResolvePayload::new(Some(rx), cancel.clone())
            .await
            .expect("resolve should return payload");

        assert_eq!(payload, MockPayload(2));
        assert!(cancel.is_resolved());
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_resolve_payload_errors_if_builder_exits_without_payload() {
        let (tx, rx) = watch::channel::<Option<MockPayload>>(None);
        drop(tx);

        let _ = ResolvePayload::new(Some(rx), PayloadJobCancellation::new())
            .await
            .expect_err("resolve should error when sender closes before value");
    }

    #[tokio::test]
    async fn test_resolve_payload_errors_if_receiver_missing() {
        let _ = ResolvePayload::<MockPayload>::new(None, PayloadJobCancellation::new())
            .await
            .expect_err("resolve should error when receiver is missing");
    }

    #[tokio::test]
    async fn test_resolve_payload_cancels_after_payload_arrives() {
        let (tx, rx) = watch::channel::<Option<MockPayload>>(None);
        let cancel = PayloadJobCancellation::new();
        let handle = tokio::spawn(ResolvePayload::new(Some(rx), cancel.clone()));

        sleep(Duration::from_millis(20)).await;
        assert!(!cancel.is_cancelled());

        tx.send_replace(Some(MockPayload(9)));
        let payload = timeout(Duration::from_secs(1), handle)
            .await
            .expect("task should finish")
            .expect("task should not panic")
            .expect("resolve should return payload");

        assert_eq!(payload, MockPayload(9));
        assert!(cancel.is_resolved());
        assert!(cancel.is_cancelled());
    }
}
