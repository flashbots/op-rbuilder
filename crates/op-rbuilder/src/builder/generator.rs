use alloy_primitives::B256;
use futures_util::{Future, FutureExt};
use reth::providers::{BlockReaderIdExt, StateProviderFactory};
use reth_basic_payload_builder::{
    BasicPayloadJobGeneratorConfig, HeaderForPayload, PayloadConfig, PrecachedState,
};
use reth_node_api::{NodePrimitives, PayloadKind};
use reth_payload_builder::{
    BuildNewPayload, KeepPayloadJobAlive, PayloadBuilderError, PayloadId, PayloadJob,
    PayloadJobGenerator,
};
use reth_payload_primitives::BuiltPayload;
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::HeaderTy;
use reth_provider::CanonStateNotification;
use reth_revm::cached::CachedReads;
use reth_tasks::Runtime;
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Notify, oneshot},
    time::{Duration, Sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::info;

/// A trait for building payloads that encapsulate Ethereum transactions.
///
/// This trait provides the `try_build` method to construct a transaction payload
/// using `BuildArguments`. It returns a `Result` indicating success or a
/// `PayloadBuilderError` if building fails.
///
/// Generic parameters `Pool` and `Client` represent the transaction pool and
/// Ethereum client types.
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
    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
        best_payload: BlockCell<Self::BuiltPayload>,
    ) -> Result<(), PayloadBuilderError>;
}

/// The generator type that creates new jobs that builds empty blocks.
#[derive(Debug)]
pub(super) struct BlockPayloadJobGenerator<Client, Builder> {
    /// The client that can interact with the chain.
    client: Client,
    /// How to spawn building tasks
    executor: Runtime,
    /// The configuration for the job generator.
    _config: BasicPayloadJobGeneratorConfig,
    /// The type responsible for building payloads.
    ///
    /// See [PayloadBuilder]
    builder: Builder,
    /// Whether to ensure only one payload is being processed at a time
    ensure_only_one_payload: bool,
    /// The last payload being processed
    last_payload: Arc<Mutex<CancellationToken>>,
    /// The extra block deadline in seconds
    extra_block_deadline: std::time::Duration,
    /// Stored `cached_reads` for new payload jobs.
    pre_cached: Option<PrecachedState>,
}

// === impl EmptyBlockPayloadJobGenerator ===

impl<Client, Builder> BlockPayloadJobGenerator<Client, Builder> {
    /// Creates a new [EmptyBlockPayloadJobGenerator] with the given config and custom
    /// [PayloadBuilder]
    pub(super) fn with_builder(
        client: Client,
        executor: Runtime,
        config: BasicPayloadJobGeneratorConfig,
        builder: Builder,
        ensure_only_one_payload: bool,
        extra_block_deadline: std::time::Duration,
    ) -> Self {
        Self {
            client,
            executor,
            _config: config,
            builder,
            ensure_only_one_payload,
            last_payload: Arc::new(Mutex::new(CancellationToken::new())),
            extra_block_deadline,
            pre_cached: None,
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

        let cancel_token = if self.ensure_only_one_payload {
            // Cancel existing payload
            {
                let last_payload = self.last_payload.lock().unwrap();
                last_payload.cancel();
            }

            // Create and set new cancellation token with a fresh lock
            let cancel_token = CancellationToken::new();
            {
                let mut last_payload = self.last_payload.lock().unwrap();
                *last_payload = cancel_token.clone();
            }
            cancel_token
        } else {
            CancellationToken::new()
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

        info!("Spawn block building job");

        let deadline = job_deadline(rpc_attributes.timestamp()) + self.extra_block_deadline;

        let deadline = Box::pin(tokio::time::sleep(deadline));
        let config = PayloadConfig::new(Arc::new(parent_header.clone()), builder_attributes, id);

        let mut job = BlockPayloadJob {
            executor: self.executor.clone(),
            builder: self.builder.clone(),
            config,
            rpc_attributes,
            cell: BlockCell::new(),
            cancel: cancel_token,
            deadline,
            build_complete: None,
            cached_reads: self.maybe_pre_cached(parent_header.hash()),
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

use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// A [PayloadJob] that builds empty blocks.
pub(super) struct BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder,
{
    /// The configuration for how the payload will be created.
    pub(crate) config: PayloadConfig<Builder::Attributes, HeaderForPayload<Builder::BuiltPayload>>,
    /// The original RPC-level attributes (returned by payload_attributes())
    pub(crate) rpc_attributes: Builder::RpcAttributes,
    /// How to spawn building tasks
    pub(crate) executor: Runtime,
    /// The type responsible for building payloads.
    ///
    /// See [PayloadBuilder]
    pub(crate) builder: Builder,
    /// The cell that holds the built payload.
    pub(crate) cell: BlockCell<Builder::BuiltPayload>,
    /// Cancellation token for the running job
    pub(crate) cancel: CancellationToken,
    pub(crate) deadline: Pin<Box<Sleep>>, // Add deadline
    pub(crate) build_complete: Option<oneshot::Receiver<Result<(), PayloadBuilderError>>>,
    /// Caches all disk reads for the state the new payloads builds on
    pub(crate) cached_reads: Option<CachedReads>,
}

impl<Builder> PayloadJob for BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
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

        // check if self.cell has a payload
        self.cancel.cancel();

        let resolve_future = ResolvePayload::new(self.cell.wait_for_value());
        (resolve_future, KeepPayloadJobAlive::No)
    }
}

pub(super) struct BuildArguments<Attributes, Payload: BuiltPayload> {
    /// Previously cached disk reads
    pub cached_reads: CachedReads,
    /// How to configure the payload.
    pub config: PayloadConfig<Attributes, HeaderTy<Payload::Primitives>>,
    /// A marker that can be used to cancel the job.
    pub cancel: CancellationToken,
}

/// A [PayloadJob] is a future that's being polled by the `PayloadBuilderService`
impl<Builder> BlockPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    pub(super) fn spawn_build_job(&mut self) {
        let builder = self.builder.clone();
        let payload_config = self.config.clone();
        let cell = self.cell.clone();
        let cancel = self.cancel.clone();

        let (tx, rx) = oneshot::channel();
        self.build_complete = Some(rx);
        let cached_reads = self.cached_reads.take().unwrap_or_default();
        self.executor.spawn_blocking_task(Box::pin(async move {
            let args = BuildArguments {
                cached_reads,
                config: payload_config,
                cancel,
            };

            let result = builder.try_build(args, cell);
            let _ = tx.send(result);
        }));
    }
}

/// A [PayloadJob] is a a future that's being polled by the `PayloadBuilderService`
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
            this.cancel.cancel();
            tracing::debug!("Deadline reached");
            return Poll::Ready(Ok(()));
        }

        // If cancelled via resolve_kind()
        if this.cancel.is_cancelled() {
            tracing::debug!("Job cancelled");
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

// A future that resolves when a payload becomes available in the BlockCell
pub(super) struct ResolvePayload<T> {
    future: WaitForValue<T>,
}

impl<T> ResolvePayload<T> {
    pub(super) fn new(future: WaitForValue<T>) -> Self {
        Self { future }
    }
}

impl<T: Clone> Future for ResolvePayload<T> {
    type Output = Result<T, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut().future.poll_unpin(cx) {
            Poll::Ready(value) => Poll::Ready(Ok(value)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone)]
pub(super) struct BlockCell<T> {
    inner: Arc<Mutex<Option<T>>>,
    notify: Arc<Notify>,
}

impl<T: Clone> BlockCell<T> {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(super) fn set(&self, value: T) {
        let mut inner = self.inner.lock().unwrap();
        *inner = Some(value);
        self.notify.notify_one();
    }

    pub(super) fn get(&self) -> Option<T> {
        let inner = self.inner.lock().unwrap();
        inner.clone()
    }

    // Return a future that resolves when value is set
    pub(super) fn wait_for_value(&self) -> WaitForValue<T> {
        WaitForValue { cell: self.clone() }
    }
}

#[derive(Clone)]
// Future that resolves when a value is set in BlockCell
pub(super) struct WaitForValue<T> {
    cell: BlockCell<T>,
}

impl<T: Clone> Future for WaitForValue<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(value) = self.cell.get() {
            Poll::Ready(value)
        } else {
            // Instead of register, we use notified() to get a future
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl<T: Clone> Default for BlockCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn job_deadline(unix_timestamp_secs: u64) -> std::time::Duration {
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
    use alloy_eips::eip7685::Requests;
    use alloy_primitives::U256;
    use reth_node_api::NodePrimitives;
    use reth_optimism_payload_builder::{
        OpPayloadAttrs, OpPayloadPrimitives, payload::OpPayloadBuilderAttributes,
    };
    use reth_optimism_primitives::OpPrimitives;
    use reth_payload_primitives::BuiltPayloadExecutedBlock;
    use reth_primitives_traits::SealedBlock;
    use tokio::{
        task,
        time::{Duration, sleep},
    };

    #[tokio::test]
    async fn test_block_cell_wait_for_value() {
        let cell = BlockCell::new();

        // Spawn a task that will set the value after a delay
        let cell_clone = cell.clone();
        task::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            cell_clone.set(42);
        });

        // Wait for the value and verify
        let wait_future = cell.wait_for_value();
        let result = wait_future.await;
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_block_cell_immediate_value() {
        let cell = BlockCell::new();
        cell.set(42);

        // Value should be immediately available
        let wait_future = cell.wait_for_value();
        let result = wait_future.await;
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_block_cell_multiple_waiters() {
        let cell = BlockCell::new();

        // Spawn multiple waiters
        let wait1 = task::spawn({
            let cell = cell.clone();
            async move { cell.wait_for_value().await }
        });

        let wait2 = task::spawn({
            let cell = cell.clone();
            async move { cell.wait_for_value().await }
        });

        // Set value after a delay
        sleep(Duration::from_millis(100)).await;
        cell.set(42);

        // All waiters should receive the value
        assert_eq!(wait1.await.unwrap(), 42);
        assert_eq!(wait2.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_block_cell_update_value() {
        let cell = BlockCell::new();

        // Set initial value
        cell.set(42);

        // Set new value
        cell.set(43);

        // Waiter should get the latest value
        let result = cell.wait_for_value().await;
        assert_eq!(result, 43);
    }

    #[derive(Debug, Clone)]
    struct MockBuilder<N> {
        events: Arc<Mutex<Vec<BlockEvent>>>,
        _marker: std::marker::PhantomData<N>,
    }

    impl<N> MockBuilder<N> {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(vec![])),
                _marker: std::marker::PhantomData,
            }
        }

        fn new_event(&self, event: BlockEvent) {
            let mut events = self.events.lock().unwrap();
            events.push(event);
        }

        fn get_events(&self) -> Vec<BlockEvent> {
            let mut events = self.events.lock().unwrap();
            std::mem::take(&mut *events)
        }
    }

    #[derive(Clone, Debug, Default)]
    struct MockPayload;

    impl BuiltPayload for MockPayload {
        type Primitives = OpPrimitives;

        fn block(&self) -> &SealedBlock<<Self::Primitives as NodePrimitives>::Block> {
            unimplemented!()
        }

        /// Returns the fees collected for the built block
        fn fees(&self) -> U256 {
            unimplemented!()
        }

        /// Returns the entire execution data for the built block, if available.
        fn executed_block(&self) -> Option<BuiltPayloadExecutedBlock<Self::Primitives>> {
            None
        }

        /// Returns the EIP-7865 requests for the payload if any.
        fn requests(&self) -> Option<Requests> {
            unimplemented!()
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    enum BlockEvent {
        Started,
        Cancelled,
    }

    #[async_trait::async_trait]
    impl<N> PayloadBuilder for MockBuilder<N>
    where
        N: OpPayloadPrimitives,
    {
        type RpcAttributes = OpPayloadAttrs;
        type Attributes = OpPayloadBuilderAttributes<N::SignedTx>;
        type BuiltPayload = MockPayload;

        fn from_rpc_attrs(
            parent: B256,
            id: PayloadId,
            attrs: Self::RpcAttributes,
        ) -> Result<Self::Attributes, PayloadBuilderError> {
            OpPayloadBuilderAttributes::from_rpc_attrs(parent, id, attrs.0)
                .map_err(|e| PayloadBuilderError::Other(Box::new(e)))
        }

        fn try_build(
            &self,
            args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
            _best_payload: BlockCell<Self::BuiltPayload>,
        ) -> Result<(), PayloadBuilderError> {
            self.new_event(BlockEvent::Started);

            loop {
                if args.cancel.is_cancelled() {
                    self.new_event(BlockEvent::Cancelled);
                    return Ok(());
                }

                // Small sleep to prevent tight loop
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

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

    // TODO: Re-enable after adapting to reth 2.0 APIs (reth_testing_utils removed)
    // #[tokio::test]
    // async fn test_payload_generator() { ... }
}
