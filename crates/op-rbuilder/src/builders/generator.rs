use alloy_primitives::B256;
use futures_util::Future;
use reth::{
    providers::{BlockReaderIdExt, StateProviderFactory},
    tasks::TaskSpawner,
};
use reth_basic_payload_builder::{
    BasicPayloadJobGeneratorConfig, HeaderForPayload, PayloadConfig, PrecachedState,
};
use reth_node_api::{NodePrimitives, PayloadBuilderAttributes, PayloadKind};
use reth_payload_builder::{
    KeepPayloadJobAlive, PayloadBuilderError, PayloadJob, PayloadJobGenerator,
};
use reth_payload_primitives::BuiltPayload;
use reth_primitives_traits::HeaderTy;
use reth_provider::CanonStateNotification;
use reth_revm::cached::CachedReads;
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::oneshot,
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
    /// The payload attributes type to accept for building.
    type Attributes: PayloadBuilderAttributes;
    /// The type of the built payload.
    type BuiltPayload: BuiltPayload;

    /// Tries to build a transaction payload using provided arguments.
    ///
    /// Constructs a transaction payload based on the given arguments,
    /// returning a `Result` indicating success or an error if building fails.
    ///
    /// # Arguments
    ///
    /// - `args`: Build arguments containing necessary components.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the build outcome or an error.
    async fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<Option<Self::BuiltPayload>, PayloadBuilderError>;
}

/// The generator type that creates new jobs that builds empty blocks.
#[derive(Debug)]
pub(super) struct BlockPayloadJobGenerator<Client, Tasks, Builder> {
    /// The client that can interact with the chain.
    client: Client,
    /// How to spawn building tasks
    executor: Tasks,
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

impl<Client, Tasks, Builder> BlockPayloadJobGenerator<Client, Tasks, Builder> {
    /// Creates a new [EmptyBlockPayloadJobGenerator] with the given config and custom
    /// [PayloadBuilder]
    pub(super) fn with_builder(
        client: Client,
        executor: Tasks,
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

impl<Client, Tasks, Builder> PayloadJobGenerator
    for BlockPayloadJobGenerator<Client, Tasks, Builder>
where
    Client: StateProviderFactory
        + BlockReaderIdExt<Header = HeaderForPayload<Builder::BuiltPayload>>
        + Clone
        + Unpin
        + 'static,
    Tasks: TaskSpawner + Clone + Unpin + 'static,
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type Job = BlockPayloadJob<Tasks, Builder>;

    /// This is invoked when the node receives payload attributes from the beacon node via
    /// `engine_forkchoiceUpdatedVX`
    fn new_payload_job(
        &self,
        attributes: <Builder as PayloadBuilder>::Attributes,
    ) -> Result<Self::Job, PayloadBuilderError> {
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

        let parent_header = if attributes.parent().is_zero() {
            // use latest block if parent is zero: genesis block
            self.client
                .latest_header()?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?
        } else {
            self.client
                .sealed_header_by_hash(attributes.parent())?
                .ok_or_else(|| PayloadBuilderError::MissingParentBlock(attributes.parent()))?
        };

        info!("Spawn block building job");

        // The deadline is critical for payload availability. If we reach the deadline,
        // the payload job stops and cannot be queried again. With tight deadlines close
        // to the block number, we risk reaching the deadline before the node queries the payload.
        //
        // Adding 0.5 seconds as wiggle room since block times are shorter here.
        // TODO: A better long-term solution would be to implement cancellation logic
        // that cancels existing jobs when receiving new block building requests.
        //
        // When batcher's max channel duration is big enough (e.g. 10m), the
        // sequencer would send an avalanche of FCUs/getBlockByNumber on
        // each batcher update (with 10m channel it's ~800 FCUs at once).
        // At such moment it can happen that the time b/w FCU and ensuing
        // getPayload would be on the scale of ~2.5s. Therefore we should
        // "remember" the payloads long enough to accommodate this corner-case
        // (without it we are losing blocks). Postponing the deadline for 5s
        // (not just 0.5s) because of that.
        let deadline = job_deadline(attributes.timestamp()) + self.extra_block_deadline;

        let deadline = Box::pin(tokio::time::sleep(deadline));
        let config = PayloadConfig::new(Arc::new(parent_header.clone()), attributes);

        let mut job = BlockPayloadJob {
            executor: self.executor.clone(),
            builder: self.builder.clone(),
            config,
            payload_rx: None,
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
pub(super) struct BlockPayloadJob<Tasks, Builder>
where
    Builder: PayloadBuilder,
{
    /// The configuration for how the payload will be created.
    pub(crate) config: PayloadConfig<Builder::Attributes, HeaderForPayload<Builder::BuiltPayload>>,
    /// How to spawn building tasks
    pub(crate) executor: Tasks,
    /// The type responsible for building payloads.
    ///
    /// See [PayloadBuilder]
    pub(crate) builder: Builder,
    /// Receiver for the final payload from the builder task.
    pub(crate) payload_rx: Option<oneshot::Receiver<Option<Builder::BuiltPayload>>>,
    /// Cancellation token for the running job
    pub(crate) cancel: CancellationToken,
    pub(crate) deadline: Pin<Box<Sleep>>, // Add deadline
    pub(crate) build_complete: Option<oneshot::Receiver<Result<(), PayloadBuilderError>>>,
    /// Caches all disk reads for the state the new payloads builds on
    ///
    /// This is used to avoid reading the same state over and over again when new attempts are
    /// triggered, because during the building process we'll repeatedly execute the transactions.
    pub(crate) cached_reads: Option<CachedReads>,
}

impl<Tasks, Builder> PayloadJob for BlockPayloadJob<Tasks, Builder>
where
    Tasks: TaskSpawner + Clone + 'static,
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type PayloadAttributes = Builder::Attributes;
    type ResolvePayloadFuture = ResolvePayload<Self::BuiltPayload>;
    type BuiltPayload = Builder::BuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        unimplemented!()
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        Ok(self.config.attributes.clone())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        info!("Resolve kind {:?}", kind);

        self.cancel.cancel();

        let rx = self.payload_rx.take().expect("payload_rx must exist");
        (ResolvePayload { rx }, KeepPayloadJobAlive::No)
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
impl<Tasks, Builder> BlockPayloadJob<Tasks, Builder>
where
    Tasks: TaskSpawner + Clone + 'static,
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    pub(super) fn spawn_build_job(&mut self) {
        let builder = self.builder.clone();
        let payload_config = self.config.clone();
        let cancel = self.cancel.clone();

        let (build_tx, build_rx) = oneshot::channel();
        let (payload_tx, payload_rx) = oneshot::channel();
        self.build_complete = Some(build_rx);
        self.payload_rx = Some(payload_rx);
        let cached_reads = self.cached_reads.take().unwrap_or_default();
        self.executor.spawn_blocking(Box::pin(async move {
            let args = BuildArguments {
                cached_reads,
                config: payload_config,
                cancel,
            };

            let result = builder.try_build(args).await;
            match result {
                Ok(payload) => {
                    let _ = payload_tx.send(payload);
                    let _ = build_tx.send(Ok(()));
                }
                Err(e) => {
                    let _ = build_tx.send(Err(e));
                }
            }
        }));
    }
}

/// A [PayloadJob] is a a future that's being polled by the `PayloadBuilderService`
impl<Tasks, Builder> Future for BlockPayloadJob<Tasks, Builder>
where
    Tasks: TaskSpawner + Clone + 'static,
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

/// A future that resolves when the builder task sends back its best payload
/// via a oneshot channel.
pub(super) struct ResolvePayload<T> {
    rx: oneshot::Receiver<Option<T>>,
}

impl<T> Future for ResolvePayload<T> {
    type Output = Result<T, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.get_mut().rx).poll(cx) {
            Poll::Ready(Ok(Some(payload))) => Poll::Ready(Ok(payload)),
            Poll::Ready(Ok(None)) => Poll::Ready(Err(PayloadBuilderError::Other(
                "builder produced no payload".into(),
            ))),
            Poll::Ready(Err(_)) => Poll::Ready(Err(PayloadBuilderError::Other(
                "builder task dropped".into(),
            ))),
            Poll::Pending => Poll::Pending,
        }
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
    use rand::rng;
    use reth::tasks::TokioTaskExecutor;
    use reth_node_api::NodePrimitives;
    use reth_optimism_payload_builder::{OpPayloadPrimitives, payload::OpPayloadBuilderAttributes};
    use reth_optimism_primitives::OpPrimitives;
    use reth_payload_primitives::BuiltPayloadExecutedBlock;
    use reth_primitives::SealedBlock;
    use reth_provider::test_utils::MockEthProvider;
    use reth_testing_utils::generators::{BlockRangeParams, random_block_range};
    use tokio::time::Duration;

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
        type Attributes = OpPayloadBuilderAttributes<N::SignedTx>;
        type BuiltPayload = MockPayload;

        async fn try_build(
            &self,
            args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
        ) -> Result<Option<Self::BuiltPayload>, PayloadBuilderError> {
            self.new_event(BlockEvent::Started);

            loop {
                if args.cancel.is_cancelled() {
                    self.new_event(BlockEvent::Cancelled);
                    return Ok(None);
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

    #[tokio::test]
    async fn test_payload_generator() -> eyre::Result<()> {
        let mut rng = rng();

        let client = MockEthProvider::default();
        let executor = TokioTaskExecutor::default();
        let config = BasicPayloadJobGeneratorConfig::default();
        let builder = MockBuilder::<OpPrimitives>::new();

        let (start, count) = (1, 10);
        let blocks = random_block_range(
            &mut rng,
            start..=start + count - 1,
            BlockRangeParams {
                tx_count: 0..2,
                ..Default::default()
            },
        );

        client.extend_blocks(blocks.iter().cloned().map(|b| (b.hash(), b.unseal())));

        let generator = BlockPayloadJobGenerator::with_builder(
            client.clone(),
            executor,
            config,
            builder.clone(),
            false,
            std::time::Duration::from_secs(1),
        );

        // this is not nice but necessary
        let mut attr = OpPayloadBuilderAttributes::default();
        attr.payload_attributes.parent = client.latest_header()?.unwrap().hash();

        {
            let job = generator.new_payload_job(attr.clone())?;
            let _ = job.await;

            // you need to give one second for the job to be dropped and cancelled the internal job
            tokio::time::sleep(Duration::from_secs(1)).await;

            let events = builder.get_events();
            assert_eq!(events, vec![BlockEvent::Started, BlockEvent::Cancelled]);
        }

        {
            // job resolve triggers cancellations from the build task
            let mut job = generator.new_payload_job(attr.clone())?;
            let _ = job.resolve();
            let _ = job.await;

            tokio::time::sleep(Duration::from_secs(1)).await;

            let events = builder.get_events();
            assert_eq!(events, vec![BlockEvent::Started, BlockEvent::Cancelled]);
        }

        Ok(())
    }
}
