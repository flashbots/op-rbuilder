//! RPC component builder

use reth_node_api::{AddOnsContext, FullNodeComponents, NodeTypes};
use reth_node_builder::rpc::{EngineApiBuilder, EngineValidatorBuilder};
use reth_node_core::version::{CARGO_PKG_VERSION, CLIENT_CODE, VERGEN_GIT_SHA};
use reth_optimism_node::OP_NAME_CLIENT;
pub use reth_optimism_rpc::OpEngineApi;
use reth_optimism_rpc::{engine::OP_ENGINE_CAPABILITIES, OpEngineApiServer};
use reth_payload_builder::PayloadStore;
use reth_rpc_engine_api::EngineCapabilities;

use alloy_eips::eip7685::Requests;
use alloy_primitives::{BlockHash, B256, U64};
use alloy_rpc_types_engine::{
    ClientVersionV1, ExecutionPayloadBodiesV1, ExecutionPayloadInputV2, ExecutionPayloadV3,
    ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus,
};
use jsonrpsee_core::{server::RpcModule, RpcResult};
use op_alloy_rpc_types_engine::{
    OpExecutionData, OpExecutionPayloadV4, ProtocolVersion, SuperchainSignal,
};
use reth_chainspec::EthereumHardforks;
use reth_node_api::{EngineTypes, EngineValidator};
use reth_rpc_api::IntoEngineApiRpcModule;
use reth_rpc_engine_api::EngineApi;
use reth_storage_api::{BlockReader, HeaderProvider, StateProviderFactory};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::TransactionPool;

use reqwest::Client;
use serde_json::json;
use tracing;

/// Builder for basic [`OpEngineApi`] implementation.
#[derive(Debug)]
pub struct OpEngineApiBuilder<EV> {
    engine_validator_builder: EV,
    engine_peers: Option<String>,
}

impl<EV> OpEngineApiBuilder<EV> {
    /// Create a new builder with engine peers configuration
    pub fn with_engine_peers(mut self, engine_peers: Option<String>) -> Self {
        self.engine_peers = engine_peers;
        self
    }
}

impl<EV> Default for OpEngineApiBuilder<EV>
where
    EV: Default,
{
    fn default() -> Self {
        Self {
            engine_validator_builder: EV::default(),
            engine_peers: None,
        }
    }
}

impl<N, EV> EngineApiBuilder<N> for OpEngineApiBuilder<EV>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthereumHardforks,
            Payload: EngineTypes<ExecutionData = OpExecutionData>,
        >,
    >,
    EV: EngineValidatorBuilder<N>,
{
    type EngineApi = OpEngineApiExt<
        N::Provider,
        <N::Types as NodeTypes>::Payload,
        N::Pool,
        EV::Validator,
        <N::Types as NodeTypes>::ChainSpec,
    >;

    async fn build_engine_api(self, ctx: &AddOnsContext<'_, N>) -> eyre::Result<Self::EngineApi> {
        let Self {
            engine_validator_builder,
            engine_peers,
        } = self;

        let engine_validator = engine_validator_builder.build(ctx).await?;
        let client = ClientVersionV1 {
            code: CLIENT_CODE,
            name: OP_NAME_CLIENT.to_string(),
            version: CARGO_PKG_VERSION.to_string(),
            commit: VERGEN_GIT_SHA.to_string(),
        };
        let inner = EngineApi::new(
            ctx.node.provider().clone(),
            ctx.config.chain.clone(),
            ctx.beacon_engine_handle.clone(),
            PayloadStore::new(ctx.node.payload_builder_handle().clone()),
            ctx.node.pool().clone(),
            Box::new(ctx.node.task_executor().clone()),
            client,
            EngineCapabilities::new(OP_ENGINE_CAPABILITIES.iter().copied()),
            engine_validator,
            ctx.config.engine.accept_execution_requests_hash,
        );

        // Parse engine peers configuration
        let engine_peers = engine_peers
            .map(|peers_str| {
                peers_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        Ok(OpEngineApiExt::new(
            OpEngineApi::new(inner),
            engine_peers,
            ctx.node.task_executor().clone(),
            Client::new(),
        ))
    }
}

pub struct OpEngineApiExt<Provider, EngineT: EngineTypes, Pool, Validator, ChainSpec> {
    inner: OpEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>,
    engine_peers: Vec<String>,
    task_executor: TaskExecutor,
    http_client: Client,
}

impl<Provider, EngineT, Pool, Validator, ChainSpec>
    OpEngineApiExt<Provider, EngineT, Pool, Validator, ChainSpec>
where
    Provider: HeaderProvider + BlockReader + StateProviderFactory + 'static,
    EngineT: EngineTypes<ExecutionData = OpExecutionData>,
    Pool: TransactionPool + 'static,
    Validator: EngineValidator<EngineT>,
    ChainSpec: EthereumHardforks + Send + Sync + 'static,
{
    pub fn new(
        engine: OpEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>,
        engine_peers: Vec<String>,
        task_executor: TaskExecutor,
        http_client: Client,
    ) -> Self {
        Self {
            inner: engine,
            engine_peers,
            task_executor,
            http_client,
        }
    }

    /// Multiplexes the given engine API call to all configured peers
    async fn multiplex_to_peers<T: serde::Serialize>(&self, method: &str, params: T) {
        if self.engine_peers.is_empty() {
            return;
        }

        let client = &self.http_client;
        let task_executor = &self.task_executor;
        let method = method.to_string(); // Convert to owned String

        // Serialize params once for all peers
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        for peer_url in &self.engine_peers {
            let peer_url = peer_url.clone();
            let client = client.clone();
            let method = method.clone(); // Clone the owned String
            let request_body = request_body.clone(); // Clone the serialized request

            task_executor.spawn(Box::pin(async move {
                if let Err(e) = client
                    .post(&peer_url)
                    .header("Content-Type", "application/json")
                    .json(&request_body)
                    .send()
                    .await
                {
                    tracing::warn!("Failed to forward {} to peer {}: {}", method, peer_url, e);
                }
            }));
        }
    }
}

#[async_trait::async_trait]
impl<Provider, EngineT, Pool, Validator, ChainSpec> OpEngineApiServer<EngineT>
    for OpEngineApiExt<Provider, EngineT, Pool, Validator, ChainSpec>
where
    Provider: HeaderProvider + BlockReader + StateProviderFactory + 'static,
    EngineT: EngineTypes<ExecutionData = OpExecutionData>,
    Pool: TransactionPool + 'static,
    Validator: EngineValidator<EngineT>,
    ChainSpec: EthereumHardforks + Send + Sync + 'static,
{
    async fn new_payload_v2(&self, payload: ExecutionPayloadInputV2) -> RpcResult<PayloadStatus> {
        self.inner.new_payload_v2(payload).await
    }

    async fn new_payload_v3(
        &self,
        payload: ExecutionPayloadV3,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
    ) -> RpcResult<PayloadStatus> {
        self.inner
            .new_payload_v3(payload, versioned_hashes, parent_beacon_block_root)
            .await
    }

    async fn new_payload_v4(
        &self,
        payload: OpExecutionPayloadV4,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        execution_requests: Requests,
    ) -> RpcResult<PayloadStatus> {
        self.new_payload_v4(
            payload,
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        )
        .await
    }

    async fn fork_choice_updated_v1(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        self.inner
            .fork_choice_updated_v1(fork_choice_state, payload_attributes)
            .await
    }

    async fn fork_choice_updated_v2(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        println!("fork_choice_updated_v2");

        // Multiplex to peers
        self.multiplex_to_peers(
            "engine_forkchoiceUpdatedV2",
            (&fork_choice_state, &payload_attributes),
        )
        .await;

        self.inner
            .fork_choice_updated_v2(fork_choice_state, payload_attributes)
            .await
    }

    async fn fork_choice_updated_v3(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        println!("fork_choice_updated_v3");

        // Multiplex to peers
        self.multiplex_to_peers(
            "engine_forkchoiceUpdatedV3",
            (&fork_choice_state, &payload_attributes),
        )
        .await;

        self.inner
            .fork_choice_updated_v3(fork_choice_state, payload_attributes)
            .await
    }

    async fn get_payload_v2(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<EngineT::ExecutionPayloadEnvelopeV2> {
        println!("get_payload_v2");
        self.inner.get_payload_v2(payload_id).await
    }

    async fn get_payload_v3(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<EngineT::ExecutionPayloadEnvelopeV3> {
        println!("get_payload_v3");
        self.inner.get_payload_v3(payload_id).await
    }

    async fn get_payload_v4(
        &self,
        payload_id: PayloadId,
    ) -> RpcResult<EngineT::ExecutionPayloadEnvelopeV4> {
        println!("get_payload_v4");
        self.inner.get_payload_v4(payload_id).await
    }

    async fn get_payload_bodies_by_hash_v1(
        &self,
        block_hashes: Vec<BlockHash>,
    ) -> RpcResult<ExecutionPayloadBodiesV1> {
        self.inner.get_payload_bodies_by_hash_v1(block_hashes).await
    }

    async fn get_payload_bodies_by_range_v1(
        &self,
        start: U64,
        count: U64,
    ) -> RpcResult<ExecutionPayloadBodiesV1> {
        self.inner
            .get_payload_bodies_by_range_v1(start, count)
            .await
    }

    async fn signal_superchain_v1(&self, signal: SuperchainSignal) -> RpcResult<ProtocolVersion> {
        self.inner.signal_superchain_v1(signal).await
    }

    async fn get_client_version_v1(
        &self,
        client: ClientVersionV1,
    ) -> RpcResult<Vec<ClientVersionV1>> {
        self.inner.get_client_version_v1(client).await
    }

    async fn exchange_capabilities(&self, capabilities: Vec<String>) -> RpcResult<Vec<String>> {
        self.inner.exchange_capabilities(capabilities).await
    }
}

impl<Provider, EngineT, Pool, Validator, ChainSpec> IntoEngineApiRpcModule
    for OpEngineApiExt<Provider, EngineT, Pool, Validator, ChainSpec>
where
    EngineT: EngineTypes,
    Self: OpEngineApiServer<EngineT>,
{
    fn into_rpc_module(self) -> RpcModule<()> {
        self.into_rpc().remove_context()
    }
}
