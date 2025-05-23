//! RPC component builder

pub use reth_optimism_rpc::OpEngineApi;
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeTypes};
use reth_node_builder::rpc::{EngineApiBuilder, EngineValidatorBuilder};
use reth_node_core::version::{CARGO_PKG_VERSION, CLIENT_CODE, VERGEN_GIT_SHA};
use reth_optimism_node::OP_NAME_CLIENT;
use reth_optimism_rpc::engine::OP_ENGINE_CAPABILITIES;
use reth_optimism_rpc::OpEngineApiServer;
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
    OpExecutionData, OpExecutionPayloadV4, ProtocolVersion,
    SuperchainSignal,
};
use reth_chainspec::EthereumHardforks;
use reth_node_api::{EngineTypes, EngineValidator};
use reth_rpc_api::IntoEngineApiRpcModule;
use reth_rpc_engine_api::EngineApi;
use reth_storage_api::{BlockReader, HeaderProvider, StateProviderFactory};
use reth_transaction_pool::TransactionPool;


/// Builder for basic [`OpEngineApi`] implementation.
#[derive(Debug, Default)]
pub struct OpEngineApiBuilder<EV> {
    engine_validator_builder: EV,
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
        let Self { engine_validator_builder } = self;

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

        Ok(OpEngineApiExt::new(OpEngineApi::new(inner)))
    }
}

pub struct OpEngineApiExt<Provider, EngineT: EngineTypes, Pool, Validator, ChainSpec>
{
    inner: OpEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>
}

impl <Provider, EngineT, Pool, Validator, ChainSpec> OpEngineApiExt<Provider, EngineT, Pool, Validator, ChainSpec>
where
    Provider: HeaderProvider + BlockReader + StateProviderFactory + 'static,
    EngineT: EngineTypes<ExecutionData = OpExecutionData>,
    Pool: TransactionPool + 'static,
    Validator: EngineValidator<EngineT>,
    ChainSpec: EthereumHardforks + Send + Sync + 'static,
{
    pub fn new(engine: OpEngineApi<Provider, EngineT, Pool, Validator, ChainSpec>) -> Self {
        Self {
            inner: engine
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
        self.inner.new_payload_v3(payload, versioned_hashes, parent_beacon_block_root).await
    }

    async fn new_payload_v4(
        &self,
        payload: OpExecutionPayloadV4,
        versioned_hashes: Vec<B256>,
        parent_beacon_block_root: B256,
        execution_requests: Requests,
    ) -> RpcResult<PayloadStatus> {
        self.new_payload_v4(payload, versioned_hashes, parent_beacon_block_root, execution_requests).await
    }

    async fn fork_choice_updated_v1(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        self.inner.fork_choice_updated_v1(fork_choice_state, payload_attributes).await
    }

    async fn fork_choice_updated_v2(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        println!("fork_choice_updated_v2");
        self.inner.fork_choice_updated_v2(fork_choice_state, payload_attributes).await
    }

    async fn fork_choice_updated_v3(
        &self,
        fork_choice_state: ForkchoiceState,
        payload_attributes: Option<EngineT::PayloadAttributes>,
    ) -> RpcResult<ForkchoiceUpdated> {
        println!("fork_choice_updated_v3");
        self.inner.fork_choice_updated_v3(fork_choice_state, payload_attributes).await
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
        self.inner.get_payload_bodies_by_range_v1(start, count).await
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
