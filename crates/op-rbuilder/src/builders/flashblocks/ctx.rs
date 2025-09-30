use crate::{
    builders::{
        BuilderConfig, OpPayloadBuilderCtx,
        flashblocks::{FlashblocksConfig, payload::FlashblocksExtraCtx},
    },
    gas_limiter::AddressGasLimiter,
    metrics::OpRBuilderMetrics,
    traits::ClientBounds,
};
use eyre::WrapErr as _;
use op_revm::OpSpecId;
use reth_basic_payload_builder::PayloadConfig;
use reth_evm::{ConfigureEvm as _, EvmEnv};
use reth_optimism_chainspec::{OpChainSpec, OpHardforks as _};
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_payload_builder::{OpPayloadBuilderAttributes, config::OpDAConfig};
use reth_optimism_primitives::OpTransactionSigned;
use reth_payload_primitives::PayloadBuilderAttributes as _;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub(super) struct OpPayloadSyncerCtx {
    /// The type that knows how to perform system calls and configure the evm.
    pub evm_config: OpEvmConfig,
    /// The DA config for the payload builder
    pub da_config: OpDAConfig,
    /// The chainspec
    pub chain_spec: Arc<OpChainSpec>,
    // /// How to build the payload.
    // pub config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    /// Block env attributes for the current block.
    //pub block_env_attributes: OpNextBlockEnvAttributes,
    /// Marker to check whether the job has been cancelled.
    //pub cancel: CancellationToken,
    /// Extra context for the payload builder
    pub extra_ctx: FlashblocksExtraCtx,
    /// Max gas that can be used by a transaction.
    pub max_gas_per_txn: Option<u64>,
}

impl OpPayloadSyncerCtx {
    pub(super) fn into_op_payload_builder_ctx(
        self,
        payload_config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
        evm_env: EvmEnv<OpSpecId>,
        block_env_attributes: OpNextBlockEnvAttributes,
        cancel: CancellationToken,
        metrics: Arc<OpRBuilderMetrics>,
        address_gas_limiter: AddressGasLimiter,
    ) -> OpPayloadBuilderCtx {
        OpPayloadBuilderCtx {
            evm_config: self.evm_config,
            da_config: self.da_config,
            chain_spec: self.chain_spec,
            config: payload_config,
            evm_env,
            block_env_attributes,
            cancel,
            builder_signer: None,
            metrics,
            extra_ctx: (),
            max_gas_per_txn: self.max_gas_per_txn,
            address_gas_limiter,
        }
    }
}

pub(super) fn get_op_payload_syncer_ctx<Client>(
    client: Client,
    evm_config: OpEvmConfig,
    builder_config: BuilderConfig<FlashblocksConfig>,
    // address_gas_limiter: AddressGasLimiter,
    // config: reth_basic_payload_builder::PayloadConfig<
    //     OpPayloadBuilderAttributes<op_alloy_consensus::OpTxEnvelope>,
    // >,
    extra_ctx: FlashblocksExtraCtx,
) -> OpPayloadSyncerCtx
where
    Client: ClientBounds,
{
    let chain_spec = client.chain_spec();
    // let timestamp = config.attributes.timestamp();
    // let block_env_attributes = OpNextBlockEnvAttributes {
    //     timestamp,
    //     suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
    //     prev_randao: config.attributes.prev_randao(),
    //     gas_limit: config
    //         .attributes
    //         .gas_limit
    //         .unwrap_or(config.parent_header.gas_limit),
    //     parent_beacon_block_root: config
    //         .attributes
    //         .payload_attributes
    //         .parent_beacon_block_root,
    //     extra_data: if chain_spec.is_holocene_active_at_timestamp(timestamp) {
    //         config
    //             .attributes
    //             .get_holocene_extra_data(chain_spec.base_fee_params_at_timestamp(timestamp))
    //             .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
    //     } else {
    //         Default::default()
    //     },
    // };

    // let evm_env = evm_config
    //     .next_evm_env(&config.parent_header, &block_env_attributes)
    //     .wrap_err("failed to create next evm env")?;

    OpPayloadSyncerCtx {
        evm_config: evm_config.clone(),
        da_config: builder_config.da_config.clone(),
        chain_spec,
        //config,
        // evm_env,
        // block_env_attributes,
        // cancel,
        // builder_signer: builder_config.builder_signer,
        // metrics: Default::default(),
        extra_ctx,
        max_gas_per_txn: builder_config.max_gas_per_txn,
        //address_gas_limiter,
    }
}
