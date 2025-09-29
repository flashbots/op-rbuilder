use crate::{
    builders::{
        BuilderConfig, OpPayloadBuilderCtx,
        flashblocks::{FlashblocksConfig, payload::FlashblocksExtraCtx},
    },
    gas_limiter::AddressGasLimiter,
    traits::ClientBounds,
};
use eyre::WrapErr as _;
use reth_evm::ConfigureEvm as _;
use reth_optimism_chainspec::OpHardforks as _;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_payload_builder::OpPayloadBuilderAttributes;
use reth_payload_primitives::PayloadBuilderAttributes as _;
use tokio_util::sync::CancellationToken;

fn get_op_payload_builder_ctx<Client>(
    client: Client,
    evm_config: OpEvmConfig,
    builder_config: BuilderConfig<FlashblocksConfig>,
    address_gas_limiter: AddressGasLimiter,
    config: reth_basic_payload_builder::PayloadConfig<
        OpPayloadBuilderAttributes<op_alloy_consensus::OpTxEnvelope>,
    >,
    cancel: CancellationToken,
    extra_ctx: FlashblocksExtraCtx,
) -> eyre::Result<OpPayloadBuilderCtx<FlashblocksExtraCtx>>
where
    Client: ClientBounds,
{
    let chain_spec = client.chain_spec();
    let timestamp = config.attributes.timestamp();
    let block_env_attributes = OpNextBlockEnvAttributes {
        timestamp,
        suggested_fee_recipient: config.attributes.suggested_fee_recipient(),
        prev_randao: config.attributes.prev_randao(),
        gas_limit: config
            .attributes
            .gas_limit
            .unwrap_or(config.parent_header.gas_limit),
        parent_beacon_block_root: config
            .attributes
            .payload_attributes
            .parent_beacon_block_root,
        extra_data: if chain_spec.is_holocene_active_at_timestamp(timestamp) {
            config
                .attributes
                .get_holocene_extra_data(chain_spec.base_fee_params_at_timestamp(timestamp))
                .wrap_err("failed to get holocene extra data for flashblocks payload builder")?
        } else {
            Default::default()
        },
    };

    let evm_env = evm_config
        .next_evm_env(&config.parent_header, &block_env_attributes)
        .wrap_err("failed to create next evm env")?;

    Ok(OpPayloadBuilderCtx::<FlashblocksExtraCtx> {
        evm_config: evm_config.clone(),
        chain_spec,
        config,
        evm_env,
        block_env_attributes,
        cancel,
        da_config: builder_config.da_config.clone(),
        builder_signer: builder_config.builder_signer,
        metrics: Default::default(),
        extra_ctx,
        max_gas_per_txn: builder_config.max_gas_per_txn,
        address_gas_limiter,
    })
}
