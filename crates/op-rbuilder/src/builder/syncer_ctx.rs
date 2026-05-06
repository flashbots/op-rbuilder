use crate::{
    builder::{BuilderConfig, OpPayloadJobCtx, context::OpPayloadBuilderCtx},
    evm::OpBlockEvmFactory,
    gas_limiter::{AddressGasLimiter, args::GasLimiterArgs},
    hardforks::ActiveHardforks,
    metrics::OpRBuilderMetrics,
    traits::ClientBounds,
};
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_forks::OpHardforks;
use reth_optimism_payload_builder::{OpPayloadBuilderAttributes, config::OpGasLimitConfig};
use reth_optimism_primitives::OpTransactionSigned;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub(super) struct OpPayloadSyncerCtx {
    builder_ctx: Arc<OpPayloadBuilderCtx>,
}

impl OpPayloadSyncerCtx {
    pub(super) fn new<Client>(
        client: &Client,
        builder_config: BuilderConfig,
        evm_config: OpEvmConfig,
        metrics: Arc<OpRBuilderMetrics>,
    ) -> eyre::Result<Self>
    where
        Client: ClientBounds,
    {
        let chain_spec = client.chain_spec();
        let builder_ctx = Arc::new(OpPayloadBuilderCtx {
            evm_config,
            da_config: builder_config.da_config,
            gas_limit_config: OpGasLimitConfig::default(),
            chain_spec,
            metrics,
            max_gas_per_txn: builder_config.max_gas_per_txn,
            max_uncompressed_block_size: builder_config.max_uncompressed_block_size,
            address_gas_limiter: AddressGasLimiter::new(GasLimiterArgs::default()),
            backrun_bundle_pool: builder_config.backrun_bundle_pool,
            backrun_bundle_args: builder_config.backrun_bundle_args,
            exclude_reverts_between_flashblocks: builder_config.exclude_reverts_between_flashblocks,
            enable_tx_tracking_debug_logs: builder_config.enable_tx_tracking_debug_logs,
            disable_state_root: false,
            enable_incremental_state_root: false,
        });
        Ok(Self { builder_ctx })
    }

    pub(super) fn evm_config(&self) -> &OpEvmConfig {
        &self.builder_ctx.evm_config
    }

    pub(super) fn max_gas_per_txn(&self) -> Option<u64> {
        self.builder_ctx.max_gas_per_txn
    }

    pub(super) fn max_uncompressed_block_size(&self) -> Option<u64> {
        self.builder_ctx.max_uncompressed_block_size
    }

    pub(super) fn enable_tx_tracking_debug_logs(&self) -> bool {
        self.builder_ctx.enable_tx_tracking_debug_logs
    }

    /// Returns true if regolith is active for the payload.
    pub(super) fn is_regolith_active(&self, timestamp: u64) -> bool {
        self.builder_ctx
            .chain_spec
            .is_regolith_active_at_timestamp(timestamp)
    }

    pub(super) fn into_op_payload_job_ctx(
        self,
        payload_config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
        evm_factory: OpBlockEvmFactory,
        block_env_attributes: OpNextBlockEnvAttributes,
        cancel: CancellationToken,
    ) -> OpPayloadJobCtx {
        let backrun_pool = self
            .builder_ctx
            .backrun_bundle_pool
            .block_pool(payload_config.parent_header.number + 1);
        let hardforks = ActiveHardforks::new(
            Arc::clone(&self.builder_ctx.chain_spec),
            block_env_attributes.timestamp,
        );

        OpPayloadJobCtx {
            builder_ctx: self.builder_ctx,
            evm_factory,
            config: payload_config,
            block_env_attributes,
            hardforks,
            cancel,
            backrun_pool,
        }
    }
}
