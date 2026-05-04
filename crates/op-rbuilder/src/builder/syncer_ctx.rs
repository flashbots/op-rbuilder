use crate::{
    backrun_bundle::{BackrunBundleArgs, BackrunBundleGlobalPool, BackrunBundlesPayloadCtx},
    builder::{BuilderConfig, OpPayloadBuilderCtx},
    evm::OpBlockEvmFactory,
    limiter::{AddressLimiter, args::GasLimiterArgs},
    metrics::OpRBuilderMetrics,
    traits::ClientBounds,
};
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_forks::OpHardforks;
use reth_optimism_payload_builder::{
    OpPayloadBuilderAttributes,
    config::{OpDAConfig, OpGasLimitConfig},
};
use reth_optimism_primitives::OpTransactionSigned;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub(super) struct OpPayloadSyncerCtx {
    /// The type that knows how to perform system calls and configure the evm.
    evm_config: OpEvmConfig,
    /// The DA config for the payload builder
    da_config: OpDAConfig,
    /// The chainspec
    chain_spec: Arc<OpChainSpec>,
    /// Max gas that can be used by a transaction.
    max_gas_per_txn: Option<u64>,
    /// Maximum cumulative uncompressed (EIP-2718 encoded) block size in bytes.
    max_uncompressed_block_size: Option<u64>,
    /// The metrics for the builder
    metrics: Arc<OpRBuilderMetrics>,
    /// Global backrun bundle pool
    backrun_bundle_pool: BackrunBundleGlobalPool,
    /// Backrun bundle configuration
    backrun_bundle_args: BackrunBundleArgs,
    /// Skip reverted txs in subsequent flashblocks
    exclude_reverts_between_flashblocks: bool,
    /// Enable transaction tracking logs
    enable_tx_tracking_debug_logs: bool,
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
        Ok(Self {
            evm_config,
            da_config: builder_config.da_config.clone(),
            chain_spec,
            max_gas_per_txn: builder_config.max_gas_per_txn,
            max_uncompressed_block_size: builder_config.max_uncompressed_block_size,
            metrics,
            backrun_bundle_pool: builder_config.backrun_bundle_pool.clone(),
            backrun_bundle_args: builder_config.backrun_bundle_args.clone(),
            exclude_reverts_between_flashblocks: builder_config.exclude_reverts_between_flashblocks,
            enable_tx_tracking_debug_logs: builder_config.enable_tx_tracking_debug_logs,
        })
    }

    pub(super) fn evm_config(&self) -> &OpEvmConfig {
        &self.evm_config
    }

    pub(super) fn max_gas_per_txn(&self) -> Option<u64> {
        self.max_gas_per_txn
    }

    pub(super) fn max_uncompressed_block_size(&self) -> Option<u64> {
        self.max_uncompressed_block_size
    }

    pub(super) fn enable_tx_tracking_debug_logs(&self) -> bool {
        self.enable_tx_tracking_debug_logs
    }

    /// Returns true if regolith is active for the payload.
    pub(super) fn is_regolith_active(&self, timestamp: u64) -> bool {
        self.chain_spec.is_regolith_active_at_timestamp(timestamp)
    }

    /// Returns true if canyon is active for the payload.
    pub(super) fn is_canyon_active(&self, timestamp: u64) -> bool {
        self.chain_spec.is_canyon_active_at_timestamp(timestamp)
    }

    pub(super) fn into_op_payload_builder_ctx(
        self,
        payload_config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
        evm_factory: OpBlockEvmFactory,
        block_env_attributes: OpNextBlockEnvAttributes,
        cancel: CancellationToken,
    ) -> OpPayloadBuilderCtx {
        let backrun_ctx = BackrunBundlesPayloadCtx {
            pool: self
                .backrun_bundle_pool
                .block_pool(payload_config.parent_header.number + 1),
            args: self.backrun_bundle_args,
        };
        OpPayloadBuilderCtx {
            evm_factory,
            da_config: self.da_config,
            gas_limit_config: OpGasLimitConfig::default(),
            chain_spec: self.chain_spec,
            config: payload_config,
            block_env_attributes,
            cancel,
            metrics: self.metrics,
            max_gas_per_txn: self.max_gas_per_txn,
            max_uncompressed_block_size: self.max_uncompressed_block_size,
            address_limiter: AddressLimiter::new(GasLimiterArgs::default()),
            backrun_ctx,
            exclude_reverts_between_flashblocks: self.exclude_reverts_between_flashblocks,
            enable_tx_tracking_debug_logs: self.enable_tx_tracking_debug_logs,
            disable_state_root: false,
            enable_incremental_state_root: false,
        }
    }
}
