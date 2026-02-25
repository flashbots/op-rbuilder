use crate::{
    backrun_bundle::{BackrunBundleArgs, BackrunBundleGlobalPool, BackrunBundlesPayloadCtx},
    builders::{BuilderConfig, OpPayloadBuilderCtx, flashblocks::FlashblocksConfig},
    gas_limiter::{AddressGasLimiter, args::GasLimiterArgs},
    metrics::OpRBuilderMetrics,
    traits::ClientBounds,
};
use op_revm::OpSpecId;
use reth_basic_payload_builder::PayloadConfig;
use reth_evm::EvmEnv;
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
    /// The metrics for the builder
    metrics: Arc<OpRBuilderMetrics>,
    /// Global backrun bundle pool
    backrun_bundle_pool: BackrunBundleGlobalPool,
    /// Backrun bundle configuration
    backrun_bundle_args: BackrunBundleArgs,
}

impl OpPayloadSyncerCtx {
    pub(super) fn new<Client>(
        client: &Client,
        builder_config: BuilderConfig<FlashblocksConfig>,
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
            metrics,
            backrun_bundle_pool: builder_config.backrun_bundle_pool.clone(),
            backrun_bundle_args: builder_config.backrun_bundle_args.clone(),
        })
    }

    pub(super) fn evm_config(&self) -> &OpEvmConfig {
        &self.evm_config
    }

    pub(super) fn max_gas_per_txn(&self) -> Option<u64> {
        self.max_gas_per_txn
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
        evm_env: EvmEnv<OpSpecId>,
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
            evm_config: self.evm_config,
            da_config: self.da_config,
            gas_limit_config: OpGasLimitConfig::default(),
            chain_spec: self.chain_spec,
            config: payload_config,
            evm_env,
            block_env_attributes,
            cancel,
            builder_signer: None,
            metrics: self.metrics,
            max_gas_per_txn: self.max_gas_per_txn,
            address_gas_limiter: AddressGasLimiter::new(GasLimiterArgs::default()),
            backrun_ctx,
        }
    }
}
