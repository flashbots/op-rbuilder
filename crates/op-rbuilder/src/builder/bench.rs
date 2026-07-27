//! Bench-only access to candidate execution and assembly internals; no API or stability guarantees.

use std::{fmt::Debug, sync::Arc};

use alloy_evm::Database;
use op_alloy_rpc_types_engine::OpFlashblockPayload;
use reth_basic_payload_builder::PayloadConfig;
use reth_node_api::PayloadBuilderError;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{OpEvmConfig, OpNextBlockEnvAttributes};
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilderAttributes};
use reth_optimism_payload_builder::config::{OpDAConfig, OpGasLimitConfig};
use reth_optimism_primitives::OpTransactionSigned;
use reth_provider::{
    HashedPostStateProvider, ProviderError, StateRootProvider, StorageRootProvider,
};
use reth_revm::State;

use super::{
    StateRootCalculator,
    cancellation::PayloadJobCancellation,
    context::{OpPayloadBuilderCtx, OpPayloadJobCtx},
    payload::FlashblocksState,
};
use crate::{
    backrun_bundle::BackrunBundleArgs,
    evm::OpBlockEvmFactory,
    hardforks::ActiveHardforks,
    limiter::{
        AddressLimiter,
        args::{ComputeLimiterArgs, GasLimiterArgs},
    },
    metrics::OpRBuilderMetrics,
    primitives::reth::ExecutionInfo,
    traits::PayloadTxsBounds,
};

/// Bench-only candidate context with no API or stability guarantees.
#[doc(hidden)]
pub struct CandidateBenchContext {
    inner: OpPayloadJobCtx,
}

impl CandidateBenchContext {
    /// Builds the real payload-job context used by candidate execution.
    pub fn new(
        chain_spec: Arc<OpChainSpec>,
        config: PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    ) -> Result<Self, PayloadBuilderError> {
        // `OpPayloadBuilder::get_op_payload_job_ctx` in `builder/payload.rs` is the source of truth;
        // keep this bench-only construction in lockstep with it.
        let timestamp = config.attributes.timestamp;
        let hardforks = ActiveHardforks::new(Arc::clone(&chain_spec), timestamp);
        let extra_data = if hardforks.is_jovian_active() {
            config
                .attributes
                .get_jovian_extra_data(hardforks.base_fee_params())
                .map_err(PayloadBuilderError::other)?
        } else if hardforks.is_holocene_active() {
            config
                .attributes
                .get_holocene_extra_data(hardforks.base_fee_params())
                .map_err(PayloadBuilderError::other)?
        } else {
            Default::default()
        };
        let block_env_attributes = OpNextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: config.attributes.suggested_fee_recipient,
            prev_randao: config.attributes.prev_randao,
            gas_limit: config
                .attributes
                .gas_limit
                .unwrap_or(config.parent_header.gas_limit),
            parent_beacon_block_root: config.attributes.parent_beacon_block_root,
            extra_data,
        };
        let evm_config = OpEvmConfig::optimism(Arc::clone(&chain_spec));
        let evm_factory = OpBlockEvmFactory::for_next_block(
            evm_config.clone(),
            &config.parent_header,
            &block_env_attributes,
        )
        .map_err(PayloadBuilderError::other)?;
        let address_limiter = AddressLimiter::new(
            GasLimiterArgs {
                gas_limiter_enabled: true,
                max_gas_per_address: u64::MAX,
                refill_rate_per_block: u64::MAX,
                cleanup_interval: u64::MAX,
            },
            ComputeLimiterArgs {
                compute_limiter_enabled: true,
                max_time_us_per_address: u64::MAX,
                compute_refill_rate_per_block: u64::MAX,
                compute_cleanup_interval: u64::MAX,
            },
        );
        let address_limiter_guard = Arc::new(address_limiter.begin());
        let builder_ctx = Arc::new(OpPayloadBuilderCtx {
            evm_config,
            da_config: OpDAConfig::default(),
            gas_limit_config: OpGasLimitConfig::default(),
            chain_spec,
            metrics: Arc::new(OpRBuilderMetrics::default()),
            max_gas_per_txn: None,
            max_uncompressed_block_size: None,
            address_limiter,
            backrun_bundle_args: BackrunBundleArgs::default(),
            // CLI default is false; true exercises 2b's `mark_excluded`/`reverted_bundle_tx_hashes`.
            exclude_reverts_between_flashblocks: true,
            enable_tx_tracking_debug_logs: false,
            disable_state_root: false,
            enable_incremental_state_root: false,
        });
        let cancel = PayloadJobCancellation::default().flashblock_child();

        Ok(Self {
            inner: OpPayloadJobCtx::new(
                builder_ctx,
                evm_factory,
                config,
                block_env_attributes,
                hardforks,
                cancel,
                None,
                address_limiter_guard,
            ),
        })
    }

    /// Runs the real candidate transaction loop; bench-only and unstable.
    #[expect(clippy::too_many_arguments)]
    pub fn execute_best_transactions<DB>(
        &self,
        info: &mut ExecutionInfo,
        state: &mut State<DB>,
        best_txs: &mut impl PayloadTxsBounds,
        block_gas_limit: u64,
        block_da_limit: Option<u64>,
        block_da_footprint_limit: Option<u64>,
        max_uncompressed_block_size: Option<u64>,
        flashblock_index: u64,
    ) -> Result<Option<()>, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + Debug,
    {
        self.inner.execute_best_transactions(
            info,
            state,
            best_txs,
            block_gas_limit,
            block_da_limit,
            block_da_footprint_limit,
            max_uncompressed_block_size,
            flashblock_index,
        )
    }

    /// Runs the real flashblock assembly path; bench-only and unstable.
    pub fn assemble<DB, P>(
        &self,
        state: &mut State<DB>,
        info: &mut ExecutionInfo,
        state_root_calc: &mut StateRootCalculator,
        flashblock_index: u64,
        previous_transaction_count: usize,
    ) -> Result<(OpBuiltPayload, OpFlashblockPayload), PayloadBuilderError>
    where
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider + StorageRootProvider,
    {
        let mut fb_state = FlashblocksState::new(10);
        for _ in 0..flashblock_index {
            fb_state = fb_state.next_after_seal(None, None);
        }
        fb_state.set_last_flashblock_tx_index(previous_transaction_count);

        self.inner.block_assembly_input()?.assemble(
            state,
            Some(&mut fb_state),
            info,
            state_root_calc,
            Arc::clone(&self.inner.metrics),
            false,
        )
    }
}
