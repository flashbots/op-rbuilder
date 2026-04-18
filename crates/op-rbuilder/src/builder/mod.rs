use core::{fmt::Debug, time::Duration};
use reth_optimism_payload_builder::config::{OpDAConfig, OpGasLimitConfig};

use crate::{
    args::OpRbuilderArgs,
    backrun_bundle::{BackrunBundleArgs, BackrunBundleGlobalPool},
    flashtestations::args::FlashtestationsArgs,
    gas_limiter::args::GasLimiterArgs,
    tx_signer::Signer,
};

mod best_txs;
mod builder_tx;
pub(crate) mod cancellation;
mod config;
mod context;
mod flashblocks_builder_tx;
mod generator;
mod p2p;
mod payload;
mod payload_handler;
mod presim;
mod service;
mod syncer_ctx;
mod timing;
mod wspub;

pub use builder_tx::{
    BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions, InvalidContractDataError,
    SimulationSuccessResult, get_balance, get_nonce,
};
pub use config::FlashblocksConfig;
pub use context::OpPayloadBuilderCtx;
pub use service::FlashblocksServiceBuilder;

/// Configuration values that are applicable to any type of block builder.
#[derive(Debug, Clone)]
pub struct BuilderConfig {
    /// Secret key of the builder that is used to sign the end of block transaction.
    pub builder_signer: Option<Signer>,

    /// When set to true, transactions are simulated by the builder and excluded from the block
    /// if they revert. They may still be included in the block if individual transactions
    /// opt-out of revert protection.
    pub revert_protection: bool,

    /// When enabled, this will invoke the flashtestions workflow. This involves a
    /// bootstrapping step that generates a new pubkey for the TEE service
    pub flashtestations_config: FlashtestationsArgs,

    /// The interval at which blocks are added to the chain.
    /// This is also the frequency at which the builder will be receiving FCU requests from the
    /// sequencer.
    pub block_time: Duration,

    /// Data Availability configuration for the OP builder
    /// Defines constraints for the maximum size of data availability transactions.
    pub da_config: OpDAConfig,

    /// Gas limit configuration for the payload builder
    pub gas_limit_config: OpGasLimitConfig,

    // The deadline is critical for payload availability. If we reach the deadline,
    // the payload job stops and cannot be queried again. With tight deadlines close
    // to the block number, we risk reaching the deadline before the node queries the payload.
    //
    // SlotCancellation now distinguishes new_fcu/resolved/deadline, so the leeway
    // is mainly for the batcher avalanche scenario described below.
    //
    // When batcher's max channel duration is big enough (e.g. 10m), the
    // sequencer would send an avalanche of FCUs/getBlockByNumber on
    // each batcher update (with 10m channel it's ~800 FCUs at once).
    // At such moment it can happen that the time b/w FCU and ensuing
    // getPayload would be on the scale of ~2.5s. Therefore we should
    // "remember" the payloads long enough to accommodate this corner-case
    // (without it we are losing blocks). Postponing the deadline for 5s
    // (not just 0.5s) because of that.
    pub block_time_leeway: Duration,

    /// Inverted sampling frequency in blocks. 1 - each block, 100 - every 100th block.
    pub sampling_ratio: u64,

    /// Maximum gas a transaction can use before being excluded.
    pub max_gas_per_txn: Option<u64>,

    /// Maximum cumulative uncompressed (EIP-2718 encoded) block size in bytes.
    pub max_uncompressed_block_size: Option<u64>,

    /// Address gas limiter stuff
    pub gas_limiter_config: GasLimiterArgs,

    /// Global pool for backrun bundles
    pub backrun_bundle_pool: BackrunBundleGlobalPool,

    /// Backrun bundle configuration
    pub backrun_bundle_args: BackrunBundleArgs,

    /// Flashblocks configuration
    pub flashblocks_config: FlashblocksConfig,

    /// Skip re-simulating reverted transactions in subsequent flashblocks
    pub exclude_reverts_between_flashblocks: bool,

    /// Enable transaction tracking logs
    pub enable_tx_tracking_debug_logs: bool,

    /// Pre-simulate pending pool transactions at the top of each block
    /// and exclude any that revert from the flashblock loop. Moves the
    /// simulation cost of adversarial reverting txs off the critical
    /// path.
    pub presim_enabled: bool,

    /// Use a random coinbase address during pre-simulation. Prevents
    /// adversaries from detecting the simulation environment by
    /// branching on the `COINBASE` opcode.
    pub presim_random_coinbase: bool,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            builder_signer: None,
            revert_protection: false,
            flashtestations_config: FlashtestationsArgs::default(),
            block_time: Duration::from_secs(2),
            block_time_leeway: Duration::from_millis(500),
            da_config: OpDAConfig::default(),
            gas_limit_config: OpGasLimitConfig::default(),
            sampling_ratio: 100,
            max_gas_per_txn: None,
            max_uncompressed_block_size: None,
            gas_limiter_config: GasLimiterArgs::default(),
            backrun_bundle_pool: BackrunBundleGlobalPool::new(false),
            backrun_bundle_args: BackrunBundleArgs::default(),
            flashblocks_config: FlashblocksConfig::default(),
            exclude_reverts_between_flashblocks: false,
            enable_tx_tracking_debug_logs: false,
            presim_enabled: false,
            presim_random_coinbase: true,
        }
    }
}

impl TryFrom<OpRbuilderArgs> for BuilderConfig {
    type Error = eyre::Report;

    fn try_from(args: OpRbuilderArgs) -> Result<Self, Self::Error> {
        let flashblocks_config = FlashblocksConfig::try_from(args.clone())?;

        Ok(Self {
            builder_signer: args.builder_signer,
            revert_protection: args.enable_revert_protection,
            flashtestations_config: args.flashtestations,
            block_time: Duration::from_millis(args.chain_block_time),
            block_time_leeway: Duration::from_secs(args.extra_block_deadline_secs),
            da_config: Default::default(),
            gas_limit_config: Default::default(),
            sampling_ratio: args.telemetry.sampling_ratio,
            max_gas_per_txn: args.max_gas_per_txn,
            max_uncompressed_block_size: args.max_uncompressed_block_size,
            gas_limiter_config: args.gas_limiter.clone(),
            backrun_bundle_pool: BackrunBundleGlobalPool::new(
                args.backrun_bundle.enforce_strict_priority_fee_ordering,
            ),
            backrun_bundle_args: args.backrun_bundle,
            flashblocks_config,
            exclude_reverts_between_flashblocks: args.exclude_reverts_between_flashblocks,
            enable_tx_tracking_debug_logs: false,
            presim_enabled: args.enable_presim,
            presim_random_coinbase: args.presim_random_coinbase,
        })
    }
}
