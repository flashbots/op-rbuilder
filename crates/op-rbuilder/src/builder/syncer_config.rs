use crate::builder::BuilderConfig;
use reth_optimism_evm::OpEvmConfig;

#[derive(Debug, Clone)]
pub(super) struct OpPayloadSyncerConfig {
    /// The type that knows how to perform system calls and configure the evm.
    pub(super) evm_config: OpEvmConfig,
    /// Max gas that can be used by a transaction.
    pub(super) max_gas_per_txn: Option<u64>,
    /// Maximum cumulative uncompressed (EIP-2718 encoded) block size in bytes.
    pub(super) max_uncompressed_block_size: Option<u64>,
    /// Enable transaction tracking logs
    pub(super) enable_tx_tracking_debug_logs: bool,
}

impl OpPayloadSyncerConfig {
    pub(super) fn new(
        builder_config: BuilderConfig,
        evm_config: OpEvmConfig,
    ) -> eyre::Result<Self> {
        Ok(Self {
            evm_config,
            max_gas_per_txn: builder_config.max_gas_per_txn,
            max_uncompressed_block_size: builder_config.max_uncompressed_block_size,
            enable_tx_tracking_debug_logs: builder_config.enable_tx_tracking_debug_logs,
        })
    }
}
