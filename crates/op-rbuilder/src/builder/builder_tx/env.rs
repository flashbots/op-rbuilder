use alloy_primitives::BlockHash;

use crate::{evm::OpBlockEvmFactory, hardforks::ActiveHardforks};

/// Minimal environment needed by [`super::producer::BuilderTxProducer`] so that
/// builder-transaction code does not depend on the full payload-job context.
pub struct BuilderTxEnv<'a> {
    pub evm_factory: &'a OpBlockEvmFactory,
    pub hardforks: &'a ActiveHardforks,
    pub base_fee: u64,
    pub block_number: u64,
    pub block_gas_limit: u64,
    pub parent_hash: BlockHash,
    pub max_uncompressed_block_size: Option<u64>,
}

impl BuilderTxEnv<'_> {
    pub fn chain_id(&self) -> u64 {
        self.hardforks.chain_id()
    }
}
