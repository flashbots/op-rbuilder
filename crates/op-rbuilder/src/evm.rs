use alloy_evm::Database;
use reth_evm::{ConfigureEvm, EvmEnvFor, EvmFor};
use reth_optimism_evm::OpEvmConfig;

pub type OpBlockEvmFactory = BlockEvmFactory<OpEvmConfig>;

/// Bundles an EVM configuration with a block-specific environment, providing a
/// simple interface for creating EVMs.
///
/// Instead of threading a `ConfigureEvm` impl + `EvmEnv` separately through
/// types that need to create an EVM, pass a single `BlockEvmFactory`.
pub struct BlockEvmFactory<C: ConfigureEvm> {
    evm_config: C,
    evm_env: EvmEnvFor<C>,
}

impl<C: ConfigureEvm> BlockEvmFactory<C> {
    pub fn new(evm_config: C, evm_env: EvmEnvFor<C>) -> Self {
        Self {
            evm_config,
            evm_env,
        }
    }

    pub fn evm<'a, DB: Database>(&self, db: &'a mut DB) -> EvmFor<C, &'a mut DB> {
        self.evm_config.evm_with_env(db, self.evm_env.clone())
    }

    pub fn evm_config(&self) -> &C {
        &self.evm_config
    }

    pub fn evm_env(&self) -> &EvmEnvFor<C> {
        &self.evm_env
    }
}
