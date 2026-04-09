use std::sync::Arc;

use reth_chainspec::{
    BaseFeeParams, EthChainSpec, EthereumHardfork, EthereumHardforks, ForkCondition,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_forks::{OpHardfork, OpHardforks};

/// Binds an [`OpChainSpec`] with a block timestamp so that hardfork activation
/// checks become simple zero-argument method calls.
///
/// Constructed once per block (the timestamp is fixed for the block's lifetime).
#[derive(Clone)]
pub struct ActiveHardforks {
    chain_spec: Arc<OpChainSpec>,
    pub timestamp: u64,
}

impl ActiveHardforks {
    pub fn new(chain_spec: Arc<OpChainSpec>, timestamp: u64) -> Self {
        Self {
            chain_spec,
            timestamp,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_spec.chain_id()
    }

    pub fn base_fee_params(&self) -> BaseFeeParams {
        self.chain_spec.base_fee_params_at_timestamp(self.timestamp)
    }

    pub fn is_regolith_active(&self) -> bool {
        self.is_regolith_active_at_timestamp(self.timestamp)
    }

    pub fn is_canyon_active(&self) -> bool {
        self.is_canyon_active_at_timestamp(self.timestamp)
    }

    pub fn is_ecotone_active(&self) -> bool {
        self.is_ecotone_active_at_timestamp(self.timestamp)
    }

    pub fn is_holocene_active(&self) -> bool {
        self.is_holocene_active_at_timestamp(self.timestamp)
    }

    pub fn is_isthmus_active(&self) -> bool {
        self.is_isthmus_active_at_timestamp(self.timestamp)
    }

    pub fn is_jovian_active(&self) -> bool {
        self.is_jovian_active_at_timestamp(self.timestamp)
    }

    pub fn is_shanghai_active(&self) -> bool {
        self.is_shanghai_active_at_timestamp(self.timestamp)
    }
}

impl EthereumHardforks for ActiveHardforks {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.chain_spec.ethereum_fork_activation(fork)
    }
}

impl OpHardforks for ActiveHardforks {
    fn op_fork_activation(&self, fork: OpHardfork) -> ForkCondition {
        self.chain_spec.op_fork_activation(fork)
    }
}
