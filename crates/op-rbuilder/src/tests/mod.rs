#![cfg(test)]

// base
mod framework;
pub use framework::*;

mod backrun;
mod data_availability;
mod flashblocks;
mod flashtestations;
mod forks;
mod gas_limiter;
mod miner_gas_limit;
mod revert;
mod smoke;
mod txpool;

// If the order of deployment from the signer changes the address will change
const FLASHBLOCKS_NUMBER_ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("95bd8d42f30351685e96c62eddc0d0613bf9a87a");
const MOCK_DCAP_ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("700b6a60ce7eaaea56f065753d8dcb9653dbad35");
const FLASHTESTATION_REGISTRY_ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("a15bb66138824a1c7167f5e85b957d04dd34e468");
const BLOCK_BUILDER_POLICY_ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("8ce361602b935680e8dec218b820ff5056beb7af");
