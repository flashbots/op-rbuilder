

use std::sync::Arc;

use alloy_primitives::{Address, Bytes};

use alloy::sol;
use alloy_provider::ProviderBuilder;
use tracing::info;
use url::Url;
use BlockBuilderPolicy::BlockBuilderPolicyInstance;
use FlashtestationRegistry::FlashtestationRegistryInstance;

use crate::tx_signer::Signer;

sol!(
    #[sol(rpc, abi)]
    FlashtestationRegistry,
    "src/flashtestations/abi/FlashtestationRegistry.json"
);

sol!(
    #[sol(rpc,  abi)]
    BlockBuilderPolicy,
    "src/flashtestations/abi/BlockBuilderPolicy.json"
);

pub struct OnchainProvider<Provider> {
    provider: Provider,
    registry_address: Address,
    builder_policy_address: Address ,
    builder_proof_version: u64,
}

impl<Provider> OnchainProvider<Provider> where Provider: alloy::providers::Provider + Clone {
    pub fn new(
        // signer: Signer,
        // rpc_url: String,
        provider: Provider,
        registry_address: Address,
        builder_policy_address: Address,
        builder_proof_version: u64,
    ) -> eyre::Result<Self>  {
        Ok(Self {
            provider, 
            registry_address, 
            builder_policy_address,
            builder_proof_version,
        })
    }

    pub async fn register_tee_service(&self, attestation: Vec<u8>) -> eyre::Result<()> {
        let quote_bytes = Bytes::from(attestation);
        let registry = FlashtestationRegistryInstance::new(self.registry_address, self.provider.clone());

        info!(target: "flashtestations", "submitting quote to registry at {}", registry.address());

        let tx_builder = registry.registerTEEService(quote_bytes);
        let receipt = tx_builder.send().await?.get_receipt().await?;
        info!(target: "flashtestations", tx_hash = %receipt.transaction_hash, "register tee transaction confirmed");
        Ok(())
    }

    // TODO: return a signed transaction that can be submitted to the network
    // pub fn verify_block_builder_proof(&self, block_content_hash: B256) -> eyre::Result<()> {
    //     info!(target: "flashtestations", "submitting block builder proof transaction", block_content_hash = block_content_hash);

    //     let tx_builder = self.builder_policy.verifyBlockBuilderProof(self.builder_proof_version, block_content_hash);
    // }
}


