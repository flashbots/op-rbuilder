sol!(
    #[sol(rpc)]
    FlashtestationRegistry,
    "abi/FlashtestationRegistry.json"
);

sol!(
    #[sol(rpc)]
    BlockBuilderPolicy,
    "abi/BlockBuilderPolicy.json"
);

pub struct OnchainProvider {
    provider: Provider,
    registry: FlashtestationRegistry,
    builder_policy: BlockBuilderPolicy,
    builder_proof_version: u64,
}

impl OnchainProvider {
    pub fn new(
        signer: Signer,
        rpc_url: String,
        registry_address: Address,
        builder_policy_address: Address,
        builder_proof_version: u64,
    ) -> Self {
        Self {
            signer,
            rpc_url,
            registry_address,
            builder_policy_address,
            builder_proof_version,
        }
    }

    pub fn register_tee_service(&self, attestation: Vec<u8>) -> eyre::Result<()> {
        let quote_bytes = Bytes::from(raw_quote);

        info!(target: "flashtestations", "submitting quote to registry at {}", self.registry.address());

        let tx_builder = self.registry.registerTEEService(quote_bytes);
        self.send_and_wait_for_confirmation(tx_builder)
    }

    // TODO: return a signed transaction that can be submitted to the network
    // pub fn verify_block_builder_proof(&self, block_content_hash: B256) -> eyre::Result<()> {
    //     info!(target: "flashtestations", "submitting block builder proof transaction", block_content_hash = block_content_hash);

    //     let tx_builder = self.builder_policy.verifyBlockBuilderProof(self.builder_proof_version, block_content_hash);
    // }
}
