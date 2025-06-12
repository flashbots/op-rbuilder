use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use tracing::info;

use crate::{builders::BuilderTxBuilder, tx_signer::Signer};

use super::{
    args::FlashtestationsArgs,
    attestation::{get_attestation_provider, AttestationConfig, AttestationProvider},
    tx_manager::TxManager,
};

pub struct FlashtestationsService {
    // Attestation provider generating attestations
    attestation_provider: Box<dyn AttestationProvider + Send + Sync>,
    // Handles the onchain attestation and TEE block building proofs
    tx_manager: TxManager,
    // TEE service generated key
    tee_service_signer: Signer,
}

// TODO: FlashtestationsService error types
impl FlashtestationsService {
    pub fn new(
        args: FlashtestationsArgs,
        tee_service_signer: Signer,
        funding_signer: Signer,
    ) -> Self {
        let attestation_provider = get_attestation_provider(AttestationConfig {
            debug: args.debug,
            debug_url: args.debug_url,
        });

        let tx_manager = TxManager::new(
            tee_service_signer,
            funding_signer,
            args.rpc_url,
            args.registry_address,
            args.builder_policy_address,
            args.builder_proof_version,
        );

        Self {
            attestation_provider,
            tx_manager,
            tee_service_signer,
        }
    }

    pub async fn bootstrap(&self) -> eyre::Result<()> {
        // Prepare report data with public key (64 bytes, no 0x04 prefix)
        let mut report_data = [0u8; 64];
        let pubkey_uncompressed = self.tee_service_signer.pubkey.serialize_uncompressed();
        report_data.copy_from_slice(&pubkey_uncompressed[1..65]); // Skip 0x04 prefix

        // Request TDX attestation
        info!(target: "flashtestations", "requesting TDX attestation");
        let attestation = self.attestation_provider.get_attestation(report_data)?;

        // Submit report onchain by registering the key of the tee service
        self.tx_manager.register_tee_service(attestation).await
    }
}

impl BuilderTxBuilder for FlashtestationsService {
    fn estimated_builder_tx_gas() -> u64 {
        todo!()
    }

    fn estimated_builder_tx_da_size() -> Option<u64> {
        todo!()
    }

    fn signed_builder_tx() -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sha3::{Digest, Keccak256};

    use crate::tx_signer::public_key_to_address;

    /// Derives Ethereum address from report data using the same logic as the Solidity contract
    fn derive_ethereum_address_from_report_data(pubkey_64_bytes: &[u8]) -> Address {
        // This exactly matches the Solidity implementation:
        // address(uint160(uint256(keccak256(reportData))))

        // Step 1: keccak256(reportData)
        let hash = Keccak256::digest(pubkey_64_bytes);

        // Step 2: Take last 20 bytes (same as uint256 -> uint160 conversion)
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);

        Address::from(address_bytes)
    }

    #[test]
    fn test_address_derivation_matches() {
        // Test that our manual derivation is correct
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        // Get address using our implementation
        let our_address = public_key_to_address(&public_key);

        // Get address using our manual derivation (matching Solidity)
        let pubkey_bytes = public_key.serialize_uncompressed();
        let report_data = &pubkey_bytes[1..65]; // Skip 0x04 prefix
        let manual_address = derive_ethereum_address_from_report_data(report_data);

        assert_eq!(
            our_address, manual_address,
            "Address derivation should match"
        );
    }
}
