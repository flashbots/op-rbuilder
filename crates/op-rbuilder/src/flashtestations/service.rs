use reth_node_builder::BuilderContext;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tracing::{info, warn};

use crate::{
    flashtestations::builder_tx::{FlashtestationsBuilderTx, FlashtestationsBuilderTxArgs},
    traits::NodeBounds,
    tx_signer::{generate_ethereum_keypair, public_key_to_address, Signer},
};

use super::{
    args::FlashtestationsArgs,
    attestation::{get_attestation_provider, AttestationConfig},
    tx_manager::TxManager,
};

pub async fn bootstrap_flashtestations<Node>(
    args: FlashtestationsArgs,
    ctx: &BuilderContext<Node>,
    builder_signer: Option<Signer>,
) -> eyre::Result<FlashtestationsBuilderTx>
where
    Node: NodeBounds,
{
    info!("Flashtestations enabled");

    let (private_key, public_key, address) = if args.debug {
        info!("Flashtestations debug mode enabled, generating debug key");
        // Generate deterministic key for debugging purposes
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        (private_key, public_key, public_key_to_address(&public_key))
    } else {
        generate_ethereum_keypair()
    };
    let tee_service_signer = Signer {
        address,
        pubkey: public_key,
        secret: private_key,
    };

    let funding_key = args
        .funding_key
        .expect("funding key required when flashtestations enabled");
    let registry_address = args
        .registry_address
        .expect("registry address required when flashtestations enabled");
    let builder_policy_address = args
        .builder_policy_address
        .expect("builder policy address required when flashtestations enabled");

    let attestation_provider = get_attestation_provider(AttestationConfig {
        debug: args.debug,
        debug_url: args.debug_url,
    });

    // Prepare report data with public key (64 bytes, no 0x04 prefix)
    let mut report_data = [0u8; 64];
    let pubkey_uncompressed = tee_service_signer.pubkey.serialize_uncompressed();
    report_data.copy_from_slice(&pubkey_uncompressed[1..65]); // Skip 0x04 prefix

    // Request TDX attestation
    info!(target: "flashtestations", "requesting TDX attestation");
    let attestation = attestation_provider.get_attestation(report_data)?;

    let (tx_manager, registered) = if let Some(rpc_url) = args.rpc_url {
        let tx_manager = TxManager::new(
            tee_service_signer,
            funding_key,
            rpc_url.clone(),
            registry_address,
        );
        // Submit report onchain by registering the key of the tee service
        match tx_manager
            .fund_and_register_tee_service(attestation.clone(), args.funding_amount)
            .await
        {
            Ok(_) => (Some(tx_manager), true),
            Err(e) => {
                warn!(error = %e, "Failed to register tee service via rpc");
                (Some(tx_manager), false)
            }
        }
    } else {
        (None, false)
    };

    let builder_tx = FlashtestationsBuilderTx::new(FlashtestationsBuilderTxArgs {
        attestation,
        tee_service_signer,
        funding_key,
        funding_amount: args.funding_amount,
        registry_address,
        builder_policy_address,
        builder_proof_version: args.builder_proof_version,
        builder_signer,
        enable_block_proofs: args.enable_block_proofs,
        registered,
    });

    ctx.task_executor()
        .spawn_critical_with_graceful_shutdown_signal(
            "flashtestations clean up task",
            |shutdown| {
                Box::pin(async move {
                    let graceful_guard = shutdown.await;
                    if let Some(tx_manager) = tx_manager {
                        if let Err(e) = tx_manager.clean_up().await {
                            warn!(
                                error = %e,
                                "Failed to complete clean up for flashtestations service",
                            );
                        }
                    }
                    drop(graceful_guard)
                })
            },
        );

    Ok(builder_tx)
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
