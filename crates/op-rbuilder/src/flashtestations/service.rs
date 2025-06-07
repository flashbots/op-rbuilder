use crate::args::FlashtestationsArgs;

/// Block header information needed for content hash computation
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub parent_hash: B256,
    pub number: U256,
    pub timestamp: U256,
}

pub struct FlashtestationsService {
    // Provides the attestation reports
    attestation_provider: AttestationProvider,
    // Handles the onchain attestation and TEE block building proofs
    onchain_provider: OnchainProvider,
    // TEE service generated key
    tee_service_signer: Signer,
}

impl FlashtestationsService {
    pub fn bootstrap(args: FlashtestationsArgs, signer: Signer) -> eyre::Result<Self> {
        if (args.debug) {
            info!(target: "flashtestations", "running in debug mode - will use HTTP service for quotes");
        }
        let attestation_provider = get_attestation_provider(AttestationConfig {
            debug: args.debug,
            debug_url: args.debug_url,
        });
        let onchain_provider = OnchainProvider::new(
            signer,
            args.rpc_url,
            args.registry_address,
            args.builder_policy_address,
        );
        
        // Step 1: Generate Ethereum keypair
        let (private_key, public_key, address) = generate_ethereum_keypair();

        // Step 2: Prepare report data with public key (64 bytes, no 0x04 prefix)
        let mut report_data = [0u8; 64];
        let pubkey_uncompressed = public_key.serialize_uncompressed();
        report_data.copy_from_slice(&pubkey_uncompressed[1..65]); // Skip 0x04 prefix

        // Step 3: Request TDX attestation
        info!(target: "flashtestations", "requesting TDX attestation");
        let attestation = attestation_provider.get_attestation(report_data)?;

        // Step 4: Submit report onchain with the builder key
        onchain_provider.register_tee_service(attestation)?;

        Ok(Self {
            attestation_provider,
            onchain_provider,
            tee_service_signer: Signer::try_from_secret(private_key)?,
        })
    }

    pub fn signed_builder_proof_tx(&self, block: Block) -> eyre::Result<OpTransactionSigned> {
        let block_content_hash = compute_block_content_hash(&block);
        let tx_builder = self.onchain_provider.verify_block_builder_proof(block_content_hash)?;
        // TODO: sign the transaction with TEE service key
        // let tx = self.tee_service_signer.sign_tx(tx_builder)?;
        Ok(tx)
    }
}

/// Computes the block content hash according to the formula:
/// keccak256(abi.encode(parentHash, blockNumber, timestamp, transactionHashes))
fn compute_block_content_hash(block: &BlockInfo, transactions: &[TxEnvelope]) -> B256 {
    // Step 1: Create ordered list of transaction hashes
    let transaction_hashes: Vec<B256> = transactions
        .iter()
        .map(|tx| {
            // RLP encode the transaction and hash it
            let mut encoded = Vec::new();
            tx.encode(&mut encoded);
            keccak256(&encoded)
        })
        .collect();

    // Step 2: ABI encode the data
    // ABI encoding format:
    // - parentHash: bytes32 (32 bytes)
    // - number: uint256 (32 bytes)
    // - timestamp: uint256 (32 bytes)
    // - transactionHashes: bytes32[] (dynamic array)

    let encoded = abi_encode_block_data(
        block.parent_hash,
        block.number,
        block.timestamp,
        &transaction_hashes,
    );

    // Step 3: Hash the ABI encoded data
    keccak256(&encoded)
}

/// ABI encodes: (bytes32, uint256, uint256, bytes32[])
fn abi_encode_block_data(
    parent_hash: B256,
    block_number: U256,
    timestamp: U256,
    transaction_hashes: &[B256],
) -> Vec<u8> {
    let mut encoded = Vec::new();

    // First 3 parameters are static (32 bytes each)
    encoded.extend_from_slice(parent_hash.as_slice());
    encoded.extend_from_slice(&block_number.to_be_bytes::<32>());
    encoded.extend_from_slice(&timestamp.to_be_bytes::<32>());

    // Dynamic array starts at position 96 (3 * 32)
    let array_offset = U256::from(96);
    encoded.extend_from_slice(&array_offset.to_be_bytes::<32>());

    // Array data: length followed by elements
    let array_length = U256::from(transaction_hashes.len());
    encoded.extend_from_slice(&array_length.to_be_bytes::<32>());

    // Each transaction hash (32 bytes each)
    for tx_hash in transaction_hashes {
        encoded.extend_from_slice(tx_hash.as_slice());
    }

    encoded
}

fn generate_ethereum_keypair() -> (SecretKey, PublicKey, Address) {
    let secp = Secp256k1::new();

    // Generate cryptographically secure random private key
    let private_key = SecretKey::new(&mut OsRng);

    // Derive public key
    let public_key = PublicKey::from_secret_key(&secp, &private_key);

    // Derive Ethereum address
    let address = public_key_to_address(&public_key);

    (private_key, public_key, address)
}

/// Converts a public key to an Ethereum address
fn public_key_to_address(public_key: &PublicKey) -> Address {
    // Get uncompressed public key (65 bytes: 0x04 + 64 bytes)
    let pubkey_bytes = public_key.serialize_uncompressed();

    // Skip the 0x04 prefix and hash the remaining 64 bytes
    let hash = Keccak256::digest(&pubkey_bytes[1..65]);

    // Take last 20 bytes as address
    Address::from_slice(&hash[12..32])
}

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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_public_key_format() {
        let secp = Secp256k1::new();
        let private_key = SecretKey::new(&mut OsRng);
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        let pubkey_bytes = public_key.serialize_uncompressed();

        // Verify the public key format
        assert_eq!(
            pubkey_bytes.len(),
            65,
            "Uncompressed public key should be 65 bytes"
        );
        assert_eq!(
            pubkey_bytes[0], 0x04,
            "Uncompressed public key should start with 0x04"
        );

        // Verify report data would be 64 bytes
        let report_data = &pubkey_bytes[1..65];
        assert_eq!(
            report_data.len(),
            64,
            "Report data should be exactly 64 bytes"
        );
    }

    #[test]
    fn test_deterministic_address_derivation() {
        // Test with a known private key to ensure deterministic results
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        let address1 = public_key_to_address(&public_key);
        let address2 = public_key_to_address(&public_key);

        assert_eq!(
            address1, address2,
            "Address derivation should be deterministic"
        );
    }
}
