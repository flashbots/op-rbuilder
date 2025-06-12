use alloy_consensus::TxEip1559;
use alloy_eips::Encodable2718;
use alloy_network::ReceiptResponse;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use op_alloy_consensus::OpTypedTransaction;
use reth_optimism_node::OpBuiltPayload;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use std::time::Duration;

use alloy::{
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolValue},
};
use alloy_provider::{Provider, ProviderBuilder};
use op_alloy_network::Optimism;
use tracing::{error, info};

use crate::tx_signer::Signer;

sol!(
    #[sol(rpc, abi)]
    interface IFlashtestationRegistry {
        function registerTEEService(bytes calldata rawQuote) external;
    }

    #[sol(rpc, abi)]
    interface IBlockBuilderPolicy {
        function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external;
    }

    struct BlockData {
        bytes32 parentHash;
        uint256 blockNumber;
        uint256 timestamp;
        bytes32[] transactionHashes;
    }
);

pub struct TxManager {
    tee_service_signer: Signer,
    funding_signer: Signer,
    rpc_url: String,
    registry_address: Address,
    builder_policy_address: Address,
    builder_proof_version: u8,
}

impl TxManager {
    pub fn new(
        tee_service_signer: Signer,
        funding_signer: Signer,
        rpc_url: String,
        registry_address: Address,
        builder_policy_address: Address,
        builder_proof_version: u8,
    ) -> Self {
        Self {
            tee_service_signer,
            funding_signer,
            rpc_url,
            registry_address,
            builder_policy_address,
            builder_proof_version,
        }
    }

    pub async fn register_tee_service(&self, attestation: Vec<u8>) -> eyre::Result<()> {
        let wallet =
            PrivateKeySigner::from_bytes(&self.tee_service_signer.secret.secret_bytes().into())?;
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .fetch_chain_id()
            .wallet(wallet)
            .network::<Optimism>()
            .connect(self.rpc_url.as_str())
            .await?;

        let quote_bytes = Bytes::from(attestation);

        let funding_wallet =
            PrivateKeySigner::from_bytes(&self.funding_signer.secret.secret_bytes().into())?;
        let funding_provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .fetch_chain_id()
            .with_gas_estimation()
            .with_cached_nonce_management()
            .wallet(funding_wallet)
            .network::<Optimism>()
            .connect(self.rpc_url.as_str())
            .await?;

        // Create funding transaction
        let funding_tx = alloy::rpc::types::TransactionRequest {
            from: Some(self.funding_signer.address),
            to: Some(TxKind::Call(self.tee_service_signer.address)),
            value: Some(U256::from(10_000_000_000_000_000u64)), // 0.001 ETH
            gas: Some(21_000),                                  // Standard gas for ETH transfer
            ..Default::default()
        };
        // Send funding transaction
        match funding_provider.send_transaction(funding_tx.into()).await {
            Ok(pending_funding_tx) => {
                let funding_tx_hash = *pending_funding_tx.tx_hash();
                info!(target: "flashtestations", tx_hash = %funding_tx_hash, "funding transaction submitted");

                // Wait for funding transaction confirmation
                match pending_funding_tx
                    .with_timeout(Some(Duration::from_secs(30)))
                    .get_receipt()
                    .await
                {
                    Ok(receipt) => {
                        if receipt.status() {
                            info!(target: "flashtestations", 
                                          tx_hash = %receipt.transaction_hash(),
                                          "funding transaction confirmed successfully");
                        } else {
                            error!(target: "flashtestations", 
                                           tx_hash = %receipt.transaction_hash(),
                                           "funding transaction reverted");
                            return Err(eyre::eyre!(
                                "Funding transaction reverted: {}",
                                funding_tx_hash
                            ));
                        }
                    }
                    Err(e) => {
                        error!(target: "flashtestations", 
                                       error = %e,
                                       tx_hash = %funding_tx_hash,
                                       "funding transaction failed to get receipt");
                        return Err(e.into());
                    }
                }
            }
            Err(e) => {
                error!(target: "flashtestations", error = %e, "funding transaction failed to be sent");
                return Err(e.into());
            }
        }

        // Get the latest block to extract base fee
        let latest_block = provider
            .get_block_by_number(alloy::rpc::types::BlockNumberOrTag::Latest)
            .await?
            .ok_or(eyre::eyre!("Failed to get latest block"))?;
        // Extract base fee per gas from the latest block
        let base_fee = latest_block
            .header
            .base_fee_per_gas
            .ok_or(eyre::eyre!("Base fee not available"))?;

        let registry = IFlashtestationRegistry::new(self.registry_address, provider);

        info!(target: "flashtestations", "submitting quote to registry at {}", registry.address());

        // TODO: add retries
        match registry
            .registerTEEService(quote_bytes)
            .gas(10_000_000) // Set gas limit manually as the contract is gas heavy
            .max_fee_per_gas((base_fee + 1).into())
            .max_priority_fee_per_gas(1)
            .nonce(0)
            .send()
            .await
        {
            Ok(pending_tx) => {
                let tx_hash = *pending_tx.tx_hash();
                info!(target: "flashtestations", tx_hash = %tx_hash, "transaction submitted, waiting for confirmation");

                match pending_tx
                    .with_timeout(Some(Duration::from_secs(20)))
                    .get_receipt()
                    .await
                {
                    Ok(receipt) => {
                        if receipt.status() {
                            info!(target: "flashtestations", 
                            tx_hash = %receipt.transaction_hash(),
                            block_number = ?receipt.block_number(),
                            gas_used = ?receipt.gas_used(),
                            "register tee transaction confirmed successfully");
                            Ok(())
                        } else {
                            error!(target: "flashtestations", 
                            tx_hash = %receipt.transaction_hash(),
                            "register tee transaction reverted");
                            Err(eyre::eyre!("Transaction reverted: {}", tx_hash))
                        }
                    }
                    Err(e) => {
                        error!(target: "flashtestations", 
                               error = %e,
                               tx_hash = %tx_hash,
                               "transaction failed to get receipt");
                        Err(e.into())
                    }
                }
            }
            Err(e) => {
                error!(target: "flashtestations", error = %e, "transaction failed to be sent");
                Err(e.into())
            }
        }
    }

    /// Computes the block content hash according to the formula:
    /// keccak256(abi.encode(parentHash, blockNumber, timestamp, transactionHashes))
    fn compute_block_content_hash(payload: OpBuiltPayload) -> B256 {
        let block = payload.block();
        let body = block.clone().into_body();
        let transactions = body.transactions();

        // Create ordered list of transaction hashes
        let transaction_hashes: Vec<B256> = transactions
            .map(|tx| {
                // RLP encode the transaction and hash it
                let mut encoded = Vec::new();
                tx.encode_2718(&mut encoded);
                keccak256(&encoded)
            })
            .collect();

        // Create struct and ABI encode
        let block_data = BlockData {
            parentHash: block.parent_hash,
            blockNumber: U256::from(block.number),
            timestamp: U256::from(block.timestamp),
            transactionHashes: transaction_hashes,
        };

        let encoded = block_data.abi_encode();
        keccak256(&encoded)
    }

    pub fn signed_block_builder_proof(
        &self,
        payload: OpBuiltPayload,
        gas_limit: u64,
        base_fee: u64,
        chain_id: u64,
        nonce: u64,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        let block_content_hash = Self::compute_block_content_hash(payload);

        info!(target: "flashtestations",  block_content_hash = ?block_content_hash, "submitting block builder proof transaction");
        let calldata = IBlockBuilderPolicy::verifyBlockBuilderProofCall {
            version: self.builder_proof_version,
            blockContentHash: block_content_hash,
        }
        .abi_encode();
        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: base_fee.into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(self.builder_policy_address),
            input: calldata.into(),
            ..Default::default()
        });
        self.tee_service_signer.sign_tx(tx)
    }
}
