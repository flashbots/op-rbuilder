use core::time::Duration;
use std::time::SystemTime;

use alloy_eips::{eip7685::Requests, BlockNumberOrTag, Encodable2718};
use alloy_primitives::{address, hex, Bytes, TxKind, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_engine::{ForkchoiceUpdated, PayloadAttributes, PayloadStatusEnum};
use alloy_rpc_types_eth::Block;
use op_alloy_consensus::{OpTypedTransaction, TxDeposit};
use op_alloy_network::Optimism;
use op_alloy_rpc_types::Transaction;
use reth_optimism_node::OpPayloadAttributes;
use rollup_boost::OpExecutionPayloadEnvelope;

use crate::{args::OpRbuilderArgs, tx_signer::Signer};

use super::{EngineApi, Ipc, LocalInstance, TransactionBuilder};

const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

/// The ChainDriver is a type that allows driving the op builder node to build new blocks manually
/// by calling the `build_new_block` method. It uses the Engine API to interact with the node
/// and the provider to fetch blocks and transactions.
pub struct ChainDriver {
    engine_api: EngineApi<Ipc>,
    provider: RootProvider<Optimism>,
    signer: Option<Signer>,
    gas_limit: Option<u64>,
    args: OpRbuilderArgs,
}

// instantiation and configuration
impl ChainDriver {
    const MIN_BLOCK_TIME: Duration = Duration::from_secs(1);

    pub async fn new(instance: &LocalInstance) -> eyre::Result<Self> {
        Ok(Self {
            engine_api: instance.engine_api(),
            provider: instance.provider().await?,
            signer: Default::default(),
            gas_limit: None,
            args: instance.args().clone(),
        })
    }

    pub fn with_signer(mut self, signer: Signer) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }
}

// public test api
impl ChainDriver {
    /// Builds a new block using the current state of the chain and the transactions in the pool.
    pub async fn build_new_block(&self) -> eyre::Result<Block<Transaction>> {
        self.build_new_block_with_txs(vec![]).await
    }

    /// Builds a new block using the current state of the chain and the transactions in the pool with a list
    /// of mandatory builder transactions. Those are usually deposit transactions.
    pub async fn build_new_block_with_txs(
        &self,
        txs: Vec<Bytes>,
    ) -> eyre::Result<Block<Transaction>> {
        let latest = self.latest().await?;
        let latest_timestamp = Duration::from_secs(latest.header.timestamp);
        let actual_timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| eyre::eyre!("Failed to get current system time"))?;

        // block timestamp will be the max of the actual timestamp and the latest block
        // timestamp plus the minimum block time. This ensures that blocks don't break any
        // assumptions, but also gives the test author the ability to control the block time
        // in the test.
        let block_timestamp = actual_timestamp.max(latest_timestamp + Self::MIN_BLOCK_TIME);

        // Add L1 block info as the first transaction in every L2 block
        // This deposit transaction contains L1 block metadata required by the L2 chain
        // Currently using hardcoded data from L1 block 124665056
        // If this info is not provided, Reth cannot decode the receipt for any transaction
        // in the block since it also includes this info as part of the result.
        // It does not matter if the to address (4200000000000000000000000000000000000015) is
        // not deployed on the L2 chain since Reth queries the block to get the info and not the contract.
        let block_info_tx: Bytes = {
            let deposit_tx = TxDeposit {
                source_hash: B256::default(),
                from: address!("DeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001"),
                to: TxKind::Call(address!("4200000000000000000000000000000000000015")),
                mint: None,
                value: U256::default(),
                gas_limit: 210000,
                is_system_transaction: false,
                input: FJORD_DATA.into(),
            };

            // Create a temporary signer for the deposit
            let signer = self.signer.unwrap_or_else(Signer::random);
            let signed_tx = signer.sign_tx(OpTypedTransaction::Deposit(deposit_tx))?;
            signed_tx.encoded_2718().into()
        };

        let fcu_result = self
            .fcu(OpPayloadAttributes {
                payload_attributes: PayloadAttributes {
                    timestamp: block_timestamp.as_secs(),
                    parent_beacon_block_root: Some(B256::ZERO),
                    withdrawals: Some(vec![]),
                    ..Default::default()
                },
                transactions: Some(vec![block_info_tx].into_iter().chain(txs).collect()),
                gas_limit: Some(self.gas_limit.unwrap_or(DEFAULT_GAS_LIMIT)),
                ..Default::default()
            })
            .await?;

        if fcu_result.payload_status.is_invalid() {
            return Err(eyre::eyre!("Forkchoice update failed: {fcu_result:?}"));
        }

        let payload_id = fcu_result
            .payload_id
            .ok_or_else(|| eyre::eyre!("Forkchoice update did not return a payload ID"))?;

        // give the builder some time to build the block
        tokio::time::sleep(Duration::from_millis(self.args.chain_block_time)).await;

        let payload =
            OpExecutionPayloadEnvelope::V4(self.engine_api.get_payload(payload_id).await?);
        let OpExecutionPayloadEnvelope::V4(payload) = payload else {
            return Err(eyre::eyre!("Expected V4 payload, got something else"));
        };
        let payload = payload.execution_payload;

        if self
            .engine_api
            .new_payload(payload.clone(), vec![], B256::ZERO, Requests::default())
            .await?
            .status
            != PayloadStatusEnum::Valid
        {
            return Err(eyre::eyre!("Invalid validation status from builder"));
        }

        let new_block_hash = payload.payload_inner.payload_inner.payload_inner.block_hash;
        self.engine_api
            .update_forkchoice(latest.header.hash, new_block_hash, None)
            .await?;

        let block = self
            .provider
            .get_block_by_number(alloy_eips::BlockNumberOrTag::Latest)
            .full()
            .await?
            .ok_or_else(|| eyre::eyre!("Failed to get latest block after building new block"))?;

        assert_eq!(
            block.header.hash, new_block_hash,
            "New block hash does not match expected hash"
        );

        Ok(block)
    }

    /// Retreives the latest built block and returns only a list of transaction
    /// hashes from its body.
    pub async fn latest(&self) -> eyre::Result<Block<Transaction>> {
        self.provider
            .get_block_by_number(alloy_eips::BlockNumberOrTag::Latest)
            .await?
            .ok_or_else(|| eyre::eyre!("Failed to get latest block"))
    }

    /// Retreives the latest built block and returns a list of full transaction
    /// contents in its body.
    pub async fn latest_full(&self) -> eyre::Result<Block<Transaction>> {
        self.provider
            .get_block_by_number(alloy_eips::BlockNumberOrTag::Latest)
            .full()
            .await?
            .ok_or_else(|| eyre::eyre!("Failed to get latest full block"))
    }

    /// retreives a specific block by its number or tag and returns a list of transaction
    /// hashes from its body.
    pub async fn get_block(
        &self,
        number: BlockNumberOrTag,
    ) -> eyre::Result<Option<Block<Transaction>>> {
        Ok(self.provider.get_block_by_number(number).await?)
    }

    /// retreives a specific block by its number or tag and returns a list of full transaction
    /// contents in its body.
    pub async fn get_block_full(
        &self,
        number: BlockNumberOrTag,
    ) -> eyre::Result<Option<Block<Transaction>>> {
        Ok(self.provider.get_block_by_number(number).full().await?)
    }

    /// Returns a transaction builder that can be used to create and send transactions.
    pub fn transaction(&self) -> TransactionBuilder {
        TransactionBuilder::new(self.provider.clone())
    }

    /// Returns a reference to the underlying alloy provider that is used to
    /// interact with the chain.
    pub const fn provider(&self) -> &RootProvider<Optimism> {
        &self.provider
    }
}

// internal methods
impl ChainDriver {
    async fn fcu(&self, attribs: OpPayloadAttributes) -> eyre::Result<ForkchoiceUpdated> {
        let latest = self.latest().await?.header.hash;
        self.engine_api
            .update_forkchoice(latest, latest, Some(attribs))
            .await
    }
}

// L1 block info for OP mainnet block 124665056 (stored in input of tx at index 0)
//
// https://optimistic.etherscan.io/tx/0x312e290cf36df704a2217b015d6455396830b0ce678b860ebfcc30f41403d7b1
const FJORD_DATA: &[u8] = &hex!(
    "440a5e200000146b000f79c500000000000000040000000066d052e700000000013ad8a
    3000000000000000000000000000000000000000000000000000000003ef12787000000
    00000000000000000000000000000000000000000000000000000000012fdf87b89884a
    61e74b322bbcf60386f543bfae7827725efaaf0ab1de2294a5900000000000000000000
    00006887246668a3b87f54deb3b94ba47a6f63f32985"
);
