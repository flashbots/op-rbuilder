use alloy::sol_types::{SolCall, SolValue};
use alloy_consensus::TxEip1559;
use alloy_eips::Encodable2718;
use alloy_op_evm::OpEvm;
use alloy_primitives::{keccak256, map::foldhash::HashMap, Address, Bytes, TxKind, B256, U256};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use reth_evm::{precompiles::PrecompilesMap, ConfigureEvm, Evm};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use reth_provider::{ProviderError, StateProvider};
use reth_revm::{database::StateProviderDatabase, State};
use revm::{
    context::result::{ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
    state::Account,
    Database, DatabaseCommit,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tracing::{debug, error, info, warn};

use crate::{
    builders::{
        BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions, OpPayloadBuilderCtx,
        StandardBuilderTx,
    },
    flashtestations::{
        BlockBuilderPolicyError, BlockData, FlashtestationRegistryError,
        FlashtestationRevertReason, IBlockBuilderPolicy, IFlashtestationRegistry,
    },
    primitives::reth::ExecutionInfo,
    tx_signer::Signer,
};

pub struct FlashtestationsBuilderTxArgs {
    pub attestation: Vec<u8>,
    pub tee_service_signer: Signer,
    pub funding_key: Signer,
    pub funding_amount: U256,
    pub registry_address: Address,
    pub builder_policy_address: Address,
    pub builder_proof_version: u8,
    pub builder_signer: Option<Signer>,
    pub enable_block_proofs: bool,
    pub registered: bool,
}

#[derive(Debug, Clone)]
pub struct FlashtestationsBuilderTx {
    // Attestation for the builder
    attestation: Vec<u8>,
    // TEE service generated key
    tee_service_signer: Signer,
    // Funding key for the TEE signer
    funding_key: Signer,
    // Funding amount for the TEE signer
    funding_amount: U256,
    // Registry address for the attestation
    registry_address: Address,
    // Builder policy address for the block builder proof
    builder_policy_address: Address,
    // Builder proof version
    builder_proof_version: u8,
    // Whether the workload and address has been registered
    registered: Arc<AtomicBool>,
    // Whether block proofs are enabled
    enable_block_proofs: bool,
    // fallback builder transaction implementation
    fallback_builder_tx: StandardBuilderTx,
}

#[derive(Debug)]
pub struct TxSimulateResult {
    pub gas_used: u64,
    pub success: bool,
    pub state_changes: HashMap<Address, Account>,
    pub revert_reason: Option<FlashtestationRevertReason>,
}

impl FlashtestationsBuilderTx {
    pub fn new(args: FlashtestationsBuilderTxArgs) -> Self {
        Self {
            attestation: args.attestation,
            tee_service_signer: args.tee_service_signer,
            funding_key: args.funding_key,
            funding_amount: args.funding_amount,
            registry_address: args.registry_address,
            builder_policy_address: args.builder_policy_address,
            builder_proof_version: args.builder_proof_version,
            registered: Arc::new(AtomicBool::new(args.registered)),
            enable_block_proofs: args.enable_block_proofs,
            fallback_builder_tx: StandardBuilderTx::new(args.builder_signer),
        }
    }

    fn signed_funding_tx(
        &self,
        to: Address,
        from: Signer,
        amount: U256,
        base_fee: u64,
        chain_id: u64,
        nonce: u64,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        // Create the EIP-1559 transaction

        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21000,
            max_fee_per_gas: base_fee.into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(to),
            value: amount,
            ..Default::default()
        });
        from.sign_tx(tx)
    }

    fn signed_register_tee_service_tx(
        &self,
        attestation: Vec<u8>,
        gas_limit: u64,
        base_fee: u64,
        chain_id: u64,
        nonce: u64,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        let quote_bytes = Bytes::from(attestation);
        let calldata = IFlashtestationRegistry::registerTEEServiceCall {
            rawQuote: quote_bytes,
        }
        .abi_encode();

        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: base_fee.into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(self.registry_address),
            input: calldata.into(),
            ..Default::default()
        });
        self.tee_service_signer.sign_tx(tx)
    }

    fn signed_block_builder_proof_tx(
        &self,
        transactions: Vec<OpTransactionSigned>,
        ctx: &OpPayloadBuilderCtx,
        gas_limit: u64,
        nonce: u64,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        let block_content_hash = Self::compute_block_content_hash(
            transactions,
            ctx.parent_hash(),
            ctx.block_number(),
            ctx.timestamp(),
        );

        let calldata = IBlockBuilderPolicy::verifyBlockBuilderProofCall {
            version: self.builder_proof_version,
            blockContentHash: block_content_hash,
        }
        .abi_encode();
        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            nonce,
            gas_limit,
            max_fee_per_gas: ctx.base_fee().into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(self.builder_policy_address),
            input: calldata.into(),
            ..Default::default()
        });
        self.tee_service_signer.sign_tx(tx)
    }

    /// Computes the block content hash according to the formula:
    /// keccak256(abi.encode(parentHash, blockNumber, timestamp, transactionHashes))
    fn compute_block_content_hash(
        transactions: Vec<OpTransactionSigned>,
        parent_hash: B256,
        block_number: u64,
        timestamp: u64,
    ) -> B256 {
        // Create ordered list of transaction hashes
        let transaction_hashes: Vec<B256> = transactions
            .iter()
            .map(|tx| {
                // RLP encode the transaction and hash it
                let mut encoded = Vec::new();
                tx.encode_2718(&mut encoded);
                keccak256(&encoded)
            })
            .collect();

        // Create struct and ABI encode
        let block_data = BlockData {
            parentHash: parent_hash,
            blockNumber: U256::from(block_number),
            timestamp: U256::from(timestamp),
            transactionHashes: transaction_hashes,
        };

        let encoded = block_data.abi_encode();
        keccak256(&encoded)
    }

    fn simulate_register_tee_service_tx<DB>(
        &self,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<&mut State<DB>, NoOpInspector, PrecompilesMap>,
        nonce: u64,
    ) -> Result<TxSimulateResult, BuilderTransactionError>
    where
        DB: revm::Database<Error = reth_provider::ProviderError>,
    {
        let register_tx = self.signed_register_tee_service_tx(
            self.attestation.clone(),
            ctx.block_gas_limit(),
            ctx.base_fee(),
            ctx.chain_id(),
            nonce,
        )?;
        let ResultAndState { result, state } = evm
            .transact(&register_tx)
            .map_err(|e| BuilderTransactionError::EvmExecutionError(Box::new(e)))?;
        match result {
            // TODO: check logs
            ExecutionResult::Success { gas_used, .. } => Ok(TxSimulateResult {
                gas_used,
                success: true,
                state_changes: state,
                revert_reason: None,
            }),
            ExecutionResult::Revert { output, .. } => {
                let revert_reason = FlashtestationRegistryError::from(output);
                warn!(target: "flashtestations", "register tee tx reverted during simulation: {}", revert_reason);
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(FlashtestationRevertReason::FlashtestationRegistry(
                        revert_reason,
                    )),
                })
            }
            _ => {
                error!(target: "flashtestations", "register tee tx halted or reverted during simulation");
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: None,
                })
            }
        }
    }

    fn check_registered(&self, revert_reason: Option<FlashtestationRevertReason>) -> bool {
        if let Some(FlashtestationRevertReason::FlashtestationRegistry(
            FlashtestationRegistryError::TEEServiceAlreadyRegistered(_, _),
        )) = revert_reason
        {
            return true;
        }
        false
    }

    fn simulate_verify_block_proof_tx<DB>(
        &self,
        transactions: Vec<OpTransactionSigned>,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<&mut State<DB>, NoOpInspector, PrecompilesMap>,
        nonce: u64,
    ) -> Result<TxSimulateResult, BuilderTransactionError>
    where
        DB: revm::Database<Error = reth_provider::ProviderError>,
    {
        let verify_block_proof_tx =
            self.signed_block_builder_proof_tx(transactions, ctx, ctx.block_gas_limit(), nonce)?;
        let ResultAndState { result, state, .. } = evm.transact(&verify_block_proof_tx)?;
        match result {
            // TODO: check logs
            ExecutionResult::Success { gas_used, .. } => Ok(TxSimulateResult {
                gas_used,
                success: true,
                state_changes: state,
                revert_reason: None,
            }),
            ExecutionResult::Revert { output, .. } => {
                let revert_reason = BlockBuilderPolicyError::from(output);
                warn!(target: "flashtestations", "verify block proof tx reverted during simulation: {}", revert_reason);
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(FlashtestationRevertReason::BlockBuilderPolicy(
                        revert_reason,
                    )),
                })
            }
            ExecutionResult::Halt { reason, .. } => {
                warn!(target: "flashtestations", "verify block proof tx halted during simulation: {:?}", reason);
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: None,
                })
            }
        }
    }
}

impl BuilderTransactions for FlashtestationsBuilderTx {
    fn simulate_builder_txs<Extra: Debug + Default>(
        &self,
        state_provider: impl StateProvider,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx,
        db: &mut State<impl Database<Error = ProviderError>>,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let state = StateProviderDatabase::new(state_provider);
        let mut simulation_state = State::builder()
            .with_database(state)
            .with_bundle_prestate(db.bundle_state.clone())
            .with_cached_prestate(db.cache.clone())
            .with_bundle_update()
            .build();

        let mut evm = ctx
            .evm_config
            .evm_with_env(&mut simulation_state, ctx.evm_env.clone());
        evm.modify_cfg(|cfg| {
            cfg.disable_balance_check = true;
        });

        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();

        let mut nonce: u64 = get_nonce(evm.db_mut(), self.tee_service_signer.address)?;
        if !self.registered.load(Ordering::Relaxed) {
            let balance = get_balance(evm.db_mut(), self.tee_service_signer.address)?;
            if balance.is_zero() {
                // funding transaction
                let funding_nonce = get_nonce(evm.db_mut(), self.funding_key.address)?;
                let funding_tx = self.signed_funding_tx(
                    self.tee_service_signer.address,
                    self.funding_key,
                    self.funding_amount,
                    ctx.base_fee(),
                    ctx.chain_id(),
                    funding_nonce,
                )?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    funding_tx.encoded_2718().as_slice(),
                );
                let ResultAndState { state, .. } = evm.transact(&funding_tx)?;
                info!(target: "flashtestations", "adding funding tx to builder txs");
                builder_txs.push(BuilderTransactionCtx {
                    gas_used: 21000,
                    da_size,
                    signed_tx: funding_tx,
                });
                evm.db_mut().commit(state);
            }
            let TxSimulateResult {
                gas_used,
                success,
                state_changes,
                revert_reason,
            } = self.simulate_register_tee_service_tx(ctx, &mut evm, nonce)?;
            let registered = self.check_registered(revert_reason);
            self.registered.store(registered, Ordering::Relaxed);
            if success {
                let register_tx = self.signed_register_tee_service_tx(
                    self.attestation.clone(),
                    gas_used * 64 / 63, // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
                    ctx.base_fee(),
                    ctx.chain_id(),
                    nonce,
                )?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    register_tx.encoded_2718().as_slice(),
                );
                info!(target: "flashtestations", "adding register tee tx to builder txs");
                builder_txs.push(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx: register_tx,
                });
                evm.db_mut().commit(state_changes);
                nonce += 1;
            }
        }

        if self.enable_block_proofs {
            // add verify block proof tx
            let TxSimulateResult {
                gas_used,
                success: should_include_tx,
                ..
            } = self.simulate_verify_block_proof_tx(
                info.executed_transactions.clone(),
                ctx,
                &mut evm,
                nonce,
            )?;
            if should_include_tx {
                // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
                let verify_block_proof_tx = self.signed_block_builder_proof_tx(
                    info.executed_transactions.clone(),
                    ctx,
                    gas_used * 64 / 63,
                    nonce,
                )?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    verify_block_proof_tx.encoded_2718().as_slice(),
                );
                debug!(target: "flashtestations", "adding verify block proof tx to builder txs");
                builder_txs.push(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx: verify_block_proof_tx,
                });
                return Ok(builder_txs);
            } else {
                warn!(target: "flashtestations", "verify block proof tx reverted, falling back to standard builder tx");
            }
        }

        // Fallback to standard builder tx (either when block proofs are disabled or when verify block proof tx fails)
        builder_txs.extend(
            self.fallback_builder_tx
                .simulate_builder_txs(ctx, evm.db_mut())?,
        );

        Ok(builder_txs)
    }
}

fn get_nonce<DB>(db: &mut State<DB>, address: Address) -> Result<u64, BuilderTransactionError>
where
    DB: revm::Database<Error = reth_provider::ProviderError>,
{
    db.load_cache_account(address)
        .map(|acc| acc.account_info().unwrap_or_default().nonce)
        .map_err(|_| BuilderTransactionError::AccountLoadFailed(address))
}

fn get_balance<DB>(db: &mut State<DB>, address: Address) -> Result<U256, BuilderTransactionError>
where
    DB: revm::Database<Error = reth_provider::ProviderError>,
{
    db.load_cache_account(address)
        .map(|acc| acc.account_info().unwrap_or_default().balance)
        .map_err(|_| BuilderTransactionError::AccountLoadFailed(address))
}
