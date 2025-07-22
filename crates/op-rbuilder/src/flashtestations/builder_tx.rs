use alloy_consensus::TxEip1559;
use alloy_eips::Encodable2718;
use alloy_evm::Database;
use alloy_op_evm::OpEvm;
use alloy_primitives::{keccak256, map::foldhash::HashMap, Address, Bytes, TxKind, B256, U256};
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use reth_evm::{precompiles::PrecompilesMap, ConfigureEvm, Evm, EvmError};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::{Log, Recovered};
use reth_provider::StateProvider;
use reth_revm::{database::StateProviderDatabase, State};
use revm::{
    context::result::{ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
    state::Account,
    DatabaseCommit,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tracing::{debug, info, warn};

use crate::{
    builders::{
        BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions, OpPayloadBuilderCtx,
        StandardBuilderTx,
    },
    flashtestations::{
        BlockBuilderPolicyError, BlockBuilderProofVerified, BlockData, FlashtestationRegistryError,
        FlashtestationRevertReason, IBlockBuilderPolicy, IFlashtestationRegistry,
        TEEServiceRegistered,
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

#[derive(Debug, Default)]
pub struct TxSimulateResult {
    pub gas_used: u64,
    pub success: bool,
    pub state_changes: HashMap<Address, Account>,
    pub revert_reason: Option<FlashtestationRevertReason>,
    pub logs: Vec<Log>,
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
        block_content_hash: B256,
        ctx: &OpPayloadBuilderCtx,
        gas_limit: u64,
        nonce: u64,
    ) -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
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
    /// https://github.com/flashbots/rollup-boost/blob/main/specs/flashtestations.md#block-building-process
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

    fn simulate_register_tee_service_tx(
        &self,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<TxSimulateResult, BuilderTransactionError> {
        let nonce = get_nonce(evm.db_mut(), self.tee_service_signer.address)?;

        let register_tx = self.signed_register_tee_service_tx(
            self.attestation.clone(),
            ctx.block_gas_limit(),
            ctx.base_fee(),
            ctx.chain_id(),
            nonce,
        )?;
        let ResultAndState { result, state } = match evm.transact(&register_tx) {
            Ok(res) => res,
            Err(err) => {
                if err.is_invalid_tx_err() {
                    warn!(target: "flashtestations", %err, "register tee service tx failed");
                    return Ok(TxSimulateResult::default());
                } else {
                    return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
                }
            }
        };
        match result {
            ExecutionResult::Success { gas_used, logs, .. } => Ok(TxSimulateResult {
                gas_used,
                success: true,
                state_changes: state,
                revert_reason: None,
                logs,
            }),
            ExecutionResult::Revert { output, .. } => {
                let revert_reason = FlashtestationRegistryError::from(output);
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(FlashtestationRevertReason::FlashtestationRegistry(
                        revert_reason,
                    )),
                    logs: vec![],
                })
            }
            ExecutionResult::Halt { reason, .. } => Ok(TxSimulateResult {
                gas_used: 0,
                success: false,
                state_changes: state,
                revert_reason: Some(FlashtestationRevertReason::Halt(
                    serde_json::to_string(&reason).unwrap_or_default(),
                )),
                logs: vec![],
            }),
        }
    }

    fn check_tee_address_registered_log(&self, logs: Vec<Log>, address: Address) -> bool {
        for log in logs {
            if log.topics().first() == Some(&TEEServiceRegistered::SIGNATURE_HASH) {
                if let Ok(decoded) = TEEServiceRegistered::decode_log(&log) {
                    if decoded.teeAddress == address {
                        return true;
                    }
                };
            }
        }
        false
    }

    fn simulate_verify_block_proof_tx(
        &self,
        block_content_hash: B256,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<TxSimulateResult, BuilderTransactionError> {
        let nonce = get_nonce(evm.db_mut(), self.tee_service_signer.address)?;

        let verify_block_proof_tx = self.signed_block_builder_proof_tx(
            block_content_hash,
            ctx,
            ctx.block_gas_limit(),
            nonce,
        )?;
        let ResultAndState { result, state } = match evm.transact(&verify_block_proof_tx) {
            Ok(res) => res,
            Err(err) => {
                if err.is_invalid_tx_err() {
                    warn!(target: "flashtestations", %err, "verify block proof tx failed");
                    return Ok(TxSimulateResult::default());
                } else {
                    return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
                }
            }
        };
        match result {
            ExecutionResult::Success { gas_used, logs, .. } => Ok(TxSimulateResult {
                gas_used,
                success: true,
                state_changes: state,
                revert_reason: None,
                logs,
            }),
            ExecutionResult::Revert { output, .. } => {
                let revert_reason = BlockBuilderPolicyError::from(output);
                Ok(TxSimulateResult {
                    gas_used: 0,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(FlashtestationRevertReason::BlockBuilderPolicy(
                        revert_reason,
                    )),
                    logs: vec![],
                })
            }
            ExecutionResult::Halt { reason, .. } => Ok(TxSimulateResult {
                gas_used: 0,
                success: false,
                state_changes: state,
                revert_reason: Some(FlashtestationRevertReason::Halt(
                    serde_json::to_string(&reason).unwrap_or_default(),
                )),
                logs: vec![],
            }),
        }
    }

    fn check_verify_block_proof_log(&self, logs: Vec<Log>) -> bool {
        for log in logs {
            if log.topics().first() == Some(&BlockBuilderProofVerified::SIGNATURE_HASH) {
                return true;
            }
        }
        false
    }

    fn fund_tee_service_tx(
        &self,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Option<BuilderTransactionCtx>, BuilderTransactionError> {
        let balance = get_balance(evm.db_mut(), self.tee_service_signer.address)?;
        if balance.is_zero() {
            let funding_nonce = get_nonce(evm.db_mut(), self.funding_key.address)?;
            let funding_tx = self.signed_funding_tx(
                self.tee_service_signer.address,
                self.funding_key,
                self.funding_amount,
                ctx.base_fee(),
                ctx.chain_id(),
                funding_nonce,
            )?;
            let da_size =
                op_alloy_flz::tx_estimated_size_fjord_bytes(funding_tx.encoded_2718().as_slice());
            let ResultAndState { state, .. } = match evm.transact(&funding_tx) {
                Ok(res) => res,
                Err(err) => {
                    if err.is_invalid_tx_err() {
                        warn!(target: "flashtestations", %err, "funding tx failed");
                        return Ok(None);
                    } else {
                        return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
                    }
                }
            };
            info!(target: "flashtestations", block_number = ctx.block_number(), tx_hash = ?funding_tx.tx_hash(), "adding funding tx to builder txs");
            evm.db_mut().commit(state);
            Ok(Some(BuilderTransactionCtx {
                gas_used: 21000,
                da_size,
                signed_tx: funding_tx,
            }))
        } else {
            Ok(None)
        }
    }

    fn register_tee_service_tx(
        &self,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<(Option<BuilderTransactionCtx>, bool), BuilderTransactionError> {
        let TxSimulateResult {
            gas_used,
            success,
            state_changes,
            revert_reason,
            logs,
        } = self.simulate_register_tee_service_tx(ctx, evm)?;
        if success {
            let has_log =
                self.check_tee_address_registered_log(logs, self.tee_service_signer.address);
            if !has_log {
                warn!(target: "flashtestations", "transaction did not emit TEEServiceRegistered log, FlashtestationRegistry contract address may be incorrect");
                Ok((None, false))
            } else {
                let nonce = get_nonce(evm.db_mut(), self.tee_service_signer.address)?;
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
                info!(target: "flashtestations", block_number = ctx.block_number(), tx_hash = ?register_tx.tx_hash(), "adding register tee tx to builder txs");
                evm.db_mut().commit(state_changes);
                Ok((
                    Some(BuilderTransactionCtx {
                        gas_used,
                        da_size,
                        signed_tx: register_tx,
                    }),
                    false,
                ))
            }
        } else if let Some(FlashtestationRevertReason::FlashtestationRegistry(
            FlashtestationRegistryError::TEEServiceAlreadyRegistered(_, _),
        )) = revert_reason
        {
            Ok((None, true))
        } else {
            warn!(target: "flashtestations", reason = ?revert_reason, "register tee service tx failed");
            Ok((None, false))
        }
    }

    fn verify_block_proof_tx(
        &self,
        transactions: Vec<OpTransactionSigned>,
        ctx: &OpPayloadBuilderCtx,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Option<BuilderTransactionCtx>, BuilderTransactionError> {
        let block_content_hash = Self::compute_block_content_hash(
            transactions.clone(),
            ctx.parent_hash(),
            ctx.block_number(),
            ctx.timestamp(),
        );

        let TxSimulateResult {
            gas_used,
            success,
            revert_reason,
            logs,
            ..
        } = self.simulate_verify_block_proof_tx(block_content_hash, ctx, evm)?;
        if success {
            let has_log = self.check_verify_block_proof_log(logs);
            if !has_log {
                warn!(target: "flashtestations", "transaction did not emit BlockBuilderProofVerified log, BlockBuilderPolicy contract address may be incorrect");
                Ok(None)
            } else {
                let nonce = get_nonce(evm.db_mut(), self.tee_service_signer.address)?;
                // Due to EIP-150, only 63/64 of available gas is forwarded to external calls so need to add a buffer
                let verify_block_proof_tx = self.signed_block_builder_proof_tx(
                    block_content_hash,
                    ctx,
                    gas_used * 64 / 63,
                    nonce,
                )?;
                let da_size = op_alloy_flz::tx_estimated_size_fjord_bytes(
                    verify_block_proof_tx.encoded_2718().as_slice(),
                );
                debug!(target: "flashtestations", block_number = ctx.block_number(), tx_hash = ?verify_block_proof_tx.tx_hash(), "adding verify block proof tx to builder txs");
                Ok(Some(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx: verify_block_proof_tx,
                }))
            }
        } else {
            warn!(target: "flashtestations", reason = ?revert_reason, "verify block proof tx failed, falling back to standard builder tx");
            self.fallback_builder_tx
                .simulate_builder_tx(ctx, evm.db_mut())
        }
    }

    fn set_registered(
        &self,
        state_provider: impl StateProvider + Clone,
        ctx: &OpPayloadBuilderCtx,
    ) {
        let state = StateProviderDatabase::new(state_provider.clone());
        let mut simulation_state = State::builder()
            .with_database(state)
            .with_bundle_update()
            .build();
        let mut evm = ctx
            .evm_config
            .evm_with_env(&mut simulation_state, ctx.evm_env.clone());
        evm.modify_cfg(|cfg| {
            cfg.disable_balance_check = true;
        });
        match self.register_tee_service_tx(ctx, &mut evm) {
            Ok((_, registered)) => {
                self.registered.store(registered, Ordering::Relaxed);
            }
            Err(e) => {
                debug!(target: "flashtestations", error = ?e, "simulation error when checking if registered");
            }
        }
    }
}

impl BuilderTransactions for FlashtestationsBuilderTx {
    fn simulate_builder_txs<Extra: Debug + Default>(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx,
        db: &mut State<impl Database>,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        let state = StateProviderDatabase::new(state_provider.clone());
        let mut simulation_state = State::builder()
            .with_database(state)
            .with_bundle_prestate(db.bundle_state.clone())
            .with_bundle_update()
            .build();

        let mut evm = ctx
            .evm_config
            .evm_with_env(&mut simulation_state, ctx.evm_env.clone());
        evm.modify_cfg(|cfg| {
            cfg.disable_balance_check = true;
        });

        let mut builder_txs = Vec::<BuilderTransactionCtx>::new();

        if !self.registered.load(Ordering::Relaxed) {
            info!(target: "flashtestations", "tee service not registered yet, attempting to register");
            self.set_registered(state_provider, ctx);
            builder_txs.extend(self.fund_tee_service_tx(ctx, &mut evm)?);
            let (register_tx, _) = self.register_tee_service_tx(ctx, &mut evm)?;
            builder_txs.extend(register_tx);
        }

        if self.enable_block_proofs {
            // add verify block proof tx
            builder_txs.extend(self.verify_block_proof_tx(
                info.executed_transactions.clone(),
                ctx,
                &mut evm,
            )?);
        } else {
            // Fallback to standard builder tx (either when block proofs are disabled or when verify block proof tx fails)
            builder_txs.extend(self.fallback_builder_tx.simulate_builder_tx(ctx, db)?);
        }

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
