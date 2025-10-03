use alloy_consensus::TxEip1559;
use alloy_eips::Encodable2718;
use alloy_evm::Database;
use alloy_op_evm::OpEvm;
use alloy_primitives::{
    Address, B256, Bytes, Signature, TxKind, U256, keccak256, map::foldhash::HashMap,
};
use alloy_sol_types::{Error, SolCall, SolEvent, SolInterface, SolValue};
use core::fmt::Debug;
use op_alloy_consensus::OpTypedTransaction;
use reth_evm::{ConfigureEvm, Evm, EvmError, precompiles::PrecompilesMap};
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::{Log, Recovered};
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use revm::{
    DatabaseCommit,
    context::result::{ExecutionResult, ResultAndState},
    inspector::NoOpInspector,
    state::Account,
};
use std::sync::{Arc, atomic::AtomicBool};
use tracing::{debug, info, warn};

use crate::{
    builders::{
        BuilderTransactionCtx, BuilderTransactionError, BuilderTransactions, OpPayloadBuilderCtx,
        get_balance, get_nonce, log_exists,
    },
    flashtestations::{
        BlockData, FlashtestationRevertReason,
        IBlockBuilderPolicy::{self, BlockBuilderProofVerified},
        IERC20Permit,
        IFlashtestationRegistry::{self, TEEServiceRegistered},
    },
    primitives::reth::ExecutionInfo,
    tx_signer::Signer,
};

pub struct FlashtestationsBuilderTxArgs {
    pub attestation: Vec<u8>,
    pub extra_registration_data: Bytes,
    pub tee_service_signer: Signer,
    pub funding_key: Signer,
    pub funding_amount: U256,
    pub registry_address: Address,
    pub builder_policy_address: Address,
    pub builder_proof_version: u8,
    pub enable_block_proofs: bool,
    pub registered: bool,
    pub use_permit: bool,
    pub builder_key: Signer,
}

#[derive(Debug, Clone)]
pub struct FlashtestationsBuilderTx<ExtraCtx = (), Extra = ()>
where
    ExtraCtx: Debug + Default,
    Extra: Debug + Default,
{
    // Attestation for the builder
    attestation: Vec<u8>,
    // Extra registration data for the builder
    extra_registration_data: Bytes,
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
    // Whether to use permit for the flashtestation builder tx
    use_permit: bool,
    // Builder key for the flashtestation permit tx
    builder_key: Signer,
    // Extra context and data
    _marker: std::marker::PhantomData<(ExtraCtx, Extra)>,
}

#[derive(Debug, Default)]
pub struct TxSimulateResult {
    pub gas_used: u64,
    pub success: bool,
    pub state_changes: HashMap<Address, Account>,
    pub revert_reason: Option<FlashtestationRevertReason>,
    pub logs: Vec<Log>,
}

#[derive(Debug, Default)]
pub struct SimulationSuccessResult {
    pub gas_used: u64,
    pub output: Bytes,
    pub state_changes: HashMap<Address, Account>,
}

impl<ExtraCtx, Extra> FlashtestationsBuilderTx<ExtraCtx, Extra>
where
    ExtraCtx: Debug + Default,
    Extra: Debug + Default,
{
    pub fn new(args: FlashtestationsBuilderTxArgs) -> Self {
        Self {
            attestation: args.attestation,
            extra_registration_data: args.extra_registration_data,
            tee_service_signer: args.tee_service_signer,
            funding_key: args.funding_key,
            funding_amount: args.funding_amount,
            registry_address: args.registry_address,
            builder_policy_address: args.builder_policy_address,
            builder_proof_version: args.builder_proof_version,
            registered: Arc::new(AtomicBool::new(args.registered)),
            enable_block_proofs: args.enable_block_proofs,
            use_permit: args.use_permit,
            builder_key: args.builder_key,
            _marker: std::marker::PhantomData,
        }
    }

    fn sign_tx(
        &self,
        to: Address,
        from: Signer,
        gas_used: u64,
        calldata: Bytes,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
    ) -> Result<Recovered<OpTransactionSigned>, BuilderTransactionError> {
        let nonce = get_nonce(db, from.address)?;
        // Create the EIP-1559 transaction
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            nonce,
            gas_limit: gas_used * 64 / 63, // Due to EIP-150, 63/64 of available gas is forwarded to external calls so need to add a buffer
            max_fee_per_gas: ctx.base_fee().into(),
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(to),
            input: calldata,
            ..Default::default()
        });
        Ok(from.sign_tx(tx)?)
    }

    fn simulate_call(
        &self,
        contract_address: Address,
        calldata: Bytes,
        expected_topic: Option<B256>,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<SimulationSuccessResult, BuilderTransactionError> {
        let tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: ctx.chain_id(),
            max_fee_per_gas: ctx.base_fee().into(),
            gas_limit: ctx.block_gas_limit(),
            to: TxKind::Call(contract_address),
            input: calldata,
            ..Default::default()
        });
        let signed_tx = self.tee_service_signer.sign_tx(tx)?;
        let ResultAndState { result, state } = match evm.transact(&signed_tx) {
            Ok(res) => res,
            Err(err) => {
                if err.is_invalid_tx_err() {
                    return Err(BuilderTransactionError::InvalidTransactionError(Box::new(
                        err,
                    )));
                } else {
                    return Err(BuilderTransactionError::EvmExecutionError(Box::new(err)));
                }
            }
        };

        match result {
            ExecutionResult::Success {
                logs,
                gas_used,
                output,
                ..
            } => {
                if let Some(topic) = expected_topic
                    && !logs.iter().any(|log| log.topics().first() == Some(&topic))
                {
                    return Err(BuilderTransactionError::other(
                        FlashtestationRevertReason::LogMismatch(contract_address, topic),
                    ));
                }
                Ok(SimulationSuccessResult {
                    gas_used,
                    output: output.into_data(),
                    state_changes: state,
                })
            }
            ExecutionResult::Revert { output, .. } => {
                let revert_reason =
                    IFlashtestationRegistry::IFlashtestationRegistryErrors::abi_decode(&output)
                        .map(FlashtestationRevertReason::FlashtestationRegistry)
                        .or_else(|_| {
                            IBlockBuilderPolicy::IBlockBuilderPolicyErrors::abi_decode(&output)
                                .map(FlashtestationRevertReason::BlockBuilderPolicy)
                        })
                        .unwrap_or_else(|e| {
                            FlashtestationRevertReason::Unknown(hex::encode(&output), e)
                        });
                Err(BuilderTransactionError::other(revert_reason))
            }
            ExecutionResult::Halt { reason, .. } => Err(BuilderTransactionError::other(
                FlashtestationRevertReason::Halt(reason),
            )),
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
            extendedRegistrationData: self.extra_registration_data.clone(),
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
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
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
        transactions: &[OpTransactionSigned],
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
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
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
                    return Err(BuilderTransactionError::InvalidTransactionError(Box::new(
                        err,
                    )));
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
            ExecutionResult::Revert { output, gas_used } => {
                let revert_reason =
                    IFlashtestationRegistry::IFlashtestationRegistryErrors::abi_decode(&output)
                        .map(FlashtestationRevertReason::FlashtestationRegistry)
                        .unwrap_or_else(|e| {
                            FlashtestationRevertReason::Unknown(hex::encode(output), e)
                        });
                Ok(TxSimulateResult {
                    gas_used,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(revert_reason),
                    logs: vec![],
                })
            }
            ExecutionResult::Halt { reason, .. } => Ok(TxSimulateResult {
                gas_used: 0,
                success: false,
                state_changes: state,
                revert_reason: Some(FlashtestationRevertReason::Halt(reason)),
                logs: vec![],
            }),
        }
    }

    fn simulate_verify_block_proof_tx(
        &self,
        block_content_hash: B256,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
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
                    return Err(BuilderTransactionError::InvalidTransactionError(Box::new(
                        err,
                    )));
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
            ExecutionResult::Revert { output, gas_used } => {
                let revert_reason =
                    IBlockBuilderPolicy::IBlockBuilderPolicyErrors::abi_decode(&output)
                        .map(FlashtestationRevertReason::BlockBuilderPolicy)
                        .unwrap_or_else(|e| {
                            FlashtestationRevertReason::Unknown(hex::encode(output), e)
                        });
                Ok(TxSimulateResult {
                    gas_used,
                    success: false,
                    state_changes: state,
                    revert_reason: Some(revert_reason),
                    logs: vec![],
                })
            }
            ExecutionResult::Halt { reason, .. } => Ok(TxSimulateResult {
                gas_used: 0,
                success: false,
                state_changes: state,
                revert_reason: Some(FlashtestationRevertReason::Halt(reason)),
                logs: vec![],
            }),
        }
    }

    fn fund_tee_service_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
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
                        return Err(BuilderTransactionError::InvalidTransactionError(Box::new(
                            err,
                        )));
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
                is_top_of_block: false,
            }))
        } else {
            Ok(None)
        }
    }

    fn register_tee_service_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Option<BuilderTransactionCtx>, BuilderTransactionError> {
        let TxSimulateResult {
            gas_used,
            success,
            state_changes,
            revert_reason,
            logs,
        } = self.simulate_register_tee_service_tx(ctx, evm)?;
        if success {
            if !log_exists(&logs, &TEEServiceRegistered::SIGNATURE_HASH) {
                Err(BuilderTransactionError::other(
                    FlashtestationRevertReason::LogMismatch(
                        self.registry_address,
                        TEEServiceRegistered::SIGNATURE_HASH,
                    ),
                ))
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
                Ok(Some(BuilderTransactionCtx {
                    gas_used,
                    da_size,
                    signed_tx: register_tx,
                    is_top_of_block: false,
                }))
            }
        } else if let Some(FlashtestationRevertReason::FlashtestationRegistry(
            IFlashtestationRegistry::IFlashtestationRegistryErrors::TEEServiceAlreadyRegistered(_),
        )) = revert_reason
        {
            Ok(None)
        } else {
            Err(BuilderTransactionError::other(revert_reason.unwrap_or(
                FlashtestationRevertReason::Unknown(
                    "unknown revert".into(),
                    Error::Other("unknown revert".into()),
                ),
            )))
        }
    }

    fn verify_block_proof_tx(
        &self,
        transactions: Vec<OpTransactionSigned>,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Option<BuilderTransactionCtx>, BuilderTransactionError> {
        let block_content_hash = Self::compute_block_content_hash(
            &transactions,
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
            if !log_exists(&logs, &BlockBuilderProofVerified::SIGNATURE_HASH) {
                Err(BuilderTransactionError::other(
                    FlashtestationRevertReason::LogMismatch(
                        self.builder_policy_address,
                        BlockBuilderProofVerified::SIGNATURE_HASH,
                    ),
                ))
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
                    is_top_of_block: false,
                }))
            }
        } else {
            Err(BuilderTransactionError::other(revert_reason.unwrap_or(
                FlashtestationRevertReason::Unknown(
                    "unknown revert".into(),
                    Error::Other("unknown revert".into()),
                ),
            )))
        }
    }

    fn set_registered(
        &self,
        state_provider: impl StateProvider + Clone,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
    ) -> Result<(), BuilderTransactionError> {
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
            cfg.disable_nonce_check = true;
        });
        let calldata = IFlashtestationRegistry::getRegistrationStatusCall {
            teeAddress: self.tee_service_signer.address,
        }
        .abi_encode();
        match self.simulate_call(self.registry_address, calldata.into(), None, ctx, &mut evm) {
            Ok(SimulationSuccessResult { output, .. }) => {
                let result =
                    IFlashtestationRegistry::getRegistrationStatusCall::abi_decode_returns(&output)
                        .map_err(|_| {
                            BuilderTransactionError::InvalidContract(self.registry_address)
                        })?;
                if result.isValid {
                    self.registered
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn get_permit_nonce(
        &self,
        contract_address: Address,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<U256, BuilderTransactionError> {
        let calldata = IERC20Permit::noncesCall {
            owner: self.tee_service_signer.address,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } =
            self.simulate_call(contract_address, calldata.into(), None, ctx, evm)?;
        U256::abi_decode(&output)
            .map_err(|_| BuilderTransactionError::InvalidContract(contract_address))
    }

    fn registration_permit_signature(
        &self,
        permit_nonce: U256,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Signature, BuilderTransactionError> {
        let struct_hash_calldata = IFlashtestationRegistry::computeStructHashCall {
            rawQuote: self.attestation.clone().into(),
            extendedRegistrationData: self.extra_registration_data.clone(),
            nonce: permit_nonce,
            deadline: U256::from(ctx.timestamp()),
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } = self.simulate_call(
            self.registry_address,
            struct_hash_calldata.into(),
            None,
            ctx,
            evm,
        )?;
        let struct_hash = B256::abi_decode(&output)
            .map_err(|_| BuilderTransactionError::InvalidContract(self.registry_address))?;
        let typed_data_hash_calldata = IFlashtestationRegistry::hashTypedDataV4Call {
            structHash: struct_hash,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } = self.simulate_call(
            self.registry_address,
            typed_data_hash_calldata.into(),
            None,
            ctx,
            evm,
        )?;
        let typed_data_hash = B256::abi_decode(&output)
            .map_err(|_| BuilderTransactionError::InvalidContract(self.registry_address))?;
        let signature = self.tee_service_signer.sign_message(typed_data_hash)?;
        Ok(signature)
    }

    fn signed_registration_permit_tx(
        &self,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<BuilderTransactionCtx, BuilderTransactionError> {
        let permit_nonce = self.get_permit_nonce(self.registry_address, ctx, evm)?;
        let signature = self.registration_permit_signature(permit_nonce, ctx, evm)?;
        let calldata = IFlashtestationRegistry::permitRegisterTEEServiceCall {
            rawQuote: self.attestation.clone().into(),
            extendedRegistrationData: self.extra_registration_data.clone(),
            nonce: permit_nonce,
            deadline: U256::from(ctx.timestamp()),
            signature: signature.as_bytes().into(),
        }
        .abi_encode();
        let SimulationSuccessResult { gas_used, .. } = self.simulate_call(
            self.registry_address,
            calldata.clone().into(),
            Some(TEEServiceRegistered::SIGNATURE_HASH),
            ctx,
            evm,
        )?;
        let signed_tx = self.sign_tx(
            self.registry_address,
            self.builder_key,
            gas_used,
            calldata.into(),
            ctx,
            evm.db_mut(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(BuilderTransactionCtx {
            gas_used,
            da_size,
            signed_tx,
            is_top_of_block: false,
        })
    }

    fn block_proof_permit_signature(
        &self,
        permit_nonce: U256,
        block_content_hash: B256,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<Signature, BuilderTransactionError> {
        let struct_hash_calldata = IBlockBuilderPolicy::computeStructHashCall {
            version: self.builder_proof_version,
            blockContentHash: block_content_hash,
            nonce: permit_nonce,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } = self.simulate_call(
            self.builder_policy_address,
            struct_hash_calldata.into(),
            None,
            ctx,
            evm,
        )?;
        let struct_hash = B256::abi_decode(&output)
            .map_err(|_| BuilderTransactionError::InvalidContract(self.builder_policy_address))?;
        let typed_data_hash_calldata = IBlockBuilderPolicy::getHashedTypeDataV4Call {
            structHash: struct_hash,
        }
        .abi_encode();
        let SimulationSuccessResult { output, .. } = self.simulate_call(
            self.builder_policy_address,
            typed_data_hash_calldata.into(),
            None,
            ctx,
            evm,
        )?;
        let typed_data_hash = B256::abi_decode(&output)
            .map_err(|_| BuilderTransactionError::InvalidContract(self.builder_policy_address))?;
        let signature = self.tee_service_signer.sign_message(typed_data_hash)?;
        Ok(signature)
    }

    fn signed_block_proof_permit_tx(
        &self,
        transactions: &[OpTransactionSigned],
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        evm: &mut OpEvm<
            &mut State<StateProviderDatabase<impl StateProvider>>,
            NoOpInspector,
            PrecompilesMap,
        >,
    ) -> Result<BuilderTransactionCtx, BuilderTransactionError> {
        let permit_nonce = self.get_permit_nonce(self.builder_policy_address, ctx, evm)?;
        let block_content_hash = Self::compute_block_content_hash(
            transactions,
            ctx.parent_hash(),
            ctx.block_number(),
            ctx.timestamp(),
        );
        let signature =
            self.block_proof_permit_signature(permit_nonce, block_content_hash, ctx, evm)?;
        let calldata = IBlockBuilderPolicy::permitVerifyBlockBuilderProofCall {
            blockContentHash: block_content_hash,
            nonce: U256::from(permit_nonce),
            version: self.builder_proof_version,
            eip712Sig: signature.as_bytes().into(),
        }
        .abi_encode();
        let SimulationSuccessResult { gas_used, .. } = self.simulate_call(
            self.builder_policy_address,
            calldata.clone().into(),
            Some(BlockBuilderProofVerified::SIGNATURE_HASH),
            ctx,
            evm,
        )?;
        let signed_tx = self.sign_tx(
            self.builder_policy_address,
            self.builder_key,
            gas_used,
            calldata.into(),
            ctx,
            evm.db_mut(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(BuilderTransactionCtx {
            gas_used,
            da_size,
            signed_tx,
            is_top_of_block: false,
        })
    }
}

impl<ExtraCtx, Extra> BuilderTransactions<ExtraCtx, Extra>
    for FlashtestationsBuilderTx<ExtraCtx, Extra>
where
    ExtraCtx: Debug + Default,
    Extra: Debug + Default,
{
    fn simulate_builder_txs(
        &self,
        state_provider: impl StateProvider + Clone,
        info: &mut ExecutionInfo<Extra>,
        ctx: &OpPayloadBuilderCtx<ExtraCtx>,
        db: &mut State<impl Database>,
        _top_of_block: bool,
    ) -> Result<Vec<BuilderTransactionCtx>, BuilderTransactionError> {
        // set registered simulating against the committed state
        if !self.registered.load(std::sync::atomic::Ordering::SeqCst) {
            self.set_registered(state_provider.clone(), ctx)?;
        }

        let state = StateProviderDatabase::new(state_provider.clone());
        let mut simulation_state = State::builder()
            .with_database(state)
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

        if !self.registered.load(std::sync::atomic::Ordering::SeqCst) {
            info!(target: "flashtestations", "tee service not registered yet, attempting to register");
            if self.use_permit {
                let register_tx = self.signed_registration_permit_tx(ctx, &mut evm)?;
                builder_txs.push(register_tx);
            } else {
                builder_txs.extend(self.fund_tee_service_tx(ctx, &mut evm)?);
                let register_tx = self.register_tee_service_tx(ctx, &mut evm)?;
                builder_txs.extend(register_tx);
            }
        }

        // don't return on error for block proof as previous txs in builder_txs will not be returned
        if self.enable_block_proofs {
            if self.use_permit {
                debug!(target: "flashtestations", "adding permit verify block proof tx");
                match self.signed_block_proof_permit_tx(&info.executed_transactions, ctx, &mut evm)
                {
                    Ok(block_proof_tx) => builder_txs.push(block_proof_tx),
                    Err(e) => {
                        warn!(target: "flashtestations", error = ?e, "failed to add permit block proof transaction")
                    }
                }
            } else {
                // add verify block proof tx
                match self.verify_block_proof_tx(info.executed_transactions.clone(), ctx, &mut evm)
                {
                    Ok(block_proof_tx) => builder_txs.extend(block_proof_tx),
                    Err(e) => {
                        warn!(target: "flashtestations", error = ?e, "failed to add block proof transaction")
                    }
                };
            }
        }
        Ok(builder_txs)
    }
}
