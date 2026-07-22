use alloy_eips::Encodable2718;
use alloy_evm::Database;
use alloy_op_evm::OpEvm;
use alloy_primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy_rpc_types_eth::TransactionInput;
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use core::fmt::Debug;
use op_alloy_rpc_types::OpTransactionRequest;
use reth_evm::{Evm, precompiles::PrecompilesMap};
use reth_optimism_primitives::OpTransactionSigned;
use reth_provider::StateProvider;
use reth_revm::{State, database::StateProviderDatabase};
use revm::{DatabaseCommit, DatabaseRef, context_interface::Cfg as _, inspector::NoOpInspector};
use std::sync::{Arc, atomic::AtomicBool};
use tracing::{debug, info, warn};

use crate::{
    builder::{
        BuilderTxEnv, BuilderTxError, BuilderTxProducer, SimulatedBuilderTx, SimulationState,
        SimulationSuccessResult, get_nonce, sign_tx, simulate_call,
    },
    flashtestations::{
        BlockData,
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
    pub registry_address: Address,
    pub builder_policy_address: Address,
    pub builder_proof_version: u8,
    pub enable_block_proofs: bool,
    pub registered: bool,
    pub builder_key: Signer,
}

#[derive(Debug, Clone)]
pub struct FlashtestationsBuilderTx {
    // Attestation for the builder
    attestation: Vec<u8>,
    // Extra registration data for the builder
    extra_registration_data: Bytes,
    // TEE service generated key
    tee_service_signer: Signer,
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
    // Builder key for the flashtestation permit tx
    builder_signer: Signer,
}

impl FlashtestationsBuilderTx {
    pub fn new(args: FlashtestationsBuilderTxArgs) -> Self {
        Self {
            attestation: args.attestation,
            extra_registration_data: args.extra_registration_data,
            tee_service_signer: args.tee_service_signer,
            registry_address: args.registry_address,
            builder_policy_address: args.builder_policy_address,
            builder_proof_version: args.builder_proof_version,
            registered: Arc::new(AtomicBool::new(args.registered)),
            enable_block_proofs: args.enable_block_proofs,
            builder_signer: args.builder_key,
        }
    }

    pub fn tee_signer(&self) -> &Signer {
        &self.tee_service_signer
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

    fn set_registered(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        env: &BuilderTxEnv<'_>,
    ) -> Result<(), BuilderTxError> {
        let mut simulation_state = State::builder()
            .with_database(StateProviderDatabase::new(state_provider))
            .with_bundle_update()
            .build();
        let mut evm = env.evm_factory.evm(&mut simulation_state);
        evm.modify_cfg(|cfg| {
            cfg.disable_balance_check = true;
            cfg.disable_nonce_check = true;
        });
        let calldata = IFlashtestationRegistry::getRegistrationStatusCall {
            teeAddress: self.tee_service_signer.address,
        };
        let SimulationSuccessResult { output, .. } =
            self.flashtestations_contract_read(self.registry_address, calldata, env, &mut evm)?;
        if output.isValid {
            self.registered
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    fn get_permit_nonce(
        &self,
        contract_address: Address,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<U256, BuilderTxError> {
        let calldata = IERC20Permit::noncesCall {
            owner: self.tee_service_signer.address,
        };
        let SimulationSuccessResult { output, .. } =
            self.flashtestations_contract_read(contract_address, calldata, env, evm)?;
        Ok(output)
    }

    fn registration_permit_signature(
        &self,
        permit_nonce: U256,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<Signature, BuilderTxError> {
        let struct_hash_calldata = IFlashtestationRegistry::computeStructHashCall {
            rawQuote: self.attestation.clone().into(),
            extendedRegistrationData: self.extra_registration_data.clone(),
            nonce: permit_nonce,
            deadline: U256::from(env.hardforks.timestamp),
        };
        let SimulationSuccessResult { output, .. } = self.flashtestations_contract_read(
            self.registry_address,
            struct_hash_calldata,
            env,
            evm,
        )?;
        let typed_data_hash_calldata =
            IFlashtestationRegistry::hashTypedDataV4Call { structHash: output };
        let SimulationSuccessResult { output, .. } = self.flashtestations_contract_read(
            self.registry_address,
            typed_data_hash_calldata,
            env,
            evm,
        )?;
        let signature = self.tee_service_signer.sign_message(output)?;
        Ok(signature)
    }

    fn signed_registration_permit_tx(
        &self,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<&mut State<impl Database + DatabaseRef>, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulatedBuilderTx, BuilderTxError> {
        let permit_nonce = self.get_permit_nonce(self.registry_address, env, evm)?;
        let signature = self.registration_permit_signature(permit_nonce, env, evm)?;
        let calldata = IFlashtestationRegistry::permitRegisterTEEServiceCall {
            rawQuote: self.attestation.clone().into(),
            extendedRegistrationData: self.extra_registration_data.clone(),
            nonce: permit_nonce,
            deadline: U256::from(env.hardforks.timestamp),
            signature: signature.as_bytes().into(),
        };
        let SimulationSuccessResult {
            gas_used,
            state_changes,
            ..
        } = self.flashtestations_call(
            self.registry_address,
            calldata.clone(),
            vec![TEEServiceRegistered::SIGNATURE_HASH],
            env,
            evm,
        )?;
        let signed_tx = sign_tx(
            self.registry_address,
            self.builder_signer,
            gas_used,
            calldata.abi_encode().into(),
            env,
            evm.db(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        // commit the register transaction state so the block proof transaction can succeed
        evm.db_mut().commit(state_changes);
        Ok(SimulatedBuilderTx {
            gas_used,
            da_size,
            signed_tx,
        })
    }

    fn block_proof_permit_signature(
        &self,
        permit_nonce: U256,
        block_content_hash: B256,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<Signature, BuilderTxError> {
        let struct_hash_calldata = IBlockBuilderPolicy::computeStructHashCall {
            version: self.builder_proof_version,
            blockContentHash: block_content_hash,
            nonce: permit_nonce,
        };
        let SimulationSuccessResult { output, .. } = self.flashtestations_contract_read(
            self.builder_policy_address,
            struct_hash_calldata,
            env,
            evm,
        )?;
        let typed_data_hash_calldata =
            IBlockBuilderPolicy::getHashedTypeDataV4Call { structHash: output };
        let SimulationSuccessResult { output, .. } = self.flashtestations_contract_read(
            self.builder_policy_address,
            typed_data_hash_calldata,
            env,
            evm,
        )?;
        let signature = self.tee_service_signer.sign_message(output)?;
        Ok(signature)
    }

    fn signed_block_proof_permit_tx(
        &self,
        transactions: &[OpTransactionSigned],
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulatedBuilderTx, BuilderTxError> {
        let permit_nonce = self.get_permit_nonce(self.builder_policy_address, env, evm)?;
        let block_content_hash = Self::compute_block_content_hash(
            transactions,
            env.parent_hash,
            env.block_number,
            env.hardforks.timestamp,
        );
        let signature =
            self.block_proof_permit_signature(permit_nonce, block_content_hash, env, evm)?;
        let calldata = IBlockBuilderPolicy::permitVerifyBlockBuilderProofCall {
            blockContentHash: block_content_hash,
            nonce: permit_nonce,
            version: self.builder_proof_version,
            eip712Sig: signature.as_bytes().into(),
        };
        let SimulationSuccessResult { gas_used, .. } = self.flashtestations_call(
            self.builder_policy_address,
            calldata.clone(),
            vec![BlockBuilderProofVerified::SIGNATURE_HASH],
            env,
            evm,
        )?;
        let signed_tx = sign_tx(
            self.builder_policy_address,
            self.builder_signer,
            gas_used,
            calldata.abi_encode().into(),
            env,
            evm.db(),
        )?;
        let da_size =
            op_alloy_flz::tx_estimated_size_fjord_bytes(signed_tx.encoded_2718().as_slice());
        Ok(SimulatedBuilderTx {
            gas_used,
            da_size,
            signed_tx,
        })
    }

    fn flashtestations_contract_read<T: SolCall>(
        &self,
        contract_address: Address,
        calldata: T,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulationSuccessResult<T>, BuilderTxError> {
        self.flashtestations_call(contract_address, calldata, vec![], env, evm)
    }

    fn flashtestations_call<T: SolCall>(
        &self,
        contract_address: Address,
        calldata: T,
        expected_topics: Vec<B256>,
        env: &BuilderTxEnv<'_>,
        evm: &mut OpEvm<impl Database + DatabaseRef, NoOpInspector, PrecompilesMap>,
    ) -> Result<SimulationSuccessResult<T>, BuilderTxError> {
        let simulation_gas_limit = env.block_gas_limit.min(evm.cfg_env().tx_gas_limit_cap());
        let tx_req = OpTransactionRequest::default()
            .gas_limit(simulation_gas_limit)
            .max_fee_per_gas(env.base_fee.into())
            .to(contract_address)
            .from(self.builder_signer.address)
            .nonce(get_nonce(evm.db(), self.builder_signer.address)?)
            .input(TransactionInput::new(calldata.abi_encode().into()));
        if contract_address == self.registry_address {
            simulate_call::<T, IFlashtestationRegistry::IFlashtestationRegistryErrors>(
                tx_req,
                expected_topics,
                evm,
            )
        } else if contract_address == self.builder_policy_address {
            simulate_call::<T, IBlockBuilderPolicy::IBlockBuilderPolicyErrors>(
                tx_req,
                expected_topics,
                evm,
            )
        } else {
            Err(BuilderTxError::msg(
                "invalid contract address for flashtestations",
            ))
        }
    }
}

impl BuilderTxProducer for FlashtestationsBuilderTx {
    fn simulate_builder_txs(
        &self,
        state_provider: Arc<dyn StateProvider + Send>,
        info: &ExecutionInfo,
        env: &BuilderTxEnv<'_>,
        sim_state: &mut SimulationState,
    ) -> Result<Vec<SimulatedBuilderTx>, BuilderTxError> {
        // set registered by simulating against the committed state
        if !self.registered.load(std::sync::atomic::Ordering::SeqCst) {
            self.set_registered(state_provider, env)?;
        }

        let mut evm = env.evm_factory.evm(&mut *sim_state);
        evm.modify_cfg(|cfg| {
            cfg.disable_balance_check = true;
            cfg.disable_block_gas_limit = true;
        });

        let mut builder_txs = Vec::<SimulatedBuilderTx>::new();

        if !self.registered.load(std::sync::atomic::Ordering::SeqCst) {
            info!(
                target: "flashtestations",
                "tee service not registered yet, attempting to register"
            );
            let register_tx = self.signed_registration_permit_tx(env, &mut evm)?;
            builder_txs.push(register_tx);
        }

        // don't return on error for block proof as previous txs in builder_txs will not be returned
        if self.enable_block_proofs {
            debug!(target: "flashtestations", "adding permit verify block proof tx");
            match self.signed_block_proof_permit_tx(&info.executed_transactions, env, &mut evm) {
                Ok(block_proof_tx) => builder_txs.push(block_proof_tx),
                Err(e) => {
                    warn!(
                        target: "flashtestations",
                        error = %e,
                        "failed to add permit block proof transaction"
                    )
                }
            }
        }
        Ok(builder_txs)
    }
}
