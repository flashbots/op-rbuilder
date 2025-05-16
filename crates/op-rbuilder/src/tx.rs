use std::sync::Arc;

use alloy_consensus::{BlobTransactionSidecar, BlobTransactionValidationError};
use alloy_eips::{eip7702::SignedAuthorization, Typed2718};
use alloy_primitives::{Address, Bytes, TxHash, TxKind, B256, U256};
use alloy_rpc_types_eth::AccessList;
use reth_optimism_primitives::OpTransactionSigned;
use reth_optimism_txpool::{interop::MaybeInteropTransaction, OpPooledTransaction};
use reth_primitives::{kzg::KzgSettings, Recovered};
use reth_primitives_traits::InMemorySize;
use reth_transaction_pool::{EthBlobTransactionSidecar, EthPoolTransaction, PoolTransaction};

pub trait FBPoolTransaction: EthPoolTransaction + MaybeInteropTransaction {}

#[derive(Clone, Debug)]
pub struct FBPooledTransaction {
    pub inner: OpPooledTransaction,
    pub can_revert: bool,
}

impl FBPoolTransaction for FBPooledTransaction {}

impl InMemorySize for FBPooledTransaction {
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl PoolTransaction for FBPooledTransaction {
    type TryFromConsensusError =
        <op_alloy_consensus::OpPooledTransaction as TryFrom<OpTransactionSigned>>::Error;
    type Consensus = OpTransactionSigned;
    type Pooled = op_alloy_consensus::OpPooledTransaction;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.clone_into_consensus()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.into_consensus()
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let inner = OpPooledTransaction::from_pooled(tx);
        Self {
            inner,
            can_revert: false,
        }
    }

    fn hash(&self) -> &TxHash {
        self.inner.hash()
    }

    fn sender(&self) -> Address {
        self.inner.sender()
    }

    fn sender_ref(&self) -> &Address {
        self.inner.sender_ref()
    }

    fn cost(&self) -> &U256 {
        self.inner.cost()
    }

    fn encoded_length(&self) -> usize {
        self.inner.encoded_length()
    }
}

impl Typed2718 for FBPooledTransaction {
    fn ty(&self) -> u8 {
        self.inner.ty()
    }
}

impl alloy_consensus::Transaction for FBPooledTransaction {
    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.inner.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.inner.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.inner.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.is_create()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.authorization_list()
    }
}

impl EthPoolTransaction for FBPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        sidecar: Arc<BlobTransactionSidecar>,
    ) -> Option<Recovered<Self::Pooled>> {
        self.inner.try_into_pooled_eip4844(sidecar)
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecar,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecar,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(
            self.ty(),
        ))
    }
}

impl MaybeInteropTransaction for FBPooledTransaction {
    fn interop_deadline(&self) -> Option<u64> {
        self.inner.interop_deadline()
    }

    fn set_interop_deadline(&self, deadline: u64) {
        self.inner.set_interop_deadline(deadline);
    }

    fn with_interop_deadline(self, interop: u64) -> Self
    where
        Self: Sized,
    {
        self.inner.with_interop_deadline(interop).into()
    }
}

impl From<OpPooledTransaction> for FBPooledTransaction {
    fn from(tx: OpPooledTransaction) -> Self {
        Self {
            inner: tx,
            can_revert: false,
        }
    }
}
