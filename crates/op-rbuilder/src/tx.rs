use std::{borrow::Cow, sync::Arc};

use alloy_consensus::BlobTransactionValidationError;
use alloy_eips::{Typed2718, eip7594::BlobTransactionSidecarVariant, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256};
use alloy_rpc_types_eth::{AccessList, erc4337::TransactionConditional};
use reth_optimism_txpool::{
    OpPooledTransaction, OpPooledTx, conditional::MaybeConditionalTransaction,
    estimated_da_size::DataAvailabilitySized, interop::MaybeInteropTransaction,
};
use reth_primitives_traits::{InMemorySize, Recovered};
use reth_transaction_pool::{EthBlobTransactionSidecar, EthPoolTransaction, PoolTransaction};

pub type FBPooledTransaction = WithFlashbotsMetadata<OpPooledTransaction>;

/// Generic wrapper that adds Flashbots-specific metadata to any transaction type
#[derive(Clone, Debug, derive_more::Deref)]
pub struct WithFlashbotsMetadata<T> {
    #[deref]
    inner: T,

    /// Hashes within a bundle that the submitter permits to revert without
    /// causing the bundle to be excluded. Sourced from the bundle's
    /// `reverting_tx_hashes` field. `None` for non-bundle transactions;
    /// `Some(vec![])` for bundles that permit no reverts.
    allowed_revert_hashes: Option<Vec<B256>>,

    /// Minimum flashblock number constraint
    min_flashblock_number: Option<u64>,

    /// Maximum flashblock number constraint
    max_flashblock_number: Option<u64>,
}

impl<T> WithFlashbotsMetadata<T> {
    /// Create a new wrapper with no metadata
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            allowed_revert_hashes: None,
            min_flashblock_number: None,
            max_flashblock_number: None,
        }
    }

    pub fn with_allowed_revert_hashes(mut self, allowed_revert_hashes: Vec<B256>) -> Self {
        self.allowed_revert_hashes = Some(allowed_revert_hashes);
        self
    }

    pub fn is_bundle(&self) -> bool {
        self.allowed_revert_hashes.is_some()
    }
}

impl<T: PoolTransaction> WithFlashbotsMetadata<T> {
    // We exclude reverting transactions if the transaction is a bundle and the
    // hash **is not** in the bundle's allowed-to-revert list
    pub fn revert_protected(&self) -> bool {
        self.allowed_revert_hashes
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(self.inner.hash()))
    }
}

impl<T> MaybeFlashblockFilter for WithFlashbotsMetadata<T> {
    fn with_min_flashblock_number(mut self, min_flashblock_number: Option<u64>) -> Self {
        self.min_flashblock_number = min_flashblock_number;
        self
    }

    fn with_max_flashblock_number(mut self, max_flashblock_number: Option<u64>) -> Self {
        self.max_flashblock_number = max_flashblock_number;
        self
    }

    fn min_flashblock_number(&self) -> Option<u64> {
        self.min_flashblock_number
    }

    fn max_flashblock_number(&self) -> Option<u64> {
        self.max_flashblock_number
    }
}

impl<T: InMemorySize> InMemorySize for WithFlashbotsMetadata<T> {
    fn size(&self) -> usize {
        self.inner.size()
            + core::mem::size_of::<Option<Vec<B256>>>()
            + core::mem::size_of::<Option<u64>>() * 2
    }
}

impl<T> PoolTransaction for WithFlashbotsMetadata<T>
where
    T: PoolTransaction,
{
    type TryFromConsensusError = T::TryFromConsensusError;
    type Consensus = T::Consensus;
    type Pooled = T::Pooled;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.clone_into_consensus()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.into_consensus()
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        Self::new(T::from_pooled(tx))
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

impl<T: Typed2718> Typed2718 for WithFlashbotsMetadata<T> {
    fn ty(&self) -> u8 {
        self.inner.ty()
    }
}

impl<T: alloy_consensus::Transaction> alloy_consensus::Transaction for WithFlashbotsMetadata<T> {
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

impl<T: EthPoolTransaction> EthPoolTransaction for WithFlashbotsMetadata<T>
where
    T: PoolTransaction,
{
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        self.inner.take_blob()
    }

    fn try_into_pooled_eip4844(
        self,
        sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        self.inner.try_into_pooled_eip4844(sidecar)
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecarVariant,
        _settings: &alloy_eips::eip4844::env_settings::KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(
            self.ty(),
        ))
    }
}

impl<T: MaybeInteropTransaction> MaybeInteropTransaction for WithFlashbotsMetadata<T> {
    fn interop_deadline(&self) -> Option<u64> {
        self.inner.interop_deadline()
    }

    fn set_interop_deadline(&self, deadline: u64) {
        self.inner.set_interop_deadline(deadline);
    }
}

impl<T: DataAvailabilitySized> DataAvailabilitySized for WithFlashbotsMetadata<T> {
    fn estimated_da_size(&self) -> u64 {
        self.inner.estimated_da_size()
    }
}

impl<T: MaybeConditionalTransaction> MaybeConditionalTransaction for WithFlashbotsMetadata<T> {
    fn set_conditional(&mut self, conditional: TransactionConditional) {
        self.inner.set_conditional(conditional);
    }

    fn conditional(&self) -> Option<&TransactionConditional> {
        self.inner.conditional()
    }
}

impl<T: OpPooledTx> OpPooledTx for WithFlashbotsMetadata<T> {
    fn encoded_2718(&self) -> Cow<'_, Bytes> {
        self.inner.encoded_2718()
    }
}

impl<T> From<T> for WithFlashbotsMetadata<T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

pub trait MaybeFlashblockFilter {
    fn with_min_flashblock_number(self, min_flashblock_number: Option<u64>) -> Self;
    fn with_max_flashblock_number(self, max_flashblock_number: Option<u64>) -> Self;
    fn min_flashblock_number(&self) -> Option<u64>;
    fn max_flashblock_number(&self) -> Option<u64>;
}
