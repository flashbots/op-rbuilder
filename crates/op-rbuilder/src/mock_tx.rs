use crate::tx::{MaybeFlashblockFilter, WithFlashbotsMetadata};
use alloy_consensus::TxEip4844WithSidecar;
use alloy_eips::eip7594::BlobTransactionSidecarVariant;
use reth_transaction_pool::{
    TransactionOrigin, ValidPoolTransaction,
    identifier::TransactionId,
    test_utils::{MockTransaction, MockTransactionFactory},
};
use std::{sync::Arc, time::Instant};

/// A factory for creating and managing various types of mock transactions.
#[derive(Debug, Default)]
pub struct MockFbTransactionFactory {
    pub(crate) factory: MockTransactionFactory,
}

// === impl MockTransactionFactory ===

impl MockFbTransactionFactory {
    /// Generates a transaction ID for the given [`MockTransaction`].
    pub fn tx_id(&mut self, tx: &MockFbTransaction) -> TransactionId {
        self.factory.tx_id(&tx.inner)
    }

    /// Validates a [`MockTransaction`] and returns a [`MockValidFbTx`].
    pub fn validated(&mut self, transaction: MockFbTransaction) -> MockValidFbTx {
        self.validated_with_origin(TransactionOrigin::External, transaction)
    }

    /// Validates a [`MockTransaction`] and returns a shared [`Arc<MockValidFbTx>`].
    pub fn validated_arc(&mut self, transaction: MockFbTransaction) -> Arc<MockValidFbTx> {
        Arc::new(self.validated(transaction))
    }

    /// Converts the transaction into a validated transaction with a specified origin.
    pub fn validated_with_origin(
        &mut self,
        origin: TransactionOrigin,
        transaction: MockFbTransaction,
    ) -> MockValidFbTx {
        MockValidFbTx {
            propagate: false,
            transaction_id: self.tx_id(&transaction),
            transaction,
            timestamp: Instant::now(),
            origin,
            authority_ids: None,
        }
    }

    /// Creates a validated legacy [`MockTransaction`].
    pub fn create_legacy(&mut self) -> MockValidFbTx {
        self.validated(MockTransaction::legacy().into())
    }

    /// Creates a validated legacy [`MockTransaction`].
    pub fn create_legacy_fb(&mut self, min: Option<u64>, max: Option<u64>) -> MockValidFbTx {
        self.validated(
            MockFbTransaction::new(MockTransaction::legacy())
                .with_min_flashblock_number(min)
                .with_max_flashblock_number(max),
        )
    }

    /// Creates a validated EIP-1559 [`MockTransaction`].
    pub fn create_eip1559(&mut self) -> MockValidFbTx {
        self.validated(MockTransaction::legacy().into())
    }

    /// Creates a validated EIP-4844 [`MockTransaction`].
    pub fn create_eip4844(&mut self) -> MockValidFbTx {
        self.validated(MockTransaction::legacy().into())
    }
}

pub type MockFbTransaction = WithFlashbotsMetadata<MockTransaction>;

/// A validated transaction in the transaction pool, using [`MockTransaction`] as the transaction
/// type.
///
/// This type is an alias for [`ValidPoolTransaction<MockTransaction>`].
pub type MockValidFbTx = ValidPoolTransaction<MockFbTransaction>;

pub type PooledTransactionVariant =
    alloy_consensus::EthereumTxEnvelope<TxEip4844WithSidecar<BlobTransactionSidecarVariant>>;
