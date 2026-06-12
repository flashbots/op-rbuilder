use std::sync::Arc;

use alloy_eips::{
    eip4844::{BlobAndProofV1, BlobAndProofV2, BlobCellsAndProofsV1},
    eip7594::BlobTransactionSidecarVariant,
};
use alloy_primitives::{Address, B128, B256, TxHash, map::AddressSet};
use delegate::delegate;
use reth::network::types::HandleMempoolData;
use reth_primitives_traits::Recovered;
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, AllTransactionsEvents, BestTransactions,
    BestTransactionsAttributes, BlockInfo, GetPooledTransactionLimit, NewBlobSidecar,
    NewTransactionEvent, PoolResult, PoolSize, PoolTransaction, PropagatedTransactions,
    TransactionEvents, TransactionListenerKind, TransactionOrigin, TransactionPool,
    ValidPoolTransaction,
    blobstore::{BlobStore, BlobStoreError},
};
use tokio::sync::mpsc::Receiver;

use crate::{pool::Flashpool, tx::FBPooledTransaction};

impl<P: TransactionPool<Transaction = FBPooledTransaction> + 'static> TransactionPool
    for Flashpool<P>
{
    type Transaction = FBPooledTransaction;

    fn add_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> impl Future<Output = PoolResult<AddedTransactionOutcome>> + Send {
        self.add_transaction_override(origin, transaction)
    }

    delegate! {
        to self.inner {
            fn pool_size(&self) -> PoolSize;
            fn block_info(&self) -> BlockInfo;
            fn add_transaction_and_subscribe(
                &self,
                origin: TransactionOrigin,
                transaction: Self::Transaction,
            ) -> impl Future<Output = PoolResult<TransactionEvents>> + Send;

            fn add_transactions(
                &self,
                origin: TransactionOrigin,
                transactions: Vec<Self::Transaction>,
            ) -> impl Future<Output = Vec<PoolResult<AddedTransactionOutcome>>> + Send;
            fn add_transactions_with_origins(
                &self,
                transactions: Vec<(TransactionOrigin, Self::Transaction)>,
            ) -> impl Future<Output = Vec<PoolResult<AddedTransactionOutcome>>> + Send;
            fn transaction_event_listener(
                &self,
                tx_hash: TxHash,
            ) -> Option<TransactionEvents>;
            fn all_transactions_event_listener(
                &self,
            ) -> AllTransactionsEvents<Self::Transaction>;
            fn pending_transactions_listener_for(
                &self,
                kind: TransactionListenerKind,
            ) -> Receiver<TxHash>;
            fn blob_transaction_sidecars_listener(&self) -> Receiver<NewBlobSidecar>;
            fn new_transactions_listener_for(
                &self,
                kind: TransactionListenerKind,
            ) -> Receiver<NewTransactionEvent<Self::Transaction>>;
            fn pooled_transaction_hashes(&self) -> Vec<TxHash>;
            fn pooled_transaction_hashes_max(&self, max: usize) -> Vec<TxHash>;
            fn pooled_transactions(
                &self,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn pooled_transactions_max(
                &self,
                max: usize,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_pooled_transaction_elements(
                &self,
                tx_hashes: Vec<TxHash>,
                limit: GetPooledTransactionLimit,
            ) -> Vec<<Self::Transaction as PoolTransaction>::Pooled>;
            fn get_pooled_transaction_element(
                &self,
                tx_hash: TxHash,
            ) -> Option<Recovered<<Self::Transaction as PoolTransaction>::Pooled>>;
            fn best_transactions(
                &self,
            ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>>;
            fn best_transactions_with_attributes(
                &self,
                best_transactions_attributes: BestTransactionsAttributes,
            ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>>;
            fn pending_transactions(
                &self,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn pending_transactions_max(
                &self,
                max: usize,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn queued_transactions(
                &self,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn pending_and_queued_txn_count(&self) -> (usize, usize);
            fn all_transactions(&self) -> AllPoolTransactions<Self::Transaction>;
            fn all_transaction_hashes(&self) -> Vec<TxHash>;
            fn remove_transactions(
                &self,
                hashes: Vec<TxHash>,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn remove_transactions_and_descendants(
                &self,
                hashes: Vec<TxHash>,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn remove_transactions_by_sender(
                &self,
                sender: Address,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn prune_transactions(
                &self,
                hashes: Vec<TxHash>,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn retain_unknown<A>(&self, announcement: &mut A)
            where
                A: HandleMempoolData;
            fn retain_contains<A>(&self, announcement: &mut A)
            where
                A: HandleMempoolData;
            fn get(
                &self,
                tx_hash: &TxHash,
            ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_all(
                &self,
                txs: Vec<TxHash>,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn on_propagated(&self, txs: PropagatedTransactions);
            fn get_transactions_by_sender(
                &self,
                sender: Address,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_pending_transactions_with_predicate(
                &self,
                predicate: impl FnMut(&ValidPoolTransaction<Self::Transaction>) -> bool,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_pending_transactions_by_sender(
                &self,
                sender: Address,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_queued_transactions_by_sender(
                &self,
                sender: Address,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_highest_transaction_by_sender(
                &self,
                sender: Address,
            ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_highest_consecutive_transaction_by_sender(
                &self,
                sender: Address,
                on_chain_nonce: u64,
            ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_transaction_by_sender_and_nonce(
                &self,
                sender: Address,
                nonce: u64,
            ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_transactions_by_origin(
                &self,
                origin: TransactionOrigin,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn get_pending_transactions_by_origin(
                &self,
                origin: TransactionOrigin,
            ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
            fn unique_senders(&self) -> AddressSet;
            fn get_blob(
                &self,
                tx_hash: TxHash,
            ) -> Result<Option<Arc<BlobTransactionSidecarVariant>>, BlobStoreError>;
            fn get_all_blobs(
                &self,
                tx_hashes: Vec<TxHash>,
            ) -> Result<Vec<(TxHash, Arc<BlobTransactionSidecarVariant>)>, BlobStoreError>;
            fn get_all_blobs_exact(
                &self,
                tx_hashes: Vec<TxHash>,
            ) -> Result<Vec<Arc<BlobTransactionSidecarVariant>>, BlobStoreError>;
            fn get_blobs_for_versioned_hashes_v1(
                &self,
                versioned_hashes: &[B256],
            ) -> Result<Vec<Option<BlobAndProofV1>>, BlobStoreError>;
            fn get_blobs_for_versioned_hashes_v2(
                &self,
                versioned_hashes: &[B256],
            ) -> Result<Option<Vec<BlobAndProofV2>>, BlobStoreError>;
            fn get_blobs_for_versioned_hashes_v3(
                &self,
                versioned_hashes: &[B256],
            ) -> Result<Vec<Option<BlobAndProofV2>>, BlobStoreError>;
            fn get_blobs_for_versioned_hashes_v4(
                &self,
                versioned_hashes: &[B256],
                indices_bitarray: B128,
            ) -> Result<Vec<Option<BlobCellsAndProofsV1>>, BlobStoreError>;
            fn blob_store(&self) -> Box<dyn BlobStore>;
        }
    }
}
