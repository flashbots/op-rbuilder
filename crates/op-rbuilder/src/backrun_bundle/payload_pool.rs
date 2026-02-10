use alloy_consensus::Transaction;
use alloy_primitives::B256;
use dashmap::DashMap;
use reth_optimism_primitives::OpTransactionSigned;
use std::{cmp::Ordering, sync::Arc};

#[derive(Debug, Clone)]
pub struct BackrunBundle {
    /// Hash of the target tx; we assume it's in the txpool.
    pub target_tx_hash: B256,
    pub backrun_tx: OpTransactionSigned,
    pub block_number_min: u64,
    pub block_number_max: u64,
    pub flashblock_number_min: Option<u64>,
    pub flashblock_number_max: Option<u64>,
}

/// Ord impl: highest `max_priority_fee_per_gas` first, backrun tx hash as tiebreaker.
#[derive(Debug, Clone)]
pub struct OrderedBackrunBundle(pub BackrunBundle);

impl OrderedBackrunBundle {
    fn priority_fee(&self) -> u128 {
        self.0.backrun_tx.max_priority_fee_per_gas().unwrap_or(0)
    }

    fn backrun_tx_hash(&self) -> B256 {
        B256::from(*self.0.backrun_tx.tx_hash())
    }
}

impl PartialEq for OrderedBackrunBundle {
    fn eq(&self, other: &Self) -> bool {
        self.backrun_tx_hash() == other.backrun_tx_hash()
    }
}

impl Eq for OrderedBackrunBundle {}

impl PartialOrd for OrderedBackrunBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedBackrunBundle {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .priority_fee()
            .cmp(&self.priority_fee())
            .then_with(|| self.backrun_tx_hash().cmp(&other.backrun_tx_hash()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct TxBackruns {
    pub bundles: std::collections::BTreeSet<OrderedBackrunBundle>,
}

impl TxBackruns {
    pub fn iter(&self) -> impl Iterator<Item = &OrderedBackrunBundle> {
        self.bundles.iter()
    }
}

#[derive(Debug, Clone)]
pub struct BackrunBundlePayloadPool {
    inner: Arc<DashMap<B256, TxBackruns>>,
}

impl BackrunBundlePayloadPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn add_bundle(&self, bundle: BackrunBundle) {
        self.inner
            .entry(bundle.target_tx_hash)
            .or_default()
            .bundles
            .insert(OrderedBackrunBundle(bundle));
    }

    pub fn get_backruns(&self, target_tx_hash: &B256) -> Option<TxBackruns> {
        self.inner.get(target_tx_hash).map(|r| r.clone())
    }
}

impl Default for BackrunBundlePayloadPool {
    fn default() -> Self {
        Self::new()
    }
}
