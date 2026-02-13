use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use dashmap::DashMap;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use revm::state::AccountInfo;
use std::{cmp::Ordering, collections::HashSet, sync::Arc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ReplacementKey {
    pub uuid: Uuid,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct StoredBackrunBundle {
    /// Hash of the target tx; we assume it's in the txpool.
    pub target_tx_hash: B256,
    pub backrun_tx: Arc<Recovered<OpTransactionSigned>>,
    pub block_number: u64,
    pub block_number_max: u64,
    pub flashblock_number_min: Option<u64>,
    pub flashblock_number_max: Option<u64>,
    pub estimated_effective_priority_fee: u128,
    pub estimated_da_size: u64,
    pub replacement_key: Option<ReplacementKey>,
}

impl StoredBackrunBundle {
    /// Checks if this bundle is valid for the given block and flashblock.
    ///
    /// Flashblock constraints are scoped to the edges of the block range:
    /// - `flashblock_number_min` is only enforced on the first block (`block_number`)
    /// - `flashblock_number_max` is only enforced on the last block (`block_number_max`)
    /// - On intermediate blocks all flashblocks are valid
    pub fn is_valid(&self, block_number: u64, flashblock_number: Option<u64>) -> bool {
        if block_number < self.block_number || block_number > self.block_number_max {
            return false;
        }

        if let Some(fb) = flashblock_number {
            if block_number == self.block_number
                && self.flashblock_number_min.is_some_and(|min| fb < min)
            {
                return false;
            }
            if block_number == self.block_number_max
                && self.flashblock_number_max.is_some_and(|max| fb > max)
            {
                return false;
            }
        }

        true
    }
}

/// Ord impl: highest `estimated_effective_priority_fee` first, backrun tx hash as tiebreaker.
#[derive(Debug, Clone)]
pub struct OrderedBackrunBundle(pub StoredBackrunBundle);

impl OrderedBackrunBundle {
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
            .0
            .estimated_effective_priority_fee
            .cmp(&self.0.estimated_effective_priority_fee)
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

    pub fn add_bundle(&self, bundle: StoredBackrunBundle) {
        self.inner
            .entry(bundle.target_tx_hash)
            .or_default()
            .bundles
            .insert(OrderedBackrunBundle(bundle));
    }

    pub fn remove_bundle(&self, bundle: &StoredBackrunBundle) -> bool {
        if let Some(mut tx_backruns) = self.inner.get_mut(&bundle.target_tx_hash) {
            tx_backruns
                .bundles
                .remove(&OrderedBackrunBundle(bundle.clone()))
        } else {
            false
        }
    }

    /// Returns an iterator over the bundle count for each target tx in this pool.
    pub fn per_tx_bundle_counts(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.iter().map(|entry| entry.value().bundles.len())
    }

    /// Count bundles whose `block_number_max` equals the given block number.
    /// These are bundles for which this pool is the last one they appear in.
    pub fn count_final_bundles(&self, block_number: u64) -> usize {
        self.inner
            .iter()
            .map(|entry| {
                entry
                    .value()
                    .bundles
                    .iter()
                    .filter(|b| b.0.block_number_max == block_number)
                    .count()
            })
            .sum()
    }

    /// Maximum number of candidates to iterate over when selecting backruns.
    /// Its not used if user requests more than MAX_ITER_COUNT candidates.
    const MAX_ITER_COUNT: usize = 50;

    pub fn get_backruns(
        &self,
        target_tx_hash: &B256,
        mut account_info: impl FnMut(Address) -> Option<AccountInfo>,
        base_fee: u64,
        max_count: usize,
    ) -> Vec<StoredBackrunBundle> {
        let Some(tx_backruns) = self.inner.get(target_tx_hash) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        let mut seen = HashSet::<(Address, u64)>::new();
        let base_fee = base_fee as u128;

        // limit loop size as its blocking for the block building
        let max_iter = Self::MAX_ITER_COUNT.max(max_count);

        for ordered in tx_backruns.bundles.iter().take(max_iter) {
            if result.len() >= max_count {
                break;
            }

            let bundle = &ordered.0;
            let backrun_tx = &bundle.backrun_tx;

            // Base fee check
            if backrun_tx.max_fee_per_gas() < base_fee {
                continue;
            }

            let sender = backrun_tx.signer();
            let nonce = backrun_tx.nonce();

            // Dedup by (address, nonce) — first seen wins (highest priority fee)
            if !seen.insert((sender, nonce)) {
                continue;
            }

            // Account state checks
            let Some(account) = account_info(sender) else {
                continue;
            };

            // Nonce check
            if account.nonce != nonce {
                continue;
            }

            // Balance check: max_fee_per_gas * gas_limit + value
            let max_cost = U256::from(backrun_tx.max_fee_per_gas())
                * U256::from(backrun_tx.gas_limit())
                + U256::from(backrun_tx.value());
            if account.balance < max_cost {
                continue;
            }

            result.push(bundle.clone());
        }

        result
    }
}

impl Default for BackrunBundlePayloadPool {
    fn default() -> Self {
        Self::new()
    }
}
