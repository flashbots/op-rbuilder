use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use dashmap::DashMap;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;
use revm::state::AccountInfo;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    sync::Arc,
};
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
    pub flashblock_number_min: u64,
    pub flashblock_number_max: u64,
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
            if block_number == self.block_number && fb < self.flashblock_number_min {
                return false;
            }
            if block_number == self.block_number_max && fb > self.flashblock_number_max {
                return false;
            }
        }

        true
    }
}

/// Ord impl: highest `estimated_effective_priority_fee` first, backrun tx hash as tiebreaker.
#[derive(Debug, Clone)]
pub(super) struct OrderedBackrunBundle(StoredBackrunBundle);

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
pub(super) struct TxBackruns {
    pub(super) bundles: BTreeSet<OrderedBackrunBundle>,
}

/// Per-block pool of backrun bundles, keyed by target transaction hash.
///
/// Each block number in [`super::global_pool::BackrunBundleGlobalPool`] maps to
/// one `BackrunBundlePayloadPool`. During block building the payload builder
/// calls [`Self::get_backruns`] after each successfully committed transaction
/// to retrieve candidate backruns sorted by descending priority fee.
///
/// `get_backruns` performs lightweight pre-filtering (base fee, sender nonce,
/// balance, dedup by `(address, nonce)`) so the builder only simulates
/// plausible candidates.
#[derive(Debug, Clone)]
pub struct BackrunBundlePayloadPool {
    inner: Arc<DashMap<B256, TxBackruns>>,
}

impl BackrunBundlePayloadPool {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub(super) fn add_bundle(&self, bundle: StoredBackrunBundle) {
        self.inner
            .entry(bundle.target_tx_hash)
            .or_default()
            .bundles
            .insert(OrderedBackrunBundle(bundle));
    }

    pub(super) fn remove_bundle(&self, bundle: &StoredBackrunBundle) -> bool {
        if let Some(mut tx_backruns) = self.inner.get_mut(&bundle.target_tx_hash) {
            tx_backruns
                .bundles
                .remove(&OrderedBackrunBundle(bundle.clone()))
        } else {
            false
        }
    }

    /// Returns an iterator over the bundle count for each target tx in this pool.
    pub(super) fn per_tx_bundle_counts(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.iter().map(|entry| entry.value().bundles.len())
    }

    /// Count bundles whose `block_number_max` equals the given block number.
    /// These are bundles for which this pool is the last one they appear in.
    pub(super) fn count_final_bundles(&self, block_number: u64) -> usize {
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
    /// It's not used if the user requests more than MAX_ITER_COUNT candidates.
    const MAX_ITER_COUNT: usize = 50;

    /// Returns up to `max_count` backrun candidates for the given target tx, sorted by
    /// descending `estimated_effective_priority_fee`. Note that this ordering uses the
    /// estimated priority fee computed at bundle submission time (based on the then-current
    /// base fee), which may differ from the actual priority fee at block-building time.
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

#[cfg(test)]
mod tests {
    use super::{super::test_utils::make_backrun_bundle, *};
    use crate::tx_signer::Signer;

    #[test]
    fn test_is_valid() {
        let s = Signer::random();
        let target = B256::random();
        let mut b = make_backrun_bundle(&s, target, (10, 15)).build();

        // Block range
        assert!(!b.is_valid(9, None), "before range");
        assert!(b.is_valid(10, None), "at start");
        assert!(b.is_valid(12, None), "middle");
        assert!(b.is_valid(15, None), "at end");
        assert!(!b.is_valid(16, None), "after range");

        // Flashblock min only enforced on first block
        b.flashblock_number_min = 3;
        assert!(!b.is_valid(10, Some(2)), "fb < min on first block");
        assert!(b.is_valid(10, Some(3)), "fb == min on first block");
        assert!(b.is_valid(11, Some(0)), "fb < min on non-first block OK");

        // Flashblock max only enforced on last block
        b.flashblock_number_max = 5;
        assert!(!b.is_valid(15, Some(6)), "fb > max on last block");
        assert!(b.is_valid(15, Some(5)), "fb == max on last block");
        assert!(b.is_valid(14, Some(99)), "fb > max on non-last block OK");

        // Single-block range: both min and max enforced
        let mut single = make_backrun_bundle(&s, target, (10, 10)).build();
        single.flashblock_number_min = 2;
        single.flashblock_number_max = 5;
        assert!(!single.is_valid(10, Some(1)), "below min");
        assert!(single.is_valid(10, Some(3)), "in range");
        assert!(!single.is_valid(10, Some(6)), "above max");

        // No flashblock number: constraints ignored
        assert!(b.is_valid(10, None));
    }

    #[test]
    fn test_ordering() {
        let s = Signer::random();
        let target = B256::random();
        let block_range = (10, 10);

        let high = OrderedBackrunBundle(
            make_backrun_bundle(&s, target, block_range)
                .with_priority_fee(200)
                .build(),
        );
        // Different nonce so the signed tx hash differs (equality is by tx hash)
        let low = OrderedBackrunBundle(
            make_backrun_bundle(&s, target, block_range)
                .with_nonce(1)
                .with_priority_fee(100)
                .build(),
        );

        // Higher priority fee sorts first (is "less" in Ord)
        assert!(high < low);

        // Equality is by tx hash
        assert_eq!(high, high.clone());
        assert_ne!(high, low);

        // BTreeSet iteration: highest fee first
        let mut set = std::collections::BTreeSet::new();
        set.insert(low.clone());
        set.insert(high.clone());
        let fees: Vec<_> = set
            .iter()
            .map(|o| o.0.estimated_effective_priority_fee)
            .collect();
        assert_eq!(fees, vec![200, 100]);
    }

    #[test]
    fn test_add_remove_counts() {
        let s = Signer::random();
        let target_a = B256::random();
        let target_b = B256::random();
        let pool = BackrunBundlePayloadPool::new();

        let b1 = make_backrun_bundle(&s, target_a, (10, 12)).build();
        let b2 = make_backrun_bundle(&s, target_a, (10, 10))
            .with_nonce(1)
            .with_priority_fee(200)
            .build();
        let b3 = make_backrun_bundle(&s, target_b, (10, 12))
            .with_nonce(2)
            .with_priority_fee(150)
            .build();

        pool.add_bundle(b1.clone());
        pool.add_bundle(b2.clone());
        pool.add_bundle(b3.clone());

        // per_tx_bundle_counts
        let mut counts: Vec<_> = pool.per_tx_bundle_counts().collect();
        counts.sort();
        assert_eq!(counts, vec![1, 2]); // target_a=2, target_b=1

        // count_final_bundles: b2 has max=10, b1+b3 have max=12
        assert_eq!(pool.count_final_bundles(10), 1);
        assert_eq!(pool.count_final_bundles(12), 2);
        assert_eq!(pool.count_final_bundles(11), 0);

        // remove
        assert!(pool.remove_bundle(&b1));
        assert!(!pool.remove_bundle(&b1), "double remove returns false");
        let mut counts: Vec<_> = pool.per_tx_bundle_counts().collect();
        counts.sort();
        assert_eq!(counts, vec![1, 1]);
    }

    #[test]
    fn test_get_backruns_filtering() {
        let s1 = Signer::random();
        let s2 = Signer::random();
        let target = B256::random();
        let pool = BackrunBundlePayloadPool::new();
        let block_range = (10, 10);
        let base_fee = 100;
        let max_backruns = 10;

        // s1/nonce=0/priority=200: should land
        let b1 = make_backrun_bundle(&s1, target, block_range)
            .with_priority_fee(200)
            .build();
        // s1/nonce=0/priority=100: deduped (same sender+nonce, lower priority)
        let b2 = make_backrun_bundle(&s1, target, block_range)
            .with_priority_fee(100)
            .build();
        // s2/nonce=0/fee=50: filtered (max_fee_per_gas < base_fee)
        let b3 = make_backrun_bundle(&s2, target, block_range)
            .with_max_fee_per_gas(50)
            .with_priority_fee(50)
            .build();
        // s2/nonce=5/priority=150: filtered (nonce mismatch)
        let b4 = make_backrun_bundle(&s2, target, block_range)
            .with_nonce(5)
            .with_priority_fee(150)
            .build();

        pool.add_bundle(b1);
        pool.add_bundle(b2);
        pool.add_bundle(b3);
        pool.add_bundle(b4);

        let good_account = |addr: Address| -> Option<AccountInfo> {
            if addr == s1.address || addr == s2.address {
                Some(AccountInfo {
                    nonce: 0,
                    balance: U256::from(1_000_000_000u128),
                    ..Default::default()
                })
            } else {
                None
            }
        };

        let results = pool.get_backruns(&target, good_account, base_fee, max_backruns);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].estimated_effective_priority_fee, 200);

        // Unknown target returns empty
        assert!(
            pool.get_backruns(&B256::random(), good_account, base_fee, max_backruns)
                .is_empty()
        );

        // max_count respected
        let s3 = Signer::random();
        pool.add_bundle(
            make_backrun_bundle(&s3, target, block_range)
                .with_priority_fee(180)
                .build(),
        );
        let all_known = |_: Address| -> Option<AccountInfo> {
            Some(AccountInfo {
                nonce: 0,
                balance: U256::from(1_000_000_000u128),
                ..Default::default()
            })
        };
        let results = pool.get_backruns(&target, all_known, base_fee, 1);
        assert_eq!(results.len(), 1, "max_count=1");

        // Balance check: no balance filters all
        let poor = |_: Address| -> Option<AccountInfo> {
            Some(AccountInfo {
                nonce: 0,
                balance: U256::ZERO,
                ..Default::default()
            })
        };
        assert!(
            pool.get_backruns(&target, poor, base_fee, max_backruns)
                .is_empty()
        );
    }
}
