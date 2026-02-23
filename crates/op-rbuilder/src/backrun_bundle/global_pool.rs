use super::{
    metrics::BackrunPoolMetrics,
    payload_pool::{BackrunBundlePayloadPool, StoredBackrunBundle},
};
use alloy_consensus::BlockHeader;
use dashmap::DashMap;
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{Block, RecoveredBlock};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use uuid::Uuid;

struct BackrunBundleGlobalPoolInner {
    payload_pools: DashMap<u64, BackrunBundlePayloadPool>,
    replacements: DashMap<Uuid, StoredBackrunBundle>,
    metrics: BackrunPoolMetrics,
    estimated_base_fee_per_gas: AtomicU64,
}

impl fmt::Debug for BackrunBundleGlobalPoolInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackrunBundleGlobalPoolInner")
            .field("payload_pools", &self.payload_pools)
            .field("replacements", &self.replacements)
            .finish()
    }
}

/// Long-lived, shared pool that stores all pending backrun bundles.
///
/// Created once at node startup and shared (via `Arc`) between the RPC layer
/// (which inserts bundles) and the payload builder (which reads them).
/// A background [`super::maintain`] task listens to canonical state
/// notifications and calls [`Self::on_canonical_state_change`] for every new
/// tip, which:
///
/// 1. Removes per-block payload pools that are at or below the new tip
///    (their blocks are already sealed).
/// 2. Evicts replacement-tracking entries whose `block_number_max` is in the
///    past.
/// 3. Updates the estimated base fee used for priority-fee estimation on
///    incoming bundles.
///
/// Bundles are stored in per-block [`BackrunBundlePayloadPool`]s. A single
/// bundle whose block range spans N blocks appears in N payload pools.
/// Bundles with a `replacement_key` are additionally tracked in a separate
/// map so that newer submissions (higher replacement nonce) atomically
/// replace older ones.
#[derive(Debug, Clone)]
pub struct BackrunBundleGlobalPool {
    inner: Arc<BackrunBundleGlobalPoolInner>,
}

impl BackrunBundleGlobalPool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(BackrunBundleGlobalPoolInner {
                payload_pools: DashMap::new(),
                replacements: DashMap::new(),
                metrics: Default::default(),
                estimated_base_fee_per_gas: AtomicU64::new(0),
            }),
        }
    }

    fn get_or_create_pool(&self, block_number: u64) -> BackrunBundlePayloadPool {
        if let Some(pool) = self.inner.payload_pools.get(&block_number) {
            return pool.clone();
        }
        self.inner
            .payload_pools
            .entry(block_number)
            .or_default()
            .clone()
    }

    /// Add a bundle to the global pool. Returns `false` if the bundle was rejected
    /// due to a stale replacement nonce or an already-expired block range.
    pub(super) fn add_bundle(&self, bundle: StoredBackrunBundle, last_block_number: u64) -> bool {
        if bundle.block_number_max <= last_block_number {
            return false;
        }
        let metrics = &self.inner.metrics;
        let first_pool_block = (last_block_number + 1).max(bundle.block_number_min);
        if let Some(ref key) = bundle.replacement_key {
            // We use the entry API as a per-UUID write lock: payload pool
            // insertion happens inside the guard so that remove-old + insert-new
            // is atomic w.r.t. concurrent calls for the same UUID.
            match self.inner.replacements.entry(key.uuid) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    let old_nonce = entry
                        .get()
                        .replacement_key
                        .as_ref()
                        .expect("tracked bundle must have replacement_key")
                        .nonce;
                    if key.nonce <= old_nonce {
                        return false;
                    }
                    // Remove old bundle from all its payload pools
                    let old = entry.get().clone();
                    for block in old.block_number_min..=old.block_number_max {
                        if let Some(pool) = self.inner.payload_pools.get(&block) {
                            pool.remove_bundle(&old);
                        }
                    }
                    metrics.bundle_count.decrement(1.0);
                    entry.insert(bundle.clone());
                    for block in first_pool_block..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                    metrics.bundle_count.increment(1.0);
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(bundle.clone());
                    for block in first_pool_block..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                    metrics.bundle_count.increment(1.0);
                }
            }
        } else {
            for block in first_pool_block..=bundle.block_number_max {
                self.get_or_create_pool(block).add_bundle(bundle.clone());
            }
            metrics.bundle_count.increment(1.0);
        }
        true
    }

    pub fn payload_pool(
        &self,
        config: &PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    ) -> BackrunBundlePayloadPool {
        let block_number = config.parent_header.number + 1;
        self.get_or_create_pool(block_number)
    }

    /// Returns the estimated base fee per gas from the latest canonical tip.
    pub(super) fn estimated_base_fee_per_gas(&self) -> u64 {
        self.inner
            .estimated_base_fee_per_gas
            .load(Ordering::Relaxed)
    }

    pub(super) fn on_canonical_state_change<B: Block>(&self, tip: &RecoveredBlock<B>) {
        let block_number = tip.number();

        if let Some(base_fee) = tip.base_fee_per_gas() {
            self.inner
                .estimated_base_fee_per_gas
                .store(base_fee, Ordering::Relaxed);
        }

        // Remove stale pools from the map, then record metrics outside the lock.
        let removed_pools: Vec<_> = self
            .inner
            .payload_pools
            .iter()
            .filter(|entry| *entry.key() <= block_number)
            .map(|entry| *entry.key())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|k| self.inner.payload_pools.remove(&k))
            .collect();

        let metrics = &self.inner.metrics;
        let mut unique_removed = 0u64;
        for (block, pool) in &removed_pools {
            for count in pool.per_tx_bundle_counts() {
                metrics.backruns_per_tx.record(count as f64);
            }
            // Only count bundles whose last pool is this one (block_number_max == key),
            // so each unique bundle is counted exactly once.
            unique_removed += pool.count_final_bundles(*block) as u64;
        }
        metrics.bundle_count.decrement(unique_removed as f64);

        self.inner
            .replacements
            .retain(|_, bundle| bundle.block_number_max > block_number);
    }
}

impl Default for BackrunBundleGlobalPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{payload_pool::ReplacementKey, test_utils::make_backrun_bundle},
        *,
    };
    use crate::tx_signer::Signer;
    use alloy_primitives::{B256, U256};
    use reth_optimism_primitives::OpTransactionSigned;

    fn pool_bundle_count(pool: &BackrunBundlePayloadPool) -> usize {
        pool.per_tx_bundle_counts().sum()
    }

    #[test]
    fn test_add_bundle_block_spanning() {
        let gp = BackrunBundleGlobalPool::default();
        let s = Signer::random();
        let target = B256::random();

        // Bundle valid for blocks 5-8, last sealed block is 3
        let last_block = 3;
        let b = make_backrun_bundle(&s, target, (5, 8)).build();
        assert!(gp.add_bundle(b, last_block));

        // Present in pools 5..=8, absent in 4 and 9
        for block in 5..=8 {
            assert_eq!(
                pool_bundle_count(&gp.get_or_create_pool(block)),
                1,
                "block {block}"
            );
        }
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(4)), 0);
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(9)), 0);

        let last_block = 6;
        // With last_block_number=6, sealed blocks skipped: only 7-8 get the new bundle
        let b2 = make_backrun_bundle(&s, target, (5, 8))
            .with_nonce(1)
            .with_priority_fee(200)
            .build();
        assert!(gp.add_bundle(b2, last_block));
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(5)), 1); // only b
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(7)), 2); // b + b2
    }

    #[test]
    fn test_replacement() {
        let gp = BackrunBundleGlobalPool::default();
        let s = Signer::random();
        let target = B256::random();
        let uuid = uuid::Uuid::new_v4();
        let last_block = 0;
        let block_range = (10, 12);

        // First insert with UUID
        let mut b1 = make_backrun_bundle(&s, target, block_range)
            .with_priority_fee(100)
            .build();
        b1.replacement_key = Some(ReplacementKey { uuid, nonce: 1 });
        assert!(gp.add_bundle(b1, last_block));
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(block_range.0)), 1);

        // Replace with higher nonce — old removed, new inserted
        let mut b2 = make_backrun_bundle(&s, target, block_range)
            .with_nonce(1)
            .with_priority_fee(200)
            .build();
        b2.replacement_key = Some(ReplacementKey { uuid, nonce: 2 });
        assert!(gp.add_bundle(b2, last_block));
        assert_eq!(pool_bundle_count(&gp.get_or_create_pool(block_range.0)), 1);

        // Verify the surviving bundle is b2 (priority_fee=200)
        let pp = gp.get_or_create_pool(block_range.0);
        let bundles = pp.get_backruns(
            &target,
            |_| {
                Some(revm::state::AccountInfo {
                    nonce: 1,
                    balance: U256::from(1_000_000_000u128),
                    ..Default::default()
                })
            },
            0,
            u64::MAX,
            10,
        );
        assert_eq!(bundles[0].estimated_effective_priority_fee, 200);

        // Stale nonce rejected
        let mut b3 = make_backrun_bundle(&s, target, block_range)
            .with_nonce(2)
            .with_priority_fee(300)
            .build();
        b3.replacement_key = Some(ReplacementKey { uuid, nonce: 1 });
        assert!(!gp.add_bundle(b3, last_block));

        // Equal nonce also rejected
        let mut b4 = make_backrun_bundle(&s, target, block_range)
            .with_nonce(3)
            .with_priority_fee(300)
            .build();
        b4.replacement_key = Some(ReplacementKey { uuid, nonce: 2 });
        assert!(!gp.add_bundle(b4, last_block));
    }

    #[test]
    fn test_on_canonical_state_change() {
        let gp = BackrunBundleGlobalPool::default();
        let s = Signer::random();
        let target = B256::random();
        let uuid = uuid::Uuid::new_v4();
        let last_block = 0;
        let tip_block = 11;
        let tip_base_fee = 42;

        // Add bundles across blocks 8-10 and 12-14
        let mut b1 = make_backrun_bundle(&s, target, (8, 10))
            .with_priority_fee(100)
            .build();
        b1.replacement_key = Some(ReplacementKey { uuid, nonce: 1 });
        let b2 = make_backrun_bundle(&s, target, (12, 14))
            .with_nonce(1)
            .with_priority_fee(200)
            .build();
        gp.add_bundle(b1, last_block);
        gp.add_bundle(b2, last_block);

        // Simulate canonical state change
        let header = alloy_consensus::Header {
            number: tip_block,
            base_fee_per_gas: Some(tip_base_fee),
            ..Default::default()
        };
        let block = alloy_consensus::Block::<OpTransactionSigned> {
            header,
            body: Default::default(),
        };
        let tip = RecoveredBlock::new_unhashed(block, vec![]);
        gp.on_canonical_state_change(&tip);

        // Pools <= tip_block removed, pool 12+ retained
        assert_eq!(gp.inner.payload_pools.len(), 3); // 12, 13, 14

        // Replacement for b1 (max=10 <= tip_block) cleaned up
        assert!(gp.inner.replacements.is_empty());

        // Base fee updated
        assert_eq!(gp.estimated_base_fee_per_gas(), tip_base_fee);
    }
}
