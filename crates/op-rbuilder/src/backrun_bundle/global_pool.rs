use super::{
    args::BackrunBundleArgs,
    metrics::BackrunPoolMetrics,
    payload_pool::{BackrunBundlePayloadPool, StoredBackrunBundle},
};
use alloy_consensus::BlockHeader;
use dashmap::DashMap;
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{Block, RecoveredBlock};
use std::{fmt, sync::Arc};
use uuid::Uuid;

struct BackrunBundleGlobalPoolInner {
    payload_pools: DashMap<u64, BackrunBundlePayloadPool>,
    replacements: DashMap<Uuid, StoredBackrunBundle>,
    metrics: BackrunPoolMetrics,
}

impl fmt::Debug for BackrunBundleGlobalPoolInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackrunBundleGlobalPoolInner")
            .field("payload_pools", &self.payload_pools)
            .field("replacements", &self.replacements)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct BackrunBundleGlobalPool {
    inner: Arc<BackrunBundleGlobalPoolInner>,
}

impl BackrunBundleGlobalPool {
    pub fn new(_args: BackrunBundleArgs) -> Self {
        Self {
            inner: Arc::new(BackrunBundleGlobalPoolInner {
                payload_pools: DashMap::new(),
                replacements: DashMap::new(),
                metrics: Default::default(),
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
    /// due to a stale replacement nonce.
    pub fn add_bundle(&self, bundle: StoredBackrunBundle) -> bool {
        let metrics = &self.inner.metrics;
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
                    for block in old.block_number..=old.block_number_max {
                        if let Some(pool) = self.inner.payload_pools.get(&block) {
                            pool.remove_bundle(&old);
                        }
                    }
                    metrics.bundle_count.decrement(1.0);
                    entry.insert(bundle.clone());
                    for block in bundle.block_number..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                    metrics.bundle_count.increment(1.0);
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(bundle.clone());
                    for block in bundle.block_number..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                    metrics.bundle_count.increment(1.0);
                }
            }
        } else {
            for block in bundle.block_number..=bundle.block_number_max {
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

    pub fn on_canonical_state_change<B: Block>(&self, tip: &RecoveredBlock<B>) {
        let block_number = tip.number();

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
        Self::new(BackrunBundleArgs::default())
    }
}
