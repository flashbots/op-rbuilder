use super::{
    args::BackrunBundleArgs,
    payload_pool::{BackrunBundlePayloadPool, StoredBackrunBundle},
};
use alloy_consensus::BlockHeader;
use dashmap::DashMap;
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{Block, RecoveredBlock};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
struct BackrunBundleGlobalPoolInner {
    payload_pools: DashMap<u64, BackrunBundlePayloadPool>,
    replacements: DashMap<Uuid, StoredBackrunBundle>,
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
                    entry.insert(bundle.clone());
                    for block in bundle.block_number..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(bundle.clone());
                    for block in bundle.block_number..=bundle.block_number_max {
                        self.get_or_create_pool(block).add_bundle(bundle.clone());
                    }
                }
            }
        } else {
            for block in bundle.block_number..=bundle.block_number_max {
                self.get_or_create_pool(block).add_bundle(bundle.clone());
            }
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
        self.inner.payload_pools.retain(|k, _| *k > block_number);
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
