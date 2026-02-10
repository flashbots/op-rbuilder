use super::{
    args::BackrunBundleArgs,
    payload_pool::{BackrunBundle, BackrunBundlePayloadPool},
};
use alloy_consensus::BlockHeader;
use dashmap::DashMap;
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives_traits::{Block, RecoveredBlock};
use std::sync::Arc;

#[derive(Debug)]
struct BackrunBundleGlobalPoolInner {
    payload_pools: DashMap<u64, BackrunBundlePayloadPool>,
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

    pub fn add_bundle(&self, bundle: BackrunBundle) {
        for block in bundle.block_number_min..=bundle.block_number_max {
            self.get_or_create_pool(block).add_bundle(bundle.clone());
        }
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
    }
}

impl Default for BackrunBundleGlobalPool {
    fn default() -> Self {
        Self::new(BackrunBundleArgs::default())
    }
}
