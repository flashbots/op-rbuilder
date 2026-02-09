use super::args::BackrunBundleArgs;
use crate::primitives::bundle::Bundle;
use reth_basic_payload_builder::PayloadConfig;
use reth_optimism_node::OpPayloadBuilderAttributes;
use reth_optimism_primitives::OpTransactionSigned;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct BackrunBundleGlobalPoolInner {
    _state: Arc<u64>,
}

#[derive(Debug, Clone)]
pub struct BackrunBundleGlobalPool {
    inner: Arc<BackrunBundleGlobalPoolInner>,
}

impl BackrunBundleGlobalPool {
    pub fn new(_args: BackrunBundleArgs) -> Self {
        Self {
            inner: Arc::new(BackrunBundleGlobalPoolInner {
                _state: Arc::new(0),
            }),
        }
    }

    pub fn add_rpc_backrun_bundle(&self, _bundle: Bundle) {
        // dummy: does nothing
    }

    pub fn payload_pool(
        &self,
        config: &PayloadConfig<OpPayloadBuilderAttributes<OpTransactionSigned>>,
    ) -> BackrunBundlePayloadPool {
        let block_number = config.parent_header.number + 1;
        BackrunBundlePayloadPool {
            inner: Arc::new(BackrunBundlePayloadPoolInner {
                _state: self.inner._state.clone(),
                _block_number: block_number,
            }),
        }
    }
}

impl Default for BackrunBundleGlobalPool {
    fn default() -> Self {
        Self::new(BackrunBundleArgs::default())
    }
}

#[derive(Debug, Clone)]
struct BackrunBundlePayloadPoolInner {
    _state: Arc<u64>,
    _block_number: u64,
}

#[derive(Debug, Clone)]
pub struct BackrunBundlePayloadPool {
    #[allow(dead_code)]
    inner: Arc<BackrunBundlePayloadPoolInner>,
}

impl Default for BackrunBundlePayloadPool {
    fn default() -> Self {
        Self {
            inner: Arc::new(BackrunBundlePayloadPoolInner {
                _state: Arc::new(0),
                _block_number: 0,
            }),
        }
    }
}
