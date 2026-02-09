use alloy_primitives::B256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::primitives::bundle::{Bundle, BundleResult};

use super::pool::BackrunBundleGlobalPool;

#[rpc(server, namespace = "eth")]
pub trait BackrunBundleApi {
    #[method(name = "sendBackrunBundle")]
    async fn send_backrun_bundle(&self, bundle: Bundle) -> RpcResult<BundleResult>;
}

pub struct BackrunBundleRpc {
    global_pool: BackrunBundleGlobalPool,
}

impl BackrunBundleRpc {
    pub fn new(global_pool: BackrunBundleGlobalPool) -> Self {
        Self { global_pool }
    }
}

#[jsonrpsee::core::async_trait]
impl BackrunBundleApiServer for BackrunBundleRpc {
    async fn send_backrun_bundle(&self, bundle: Bundle) -> RpcResult<BundleResult> {
        self.global_pool.add_rpc_backrun_bundle(bundle);
        Ok(BundleResult {
            bundle_hash: B256::ZERO,
        })
    }
}
