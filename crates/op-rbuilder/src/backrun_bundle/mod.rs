pub mod args;
pub mod global_pool;
pub mod maintain;
pub mod payload_pool;
pub mod rpc;

use args::BackrunBundleArgs;
use payload_pool::BackrunBundlePayloadPool;

#[derive(Debug, Clone)]
pub struct BackrunBundlesPayloadCtx {
    pub pool: BackrunBundlePayloadPool,
    pub args: BackrunBundleArgs,
}
