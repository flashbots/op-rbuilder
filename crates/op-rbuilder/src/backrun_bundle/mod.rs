pub mod args;
pub mod global_pool;
pub mod maintain;
mod metrics;
pub mod payload_pool;
pub mod rpc;
#[cfg(test)]
mod test_utils;

use args::BackrunBundleArgs;
use payload_pool::BackrunBundlePayloadPool;

#[derive(Debug, Clone)]
pub struct BackrunBundlesPayloadCtx {
    pub pool: BackrunBundlePayloadPool,
    pub args: BackrunBundleArgs,
}
