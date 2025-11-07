use alloy_primitives::{hex, keccak256, Bytes};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee_core::RpcResult;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    args::FlashtestationsArgs,
    attestation::{AttestationConfig, get_attestation_provider},
    service::load_or_generate_tee_key,
};

/// Admin API for op-rbuilder flashtestations
#[rpc(server, namespace = "admin")]
pub trait AdminApi {
    /// Get the raw attestation quote (cached after first request)
    #[method(name = "getAttestationQuote")]
    async fn get_attestation_quote(&self) -> RpcResult<Option<String>>;
}

/// Admin RPC server implementation
pub struct AdminRpcServer {
    flashtestations_args: FlashtestationsArgs,
    cached_quote: Arc<RwLock<Option<Vec<u8>>>>,
}

impl AdminRpcServer {
    pub fn new(flashtestations_args: FlashtestationsArgs) -> Self {
        Self {
            flashtestations_args,
            cached_quote: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl AdminApiServer for AdminRpcServer {
    async fn get_attestation_quote(&self) -> RpcResult<Option<String>> {
        // Check if quote is already cached
        {
            let cache = self.cached_quote.read().await;
            if let Some(quote) = cache.as_ref() {
                return Ok(Some(hex::encode(quote)));
            }
        }

        // Load TEE key using same logic as bootstrap
        let tee_service_signer = match load_or_generate_tee_key(
            &self.flashtestations_args.flashtestations_key_path,
            self.flashtestations_args.debug,
            &self.flashtestations_args.debug_tee_key_seed,
        ) {
            Ok(signer) => signer,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load TEE key");
                return Ok(None);
            }
        };

        // Quote not cached, fetch it
        let attestation_provider = get_attestation_provider(AttestationConfig {
            debug: self.flashtestations_args.debug,
            quote_provider: self.flashtestations_args.quote_provider.clone(),
        });

        // Prepare report data same as in bootstrap
        let mut report_data = [0u8; 64];
        let tee_address_bytes: [u8; 20] = tee_service_signer.address.into();
        report_data[0..20].copy_from_slice(&tee_address_bytes);

        // Use empty ext_data same as bootstrap
        let ext_data = Bytes::from(b"");
        let ext_data_hash = keccak256(ext_data.as_ref());
        report_data[20..52].copy_from_slice(ext_data_hash.as_ref());

        // Request attestation
        match attestation_provider.get_attestation(report_data).await {
            Ok(quote) => {
                // Cache the quote for future requests
                let mut cache = self.cached_quote.write().await;
                *cache = Some(quote.clone());
                Ok(Some(hex::encode(quote)))
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to get attestation quote");
                Ok(None)
            }
        }
    }
}
