use std::io::Read;
#[cfg(feature = "flashtestations")]
use tdx::{device::DeviceOptions, Tdx};
use tracing::info;
use ureq;

const DEBUG_QUOTE_SERVICE_URL: &str = "http://ns31695324.ip-141-94-163.eu:10080/attest";

/// Configuration for attestation
#[derive(Default)]
pub struct AttestationConfig {
    /// If true, uses the debug HTTP service instead of real TDX hardware
    pub debug: bool,
    /// The URL of the quote provider
    pub quote_provider: Option<String>,
}

/// Trait for attestation providers
pub trait AttestationProvider {
    fn get_attestation(&self, report_data: [u8; 64]) -> eyre::Result<Vec<u8>>;
}

/// Real TDX hardware attestation provider
#[cfg(feature = "flashtestations")]
pub struct TdxAttestationProvider {
    tdx: Tdx,
}

#[cfg(feature = "flashtestations")]
impl Default for TdxAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "flashtestations")]
impl TdxAttestationProvider {
    pub fn new() -> Self {
        Self { tdx: Tdx::new() }
    }
}

#[cfg(feature = "flashtestations")]
impl AttestationProvider for TdxAttestationProvider {
    fn get_attestation(&self, report_data: [u8; 64]) -> eyre::Result<Vec<u8>> {
        self.tdx
            .get_attestation_report_raw_with_options(DeviceOptions {
                report_data: Some(report_data),
            })
            .map_err(|e| e.into())
    }
}

/// Remote HTTP service attestation provider
pub struct RemoteAttestationProvider {
    service_url: String,
}

impl RemoteAttestationProvider {
    pub fn new(service_url: String) -> Self {
        Self { service_url }
    }
}

impl AttestationProvider for RemoteAttestationProvider {
    fn get_attestation(&self, report_data: [u8; 64]) -> eyre::Result<Vec<u8>> {
        let report_data_hex = hex::encode(report_data);
        let url = format!("{}/{}", self.service_url, report_data_hex);

        info!(target: "flashtestations", url = url, "fetching quote in debug mode");

        let response = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .call()?;

        let mut body = Vec::new();
        response.into_reader().read_to_end(&mut body)?;

        Ok(body)
    }
}

pub fn get_attestation_provider(
    config: AttestationConfig,
) -> Box<dyn AttestationProvider + Send + Sync> {
    if let Some(quote_provider) = config.quote_provider {
        Box::new(RemoteAttestationProvider::new(quote_provider))
    } else if config.debug {
        Box::new(RemoteAttestationProvider::new(
            config
                .quote_provider
                .unwrap_or(DEBUG_QUOTE_SERVICE_URL.to_string()),
        ))
    } else {
        #[cfg(feature = "flashtestations")]
        {
            Box::new(TdxAttestationProvider::new())
        }
        #[cfg(not(feature = "flashtestations"))]
        {
            info!("Using debug attestation provider as flashtestations feature is disabled");
            Box::new(RemoteAttestationProvider::new(
                DEBUG_QUOTE_SERVICE_URL.to_string(),
            ))
        }
    }
}
