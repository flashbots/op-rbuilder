use reqwest::Client;
use sha3::{Digest, Keccak256};
use tracing::info;

const DEBUG_QUOTE_SERVICE_URL: &str = "http://ns31695324.ip-141-94-163.eu:10080/attest";

// Raw TDX v4 quote structure constants
// Raw quote has a 48-byte header before the TD10ReportBody
const HEADER_LENGTH: usize = 48;
const TD_REPORT10_LENGTH: usize = 584;

// TDX workload constants
const TD_XFAM_FPU: u64 = 0x0000000000000001;
const TD_XFAM_SSE: u64 = 0x0000000000000002;
const TD_TDATTRS_VE_DISABLED: u64 = 0x0000000010000000;
const TD_TDATTRS_PKS: u64 = 0x0000000040000000;
const TD_TDATTRS_KL: u64 = 0x0000000080000000;

/// Configuration for attestation
#[derive(Default)]
pub struct AttestationConfig {
    /// If true, uses the debug HTTP service instead of real TDX hardware
    pub debug: bool,
    /// The URL of the quote provider
    pub quote_provider: Option<String>,
}
/// Remote attestation provider
#[derive(Debug, Clone)]
pub struct RemoteAttestationProvider {
    client: Client,
    service_url: String,
}

impl RemoteAttestationProvider {
    pub fn new(service_url: String) -> Self {
        let client = Client::new();
        Self {
            client,
            service_url,
        }
    }
}

impl RemoteAttestationProvider {
    pub async fn get_attestation(&self, report_data: [u8; 64]) -> eyre::Result<Vec<u8>> {
        let report_data_hex = hex::encode(report_data);
        let url = format!("{}/{}", self.service_url, report_data_hex);

        info!(target: "flashtestations", url = url, "fetching quote from remote attestation provider");

        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?;
        let body = response.bytes().await?.to_vec();

        Ok(body)
    }
}

pub fn get_attestation_provider(config: AttestationConfig) -> RemoteAttestationProvider {
    if config.debug {
        RemoteAttestationProvider::new(
            config
                .quote_provider
                .unwrap_or(DEBUG_QUOTE_SERVICE_URL.to_string()),
        )
    } else {
        RemoteAttestationProvider::new(
            config
                .quote_provider
                .expect("remote quote provider must be specified when not in debug mode"),
        )
    }
}

/// ComputeWorkloadID computes the workload ID from Automata's serialized verifier output
/// This corresponds to QuoteParser.parseV4VerifierOutput in Solidity implementation
/// https://github.com/flashbots/flashtestations/tree/7cc7f68492fe672a823dd2dead649793aac1f216
/// The workload ID uniquely identifies a TEE workload based on its measurement registers
pub fn compute_workload_id(raw_quote: &[u8]) -> eyre::Result<[u8; 32]> {
    // Validate quote length
    if raw_quote.len() < HEADER_LENGTH + TD_REPORT10_LENGTH {
        eyre::bail!(
            "invalid quote length: {}, expected at least {}",
            raw_quote.len(),
            HEADER_LENGTH + TD_REPORT10_LENGTH
        );
    }

    // Skip the 48-byte header to get to the TD10ReportBody
    let report_body = &raw_quote[HEADER_LENGTH..];

    // Extract fields exactly as parseRawReportBody does in Solidity
    // Using hardcoded offsets to match Solidity implementation exactly
    let mr_td = &report_body[136..136 + 48];
    let rt_mr0 = &report_body[328..328 + 48];
    let rt_mr1 = &report_body[376..376 + 48];
    let rt_mr2 = &report_body[424..424 + 48];
    let rt_mr3 = &report_body[472..472 + 48];
    let mr_config_id = &report_body[184..184 + 48];

    // Extract xFAM and tdAttributes (8 bytes each)
    // In Solidity, bytes8 is treated as big-endian for bitwise operations
    let xfam = u64::from_be_bytes(report_body[128..128 + 8].try_into().unwrap());
    let td_attributes = u64::from_be_bytes(report_body[120..120 + 8].try_into().unwrap());

    // Apply transformations as per the Solidity implementation
    // expectedXfamBits = TD_XFAM_FPU | TD_XFAM_SSE
    let expected_xfam_bits = TD_XFAM_FPU | TD_XFAM_SSE;

    // ignoredTdAttributesBitmask = TD_TDATTRS_VE_DISABLED | TD_TDATTRS_PKS | TD_TDATTRS_KL
    let ignored_td_attributes_bitmask = TD_TDATTRS_VE_DISABLED | TD_TDATTRS_PKS | TD_TDATTRS_KL;

    // Transform xFAM: xFAM ^ expectedXfamBits
    let transformed_xfam = xfam ^ expected_xfam_bits;

    // Transform tdAttributes: tdAttributes & ~ignoredTdAttributesBitmask
    let transformed_td_attributes = td_attributes & !ignored_td_attributes_bitmask;

    // Convert transformed values to bytes (big-endian, to match Solidity bytes8)
    let xfam_bytes = transformed_xfam.to_be_bytes();
    let td_attributes_bytes = transformed_td_attributes.to_be_bytes();

    // Concatenate all fields
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(mr_td);
    concatenated.extend_from_slice(rt_mr0);
    concatenated.extend_from_slice(rt_mr1);
    concatenated.extend_from_slice(rt_mr2);
    concatenated.extend_from_slice(rt_mr3);
    concatenated.extend_from_slice(mr_config_id);
    concatenated.extend_from_slice(&xfam_bytes);
    concatenated.extend_from_slice(&td_attributes_bytes);

    // Compute keccak256 hash
    let mut hasher = Keccak256::new();
    hasher.update(&concatenated);
    let result = hasher.finalize();

    let mut workload_id = [0u8; 32];
    workload_id.copy_from_slice(&result);

    Ok(workload_id)
}

#[cfg(test)]
mod tests {
    use crate::tests::WORKLOAD_ID;

    use super::*;

    #[test]
    fn test_compute_workload_id_from_test_quote() {
        // Load the test quote output used in integration tests
        let quote_output = include_bytes!("../tests/framework/artifacts/test-quote.bin");

        // Compute the workload ID
        let workload_id = compute_workload_id(quote_output)
            .expect("failed to compute workload ID from test quote");

        assert_eq!(
            workload_id, WORKLOAD_ID,
            "workload ID mismatch for test quote"
        );
    }
}
