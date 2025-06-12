use alloy_primitives::Address;

/// Parameters for Flashtestations configuration
/// The names in the struct are prefixed with `flashtestations`
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct FlashtestationsArgs {
    /// When set to true, the builder will initiate the flashtestations
    /// workflow within the bootstrapping and block building process.
    #[arg(
        long = "flashtestations.enabled",
        default_value = "false",
        env = "ENABLE_FLASHTESTATIONS"
    )]
    pub flashtestations_enabled: bool,

    /// Whether to use the debug HTTP service for quotes
    #[arg(
        long = "flashtestations.debug",
        default_value = "false",
        env = "FLASHTESTATIONS_DEBUG"
    )]
    pub debug: bool,

    /// flashtestations debug url
    #[arg(long = "flashtestations.debug-url", env = "FLASHTESTATIONS_DEBUG_URL")]
    pub debug_url: Option<String>,

    /// The rpc url to post the onchain attestation requests to
    #[arg(
        long = "flashtestations.rpc-url",
        env = "FLASHTESTATIONS_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub rpc_url: String,

    /// The address of the flashtestations registry contract
    #[arg(
        long = "flashtestations.registry-address",
        env = "FLASHTESTATIONS_REGISTRY_ADDRESS",
        default_value = "0x0000000000000000000000000000000000000000"
    )]
    pub registry_address: Address,

    /// The address of the builder policy contract
    #[arg(
        long = "flashtestations.builder-policy-address",
        env = "FLASHTESTATIONS_BUILDER_POLICY_ADDRESS",
        default_value = "0x0000000000000000000000000000000000000000"
    )]
    pub builder_policy_address: Address,

    /// The version of the block builder verification proof
    #[arg(
        long = "flashtestations.builder-proof-version",
        env = "FLASHTESTATIONS_BUILDER_PROOF_VERSION",
        default_value = "1"
    )]
    pub builder_proof_version: u8,
}
