use alloy::{sol, sol_types::SolError};
use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};

sol!(
    #[sol(rpc, abi)]
    interface IFlashtestationRegistry {
        function registerTEEService(bytes calldata rawQuote) external;
    }

    #[sol(rpc, abi)]
    interface IBlockBuilderPolicy {
        function verifyBlockBuilderProof(uint8 version, bytes32 blockContentHash) external;
    }

    struct BlockData {
        bytes32 parentHash;
        uint256 blockNumber;
        uint256 timestamp;
        bytes32[] transactionHashes;
    }

    type WorkloadId is bytes32;

    event TEEServiceRegistered(
        address teeAddress, WorkloadId workloadId, bytes rawQuote, bytes publicKey, bool alreadyExists
    );

    event BlockBuilderProofVerified(
        address caller, WorkloadId workloadId, uint256 blockNumber, uint8 version, bytes32 blockContentHash
    );

    // FlashtestationRegistry errors
    error InvalidQuote(bytes output);
    error TEEServiceAlreadyRegistered(address teeAddress, WorkloadId workloadId);
    error SenderMustMatchTEEAddress(address sender, address teeAddress);
    error InvalidTEEType(bytes4 teeType);
    error InvalidTEEVersion(uint16 version);
    error InvalidReportDataLength(uint256 length);
    error InvalidQuoteLength(uint256 length);

    // BlockBuilderPolicy errors
    error UnauthorizedBlockBuilder(address caller);
    error UnsupportedVersion(uint8 version);

    // EIP-712 permit errors
    error InvalidSignature();
    error InvalidNonce(uint256 expected, uint256 provided);
);

#[derive(Debug, thiserror::Error)]
pub enum FlashtestationRevertReason {
    #[error("flashtestation registry error: {0}")]
    FlashtestationRegistry(FlashtestationRegistryError),
    #[error("block builder policy error: {0}")]
    BlockBuilderPolicy(BlockBuilderPolicyError),
    #[error("halt: {0}")]
    Halt(String),
}

#[derive(Debug, thiserror::Error)]
pub enum FlashtestationRegistryError {
    #[error("invalid quote: {0}")]
    InvalidQuote(Bytes),
    #[error("tee address {0} already registered with workload id {1}")]
    TEEServiceAlreadyRegistered(Address, B256),
    #[error("sender address {0} must match quote tee address {1}")]
    SenderMustMatchTEEAddress(Address, Address),
    #[error("invalid tee type: {0}")]
    InvalidTEEType(FixedBytes<4>),
    #[error("invalid tee version: {0}")]
    InvalidTEEVersion(u16),
    #[error("invalid report data length: {0}")]
    InvalidReportDataLength(U256),
    #[error("invalid quote length: {0}")]
    InvalidQuoteLength(U256),
    #[error("invalid signature")]
    InvalidSignature(),
    #[error("invalid nonce: expected {0}, provided {1}")]
    InvalidNonce(U256, U256),
    #[error("unknown revert: {0}")]
    Unknown(String),
}

impl From<Bytes> for FlashtestationRegistryError {
    fn from(value: Bytes) -> Self {
        // Empty revert
        if value.is_empty() {
            return FlashtestationRegistryError::Unknown(
                "Transaction reverted without reason".to_string(),
            );
        }

        // Try to decode each custom error type
        if let Ok(InvalidQuote { output }) = InvalidQuote::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidQuote(output);
        }

        if let Ok(TEEServiceAlreadyRegistered {
            teeAddress,
            workloadId,
        }) = TEEServiceAlreadyRegistered::abi_decode(&value)
        {
            return FlashtestationRegistryError::TEEServiceAlreadyRegistered(
                teeAddress, workloadId,
            );
        }

        if let Ok(SenderMustMatchTEEAddress { sender, teeAddress }) =
            SenderMustMatchTEEAddress::abi_decode(&value)
        {
            return FlashtestationRegistryError::SenderMustMatchTEEAddress(sender, teeAddress);
        }

        if let Ok(InvalidTEEType { teeType }) = InvalidTEEType::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidTEEType(teeType);
        }

        if let Ok(InvalidTEEVersion { version }) = InvalidTEEVersion::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidTEEVersion(version);
        }

        if let Ok(InvalidReportDataLength { length }) = InvalidReportDataLength::abi_decode(&value)
        {
            return FlashtestationRegistryError::InvalidReportDataLength(length);
        }

        if let Ok(InvalidQuoteLength { length }) = InvalidQuoteLength::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidQuoteLength(length);
        }

        if let Ok(InvalidSignature {}) = InvalidSignature::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidSignature();
        }

        if let Ok(InvalidNonce { expected, provided }) = InvalidNonce::abi_decode(&value) {
            return FlashtestationRegistryError::InvalidNonce(expected, provided);
        }

        FlashtestationRegistryError::Unknown(hex::encode(value))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockBuilderPolicyError {
    #[error("unauthorized block builder: {0}")]
    UnauthorizedBlockBuilder(Address),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid signature")]
    InvalidSignature(),
    #[error("invalid nonce: expected {0}, provided {1}")]
    InvalidNonce(U256, U256),
    #[error("unknown revert: {0}")]
    Unknown(String),
}

impl From<Bytes> for BlockBuilderPolicyError {
    fn from(value: Bytes) -> Self {
        // Empty revert
        if value.is_empty() {
            return BlockBuilderPolicyError::Unknown(
                "Transaction reverted without reason".to_string(),
            );
        }

        // Try to decode each custom error type
        if let Ok(UnauthorizedBlockBuilder { caller }) =
            UnauthorizedBlockBuilder::abi_decode(&value)
        {
            return BlockBuilderPolicyError::UnauthorizedBlockBuilder(caller);
        }

        if let Ok(UnsupportedVersion { version }) = UnsupportedVersion::abi_decode(&value) {
            return BlockBuilderPolicyError::UnsupportedVersion(version);
        }

        if let Ok(InvalidSignature {}) = InvalidSignature::abi_decode(&value) {
            return BlockBuilderPolicyError::InvalidSignature();
        }

        if let Ok(InvalidNonce { expected, provided }) = InvalidNonce::abi_decode(&value) {
            return BlockBuilderPolicyError::InvalidNonce(expected, provided);
        }

        BlockBuilderPolicyError::Unknown(hex::encode(value))
    }
}

pub mod args;
pub mod attestation;
pub mod builder_tx;
pub mod service;
pub mod tx_manager;
