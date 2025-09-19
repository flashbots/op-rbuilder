use alloy_sol_types::sol;
use op_revm::OpHaltReason;

sol!(
    #[sol(rpc, abi)]
    interface IFlashtestationRegistry {
        function registerTEEService(bytes calldata rawQuote, bytes calldata extendedRegistrationData) external;
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

    event TEEServiceRegistered(address teeAddress, bytes rawQuote, bool alreadyExists);

    event BlockBuilderProofVerified(
        address caller,
        WorkloadId workloadId,
        uint256 blockNumber,
        uint8 version,
        bytes32 blockContentHash,
        string commit_hash
    );

    #[derive(Debug, PartialEq, Eq)]
    library FlashtestationRegistryError {
        error InvalidQuote(bytes output);
        error TEEServiceAlreadyRegistered(address teeAddress);
        error InvalidRegistrationDataHash(bytes32 expected, bytes32 received);
        error ByteSizeExceeded(uint256 size);
        error SenderMustMatchTEEAddress(address sender, address teeAddress);
        error InvalidTEEType(bytes4 teeType);
        error InvalidTEEVersion(uint16 version);
        error InvalidReportDataLength(uint256 length);
        error InvalidQuoteLength(uint256 length);
        error InvalidSignature();
        error InvalidNonce(uint256 expected, uint256 provided);
    }

    #[derive(Debug, PartialEq, Eq)]
    library BlockBuilderPolicyError {
        error UnauthorizedBlockBuilder(address caller);
        error UnsupportedVersion(uint8 version);
        error InvalidSignature();
        error InvalidNonce(uint256 expected, uint256 provided);
    }
);

#[derive(Debug, derive_more::From)]
pub enum FlashtestationRevertReason {
    FlashtestationRegistry(FlashtestationRegistryError::FlashtestationRegistryErrorErrors),
    BlockBuilderPolicy(BlockBuilderPolicyError::BlockBuilderPolicyErrorErrors),
    Halt(OpHaltReason),
}

pub mod args;
pub mod attestation;
pub mod builder_tx;
pub mod service;
pub mod tx_manager;
