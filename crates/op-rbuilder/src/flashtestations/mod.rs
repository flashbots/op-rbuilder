use alloy::sol;

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

    event TEEServiceRegistered(
        address teeAddress, bytes32 workloadId, bytes rawQuote, bytes publicKey, bool alreadyExists
    );
);

pub mod args;
pub mod attestation;
pub mod builder_tx;
pub mod service;
pub mod tx_manager;
