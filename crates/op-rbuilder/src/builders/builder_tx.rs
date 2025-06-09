use reth_optimism_primitives::OpTransactionSigned;
use reth_primitives::Recovered;

pub trait BuilderTxBuilder {
    fn estimated_builder_tx_gas() -> u64;
    fn estimated_builder_tx_da_size() -> Option<u64>;
    fn signed_builder_tx() -> Result<Recovered<OpTransactionSigned>, secp256k1::Error>;
}

pub struct StandardBuilderTxBuilder;

impl BuilderTxBuilder for StandardBuilderTxBuilder {
    fn estimated_builder_tx_gas() -> u64 {
        todo!()
    }

    fn estimated_builder_tx_da_size() -> Option<u64> {
        todo!()
    }

    fn signed_builder_tx() -> Result<Recovered<OpTransactionSigned>, secp256k1::Error> {
        todo!()
    }
}