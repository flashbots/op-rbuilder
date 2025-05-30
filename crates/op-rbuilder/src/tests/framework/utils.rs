use alloy_eips::Encodable2718;
use alloy_primitives::{hex, Address, TxKind, B256, U256};
use alloy_rpc_types_eth::{Block, BlockTransactionHashes};
use core::future::Future;
use op_alloy_consensus::{OpTypedTransaction, TxDeposit};
use op_alloy_rpc_types::Transaction;

use crate::{tests::ONE_ETH, tx_signer::Signer};

use super::{TransactionBuilder, FUNDED_PRIVATE_KEYS};

pub trait TransactionBuilderExt {
    fn random_valid_transfer(self) -> Self;
    fn random_reverting_transaction(self) -> Self;
}

impl TransactionBuilderExt for TransactionBuilder {
    fn random_valid_transfer(self) -> Self {
        self.with_to(rand::random::<Address>()).with_value(1)
    }

    fn random_reverting_transaction(self) -> Self {
        self.with_create().with_input(hex!("60006000fd").into()) // PUSH1 0x00 PUSH1 0x00 REVERT
    }
}

pub trait ChainDriverExt {
    fn fund_default_accounts(&self) -> impl Future<Output = eyre::Result<()>>;
    fn fund(&self, address: Address, amount: u128) -> impl Future<Output = eyre::Result<()>>;
    fn first_funded_address(&self) -> Address {
        FUNDED_PRIVATE_KEYS[0]
            .parse()
            .expect("Invalid funded private key")
    }

    fn fund_accounts(
        &self,
        count: usize,
        amount: u128,
    ) -> impl Future<Output = eyre::Result<Vec<Signer>>> {
        async move {
            let accounts = (0..count).map(|_| Signer::random()).collect::<Vec<_>>();

            for account in &accounts {
                self.fund(account.address, amount).await?;
            }

            Ok(accounts)
        }
    }
}

impl ChainDriverExt for super::ChainDriver {
    async fn fund_default_accounts(&self) -> eyre::Result<()> {
        for key in FUNDED_PRIVATE_KEYS {
            let signer: Signer = key.parse()?;
            self.fund(signer.address, ONE_ETH).await?;
        }
        Ok(())
    }

    async fn fund(&self, address: Address, amount: u128) -> eyre::Result<()> {
        let deposit = TxDeposit {
            source_hash: B256::default(),
            from: address, // Set the sender to the address of the account to seed
            to: TxKind::Create,
            mint: Some(amount), // Amount to deposit
            value: U256::default(),
            gas_limit: 210000,
            is_system_transaction: false,
            input: Default::default(), // No input data for the deposit
        };

        let signer = Signer::random();
        let signed_tx = signer.sign_tx(OpTypedTransaction::Deposit(deposit))?;
        let signed_tx_rlp = signed_tx.encoded_2718();
        self.build_new_block_with_txs(vec![signed_tx_rlp.into()])
            .await?;
        Ok(())
    }
}

pub trait BlockTransactionsExt {
    fn includes(&self, tx_hash: &B256) -> bool;
}

impl BlockTransactionsExt for Block<Transaction> {
    fn includes(&self, tx_hash: &B256) -> bool {
        self.transactions.hashes().any(|tx| tx == *tx_hash)
    }
}

impl<'a> BlockTransactionsExt for BlockTransactionHashes<'a, Transaction> {
    fn includes(&self, tx_hash: &B256) -> bool {
        let mut iter = self.clone();
        iter.any(|tx| tx == *tx_hash)
    }
}

pub trait OpRbuilderArgsTestExt {
    fn test_default() -> Self;
}

impl OpRbuilderArgsTestExt for crate::args::OpRbuilderArgs {
    fn test_default() -> Self {
        let mut default = Self::default();
        default.flashblocks.flashblocks_port = 0; // randomize port
        default
    }
}
