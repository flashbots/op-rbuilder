use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy_primitives::{map::foldhash::HashSet, Address};
use reth_payload_util::PayloadTransactions;
use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};
use tracing::debug;

use crate::tx::MaybeFlashblockFilter;

pub struct BestFlashblocksTxs<T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    invalid: HashSet<Address>,
    best: I,

    // The following two fields are for filtering based on a user-specified
    // flashblock range. If a user specifies a min flashblock number and we're
    // not at that number yet, store the transaction until we get there. The
    // key in the BTreeMap is the min flashblock number we need to wait until.
    current_flashblock_number: Arc<AtomicU64>,
    early_transactions: BTreeMap<u64, T>,
}

impl<T, I> BestFlashblocksTxs<T, I>
where
    T: PoolTransaction,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    /// Create a new `BestPayloadTransactions` with the given iterator.
    pub fn new(best: I, current_flashblock_number: Arc<AtomicU64>) -> Self {
        Self {
            invalid: Default::default(),
            best,
            current_flashblock_number,
            early_transactions: Default::default(),
        }
    }
}

impl<T, I> PayloadTransactions for BestFlashblocksTxs<T, I>
where
    T: PoolTransaction + MaybeFlashblockFilter,
    I: Iterator<Item = Arc<ValidPoolTransaction<T>>>,
{
    type Transaction = T;

    fn next(&mut self, _ctx: ()) -> Option<Self::Transaction> {
        loop {
            let flashblock_number = self.current_flashblock_number.load(Ordering::Relaxed);

            if let Some((min_flashblock_number, tx)) = self.early_transactions.first_key_value() {
                if *min_flashblock_number <= flashblock_number {
                    return Some(tx.clone());
                }
            }

            let tx = self.best.next()?;
            if self.invalid.contains(tx.sender_ref()) {
                continue;
            }

            let flashblock_number_min = tx.transaction.flashblock_number_min();
            let flashblock_number_max = tx.transaction.flashblock_number_max();

            if let Some(flashblock_number_min) = flashblock_number_min {
                if flashblock_number < flashblock_number_min {
                    self.early_transactions
                        .insert(flashblock_number_min, tx.transaction.clone());
                    continue;
                }
            }

            if let Some(flashblock_number_max) = flashblock_number_max {
                if flashblock_number > flashblock_number_max {
                    debug!(
                        target: "payload_builder",
                        message = "Considering transaction",
                        result = "FlashblockNumberMaxTooLow"
                    );
                    self.mark_invalid(*tx.sender_ref(), tx.nonce());
                    continue;
                }
            }

            return Some(tx.transaction.clone());
        }
    }

    fn mark_invalid(&mut self, sender: Address, _nonce: u64) {
        self.invalid.insert(sender);
    }
}
