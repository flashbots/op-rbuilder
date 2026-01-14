use std::sync::Arc;

use alloy_consensus::Transaction as ConsensusTx;
use alloy_primitives::Address;
use reth_payload_util::PayloadTransactions;
use reth_transaction_pool::PoolTransaction;

use crate::rules::RuleSet;

/// Wrapper over an inner `PayloadTransactions` iterator that scores and reorders
/// transactions according to the ruleset's sorting rules
pub struct ScoredPayloadTransactions<T, I> {
    inner: I,
    rule_set: Arc<RuleSet>,
    ordered: Vec<T>,
}

impl<T, I> ScoredPayloadTransactions<T, I> {
    pub fn new(inner: I, rule_set: Arc<RuleSet>) -> Self {
        Self {
            inner,
            rule_set,
            ordered: Vec::new(),
        }
    }
}

impl<T, I> PayloadTransactions for ScoredPayloadTransactions<T, I>
where
    T: PoolTransaction + Clone,
    T::Consensus: ConsensusTx,
    I: PayloadTransactions<Transaction = T>,
{
    type Transaction = T;

    fn next(&mut self, ctx: ()) -> Option<Self::Transaction> {
        if !self.rule_set.has_scoring_rules() {
            return self.inner.next(ctx);
        }

        if self.ordered.is_empty() {
            let mut items: Vec<T> = Vec::new();
            while let Some(tx) = self.inner.next(ctx) {
                items.push(tx);
            }

            self.ordered = self.rule_set.sort_transactions(items);
            self.ordered.reverse();
        }

        self.ordered.pop()
    }

    fn mark_invalid(&mut self, sender: Address, nonce: u64) {
        self.inner.mark_invalid(sender, nonce)
    }
}
