use crate::rules::global_ruleset;
use reth_transaction_pool::{PoolTransaction, Priority, TransactionOrdering};
use std::{cmp::Ordering, fmt::Debug, marker::PhantomData};

/// Composite priority: (rule-based score, effective tip per gas).
///
/// Higher score = higher priority. Equal scores break ties by effective tip.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScorePriority {
    pub score: i64,
    pub effective_tip: u128,
}

impl Ord for ScorePriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| self.effective_tip.cmp(&other.effective_tip))
    }
}

impl PartialOrd for ScorePriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Transaction ordering that integrates rule-based scoring directly into the pool.
///
/// On each call to `priority()`, reads the current global ruleset and computes
/// a composite score: (rule_score, effective_tip). When no scoring rules are
/// configured, all transactions get score=0 and ordering degrades gracefully
/// to tip-based (identical to `CoinbaseTipOrdering`).
///
/// The pool's `PendingPool` calls `priority()` when:
/// - A transaction is added (`add_transaction`)
/// - Base fee changes (`update_base_fee`) — which also re-scores with latest rules
#[derive(Debug)]
pub struct ScoreOrdering<T>(PhantomData<T>);

impl<T> Default for ScoreOrdering<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> Clone for ScoreOrdering<T> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<T> TransactionOrdering for ScoreOrdering<T>
where
    T: PoolTransaction + 'static,
{
    type PriorityValue = ScorePriority;
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let ruleset = global_ruleset();
        let score = if ruleset.has_scoring_rules() {
            ruleset.score_transaction(transaction)
        } else {
            0
        };

        let effective_tip = transaction.effective_tip_per_gas(base_fee).unwrap_or(0);

        Priority::Value(ScorePriority {
            score,
            effective_tip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_priority_ordering() {
        let high_score = ScorePriority {
            score: 100,
            effective_tip: 50,
        };
        let low_score = ScorePriority {
            score: 10,
            effective_tip: 1000,
        };
        assert!(
            high_score > low_score,
            "higher score wins regardless of tip"
        );

        let same_score_high_tip = ScorePriority {
            score: 50,
            effective_tip: 200,
        };
        let same_score_low_tip = ScorePriority {
            score: 50,
            effective_tip: 100,
        };
        assert!(
            same_score_high_tip > same_score_low_tip,
            "equal score, higher tip wins"
        );

        let default = ScorePriority::default();
        assert_eq!(
            default,
            ScorePriority {
                score: 0,
                effective_tip: 0
            }
        );
    }
}
