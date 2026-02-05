use crate::rules::state::get_tx_score;
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

/// Transaction ordering that uses pre-computed scores from the global score cache.
///
/// Scores are inserted at validation time by [`RuleBasedValidator`] and looked up
/// here via [`get_tx_score`]. Transactions without a cached score get score=0,
/// degrading to tip-based ordering (identical to `CoinbaseTipOrdering`).
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
        let score = get_tx_score(transaction.hash()).unwrap_or(0);
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
