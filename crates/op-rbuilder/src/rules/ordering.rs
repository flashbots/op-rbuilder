use crate::rules::{metrics::RulesMetrics, state::get_tx_score};
use reth_transaction_pool::{CoinbaseTipOrdering, PoolTransaction, Priority, TransactionOrdering};
use std::cmp::Ordering;

/// Composite priority: (rule-based score, effective tip per gas).
///
/// Higher score = higher priority. Equal scores fall back to the inner ordering
/// (delegated to `CoinbaseTipOrdering`).
///
/// Transactions without a cached score default to `score = 0`. Negative scores
/// are supported and will deprioritize transactions below unscored ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScorePriority<P>
where
    P: Ord + Clone,
{
    pub score: i64,
    pub effective_tip: Priority<P>,
}

impl<P: Ord + Clone> Default for ScorePriority<P> {
    fn default() -> Self {
        Self {
            score: 0,
            effective_tip: Priority::None,
        }
    }
}

impl<P: Ord + Clone> Ord for ScorePriority<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .cmp(&other.score)
            .then_with(|| self.effective_tip.cmp(&other.effective_tip))
    }
}

impl<P: Ord + Clone> PartialOrd for ScorePriority<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Transaction ordering that uses pre-computed scores from the global score cache.
///
/// Scores are inserted at validation time by [`RuleBasedValidator`] and looked up
/// here via [`get_tx_score`]. Transactions without a cached score get `score = 0`
/// and fall back to `CoinbaseTipOrdering` for tie-breaking.
///
/// Negative scores are supported: a transaction with `score < 0` will be ordered
/// below unscored transactions (`score = 0`), effectively deprioritizing it.
#[derive(Debug)]
pub struct ScoreOrdering<T> {
    inner: CoinbaseTipOrdering<T>,
    metrics: RulesMetrics,
}

impl<T> Default for ScoreOrdering<T> {
    fn default() -> Self {
        Self {
            inner: CoinbaseTipOrdering::<T>::default(),
            metrics: RulesMetrics::default(),
        }
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
    type PriorityValue =
        ScorePriority<<CoinbaseTipOrdering<T> as TransactionOrdering>::PriorityValue>;
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let score = match get_tx_score(transaction.hash()) {
            Some(s) => s,
            None => {
                self.metrics.record_score_cache_miss();
                0
            }
        };
        Priority::Value(ScorePriority {
            score,
            effective_tip: self.inner.priority(transaction, base_fee),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_priority_ordering() {
        let high_score: ScorePriority<u128> = ScorePriority {
            score: 100,
            effective_tip: Priority::Value(50),
        };
        let low_score: ScorePriority<u128> = ScorePriority {
            score: 10,
            effective_tip: Priority::Value(1000),
        };
        assert!(
            high_score > low_score,
            "higher score wins regardless of tip"
        );

        let same_score_high_tip: ScorePriority<u128> = ScorePriority {
            score: 50,
            effective_tip: Priority::Value(200),
        };
        let same_score_low_tip: ScorePriority<u128> = ScorePriority {
            score: 50,
            effective_tip: Priority::Value(100),
        };
        assert!(
            same_score_high_tip > same_score_low_tip,
            "equal score, higher tip wins"
        );

        let default: ScorePriority<u128> = ScorePriority::default();
        assert_eq!(default.score, 0);
        assert_eq!(default.effective_tip, Priority::None);
    }

    #[test]
    fn test_negative_score_deprioritized() {
        let unscored: ScorePriority<u128> = ScorePriority {
            score: 0,
            effective_tip: Priority::Value(100),
        };
        let negative: ScorePriority<u128> = ScorePriority {
            score: -50,
            effective_tip: Priority::Value(1000),
        };
        assert!(
            unscored > negative,
            "negative score is deprioritized below unscored (score=0)"
        );
    }
}
