//! Transaction pool validator that integrates rule checks.
//!
//! This validator wraps any base validator and adds custom ingress filtering in front of it. The
//! additional checks include rule-based deny lists backed by the shared global ruleset.

use crate::rules::{
    global_ruleset,
    metrics::RulesMetrics,
    state::{insert_tx_score, score_cache_len},
};
use reth_primitives_traits::{Block, SealedBlock};
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    error::{InvalidPoolTransactionError, PoolTransactionError},
};
use std::{any::Any, fmt};
use tracing::warn;

/// Rule-based transaction validator that applies ingress-phase rules.
///
/// This validator wraps `OpTransactionValidator` (or any other `TransactionValidator`) and adds
/// optional rule-based deny checking backed by the shared global ruleset.
///
/// The check happens before delegating to the wrapped validator. When rules are disabled,
/// the validator acts as a simple passthrough.
#[derive(Debug)]
pub struct RuleBasedValidator<V> {
    /// The wrapped validator (typically `OpTransactionValidator`).
    inner: V,
    /// Metrics for rule-based validation.
    metrics: RulesMetrics,
}

impl<V: Clone> Clone for RuleBasedValidator<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<V> RuleBasedValidator<V> {
    pub fn new(inner: V) -> Self {
        Self {
            inner,
            metrics: RulesMetrics::default(),
        }
    }

    fn validate_against_rules<T>(&self, transaction: &T) -> Result<(), String>
    where
        T: PoolTransaction,
    {
        let sender = transaction.sender();
        let kind = transaction.kind();
        let ruleset = global_ruleset();

        if ruleset.is_denied(&sender, &kind) {
            self.metrics.record_transaction_denied();
            warn!(
                target: "rule_validator",
                tx_hash = %transaction.hash(),
                sender = %sender,
                "Transaction denied by ingress rules"
            );
            return Err("Transaction denied by rules".to_string());
        }

        self.metrics.record_transaction_validated();
        Ok(())
    }
}

/// Error type for rule-based validation failures.
///
/// This error type implements `PoolTransactionError` to integrate with the
/// transaction pool's error handling.
#[derive(Debug)]
struct RuleValidationError {
    message: String,
    /// Whether this is a "bad" transaction that should never be retried.
    ///
    /// - `true`: The transaction is permanently invalid (e.g., sender is on deny list).
    ///   It should be discarded immediately and not re-validated later.
    /// - `false`: The transaction is temporarily invalid. It may become valid later
    ///   and can be retried.
    is_bad: bool,
}

impl RuleValidationError {
    fn new(message: impl Into<String>, is_bad: bool) -> Self {
        Self {
            message: message.into(),
            is_bad,
        }
    }
}

impl fmt::Display for RuleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RuleValidationError {}

impl PoolTransactionError for RuleValidationError {
    fn is_bad_transaction(&self) -> bool {
        self.is_bad
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<V> TransactionValidator for RuleBasedValidator<V>
where
    V: TransactionValidator,
{
    type Transaction = V::Transaction;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        if let Err(e) = self.validate_against_rules(&transaction) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(RuleValidationError::new(e, false)),
            );
        }

        let outcome = self.inner.validate_transaction(origin, transaction).await;

        if let TransactionValidationOutcome::Valid {
            transaction: ref valid_tx,
            ..
        } = outcome
        {
            let ruleset = global_ruleset();
            let tx = valid_tx.transaction();
            let tx_hash = *tx.hash();
            if ruleset.has_scoring_rules() {
                let score = ruleset.score_transaction(tx);
                insert_tx_score(tx_hash, score);
            } else {
                insert_tx_score(tx_hash, 0);
            }
            self.metrics.score_cache_size.set(score_cache_len() as f64);
        }

        outcome
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block)
    }
}
