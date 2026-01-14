//! Transaction pool validator that integrates rule checks and optional external validation.
//!
//! This validator wraps any base validator and adds custom ingress filtering in front of it. The
//! additional checks include rule-based deny lists backed by the shared global ruleset as well as
//! an optional HTTP call-out for bespoke validation logic.
//!
//! When validation succeeds, this validator also computes the transaction's rule-based score
//! and inserts it into the shared score index for O(k) block building.

use crate::rules::global_ruleset;
use crate::rules::metrics::RulesMetrics;
use crate::rules::score_index::SharedScoreIndex;
use alloy_consensus::Transaction as ConsensusTx;
use reqwest::Client;
use reth_primitives_traits::{Block, SealedBlock};
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    error::{InvalidPoolTransactionError, PoolTransactionError},
};
use std::{any::Any, fmt, time::{Duration, Instant}};
use tracing::{debug, trace, warn};

/// Rule-based transaction validator that applies ingress-phase rules and optional external checks.
///
/// This validator wraps `OpTransactionValidator` (or any other `TransactionValidator`) and adds:
/// 1. Optional rule-based deny checking backed by the shared global ruleset.
/// 2. Optional external validation hook.
///
/// Both checks happen before delegating to the wrapped validator. When rules are disabled or no
/// external validation is configured, the validator acts as a simple passthrough.
#[derive(Clone, Debug)]
pub struct RuleBasedValidator<V> {
    /// The wrapped validator (typically `OpTransactionValidator`).
    inner: V,
    /// HTTP client for external validation.
    client: Client,
    /// Metrics for rule-based validation.
    metrics: RulesMetrics,
    /// Shared score index for O(k) block building.
    /// When present, transaction scores are inserted at validation time.
    score_index: Option<SharedScoreIndex>,
}

impl<V> RuleBasedValidator<V> {
    /// Create a new rule-based validator without score indexing.
    ///
    /// Use [`with_score_index`] if you need O(k) block building with score-ordered iteration.
    pub fn new(inner: V) -> Self {
        Self::with_score_index(inner, None)
    }

    /// Create a new rule-based validator with optional score indexing.
    ///
    /// When `score_index` is provided, transaction scores are computed and stored
    /// at validation time, enabling O(k) block building via [`ScoreOrderedTransactions`].
    pub fn with_score_index(inner: V, score_index: Option<SharedScoreIndex>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("Failed to create HTTP client");
        Self {
            inner,
            client,
            metrics: RulesMetrics::default(),
            score_index,
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

    async fn validate_with_external_api<T>(&self, transaction: &T) -> Result<(), String>
    where
        T: PoolTransaction,
    {
        let ruleset = global_ruleset();
        let tx_hash = transaction.hash();
        let sender = transaction.sender();
        let nonce = transaction.nonce();

        let remote_endpoint_rules: Vec<_> = ruleset
            .rules
            .deny
            .iter()
            .filter_map(|rule| rule.remote_endpoint.as_ref().map(|config| (rule, config)))
            .collect();

        if remote_endpoint_rules.is_empty() {
            return Ok(());
        }

        for (rule, config) in remote_endpoint_rules {
            debug!(
                target: "rule_validator",
                tx_hash = %tx_hash,
                sender = %sender,
                endpoint = %config.endpoint,
                rule_name = ?rule.name,
                "Validating with external endpoint"
            );

            let tx_hash_str = tx_hash.to_string();
            let sender_str = sender.to_string();
            let nonce_str = nonce.to_string();
            let start = Instant::now();

            let response = self
                .client
                .get(&config.endpoint)
                .query(&[
                    ("tx_hash", tx_hash_str.as_str()),
                    ("sender", sender_str.as_str()),
                    ("nonce", nonce_str.as_str()),
                ])
                .timeout(Duration::from_millis(config.timeout))
                .send()
                .await;

            let duration = start.elapsed();

            match response {
                Ok(response) => {
                    if response.status().is_success() {
                        self.metrics.record_external_validation(true, false, duration);
                    } else {
                        self.metrics.record_external_validation(true, true, duration);
                        warn!(
                            target: "rule_validator",
                            tx_hash = %tx_hash,
                            endpoint = %config.endpoint,
                            status = %response.status(),
                            "External validation rejected"
                        );
                        return Err(format!(
                            "External validation failed: {} returned {}",
                            config.endpoint, response.status()
                        ));
                    }
                }
                Err(err) => {
                    self.metrics.record_external_validation(false, false, duration);
                    warn!(
                        target: "rule_validator",
                        tx_hash = %tx_hash,
                        endpoint = %config.endpoint,
                        error = %err,
                        allow_fail = config.allow_fail,
                        "External validation request failed"
                    );

                    if !config.allow_fail {
                        return Err(format!(
                            "External validation failed: {} (endpoint: {})",
                            err, config.endpoint
                        ));
                    }
                }
            }
        }

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
    /// - `false`: The transaction is temporarily invalid (e.g., external validation
    ///   service was unreachable). It may become valid later and can be retried.
    is_bad: bool,
}

impl RuleValidationError {
    fn new(message: impl Into<String>, is_bad: bool) -> Self {
        Self { message: message.into(), is_bad }
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
    V::Transaction: ConsensusTx,
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
                InvalidPoolTransactionError::other(RuleValidationError::new(e, true)),
            );
        }

        if let Err(e) = self.validate_with_external_api(&transaction).await {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(RuleValidationError::new(e, false)),
            );
        }

        // Compute score BEFORE delegating to inner validator, while we still have the transaction
        let ruleset = global_ruleset();
        let score_data = if self.score_index.is_some() && ruleset.has_scoring_rules() {
            let tx_hash = *transaction.hash();
            let sender = transaction.sender();
            let score = ruleset.score_transaction(&transaction);
            let tip = transaction.max_priority_fee_per_gas().unwrap_or(0);
            Some((tx_hash, sender, score, tip))
        } else {
            None
        };

        // Delegate to inner validator
        let outcome = self.inner.validate_transaction(origin, transaction).await;

        // If validation succeeded, insert score into the shared index
        // This enables O(k) block building by pre-scoring transactions at ingress
        if let TransactionValidationOutcome::Valid { .. } = outcome {
            if let (Some(score_index), Some((tx_hash, sender, score, tip))) =
                (&self.score_index, score_data)
            {
                score_index.write().upsert(tx_hash, sender, score, tip);

                trace!(
                    target: "rule_validator",
                    %tx_hash,
                    %sender,
                    score,
                    tip,
                    "Inserted transaction score into index"
                );
            }
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
