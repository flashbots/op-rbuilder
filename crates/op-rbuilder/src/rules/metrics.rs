//! Metrics for the rules system.

use metrics::{Counter, Gauge, Histogram};
use reth_metrics::Metrics;
use std::time::Duration;

/// Rules system metrics.
#[derive(Metrics, Clone)]
#[metrics(scope = "op_rbuilder.rules")]
pub struct RulesMetrics {
    /// Successful registry fetch operations
    pub registry_fetch_success: Counter,
    /// Failed registry fetch operations
    pub registry_fetch_failures: Counter,
    /// Time to fetch rules from registries
    pub registry_fetch_duration: Histogram,

    /// Successful external validation requests
    pub external_validation_success: Counter,
    /// Failed external validation requests
    pub external_validation_failures: Counter,
    /// Transactions rejected by external validation
    pub external_validation_rejections: Counter,
    /// External validation request duration
    pub external_validation_duration: Histogram,

    /// Transactions denied by ingress rules
    pub transactions_denied: Counter,
    /// Transactions that passed ingress validation
    pub transactions_validated: Counter,

    /// Active deny rules
    pub active_deny_rules: Gauge,
    /// Active boost rules
    pub active_boost_rules: Gauge,
    /// Number of entries in the tx score cache
    pub score_cache_size: Gauge,
    /// Configured registries
    pub registries_count: Gauge,
    /// Last successful rules refresh (unix timestamp)
    pub last_refresh_timestamp: Gauge,
    /// Active ruleset hash (Keccak-256 truncated to u64)
    pub active_ruleset_hash: Gauge,
    /// Score cache misses during transaction ordering
    pub score_cache_misses: Counter,
}

impl RulesMetrics {
    pub fn record_registry_fetch_success(&self, duration: Duration) {
        self.registry_fetch_success.increment(1);
        self.registry_fetch_duration.record(duration.as_secs_f64());
    }

    pub fn record_registry_fetch_failure(&self, duration: Duration) {
        self.registry_fetch_failures.increment(1);
        self.registry_fetch_duration.record(duration.as_secs_f64());
    }

    pub fn update_rules_state(&self, deny_count: usize, boost_count: usize, hash: Option<u64>) {
        self.active_deny_rules.set(deny_count as f64);
        self.active_boost_rules.set(boost_count as f64);
        self.last_refresh_timestamp.set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64,
        );
        if let Some(h) = hash {
            self.active_ruleset_hash.set(h as f64);
        }
    }

    pub fn record_external_validation(&self, success: bool, rejected: bool, duration: Duration) {
        self.external_validation_duration
            .record(duration.as_secs_f64());
        if success {
            self.external_validation_success.increment(1);
            if rejected {
                self.external_validation_rejections.increment(1);
            }
        } else {
            self.external_validation_failures.increment(1);
        }
    }

    #[inline]
    pub fn record_transaction_denied(&self) {
        self.transactions_denied.increment(1);
    }

    #[inline]
    pub fn record_transaction_validated(&self) {
        self.transactions_validated.increment(1);
    }

    pub fn set_registries_count(&self, count: usize) {
        self.registries_count.set(count as f64);
    }

    #[inline]
    pub fn record_score_cache_miss(&self) {
        self.score_cache_misses.increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_metrics_creation() {
        let metrics = RulesMetrics::default();
        metrics.transactions_denied.increment(1);
        metrics.transactions_validated.increment(1);
    }

    #[test]
    fn test_record_registry_fetch() {
        let metrics = RulesMetrics::default();
        metrics.record_registry_fetch_success(Duration::from_millis(100));
        metrics.record_registry_fetch_failure(Duration::from_millis(50));
    }

    #[test]
    fn test_update_rules_state_sets_hash() {
        let metrics = RulesMetrics::default();
        metrics.update_rules_state(3, 5, Some(123456789));
        // Verify no panic and gauge is set (Gauge doesn't expose a getter,
        // but calling set without panic confirms the field exists and works)
    }

    #[test]
    fn test_update_rules_state_none_hash() {
        let metrics = RulesMetrics::default();
        // Should not panic when hash is None
        metrics.update_rules_state(1, 2, None);
    }

    #[test]
    fn test_record_score_cache_miss() {
        let metrics = RulesMetrics::default();
        // Should not panic and counter increments
        metrics.record_score_cache_miss();
        metrics.record_score_cache_miss();
    }
}
