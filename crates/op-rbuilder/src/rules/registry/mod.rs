pub mod file;

use crate::rules::{config::default_refresh_interval, metrics::RulesMetrics, types::RuleSet};
use std::{sync::Arc, time::Instant};

/// Result of fetching rules from all registries.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// The merged ruleset from all successful fetches
    pub ruleset: RuleSet,
    /// Number of registries that succeeded
    pub success_count: usize,
    /// Number of registries that failed
    pub failure_count: usize,
    /// Error messages from failed registries
    pub errors: Vec<String>,
}

impl FetchResult {
    /// Returns true if all registries succeeded (no failures).
    pub fn is_success(&self) -> bool {
        self.failure_count == 0
    }
}

/// Trait for sources that can provide rulesets
#[async_trait::async_trait]
pub trait RuleRegistry: Send + Sync {
    /// Fetch the current ruleset from this registry
    async fn get_rules(&self) -> anyhow::Result<RuleSet>;

    /// Name for this registry
    fn name(&self) -> &str {
        "unknown"
    }
}

/// Aggregates rules from multiple registries and manages global ruleset state.
#[derive(Clone)]
pub struct RuleFetcher {
    registries: Vec<Arc<dyn RuleRegistry>>,
    metrics: RulesMetrics,
}

impl RuleFetcher {
    pub fn new() -> Self {
        Self {
            registries: Vec::new(),
            metrics: RulesMetrics::default(),
        }
    }

    /// Add a registry to fetch from
    pub fn add_registry(&mut self, registry: Arc<dyn RuleRegistry>) {
        self.registries.push(registry);
    }

    /// Fetch rules from all registries and merge them.
    ///
    /// Returns a `FetchResult` containing the merged ruleset and information about
    /// which registries succeeded or failed. Callers can use this to decide how
    /// to proceed (e.g., only update global state if all registries succeeded).
    pub async fn fetch_all(&self) -> FetchResult {
        let mut merged = RuleSet::new();
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut errors = Vec::new();

        for registry in &self.registries {
            let start = Instant::now();

            match registry.get_rules().await {
                Ok(ruleset) => {
                    let duration = start.elapsed();
                    merged.merge(&ruleset);
                    self.metrics.record_registry_fetch_success(duration);
                    success_count += 1;

                    tracing::info!(
                        source = registry.name(),
                        deny_rules = ruleset.rules.deny.len(),
                        boost_rules = ruleset.rules.boost.len(),
                        duration_ms = duration.as_millis(),
                        "Fetched rules from registry"
                    );
                }
                Err(e) => {
                    let duration = start.elapsed();
                    self.metrics.record_registry_fetch_failure(duration);
                    failure_count += 1;
                    errors.push(format!("{}: {}", registry.name(), e));

                    tracing::warn!(
                        source = registry.name(),
                        error = %e,
                        duration_ms = duration.as_millis(),
                        "Failed to fetch rules from registry"
                    );
                }
            }
        }

        FetchResult {
            ruleset: merged,
            success_count,
            failure_count,
            errors,
        }
    }

    /// Fetch rules and update global state.
    ///
    /// Returns the `FetchResult` containing the fetched ruleset and status information.
    /// The global ruleset is only updated if all registries succeeded (no failures).
    /// This prevents partial/corrupted rulesets from being applied.
    pub async fn refresh_global_ruleset(&self) -> FetchResult {
        use crate::rules::set_global_ruleset;

        self.refresh_ruleset_with(set_global_ruleset).await
    }

    /// Fetch rules and update a caller-provided global state target.
    ///
    /// The target setter is only invoked when all registries succeed.
    pub async fn refresh_ruleset_with<F>(&self, mut set_ruleset: F) -> FetchResult
    where
        F: FnMut(RuleSet),
    {
        let mut result = self.fetch_all().await;

        // Only update global ruleset if all registries succeeded
        if result.is_success() {
            let deny_count = result.ruleset.rules.deny.len();
            let boost_count = result.ruleset.rules.boost.len();

            // Pre-parse boost rule targets for faster matching
            result.ruleset.prepare();

            set_ruleset(result.ruleset.clone());
            self.metrics
                .update_rules_state(deny_count, boost_count, result.ruleset.hash);

            tracing::info!(
                deny_rules = deny_count,
                boost_rules = boost_count,
                ruleset_hash = ?result.ruleset.hash,
                "Global ruleset updated"
            );
        } else {
            tracing::warn!(
                success_count = result.success_count,
                failure_count = result.failure_count,
                errors = ?result.errors,
                "Not updating global ruleset due to registry failures"
            );
        }

        result
    }

    /// Start a background task that periodically refreshes rules.
    ///
    /// Call `refresh_global_ruleset()` before this if you need initial rules loaded synchronously.
    pub fn start_auto_refresh(self, refresh_interval_secs: u64) -> tokio::task::JoinHandle<()> {
        self.start_auto_refresh_with(refresh_interval_secs, crate::rules::set_global_ruleset)
    }

    /// Start a background task that periodically refreshes rules and applies to
    /// a caller-provided target setter.
    pub fn start_auto_refresh_with<F>(
        self,
        refresh_interval_secs: u64,
        mut set_ruleset: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnMut(RuleSet) + Send + 'static,
    {
        let refresh_interval_secs = if refresh_interval_secs == 0 {
            let default = default_refresh_interval();
            tracing::warn!(
                default_interval = default,
                "refresh_interval is 0, using default"
            );
            default
        } else {
            refresh_interval_secs
        };

        tokio::spawn(async move {
            self.metrics.set_registries_count(self.registries.len());

            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(refresh_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            tracing::info!(
                interval_secs = refresh_interval_secs,
                registries = self.registries.len(),
                "Rules auto-refresh task started"
            );

            loop {
                interval.tick().await;
                tracing::debug!("Refreshing rules from registries");
                self.refresh_ruleset_with(&mut set_ruleset).await;
            }
        })
    }
}

impl Default for RuleFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::types::compute_rule_hash;

    /// A test registry that returns a RuleSet with a predetermined hash.
    struct MockRegistry {
        name: String,
        yaml: String,
    }

    #[async_trait::async_trait]
    impl RuleRegistry for MockRegistry {
        async fn get_rules(&self) -> anyhow::Result<RuleSet> {
            let mut rs: RuleSet = serde_yaml::from_str(&self.yaml)?;
            rs.hash = Some(compute_rule_hash(self.yaml.as_bytes()));
            Ok(rs)
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[tokio::test]
    async fn test_fetch_all_merges_hashes() {
        let yaml_a = "version: 1\nrules:\n  deny: []\n  boost: []";
        let yaml_b = "version: 2\nrules:\n  deny: []\n  boost: []";

        let ha = compute_rule_hash(yaml_a.as_bytes());
        let hb = compute_rule_hash(yaml_b.as_bytes());

        let mut fetcher = RuleFetcher::new();
        fetcher.add_registry(Arc::new(MockRegistry {
            name: "a".into(),
            yaml: yaml_a.into(),
        }));
        fetcher.add_registry(Arc::new(MockRegistry {
            name: "b".into(),
            yaml: yaml_b.into(),
        }));

        let result = fetcher.fetch_all().await;
        assert!(result.is_success());
        assert_eq!(
            result.ruleset.hash,
            Some(compute_rule_hash(
                &[ha.to_be_bytes(), hb.to_be_bytes()].concat()
            ))
        );
    }
}
