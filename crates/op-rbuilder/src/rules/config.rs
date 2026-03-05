//! Txpool policy configuration.
//!
//! Defines independent regime selection for ingress filtering and transaction
//! ordering. Each regime owns its own parameter set.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level txpool policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TxPoolPolicyConfig {
    /// Ingress validation regime.
    #[serde(default)]
    pub ingress: IngressRegimeConfig,
    /// Transaction ordering regime.
    #[serde(default)]
    pub ordering: OrderingRegimeConfig,
}

impl TxPoolPolicyConfig {
    /// Load configuration from a YAML file.
    pub async fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let content = tokio::fs::read_to_string(&path).await?;
        let config: TxPoolPolicyConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

/// Ingress filtering regime.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IngressRegimeConfig {
    /// Allow all transactions through to base validator.
    #[default]
    AllowAll,
    /// Deny transactions matching configured rules.
    DenyRules {
        /// Rule sources for ingress deny matching.
        #[serde(default)]
        sources: RuleSourcesConfig,
    },
}

impl IngressRegimeConfig {
    pub fn uses_rules(&self) -> bool {
        matches!(self, Self::DenyRules { .. })
    }

    pub fn sources(&self) -> Option<&RuleSourcesConfig> {
        match self {
            Self::AllowAll => None,
            Self::DenyRules { sources } => Some(sources),
        }
    }
}

/// Tx ordering regime.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OrderingRegimeConfig {
    /// Order by priority fee only.
    #[default]
    PriorityFee,
    /// Order by (boost score, priority fee).
    PriorityFeeWithBoost {
        /// Rule sources for boost scoring.
        #[serde(default)]
        sources: RuleSourcesConfig,
        /// Score used when no cached score exists.
        #[serde(default = "default_unscored_score")]
        unscored_score: i64,
    },
}

impl OrderingRegimeConfig {
    pub fn uses_scoring(&self) -> bool {
        matches!(self, Self::PriorityFeeWithBoost { .. })
    }

    pub fn sources(&self) -> Option<&RuleSourcesConfig> {
        match self {
            Self::PriorityFee => None,
            Self::PriorityFeeWithBoost { sources, .. } => Some(sources),
        }
    }

    pub fn unscored_score(&self) -> i64 {
        match self {
            Self::PriorityFee => 0,
            Self::PriorityFeeWithBoost { unscored_score, .. } => *unscored_score,
        }
    }
}

/// Configuration for a collection of rule registries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourcesConfig {
    /// File-based rule registries.
    #[serde(default)]
    pub file: Vec<FileRegistryConfig>,
    /// Interval in seconds for refreshing rules from registries (defaults to 60).
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
}

impl RuleSourcesConfig {
    pub fn is_empty(&self) -> bool {
        self.file.is_empty()
    }

    /// Build a RuleFetcher from this source configuration.
    pub fn build_fetcher(&self) -> crate::rules::registry::RuleFetcher {
        use crate::rules::registry::{RuleFetcher, file::FileRuleRegistry};
        use std::sync::Arc;

        let mut fetcher = RuleFetcher::new();

        for file_config in &self.file {
            if !file_config.enabled {
                tracing::debug!(
                    path = ?file_config.path,
                    "Skipping disabled file registry"
                );
                continue;
            }

            let registry = FileRuleRegistry::new(&file_config.path);
            tracing::info!(
                path = ?file_config.path,
                name = ?file_config.name,
                "Added file registry"
            );
            fetcher.add_registry(Arc::new(registry));
        }

        fetcher
    }
}

impl Default for RuleSourcesConfig {
    fn default() -> Self {
        Self {
            file: Vec::new(),
            refresh_interval: default_refresh_interval(),
        }
    }
}

/// Configuration for a file-based rule registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRegistryConfig {
    /// Path to the YAML file containing rules.
    pub path: PathBuf,
    /// Optional name for this registry (defaults to file path).
    #[serde(default)]
    pub name: Option<String>,
    /// Whether this registry is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_unscored_score() -> i64 {
    0
}

/// Default refresh interval for rule registries (60 seconds).
pub fn default_refresh_interval() -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults() {
        let config: TxPoolPolicyConfig = serde_yaml::from_str("").unwrap();
        assert!(matches!(config.ingress, IngressRegimeConfig::AllowAll));
        assert!(matches!(config.ordering, OrderingRegimeConfig::PriorityFee));
    }

    #[test]
    fn parse_regimes_with_independent_sources() {
        let yaml = r#"
ingress:
  type: deny_rules
  sources:
    refresh_interval: 30
    file:
      - path: /rules/deny.yaml
ordering:
  type: priority_fee_with_boost
  sources:
    file:
      - path: /rules/boost.yaml
  unscored_score: -5
"#;
        let config: TxPoolPolicyConfig = serde_yaml::from_str(yaml).unwrap();

        let ingress_sources = config.ingress.sources().unwrap();
        assert_eq!(ingress_sources.refresh_interval, 30);
        assert_eq!(ingress_sources.file.len(), 1);

        let ordering_sources = config.ordering.sources().unwrap();
        assert_eq!(ordering_sources.refresh_interval, 60);
        assert_eq!(ordering_sources.file.len(), 1);
        assert_eq!(config.ordering.unscored_score(), -5);
    }

    #[test]
    fn parse_file_registry_defaults() {
        let yaml = r#"
ingress:
  type: deny_rules
  sources:
    file:
      - path: /rules/deny.yaml
"#;
        let config: TxPoolPolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let sources = config.ingress.sources().unwrap();
        assert_eq!(sources.file.len(), 1);
        assert!(sources.file[0].enabled);
        assert_eq!(sources.file[0].name, None);
    }

    #[test]
    fn parse_rejects_unknown_regime() {
        let yaml = r#"
ordering:
  type: made_up_mode
"#;
        let parsed: Result<TxPoolPolicyConfig, _> = serde_yaml::from_str(yaml);
        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn load_config_from_file() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_txpool_policy.yaml");
        let yaml = r#"
ingress:
  type: allow_all
ordering:
  type: priority_fee
"#;

        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let config = TxPoolPolicyConfig::load(&config_path).await.unwrap();
        assert!(matches!(config.ingress, IngressRegimeConfig::AllowAll));
        assert!(matches!(config.ordering, OrderingRegimeConfig::PriorityFee));

        std::fs::remove_file(&config_path).ok();
    }
}
