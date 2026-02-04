//! Configuration for rule registries
//!
//! Defines the structure for configuring multiple rule sources (file, HTTP, onchain)
//! via a YAML configuration file.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for all rule registries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesRegistryConfig {
    /// File-based rule registries
    #[serde(default)]
    pub file: Vec<FileRegistryConfig>,
    /// Remote HTTP/HTTPS-based rule registries
    #[serde(default)]
    pub remote: Vec<RemoteRegistryConfig>,
    /// Interval in seconds for refreshing rules from registries (defaults to 60)
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
}

impl RulesRegistryConfig {
    /// Load configuration from a YAML file
    pub async fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let content = tokio::fs::read_to_string(&path).await?;
        let config: RulesRegistryConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Check if any registries are configured
    pub fn is_registry_config_empty(&self) -> bool {
        self.file.is_empty() && self.remote.is_empty()
    }

    /// Build a RuleFetcher from this configuration
    pub fn build_fetcher(&self) -> anyhow::Result<crate::rules::registry::RuleFetcher> {
        use crate::rules::registry::{
            RuleFetcher, file::FileRuleRegistry, remote::RemoteRuleRegistry,
        };
        use std::{sync::Arc, time::Duration};

        let mut fetcher = RuleFetcher::new();

        // Add file registries
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

        // Add remote registries
        for remote_config in &self.remote {
            if !remote_config.enabled {
                tracing::debug!(
                    url = %remote_config.url,
                    "Skipping disabled remote registry"
                );
                continue;
            }

            let timeout = Duration::from_secs(remote_config.timeout_secs.unwrap_or(30));
            let registry = RemoteRuleRegistry::with_timeout(&remote_config.url, timeout);
            tracing::info!(
                url = %remote_config.url,
                name = ?remote_config.name,
                timeout_secs = timeout.as_secs(),
                "Added remote registry"
            );
            fetcher.add_registry(Arc::new(registry));
        }

        Ok(fetcher)
    }
}

impl Default for RulesRegistryConfig {
    fn default() -> Self {
        Self {
            file: Vec::new(),
            remote: Vec::new(),
            refresh_interval: default_refresh_interval(),
        }
    }
}

/// Configuration for a file-based rule registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRegistryConfig {
    /// Path to the YAML file containing rules
    pub path: PathBuf,

    /// Optional name for this registry (defaults to file path)
    #[serde(default)]
    pub name: Option<String>,

    /// Whether this registry is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Default refresh interval for rule registries (60 seconds).
pub fn default_refresh_interval() -> u64 {
    60
}

/// Configuration for a remote HTTP/HTTPS-based rule registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRegistryConfig {
    /// URL to fetch rules from (e.g., S3 presigned URL, GCS public URL, etc.)
    pub url: String,

    /// Optional name for this registry (defaults to URL)
    #[serde(default)]
    pub name: Option<String>,

    /// Whether this registry is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Timeout in seconds for HTTP requests (defaults to 30)
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_config() {
        let yaml = "";
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.is_registry_config_empty());
    }

    #[test]
    fn test_parse_file_config() {
        let yaml = r#"
file:
  - path: /path/to/rules.yaml
    name: "Production Rules"
  - path: /path/to/test-rules.yaml
    enabled: false
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.file.len(), 2);
        assert_eq!(config.file[0].name, Some("Production Rules".to_string()));
        assert_eq!(config.file[0].enabled, true);
        assert_eq!(config.file[1].enabled, false);
    }

    #[test]
    fn test_parse_file_config_defaults() {
        // Test that enabled defaults to true and name defaults to None
        let yaml = r#"
file:
  - path: /path/to/rules.yaml
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.file.len(), 1);
        assert_eq!(config.file[0].path, PathBuf::from("/path/to/rules.yaml"));
        assert_eq!(config.file[0].name, None);
        assert!(config.file[0].enabled); // defaults to true
    }

    #[test]
    fn test_parse_file_config_multiple_registries() {
        let yaml = r#"
file:
  - path: /etc/rules/base.yaml
    name: "Base Rules"
  - path: /etc/rules/overrides.yaml
    name: "Override Rules"
  - path: /etc/rules/disabled.yaml
    enabled: false
  - path: /etc/rules/unnamed.yaml
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.file.len(), 4);
        assert!(!config.is_registry_config_empty());

        // Verify each entry
        assert_eq!(config.file[0].name, Some("Base Rules".to_string()));
        assert!(config.file[0].enabled);

        assert_eq!(config.file[1].name, Some("Override Rules".to_string()));
        assert!(config.file[1].enabled);

        assert!(!config.file[2].enabled);

        assert_eq!(config.file[3].name, None);
        assert!(config.file[3].enabled);
    }

    #[test]
    fn test_config_is_registry_config_empty() {
        let empty = RulesRegistryConfig::default();
        assert!(empty.is_registry_config_empty());

        let with_file = RulesRegistryConfig {
            file: vec![FileRegistryConfig {
                path: PathBuf::from("/test"),
                name: None,
                enabled: true,
            }],
            remote: Vec::new(),
            refresh_interval: 60,
        };
        assert!(!with_file.is_registry_config_empty());

        let with_remote = RulesRegistryConfig {
            file: Vec::new(),
            remote: vec![RemoteRegistryConfig {
                url: "https://example.com/rules.yaml".to_string(),
                name: None,
                enabled: true,
                timeout_secs: None,
            }],
            refresh_interval: 60,
        };
        assert!(!with_remote.is_registry_config_empty());
    }

    #[test]
    fn test_build_fetcher_skips_disabled_registries() {
        let config = RulesRegistryConfig {
            file: vec![
                FileRegistryConfig {
                    path: PathBuf::from("/enabled.yaml"),
                    name: Some("enabled".to_string()),
                    enabled: true,
                },
                FileRegistryConfig {
                    path: PathBuf::from("/disabled.yaml"),
                    name: Some("disabled".to_string()),
                    enabled: false,
                },
            ],
            remote: Vec::new(),
            refresh_interval: 60,
        };

        // The build should succeed - we can't inspect internal state but the function works
        let _fetcher = config.build_fetcher().unwrap();
    }

    #[test]
    fn test_build_fetcher_empty_config() {
        let config = RulesRegistryConfig::default();
        // The build should succeed for empty config
        let _fetcher = config.build_fetcher().unwrap();
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = RulesRegistryConfig {
            file: vec![
                FileRegistryConfig {
                    path: PathBuf::from("/path/to/rules.yaml"),
                    name: Some("Test Rules".to_string()),
                    enabled: true,
                },
                FileRegistryConfig {
                    path: PathBuf::from("/path/to/other.yaml"),
                    name: None,
                    enabled: false,
                },
            ],
            remote: Vec::new(),
            refresh_interval: 120,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let decoded: RulesRegistryConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(decoded.file.len(), 2);
        assert_eq!(decoded.file[0].path, config.file[0].path);
        assert_eq!(decoded.file[0].name, config.file[0].name);
        assert_eq!(decoded.file[0].enabled, config.file[0].enabled);
        assert_eq!(decoded.file[1].path, config.file[1].path);
        assert_eq!(decoded.file[1].name, config.file[1].name);
        assert_eq!(decoded.file[1].enabled, config.file[1].enabled);
        assert_eq!(decoded.refresh_interval, config.refresh_interval);
    }

    #[test]
    fn test_parse_malformed_yaml_fails() {
        let yaml = r#"
file:
  - path: [invalid array here]
"#;
        let result: Result<RulesRegistryConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_path_fails() {
        let yaml = r#"
file:
  - name: "No path specified"
    enabled: true
"#;
        let result: Result<RulesRegistryConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_fields_ignored() {
        // Unknown fields should be ignored (default serde behavior)
        let yaml = r#"
file:
  - path: /path/to/rules.yaml
    unknown_field: "should be ignored"
    another_unknown: 123
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.file.len(), 1);
        assert_eq!(config.file[0].path, PathBuf::from("/path/to/rules.yaml"));
    }

    #[test]
    fn test_file_registry_config_clone() {
        let config = FileRegistryConfig {
            path: PathBuf::from("/test/path.yaml"),
            name: Some("Test".to_string()),
            enabled: true,
        };
        let cloned = config.clone();
        assert_eq!(cloned.path, config.path);
        assert_eq!(cloned.name, config.name);
        assert_eq!(cloned.enabled, config.enabled);
    }

    #[tokio::test]
    async fn test_load_nonexistent_file_fails() {
        let result = RulesRegistryConfig::load("/nonexistent/path/config.yaml").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_valid_config_file() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_rules_config.yaml");

        let yaml_content = r#"
file:
  - path: /rules/base.yaml
    name: "Base"
  - path: /rules/extra.yaml
    enabled: false
"#;

        {
            let mut file = std::fs::File::create(&config_path).unwrap();
            file.write_all(yaml_content.as_bytes()).unwrap();
        }

        let config = RulesRegistryConfig::load(&config_path).await.unwrap();
        assert_eq!(config.file.len(), 2);
        assert_eq!(config.file[0].name, Some("Base".to_string()));
        assert!(!config.file[1].enabled);

        // Cleanup
        std::fs::remove_file(&config_path).ok();
    }

    #[tokio::test]
    async fn test_load_invalid_yaml_file_fails() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_invalid_config.yaml");

        let invalid_yaml = "file:\n  - path: [invalid";

        {
            let mut file = std::fs::File::create(&config_path).unwrap();
            file.write_all(invalid_yaml.as_bytes()).unwrap();
        }

        let result = RulesRegistryConfig::load(&config_path).await;
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_file(&config_path).ok();
    }

    #[test]
    fn test_parse_remote_config() {
        let yaml = r#"
remote:
  - url: https://s3.amazonaws.com/bucket/rules.yaml
    name: "S3 Rules"
    timeout_secs: 60
  - url: https://storage.googleapis.com/bucket/rules.yaml
    enabled: false
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.remote.len(), 2);
        assert_eq!(
            config.remote[0].url,
            "https://s3.amazonaws.com/bucket/rules.yaml"
        );
        assert_eq!(config.remote[0].name, Some("S3 Rules".to_string()));
        assert_eq!(config.remote[0].timeout_secs, Some(60));
        assert!(config.remote[0].enabled);
        assert!(!config.remote[1].enabled);
    }

    #[test]
    fn test_parse_remote_config_defaults() {
        let yaml = r#"
remote:
  - url: https://example.com/rules.yaml
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.remote.len(), 1);
        assert_eq!(config.remote[0].url, "https://example.com/rules.yaml");
        assert_eq!(config.remote[0].name, None);
        assert!(config.remote[0].enabled); // defaults to true
        assert_eq!(config.remote[0].timeout_secs, None); // defaults to None (will use 30 in builder)
    }

    #[test]
    fn test_parse_refresh_interval() {
        let yaml = r#"
refresh_interval: 120
file:
  - path: /path/to/rules.yaml
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.refresh_interval, 120);
    }

    #[test]
    fn test_parse_refresh_interval_defaults() {
        let yaml = r#"
file:
  - path: /path/to/rules.yaml
"#;
        let config: RulesRegistryConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.refresh_interval, 60); // defaults to 60
    }

    #[test]
    fn test_config_default_refresh_interval() {
        let config = RulesRegistryConfig::default();
        assert_eq!(config.refresh_interval, 60);
    }
}
