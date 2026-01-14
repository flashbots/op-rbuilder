use crate::rules::{registry::RuleRegistry, types::RuleSet};
use std::time::Duration;

/// Registry that loads rules from a remote HTTP/HTTPS endpoint
///
/// This registry is backend-agnostic and works with any storage service
/// that exposes files via HTTP URLs, including:
/// - AWS S3 (via presigned URLs or public buckets)
/// - Google Cloud Storage (via public URLs)
/// - Azure Blob Storage (via public URLs)
/// - Any HTTP/HTTPS endpoint serving YAML content
pub struct RemoteRuleRegistry {
    url: String,
    name: String,
    client: reqwest::Client,
}

impl RemoteRuleRegistry {
    /// Create a new remote registry with default timeout (30 seconds)
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_timeout(url, Duration::from_secs(30))
    }

    /// Create a new remote registry with a custom timeout
    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        let url = url.into();
        let name = format!("remote:{}", url);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            url,
            name,
            client,
        }
    }
}

#[async_trait::async_trait]
impl RuleRegistry for RemoteRuleRegistry {
    async fn get_rules(&self) -> anyhow::Result<RuleSet> {
        tracing::debug!(url = %self.url, "Fetching rules from remote endpoint");

        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch rules from {}: {}", self.url, e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch rules from {}: HTTP {}",
                self.url,
                response.status()
            ));
        }

        let content = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from {}: {}", self.url, e))?;

        let ruleset: RuleSet = serde_yaml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse YAML from {}: {}", self.url, e))?;

        tracing::debug!(
            url = %self.url,
            version = ruleset.version,
            rules_count = ruleset.rules.len(),
            "Successfully fetched and parsed rules from remote endpoint"
        );

        Ok(ruleset)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_remote_registry_name_format() {
        let registry = RemoteRuleRegistry::new("https://example.com/rules.yaml");
        assert_eq!(registry.name(), "remote:https://example.com/rules.yaml");
    }

    #[tokio::test]
    async fn test_remote_registry_with_timeout() {
        let registry = RemoteRuleRegistry::with_timeout(
            "https://example.com/rules.yaml",
            Duration::from_secs(10),
        );
        assert_eq!(registry.name(), "remote:https://example.com/rules.yaml");
    }

    #[tokio::test]
    async fn test_get_rules_invalid_url() {
        let registry = RemoteRuleRegistry::new("https://nonexistent-domain-12345.com/rules.yaml");
        let result = registry.get_rules().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_rules_404() {
        let registry = RemoteRuleRegistry::new("https://httpbin.org/status/404");
        let result = registry.get_rules().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HTTP 404"));
    }

    #[tokio::test]
    async fn test_get_rules_invalid_yaml() {
        // Use httpbin to return invalid YAML
        let registry = RemoteRuleRegistry::new("https://httpbin.org/base64/dGVzdA==");
        let result = registry.get_rules().await;
        assert!(result.is_err());
    }

    // Note: Integration tests that actually fetch from a real endpoint
    // would require a test server or mock server setup.
    // For now, we test error cases and the structure.
}
