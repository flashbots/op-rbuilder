//! Rule engine - orchestrates rule fetching and application.

use crate::rules::registry::{FetchResult, RuleFetcher};

/// Rule engine that manages rule fetching and application.
pub struct RuleEngine {
    fetcher: Option<RuleFetcher>,
}

impl RuleEngine {
    pub fn new(fetcher: Option<RuleFetcher>) -> Self {
        Self { fetcher }
    }

    /// Get the fetcher if configured.
    pub fn fetcher(&self) -> Option<&RuleFetcher> {
        self.fetcher.as_ref()
    }

    /// Refresh rules and update global state.
    ///
    /// Returns `Some(FetchResult)` if a fetcher is configured, `None` otherwise.
    /// The `FetchResult` contains information about which registries succeeded or failed,
    /// allowing callers to determine how to proceed.
    pub async fn refresh_rules(&self) -> Option<FetchResult> {
        if let Some(fetcher) = &self.fetcher {
            Some(fetcher.refresh_global_ruleset().await)
        } else {
            None
        }
    }
}
