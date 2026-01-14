//! Rule-based transaction filtering, boosting, and ordering system
//!
//! This module provides a system for:
//! - **Denying** transactions at ingress or build time
//! - **Boosting** transactions for priority ordering
//! - **Fetching** rules from multiple sources (file, remote)
//!
//! # Architecture
//!
//! ## Core Types
//! - `Rule`: A single rule with a phase and action (deny or boosting)
//! - `RuleSet`: A collection of rules with aliases
//!
//! ## Rule Sources
//! - `RuleRegistry`: Trait for sources that provide rules
//!   - `FileRuleRegistry`: Load from YAML files
//!   - `RemoteRuleRegistry`: Fetch from HTTP endpoints
//!
//! ## Application
//! - `RuleEngine`: Orchestrates rule fetching and application
//! - `RuleFetcher`: Aggregates rules from multiple registries
//! - Global state: `global_ruleset()` / `set_global_ruleset()`
//!
//! ## Transaction Ordering (O(k) Block Building)
//!
//! - [`score_index`]: Index of transaction scores populated at validation time
//! - [`ScoreOrderedTransactions`]: Iterator that uses the score index for O(k) block building
//! - [`BestTransactionsWithScores`]: Adapter that yields transactions in score order

pub mod args;
pub mod config;
pub mod engine;
pub mod metrics;
pub mod payload;
pub mod registry;
pub mod score_index;
pub mod scored_iter;
pub mod state;
pub mod types;
pub mod validator;

// Re-export main types
pub use config::{FileRegistryConfig, RulesRegistryConfig};
pub use engine::RuleEngine;
pub use metrics::RulesMetrics;
pub use payload::ScoredPayloadTransactions;
pub use registry::{FetchResult, RuleFetcher, RuleRegistry, file::FileRuleRegistry};
pub use score_index::{SharedScoreIndex, new_shared_score_index};
pub use scored_iter::{BestTransactionsWithScores, ScoreOrderedTransactions};
pub use state::{
    add_deny_rule, add_scoring_rule, add_to_alias_group, clear_rules, get_alias_group,
    global_ruleset, list_alias_groups, set_global_ruleset, update_global_ruleset,
};
pub use types::{AddrSet, AddressAliases, BoostRule, DenyRule, MatchType, RuleSet, Rules};
pub use validator::RuleBasedValidator;
