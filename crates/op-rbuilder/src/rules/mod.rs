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
//! - `RuleSet`: A collection of rules with aliases
//! - `BoostRule` / `DenyRule`: Individual rule definitions
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
//! ## Transaction Ordering
//! - [`ScoreOrdering`]: `TransactionOrdering` impl that scores transactions via the global ruleset
//! - [`ScorePriority`]: Composite priority (rule score, effective tip) used by the pool

pub mod args;
pub mod config;
pub mod engine;
pub mod metrics;
pub mod ordering;
pub mod registry;
pub mod state;
pub mod types;
pub mod validator;

// Re-export main types
pub use config::{FileRegistryConfig, RulesRegistryConfig};
pub use engine::RuleEngine;
pub use metrics::RulesMetrics;
pub use ordering::{ScoreOrdering, ScorePriority};
pub use registry::{FetchResult, RuleFetcher, RuleRegistry, file::FileRuleRegistry};
pub use state::{
    add_deny_rule, add_scoring_rule, add_to_alias_group, clear_rules, get_alias_group,
    global_ruleset, list_alias_groups, set_global_ruleset, update_global_ruleset,
};
pub use types::{AddrSet, AddressAliases, BoostRule, DenyRule, MatchType, RuleSet, Rules};
pub use validator::RuleBasedValidator;
