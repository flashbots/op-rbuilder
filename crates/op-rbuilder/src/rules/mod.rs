//! Rule-based transaction filtering, boosting, and ordering system
//!
//! This module provides a system for:
//! - **Denying** transactions at ingress or build time
//! - **Boosting** transactions for priority ordering
//! - **Fetching** rules from multiple sources (file)
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
//!
//! ## Application
//! - `RuleFetcher`: Aggregates rules from multiple registries
//! - Global state: `global_ruleset()` / `set_global_ruleset()`
//!
//! ## Transaction Ordering
//! - [`ScoreOrdering`]: `TransactionOrdering` impl that scores transactions via the global ruleset
//! - [`ScorePriority`]: Composite priority (rule score, effective tip) used by the pool

pub mod args;
pub mod config;
pub mod metrics;
pub mod ordering;
pub mod registry;
pub mod state;
pub mod types;
pub mod validator;

// Re-export main types
pub use config::RulesRegistryConfig;
pub use metrics::RulesMetrics;
pub use ordering::{ScoreOrdering, ScorePriority};
pub use registry::RuleFetcher;
pub use state::{
    add_deny_rule, add_scoring_rule, add_to_alias_group, clear_rules, get_alias_group,
    get_tx_score, global_ruleset, insert_tx_score, list_alias_groups, remove_tx_score,
    set_global_ruleset,
};
pub use types::{AddrSet, AddressAliases, BoostRule, DenyRule, MatchType, RuleSet, Rules};
pub use validator::RuleBasedValidator;
