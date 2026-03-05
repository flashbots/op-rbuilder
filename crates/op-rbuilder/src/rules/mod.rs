//! Transaction-pool policy system.
//!
//! This module provides a system for:
//! - **Denying** transactions at ingress or build time
//! - **Boosting** transactions for priority ordering
//! - **Fetching** rules from multiple sources (file)
//! - **Selecting regimes** independently for ingress and ordering
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
//! - Global state: ingress ruleset + ordering ruleset
//!
//! ## Transaction Ordering
//! - [`ScoreOrdering`]: `TransactionOrdering` impl that optionally scores transactions
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
pub use config::{
    IngressRegimeConfig, OrderingRegimeConfig, RuleSourcesConfig, TxPoolPolicyConfig,
};
pub use metrics::RulesMetrics;
pub use ordering::{ScoreOrdering, ScorePriority};
pub use registry::RuleFetcher;
pub use state::{
    add_deny_rule, add_scoring_rule, add_to_alias_group, clear_rules, get_alias_group,
    get_ingress_ruleset, get_ordering_ruleset, get_tx_score, global_ruleset, insert_tx_score,
    list_alias_groups, remove_tx_score, set_global_ruleset, set_ingress_ruleset,
    set_ordering_ruleset,
};
pub use types::{AddrSet, AddressAliases, BoostRule, DenyRule, MatchType, RuleSet, Rules};
pub use validator::RuleBasedValidator;
