//! Global ruleset state management.
//!
//! Provides a global, thread-safe ruleset that can be updated atomically.
//! The ruleset lives behind a global singleton that hot-path components (pool
//! ingress, payload execution) access directly.
use crate::rules::types::{BoostRule, DenyRule, RuleSet};
use alloy_primitives::{Address, B256};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
};

/// Global ingress ruleset singleton.
static GLOBAL_INGRESS_RULESET: OnceLock<RwLock<Arc<RuleSet>>> = OnceLock::new();
/// Global ordering ruleset singleton.
static GLOBAL_ORDERING_RULESET: OnceLock<RwLock<Arc<RuleSet>>> = OnceLock::new();

/// Global score cache: tx_hash → pre-computed rule score.
///
/// Populated at validation time by [`RuleBasedValidator`], read by
/// [`ScoreOrdering::priority()`] for cheap lookups instead of re-computing.
static GLOBAL_SCORE_CACHE: OnceLock<RwLock<HashMap<B256, i64>>> = OnceLock::new();

/// Get a reference to the ingress ruleset.
pub fn get_ingress_ruleset() -> Arc<RuleSet> {
    let lock = GLOBAL_INGRESS_RULESET.get_or_init(|| RwLock::new(Arc::new(RuleSet::default())));
    lock.read().expect("ingress ruleset lock poisoned").clone()
}

/// Set the ingress ruleset (replaces entirely).
pub fn set_ingress_ruleset(ruleset: RuleSet) {
    let lock = GLOBAL_INGRESS_RULESET.get_or_init(|| RwLock::new(Arc::new(RuleSet::default())));
    let mut guard = lock.write().expect("ingress ruleset lock poisoned");
    *guard = Arc::new(ruleset);
}

/// Get a reference to the ordering ruleset.
pub fn get_ordering_ruleset() -> Arc<RuleSet> {
    let lock = GLOBAL_ORDERING_RULESET.get_or_init(|| RwLock::new(Arc::new(RuleSet::default())));
    lock.read().expect("ordering ruleset lock poisoned").clone()
}

/// Set the ordering ruleset (replaces entirely).
pub fn set_ordering_ruleset(ruleset: RuleSet) {
    let lock = GLOBAL_ORDERING_RULESET.get_or_init(|| RwLock::new(Arc::new(RuleSet::default())));
    let mut guard = lock.write().expect("ordering ruleset lock poisoned");
    *guard = Arc::new(ruleset);
}

/// Compatibility helper returning the ingress ruleset.
pub fn global_ruleset() -> Arc<RuleSet> {
    get_ingress_ruleset()
}

/// Compatibility helper that sets both ingress and ordering rulesets.
pub fn set_global_ruleset(ruleset: RuleSet) {
    set_ingress_ruleset(ruleset.clone());
    set_ordering_ruleset(ruleset);
}

/// Update the global ruleset atomically by cloning, mutating, then swapping.
pub fn update_global_ruleset<F>(mutator: F)
where
    F: FnOnce(&mut RuleSet),
{
    let lock = GLOBAL_INGRESS_RULESET.get_or_init(|| RwLock::new(Arc::new(RuleSet::default())));
    let mut guard = lock.write().expect("ingress ruleset lock poisoned");
    // Clone the current ruleset, mutate it, then swap
    let mut new = (**guard).clone();
    mutator(&mut new);
    *guard = Arc::new(new);
}

// ========== Convenience Functions ==========

/// Add a deny rule to the global ruleset.
pub fn add_deny_rule(rule: DenyRule) {
    update_global_ruleset(|rs| rs.rules.deny.push(rule));
}

/// Add a boost rule to the global ruleset.
pub fn add_scoring_rule(mut rule: BoostRule) {
    // Pre-parse targets before adding
    rule.prepare();
    update_global_ruleset(|rs| rs.rules.boost.push(rule));
}

/// Clear all rules from the global ruleset
pub fn clear_rules() {
    update_global_ruleset(|rs| {
        rs.rules.deny.clear();
        rs.rules.boost.clear();
    });
}

/// Add addresses to an alias group (creates group if it doesn't exist)
pub fn add_to_alias_group(name: impl Into<String>, addrs: impl IntoIterator<Item = Address>) {
    let name = name.into();
    let addrs: Vec<Address> = addrs.into_iter().collect();
    if addrs.is_empty() {
        return;
    }

    update_global_ruleset(|rs| {
        let group = rs
            .aliases
            .groups
            .entry(name)
            .or_insert_with(std::collections::HashSet::new);
        group.extend(addrs);
    });
}

/// Get addresses in an alias group
pub fn get_alias_group(name: &str) -> Option<Vec<Address>> {
    let rs = global_ruleset();
    rs.aliases
        .groups
        .get(name)
        .map(|set| set.iter().copied().collect())
}

/// Get all alias group names
pub fn list_alias_groups() -> Vec<String> {
    let rs = global_ruleset();
    rs.aliases.groups.keys().cloned().collect()
}

// ========== Score Cache ==========

fn score_cache() -> &'static RwLock<HashMap<B256, i64>> {
    GLOBAL_SCORE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_tx_score(tx_hash: &B256) -> Option<i64> {
    score_cache()
        .read()
        .expect("score cache lock poisoned")
        .get(tx_hash)
        .copied()
}

pub fn insert_tx_score(tx_hash: B256, score: i64) {
    score_cache()
        .write()
        .expect("score cache lock poisoned")
        .insert(tx_hash, score);
}

pub fn remove_tx_score(tx_hash: &B256) {
    score_cache()
        .write()
        .expect("score cache lock poisoned")
        .remove(tx_hash);
}

/// Returns the current number of entries in the score cache.
pub fn score_cache_len() -> usize {
    score_cache()
        .read()
        .expect("score cache lock poisoned")
        .len()
}
