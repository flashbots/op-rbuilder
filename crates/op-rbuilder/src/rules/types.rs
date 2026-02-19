use alloy_consensus::Transaction as ConsensusTx;
use alloy_primitives::{Address, TxKind};
use reth_transaction_pool::PoolTransaction;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};
use tracing::warn;

/// Compute a rule hash from raw bytes (Keccak-256 truncated to u64).
pub fn compute_rule_hash(content: &[u8]) -> u64 {
    let digest = Keccak256::digest(content);
    u64::from_be_bytes(digest[..8].try_into().expect("digest is 32 bytes"))
}

/// A set of addresses that can be specified directly or via aliases.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddrSet {
    /// Direct addresses (O(n) lookup)
    #[serde(default)]
    pub addresses: Vec<Address>,
    /// Alias group names (resolved at runtime via alias table)
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl AddrSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.aliases.is_empty()
    }

    /// Check if an address matches (directly or via alias).
    pub fn contains(&self, addr: &Address, alias_table: &AddressAliases) -> bool {
        // Check direct addresses (O(n) linear scan)
        if self.addresses.contains(addr) {
            return true;
        }
        // Check aliases (O(1) lookup per alias group)
        for alias in &self.aliases {
            if alias_table.contains(alias, addr) {
                return true;
            }
        }
        false
    }
}

/// Configuration for the optional external denylist validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalDenyListConfig {
    /// Remote endpoint to call for validation.
    pub endpoint: String,
    /// Whether to allow transactions to pass when the HTTP request fails.
    pub allow_fail: bool,
    /// Timeout applied to the HTTP request in milliseconds.
    pub timeout: u64,
}

impl Default for ExternalDenyListConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://www.google.com".to_string(),
            allow_fail: true,
            timeout: 1000,
        }
    }
}

/// Deny rule - blocks transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DenyRule {
    /// Optional name for this rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Addresses to deny (direct or via aliases)
    #[serde(default, flatten)]
    pub addrs: AddrSet,
    /// Optional remote denylist endpoint like https://denylist.example.com/check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_endpoint: Option<ExternalDenyListConfig>,
}

/// Match type for boost rules
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    #[default]
    From,
    To,
    Selector,
}

/// Boost rule - assigns weight to transactions
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BoostRule {
    /// Optional name for this rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What to match on (from/to/selector)
    #[serde(rename = "type")]
    pub match_type: MatchType,
    /// The target to match (address or selector hex string)
    #[serde(default)]
    pub target: Vec<String>,
    /// Optional alias names
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Weight to add to transaction score when matched
    pub weight: i64,
    /// Pre-parsed addresses for From/To match types (populated by prepare())
    #[serde(skip, default)]
    pub parsed_addresses: Vec<Address>,
    /// Pre-parsed selectors for Selector match type (populated by prepare())
    #[serde(skip, default)]
    pub parsed_selectors: Vec<[u8; 4]>,
}

impl BoostRule {
    /// Pre-parse target strings into typed values for faster comparison.
    /// Call this after deserialization.
    pub fn prepare(&mut self) {
        match self.match_type {
            MatchType::From | MatchType::To => {
                self.parsed_addresses = self
                    .target
                    .iter()
                    .filter_map(|s| {
                        s.parse::<Address>().ok().or_else(|| {
                            warn!(
                                rule_name = ?self.name,
                                target = %s,
                                "Invalid address in boost rule target, skipping"
                            );
                            None
                        })
                    })
                    .collect();
            }
            MatchType::Selector => {
                self.parsed_selectors = self
                    .target
                    .iter()
                    .filter_map(|s| {
                        parse_selector(s).or_else(|| {
                            warn!(
                                rule_name = ?self.name,
                                target = %s,
                                "Invalid selector in boost rule target, skipping"
                            );
                            None
                        })
                    })
                    .collect();
            }
        }
    }
}

/// Parse a hex selector string (with or without 0x prefix) into 4 bytes
fn parse_selector(s: &str) -> Option<[u8; 4]> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.len() != 8 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// Alias table mapping group names to sets of addresses
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AddressAliases {
    /// group name -> set of addresses
    #[serde(flatten, deserialize_with = "deserialize_address_groups")]
    pub groups: HashMap<String, HashSet<Address>>,
}

fn deserialize_address_groups<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, HashSet<Address>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    // Deserialize as strings first to handle padding
    let map: HashMap<String, Vec<String>> = HashMap::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (key, addrs) in map {
        let mut set = HashSet::new();
        for addr_str in addrs {
            if let Some(addr) = parse_address_string(&addr_str) {
                set.insert(addr);
            } else {
                warn!(
                    alias_group = %key,
                    address = %addr_str,
                    "Skipping invalid address in alias group"
                );
            }
        }
        result.insert(key, set);
    }
    Ok(result)
}

fn parse_address_string(addr_str: &str) -> Option<Address> {
    if let Ok(addr) = addr_str.parse::<Address>() {
        return Some(addr);
    }

    // Try zero-padding odd-length hex strings (e.g., "0x1" -> "0x01")
    if let Some(stripped) = addr_str.strip_prefix("0x")
        && stripped.len() % 2 == 1
    {
        let padded = format!("0x0{}", stripped);
        if let Ok(addr) = padded.parse::<Address>() {
            tracing::debug!(
                original = %addr_str,
                padded = %padded,
                "Zero-padded odd-length address string"
            );
            return Some(addr);
        }
    }

    None
}

impl AddressAliases {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_group<I: IntoIterator<Item = Address>>(
        &mut self,
        name: impl Into<String>,
        addrs: I,
    ) {
        let set: HashSet<Address> = addrs.into_iter().collect();
        self.groups.insert(name.into(), set);
    }

    pub fn contains(&self, name: &str, addr: &Address) -> bool {
        self.groups.get(name).is_some_and(|set| set.contains(addr))
    }

    pub fn get_group(&self, name: &str) -> Option<&HashSet<Address>> {
        self.groups.get(name)
    }

    pub fn merge(&mut self, other: &AddressAliases) {
        for (name, addrs) in &other.groups {
            self.groups.entry(name.clone()).or_default().extend(addrs);
        }
    }
}

/// Rules container
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Rules {
    /// Deny rules (applied at ingress)
    #[serde(default)]
    pub deny: Vec<DenyRule>,
    /// Boost rules (applied at sorting)
    #[serde(default)]
    pub boost: Vec<BoostRule>,
}

impl Rules {
    pub fn len(&self) -> usize {
        self.deny.len() + self.boost.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.boost.is_empty()
    }
}

/// A collection of rules organized by phase
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleSet {
    /// Version identifier for this ruleset
    #[serde(default)]
    pub version: u32,
    /// All rules
    #[serde(default)]
    pub rules: Rules,
    /// Address aliases used by rules
    #[serde(default)]
    pub aliases: AddressAliases,
    /// Deterministic rule hash (Keccak-256 truncated to u64).
    /// `None` for default/uninitialized rulesets.
    #[serde(skip)]
    pub hash: Option<u64>,
}

impl RuleSet {
    pub fn has_scoring_rules(&self) -> bool {
        !self.rules.boost.is_empty()
    }

    /// Compute a boost score for the given transaction.
    pub fn score_transaction<T>(&self, tx: &T) -> i64
    where
        T: PoolTransaction + ConsensusTx,
    {
        let sender = tx.sender();
        let to = tx.kind();
        let input = tx.input();

        let mut score: i64 = 0;

        for rule in &self.rules.boost {
            if self.scoring_rule_matches(&sender, &to, input, rule) {
                score = score.saturating_add(rule.weight);
            }
        }

        score
    }

    /// Sort transactions by descending score while preserving stability.
    pub fn sort_transactions<T>(&self, txs: Vec<T>) -> Vec<T>
    where
        T: PoolTransaction + ConsensusTx + Clone,
    {
        let mut scored: Vec<(i64, usize, T)> = txs
            .into_iter()
            .enumerate()
            .map(|(idx, tx)| {
                let score = self.score_transaction(&tx);
                (score, idx, tx)
            })
            .collect();

        scored.sort_by(|a, b| match b.0.cmp(&a.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            other => other,
        });

        scored.into_iter().map(|(_, _, tx)| tx).collect()
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the first deny rule match for the given transaction participants.
    pub fn denied_match(&self, sender: &Address, to: &TxKind) -> Option<DenyMatchReason> {
        for rule in &self.rules.deny {
            if rule.addrs.contains(sender, &self.aliases) {
                return Some(DenyMatchReason::Sender(*sender));
            }

            if let TxKind::Call(addr) = to
                && rule.addrs.contains(addr, &self.aliases)
            {
                return Some(DenyMatchReason::Receiver(*addr));
            }
        }

        None
    }

    /// Returns true if the transaction participants are denied.
    pub fn is_denied(&self, sender: &Address, to: &TxKind) -> bool {
        self.denied_match(sender, to).is_some()
    }

    /// Returns true if the transaction fields are restricted.
    ///
    /// Today this reuses deny rules, but can be extended with selector-based restrictions.
    pub fn is_restricted_fields(&self, sender: &Address, to: &TxKind, _input: &[u8]) -> bool {
        self.is_denied(sender, to)
    }

    /// Merge another ruleset into this one.
    /// Note: Call `prepare()` after merging to pre-parse boost rule targets.
    pub fn merge(&mut self, other: &RuleSet) {
        self.rules.deny.extend(other.rules.deny.clone());
        self.rules.boost.extend(other.rules.boost.clone());
        self.aliases.merge(&other.aliases);

        // Merge hash
        match (self.hash, other.hash) {
            (None, other_hash) => self.hash = other_hash,
            (Some(_), None) => {} // keep self.hash
            (Some(h1), Some(h2)) => {
                self.hash = Some(compute_rule_hash(
                    &[h1.to_be_bytes(), h2.to_be_bytes()].concat(),
                ));
            }
        }
    }

    /// Pre-parse all boost rule targets for faster matching.
    /// Should be called after loading/merging rulesets.
    pub fn prepare(&mut self) {
        for rule in &mut self.rules.boost {
            rule.prepare();
        }
    }

    fn scoring_rule_matches(
        &self,
        sender: &Address,
        to: &TxKind,
        input: &[u8],
        rule: &BoostRule,
    ) -> bool {
        match rule.match_type {
            MatchType::From => {
                // Use pre-parsed addresses if available (faster)
                if !rule.parsed_addresses.is_empty() {
                    if rule.parsed_addresses.contains(sender) {
                        return true;
                    }
                } else {
                    // Fallback to parsing at runtime (before prepare() is called)
                    for target_str in &rule.target {
                        if let Ok(addr) = target_str.parse::<Address>()
                            && sender == &addr
                        {
                            return true;
                        }
                    }
                }

                for alias in &rule.aliases {
                    if self.aliases.contains(alias, sender) {
                        return true;
                    }
                }

                false
            }
            MatchType::To => {
                if let TxKind::Call(to_addr) = to {
                    // Use pre-parsed addresses if available (faster)
                    if !rule.parsed_addresses.is_empty() {
                        if rule.parsed_addresses.contains(to_addr) {
                            return true;
                        }
                    } else {
                        // Fallback to parsing at runtime (before prepare() is called)
                        for target_str in &rule.target {
                            if let Ok(addr) = target_str.parse::<Address>()
                                && to_addr == &addr
                            {
                                return true;
                            }
                        }
                    }

                    for alias in &rule.aliases {
                        if self.aliases.contains(alias, to_addr) {
                            return true;
                        }
                    }
                }

                false
            }
            MatchType::Selector => {
                if input.len() < 4 {
                    return false;
                }

                let input_sel: [u8; 4] = [input[0], input[1], input[2], input[3]];

                // Use pre-parsed selectors if available (faster)
                if !rule.parsed_selectors.is_empty() {
                    rule.parsed_selectors.contains(&input_sel)
                } else {
                    // Fallback to parsing at runtime (before prepare() is called)
                    rule.target
                        .iter()
                        .any(|s| parse_selector(s) == Some(input_sel))
                }
            }
        }
    }
}

/// Reason a deny rule matched a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyMatchReason {
    Sender(Address),
    Receiver(Address),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_rule_hash_golden_value() {
        // Keccak-256("test") first 8 bytes as u64 big-endian.
        // Pinned to detect accidental hash function changes.
        assert_eq!(compute_rule_hash(b"test"), 11250835603181320219);
    }

    #[test]
    fn test_compute_rule_hash_deterministic() {
        let content = b"version: 1\nrules:\n  deny: []";
        let h1 = compute_rule_hash(content);
        let h2 = compute_rule_hash(content);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_rule_hash_changes_on_different_input() {
        let h1 = compute_rule_hash(b"version: 1");
        let h2 = compute_rule_hash(b"version: 2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_default_ruleset_hash_is_none() {
        let rs = RuleSet::default();
        assert!(rs.hash.is_none());
    }

    #[test]
    fn test_merge_both_none() {
        let mut merged = RuleSet::default();
        let other = RuleSet::default();
        merged.merge(&other);
        assert!(merged.hash.is_none());
    }

    #[test]
    fn test_merge_into_none_hash() {
        let mut merged = RuleSet::default();
        assert!(merged.hash.is_none());

        let other = RuleSet {
            hash: Some(42),
            ..Default::default()
        };
        merged.merge(&other);

        assert_eq!(merged.hash, Some(42));
    }

    #[test]
    fn test_merge_some_with_none() {
        let mut merged = RuleSet {
            hash: Some(42),
            ..Default::default()
        };
        let other = RuleSet::default();
        merged.merge(&other);

        assert_eq!(merged.hash, Some(42));
    }

    #[test]
    fn test_merge_both_some() {
        let h1 = compute_rule_hash(b"ruleset A");
        let h2 = compute_rule_hash(b"ruleset B");

        let mut merged = RuleSet {
            hash: Some(h1),
            ..Default::default()
        };
        let other = RuleSet {
            hash: Some(h2),
            ..Default::default()
        };
        merged.merge(&other);

        assert_eq!(
            merged.hash,
            Some(compute_rule_hash(
                &[h1.to_be_bytes(), h2.to_be_bytes()].concat()
            ))
        );
    }

    #[test]
    fn test_merge_hash_order_sensitive() {
        let ha = compute_rule_hash(b"ruleset A");
        let hb = compute_rule_hash(b"ruleset B");

        // Merge A then B
        let mut ab = RuleSet {
            hash: Some(ha),
            ..Default::default()
        };
        ab.merge(&RuleSet {
            hash: Some(hb),
            ..Default::default()
        });

        // Merge B then A
        let mut ba = RuleSet {
            hash: Some(hb),
            ..Default::default()
        };
        ba.merge(&RuleSet {
            hash: Some(ha),
            ..Default::default()
        });

        assert_ne!(ab.hash, ba.hash);
    }

    #[test]
    fn test_merge_hash_incremental_consistency() {
        let ha = compute_rule_hash(b"ruleset A");
        let hb = compute_rule_hash(b"ruleset B");
        let hc = compute_rule_hash(b"ruleset C");

        // Path 1: merge A → B → C
        let mut path1 = RuleSet {
            hash: Some(ha),
            ..Default::default()
        };
        path1.merge(&RuleSet {
            hash: Some(hb),
            ..Default::default()
        });
        path1.merge(&RuleSet {
            hash: Some(hc),
            ..Default::default()
        });

        // Path 2: merge (A+B) → C
        let mut ab = RuleSet {
            hash: Some(ha),
            ..Default::default()
        };
        ab.merge(&RuleSet {
            hash: Some(hb),
            ..Default::default()
        });
        ab.merge(&RuleSet {
            hash: Some(hc),
            ..Default::default()
        });

        assert_eq!(path1.hash, ab.hash);
    }
}
