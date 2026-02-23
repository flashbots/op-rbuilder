#![cfg(all(test, feature = "rules"))]
//! Tests for the refactored rules subsystem.

use crate::{
    mock_tx::MockFbTransaction,
    rules::{
        AddrSet, AddressAliases, BoostRule, DenyRule, MatchType, RuleFetcher, RuleSet,
        add_deny_rule, add_scoring_rule, add_to_alias_group, clear_rules, get_alias_group,
        get_tx_score, global_ruleset, list_alias_groups, registry::RuleRegistry, remove_tx_score,
        set_global_ruleset, validator::RuleBasedValidator,
    },
};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use async_trait::async_trait;
use futures::executor::block_on;
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    test_utils::MockTransaction, validate::ValidTransaction,
};
use serial_test::serial;
use std::{future::ready, sync::Arc};

fn reset_global_rules() {
    set_global_ruleset(RuleSet::default());
}

fn make_mock_tx(sender: Address, to: Address, input: impl AsRef<[u8]>) -> MockFbTransaction {
    let mut inner = MockTransaction::legacy()
        .with_sender(sender)
        .with_input(Bytes::copy_from_slice(input.as_ref()));

    if let MockTransaction::Legacy { to: tx_to, .. } = &mut inner {
        *tx_to = TxKind::Call(to);
    }

    MockFbTransaction {
        inner,
        reverted_hashes: None,
        flashblock_number_min: None,
        flashblock_number_max: None,
    }
}

#[derive(Clone)]
struct StaticRegistry {
    name: &'static str,
    ruleset: RuleSet,
}

#[async_trait]
impl RuleRegistry for StaticRegistry {
    async fn get_rules(&self) -> anyhow::Result<RuleSet> {
        Ok(self.ruleset.clone())
    }

    fn name(&self) -> &str {
        self.name
    }
}

#[test]
fn test_ruleset_deny_matches_sender_and_receiver() {
    let sender = Address::random();
    let receiver = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    assert!(ruleset.is_denied(&sender, &TxKind::Call(receiver)));
    assert!(!ruleset.is_denied(&Address::random(), &TxKind::Call(Address::random())));

    ruleset.rules.deny.push(DenyRule {
        name: Some("deny receiver".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![receiver],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    assert!(ruleset.is_denied(&Address::random(), &TxKind::Call(receiver)));
}

#[test]
fn test_ruleset_alias_matching() {
    let sender = Address::random();
    let receiver = Address::random();

    let mut aliases = AddressAliases::new();
    aliases.insert_group("blocked", vec![sender, receiver]);

    let mut ruleset = RuleSet::default();
    ruleset.aliases = aliases;
    ruleset.rules.deny.push(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![],
            aliases: vec!["blocked".into()],
        },
        remote_endpoint: None,
    });

    assert!(ruleset.is_denied(&sender, &TxKind::Call(Address::random())));
    assert!(ruleset.is_denied(&Address::random(), &TxKind::Call(receiver)));
}

#[test]
fn test_ruleset_has_scoring_rules_flag() {
    let mut ruleset = RuleSet::default();
    assert!(!ruleset.has_scoring_rules());

    ruleset.rules.boost.push(BoostRule {
        name: Some("vip boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["vip".into()],
        weight: 10,
        ..Default::default()
    });

    assert!(ruleset.has_scoring_rules());
}

#[test]
fn test_ruleset_score_transaction_from_alias() {
    let sender = Address::random();
    let other_sender = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.aliases.insert_group("vip", vec![sender]);
    ruleset.rules.boost.push(BoostRule {
        name: Some("vip sender boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["vip".into()],
        weight: 42,
        ..Default::default()
    });

    let matching_tx = make_mock_tx(sender, Address::random(), []);
    let other_tx = make_mock_tx(other_sender, Address::random(), []);

    assert_eq!(ruleset.score_transaction(&matching_tx), 42);
    assert_eq!(ruleset.score_transaction(&other_tx), 0);
}

#[test]
fn test_ruleset_score_transaction_selector() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0x12345678".into()],
        aliases: vec![],
        weight: 200,
        ..Default::default()
    });

    let matching_tx = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x12, 0x34, 0x56, 0x78],
    );
    let non_matching_tx = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0xaa, 0xbb, 0xcc, 0xdd],
    );
    let short_input_tx = make_mock_tx(Address::random(), Address::random(), &[0x12, 0x34]);

    assert_eq!(ruleset.score_transaction(&matching_tx), 200);
    assert_eq!(ruleset.score_transaction(&non_matching_tx), 0);
    assert_eq!(ruleset.score_transaction(&short_input_tx), 0);
}

#[test]
fn test_ruleset_score_transaction_to_alias() {
    let destination = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.aliases.insert_group("targets", vec![destination]);
    ruleset.rules.boost.push(BoostRule {
        name: Some("to alias boost".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![],
        aliases: vec!["targets".into()],
        weight: 17,
        ..Default::default()
    });

    let boosted_tx = make_mock_tx(Address::random(), destination, []);
    let other_tx = make_mock_tx(Address::random(), Address::random(), []);

    assert_eq!(ruleset.score_transaction(&boosted_tx), 17);
    assert_eq!(ruleset.score_transaction(&other_tx), 0);
}

#[test]
fn test_ruleset_merge_merges_rules_and_aliases() {
    let denied_sender = Address::random();
    let alias_addr = Address::random();
    let score_target = Address::random();

    let mut base = RuleSet::default();
    base.rules.deny.push(DenyRule {
        name: Some("deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![denied_sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    base.aliases.insert_group("group1", vec![alias_addr]);

    let mut extra = RuleSet::default();
    extra.rules.boost.push(BoostRule {
        name: Some("boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{score_target:#x}")],
        aliases: vec![],
        weight: 5,
        ..Default::default()
    });
    extra.aliases.insert_group("group2", vec![score_target]);

    base.merge(&extra);

    assert_eq!(base.rules.deny.len(), 1);
    assert_eq!(base.rules.boost.len(), 1);
    assert!(base.aliases.groups.contains_key("group1"));
    assert!(base.aliases.groups.contains_key("group2"));
}

#[test]
fn test_ruleset_serialization_roundtrip() {
    let sender = Address::random();
    let alias_target = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.version = 7;
    ruleset.aliases.insert_group("vip", vec![alias_target]);
    ruleset.rules.deny.push(DenyRule {
        name: Some("block sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("vip boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{alias_target:#x}")],
        aliases: vec![],
        weight: 15,
        ..Default::default()
    });

    let json = serde_json::to_string_pretty(&ruleset).unwrap();
    let decoded: RuleSet = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.version, 7);
    assert_eq!(decoded.rules.deny.len(), 1);
    assert_eq!(decoded.rules.boost.len(), 1);
    assert!(decoded.aliases.groups.contains_key("vip"));
}

#[test]
fn test_ruleset_is_restricted_fields_delegates_to_deny() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    assert!(ruleset.is_restricted_fields(&sender, &TxKind::Call(Address::random()), &[0u8; 0]));
}

#[test]
#[serial]
fn test_global_ruleset_state_roundtrip() {
    reset_global_rules();

    let blocked = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    set_global_ruleset(ruleset.clone());
    let retrieved = global_ruleset();

    assert_eq!(retrieved.rules.deny.len(), 1);
    assert_eq!(retrieved.rules.boost.len(), 0);
    assert_eq!(retrieved.rules.deny[0].addrs.addresses, vec![blocked]);
}

#[test]
#[serial]
fn test_global_ruleset_add_and_clear_rules() {
    reset_global_rules();

    let blocked = Address::random();
    add_deny_rule(DenyRule {
        name: Some("deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    add_scoring_rule(BoostRule {
        name: Some("boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{blocked:#x}")],
        aliases: vec![],
        weight: 1,
        ..Default::default()
    });

    {
        let rs = global_ruleset();
        assert_eq!(rs.rules.deny.len(), 1);
        assert_eq!(rs.rules.boost.len(), 1);
    }

    clear_rules();
    let rs = global_ruleset();
    assert!(rs.rules.deny.is_empty());
    assert!(rs.rules.boost.is_empty());
}

#[test]
#[serial]
fn test_global_alias_group_helpers_manage_groups() {
    reset_global_rules();

    let addr1 = Address::random();
    let addr2 = Address::random();

    add_to_alias_group("vip", vec![addr1]);
    add_to_alias_group("vip", vec![addr2]);

    let members = get_alias_group("vip").expect("group exists");
    assert!(members.contains(&addr1));
    assert!(members.contains(&addr2));

    let groups = list_alias_groups();
    assert!(groups.contains(&"vip".to_string()));
}
#[test]
#[serial]
fn test_set_global_ruleset_updates_state() {
    reset_global_rules();
    let sender = Address::random();
    let receiver = Address::random();

    assert!(!global_ruleset().is_denied(&sender, &TxKind::Call(receiver)));

    let mut updated = RuleSet::default();
    updated.rules.deny.push(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    set_global_ruleset(updated);
    assert!(global_ruleset().is_denied(&sender, &TxKind::Call(receiver)));
}

#[test]
#[serial]
fn test_fetcher_refresh_global_ruleset() {
    reset_global_rules();
    let blocked = Address::random();

    let mut fetched = RuleSet::default();
    fetched.rules.deny.push(DenyRule {
        name: Some("fetched deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let mut fetcher = RuleFetcher::new();
    fetcher.add_registry(Arc::new(StaticRegistry {
        name: "static",
        ruleset: fetched.clone(),
    }));

    block_on(fetcher.refresh_global_ruleset());

    assert!(global_ruleset().is_denied(&blocked, &TxKind::Call(Address::random())));
}

#[derive(Clone, Debug, Default)]
struct PassthroughValidator;

impl TransactionValidator for PassthroughValidator {
    type Transaction = MockFbTransaction;

    fn validate_transaction(
        &self,
        _origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> impl std::future::Future<Output = TransactionValidationOutcome<Self::Transaction>> + Send
    {
        ready(TransactionValidationOutcome::Valid {
            balance: U256::ZERO,
            state_nonce: 0,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(transaction),
            propagate: true,
            authorities: None,
        })
    }
}

#[test]
#[serial]
fn test_rule_based_validator_blocks_denied_sender() {
    reset_global_rules();

    let blocked = Address::random();
    add_deny_rule(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let validator = RuleBasedValidator::new(PassthroughValidator::default());

    let tx = make_mock_tx(blocked, Address::random(), []);
    let outcome = block_on(validator.validate_transaction(TransactionOrigin::External, tx));
    assert!(matches!(
        outcome,
        TransactionValidationOutcome::Invalid(_, _)
    ));
}

#[test]
#[serial]
fn test_rule_based_validator_denied_tx_does_not_mark_as_bad() {
    use reth_transaction_pool::error::InvalidPoolTransactionError;

    reset_global_rules();

    let blocked = Address::random();
    add_deny_rule(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let validator = RuleBasedValidator::new(PassthroughValidator::default());
    let tx = make_mock_tx(blocked, Address::random(), []);
    let outcome = block_on(validator.validate_transaction(TransactionOrigin::External, tx));

    match outcome {
        TransactionValidationOutcome::Invalid(_, InvalidPoolTransactionError::Other(err)) => {
            assert!(
                !err.is_bad_transaction(),
                "Denied transactions must not be marked as bad - this causes peer penalties and P2P disconnects"
            );
        }
        other => panic!("Expected Invalid(Other) outcome for denied transaction, got: {other:?}"),
    }
}

#[test]
#[serial]
fn test_rule_based_validator_allows_non_blocked_sender() {
    reset_global_rules();

    let blocked = Address::random();
    add_deny_rule(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let validator = RuleBasedValidator::new(PassthroughValidator::default());

    let allowed_sender = Address::random();
    let tx = make_mock_tx(allowed_sender, Address::random(), []);
    let outcome = block_on(validator.validate_transaction(TransactionOrigin::External, tx));
    assert!(matches!(
        outcome,
        TransactionValidationOutcome::Valid { .. }
    ));
}

#[test]
#[serial]
fn test_rule_based_validator_blocks_denied_receiver() {
    reset_global_rules();

    let blocked_receiver = Address::random();
    add_deny_rule(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![blocked_receiver],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let validator = RuleBasedValidator::new(PassthroughValidator::default());

    let tx = make_mock_tx(Address::random(), blocked_receiver, []);
    let outcome = block_on(validator.validate_transaction(TransactionOrigin::External, tx));
    assert!(matches!(
        outcome,
        TransactionValidationOutcome::Invalid(_, _)
    ));
}

#[test]
fn test_ruleset_score_transaction_negative_weight() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("penalty".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender:#x}")],
        aliases: vec![],
        weight: -100,
        ..Default::default()
    });

    let penalized_tx = make_mock_tx(sender, Address::random(), []);
    let normal_tx = make_mock_tx(Address::random(), Address::random(), []);

    assert_eq!(ruleset.score_transaction(&penalized_tx), -100);
    assert_eq!(ruleset.score_transaction(&normal_tx), 0);
}

#[test]
fn test_ruleset_score_transaction_zero_weight() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("zero weight".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender:#x}")],
        aliases: vec![],
        weight: 0,
        ..Default::default()
    });

    let tx = make_mock_tx(sender, Address::random(), []);
    assert_eq!(ruleset.score_transaction(&tx), 0);
}

#[test]
fn test_ruleset_score_transaction_saturating_addition() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    // Add multiple rules that would overflow i64
    for _ in 0..10 {
        ruleset.rules.boost.push(BoostRule {
            name: Some("large weight".into()),
            description: None,
            match_type: MatchType::From,
            target: vec![format!("{sender:#x}")],
            aliases: vec![],
            weight: i64::MAX / 5, // Large enough to potentially overflow
            ..Default::default()
        });
    }

    let tx = make_mock_tx(sender, Address::random(), []);
    let score = ruleset.score_transaction(&tx);
    // Should saturate, not overflow
    assert!(score <= i64::MAX);
    assert!(score > 0);
}

#[test]
fn test_ruleset_selector_matching_case_insensitive() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0xABCD1234".to_string()], // Uppercase
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    // Lowercase input should still match
    let tx_lower = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0xab, 0xcd, 0x12, 0x34],
    );
    // Uppercase input should match
    let tx_upper = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0xAB, 0xCD, 0x12, 0x34],
    );
    // Without 0x prefix
    let tx_no_prefix = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0xab, 0xcd, 0x12, 0x34],
    );

    assert_eq!(ruleset.score_transaction(&tx_lower), 100);
    assert_eq!(ruleset.score_transaction(&tx_upper), 100);
    assert_eq!(ruleset.score_transaction(&tx_no_prefix), 100);
}

#[test]
fn test_ruleset_selector_matching_with_prefix() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0x12345678".to_string()],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    let matching_tx = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x12, 0x34, 0x56, 0x78],
    );

    assert_eq!(ruleset.score_transaction(&matching_tx), 100);
}

#[test]
fn test_ruleset_selector_matching_without_prefix() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["12345678".to_string()], // No 0x prefix
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    let matching_tx = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x12, 0x34, 0x56, 0x78],
    );

    assert_eq!(ruleset.score_transaction(&matching_tx), 100);
}

#[test]
fn test_ruleset_multiple_selectors_match_any() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("multi selector".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec![
            "0x11111111".to_string(),
            "0x22222222".to_string(),
            "0x33333333".to_string(),
        ],
        aliases: vec![],
        weight: 50,
        ..Default::default()
    });

    let tx1 = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x11, 0x11, 0x11, 0x11],
    );
    let tx2 = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x22, 0x22, 0x22, 0x22],
    );
    let tx3 = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x33, 0x33, 0x33, 0x33],
    );
    let tx_no_match = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x99, 0x99, 0x99, 0x99],
    );

    assert_eq!(ruleset.score_transaction(&tx1), 50);
    assert_eq!(ruleset.score_transaction(&tx2), 50);
    assert_eq!(ruleset.score_transaction(&tx3), 50);
    assert_eq!(ruleset.score_transaction(&tx_no_match), 0);
}

#[test]
fn test_ruleset_empty_ruleset_behavior() {
    let ruleset = RuleSet::default();
    let tx = make_mock_tx(Address::random(), Address::random(), []);

    assert!(!ruleset.has_scoring_rules());
    assert_eq!(ruleset.score_transaction(&tx), 0);
    assert!(!ruleset.is_denied(&Address::random(), &TxKind::Call(Address::random())));
}

#[test]
fn test_ruleset_deny_create_transactions() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    // Deny should work for both Call and Create transactions
    assert!(ruleset.is_denied(&sender, &TxKind::Call(Address::random())));
    assert!(ruleset.is_denied(&sender, &TxKind::Create));
}

#[test]
fn test_ruleset_multiple_aliases_in_rule() {
    let addr1 = Address::random();
    let addr2 = Address::random();
    let addr3 = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.aliases.insert_group("group1", vec![addr1]);
    ruleset.aliases.insert_group("group2", vec![addr2, addr3]);
    ruleset.rules.boost.push(BoostRule {
        name: Some("multi alias".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["group1".into(), "group2".into()],
        weight: 100,
        ..Default::default()
    });

    let tx1 = make_mock_tx(addr1, Address::random(), []);
    let tx2 = make_mock_tx(addr2, Address::random(), []);
    let tx3 = make_mock_tx(addr3, Address::random(), []);
    let tx_no_match = make_mock_tx(Address::random(), Address::random(), []);

    assert_eq!(ruleset.score_transaction(&tx1), 100);
    assert_eq!(ruleset.score_transaction(&tx2), 100);
    assert_eq!(ruleset.score_transaction(&tx3), 100);
    assert_eq!(ruleset.score_transaction(&tx_no_match), 0);
}

#[test]
fn test_ruleset_address_and_alias_combined() {
    let direct_addr = Address::random();
    let alias_addr = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.aliases.insert_group("vip", vec![alias_addr]);
    ruleset.rules.boost.push(BoostRule {
        name: Some("combined".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{direct_addr:#x}")],
        aliases: vec!["vip".into()],
        weight: 50,
        ..Default::default()
    });

    let tx_direct = make_mock_tx(direct_addr, Address::random(), []);
    let tx_alias = make_mock_tx(alias_addr, Address::random(), []);
    let tx_no_match = make_mock_tx(Address::random(), Address::random(), []);

    assert_eq!(ruleset.score_transaction(&tx_direct), 50);
    assert_eq!(ruleset.score_transaction(&tx_alias), 50);
    assert_eq!(ruleset.score_transaction(&tx_no_match), 0);
}

#[test]
#[serial]
fn test_fetcher_merges_multiple_registries() {
    reset_global_rules();
    let addr1 = Address::random();
    let addr2 = Address::random();

    let mut ruleset1 = RuleSet::default();
    ruleset1.rules.deny.push(DenyRule {
        name: Some("registry1 deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![addr1],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let mut ruleset2 = RuleSet::default();
    ruleset2.rules.boost.push(BoostRule {
        name: Some("registry2 boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr2:#x}")],
        aliases: vec![],
        weight: 200,
        ..Default::default()
    });

    let mut fetcher = RuleFetcher::new();
    fetcher.add_registry(Arc::new(StaticRegistry {
        name: "registry1",
        ruleset: ruleset1,
    }));
    fetcher.add_registry(Arc::new(StaticRegistry {
        name: "registry2",
        ruleset: ruleset2,
    }));

    block_on(fetcher.refresh_global_ruleset());

    let ruleset = global_ruleset();
    // Both rules should be merged
    assert!(ruleset.is_denied(&addr1, &TxKind::Call(Address::random())));
    let tx = make_mock_tx(addr2, Address::random(), []);
    assert_eq!(ruleset.score_transaction(&tx), 200);
}

#[test]
#[serial]
fn test_fetcher_fetch_all_returns_merged_rules() {
    let addr = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("test".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![addr],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let mut fetcher = RuleFetcher::new();
    fetcher.add_registry(Arc::new(StaticRegistry {
        name: "static",
        ruleset: ruleset.clone(),
    }));

    let result = block_on(fetcher.fetch_all());
    assert_eq!(result.ruleset.rules.deny.len(), 1);
}

#[test]
#[serial]
fn test_global_ruleset_thread_safety() {
    use std::thread;

    reset_global_rules();

    let addr = Address::random();
    let num_threads = 10;
    let mut handles = vec![];

    for i in 0..num_threads {
        let addr_clone = addr;
        let handle = thread::spawn(move || {
            let mut ruleset = RuleSet::default();
            ruleset.rules.boost.push(BoostRule {
                name: Some(format!("thread_{}", i)),
                description: None,
                match_type: MatchType::From,
                target: vec![format!("{addr_clone:#x}")],
                aliases: vec![],
                weight: i as i64,
                ..Default::default()
            });
            set_global_ruleset(ruleset);
            let retrieved = global_ruleset();
            retrieved.rules.boost.len()
        });
        handles.push(handle);
    }

    for handle in handles {
        let count = handle.join().unwrap();
        // Each thread should see a valid ruleset (boost rules exist)
        assert!(count > 0);
    }
}

#[test]
fn test_ruleset_merge_preserves_existing_rules() {
    let addr1 = Address::random();
    let addr2 = Address::random();

    let mut base = RuleSet::default();
    base.rules.deny.push(DenyRule {
        name: Some("base deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![addr1],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    base.rules.boost.push(BoostRule {
        name: Some("base boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr1:#x}")],
        aliases: vec![],
        weight: 10,
        ..Default::default()
    });

    let mut extra = RuleSet::default();
    extra.rules.deny.push(DenyRule {
        name: Some("extra deny".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![addr2],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    extra.rules.boost.push(BoostRule {
        name: Some("extra boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr2:#x}")],
        aliases: vec![],
        weight: 20,
        ..Default::default()
    });

    base.merge(&extra);

    // Both sets of rules should be present
    assert_eq!(base.rules.deny.len(), 2);
    assert_eq!(base.rules.boost.len(), 2);
    assert!(base.is_denied(&addr1, &TxKind::Call(Address::random())));
    assert!(base.is_denied(&addr2, &TxKind::Call(Address::random())));
}

#[test]
fn test_ruleset_denied_match_reason() {
    let sender = Address::random();
    let receiver = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny receiver".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![receiver],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let sender_match = ruleset.denied_match(&sender, &TxKind::Call(Address::random()));
    assert!(sender_match.is_some());
    if let Some(reason) = sender_match {
        match reason {
            crate::rules::types::DenyMatchReason::Sender(addr) => assert_eq!(addr, sender),
            _ => panic!("Expected Sender match reason"),
        }
    }

    let receiver_match = ruleset.denied_match(&Address::random(), &TxKind::Call(receiver));
    assert!(receiver_match.is_some());
    if let Some(reason) = receiver_match {
        match reason {
            crate::rules::types::DenyMatchReason::Receiver(addr) => assert_eq!(addr, receiver),
            _ => panic!("Expected Receiver match reason"),
        }
    }
}

#[test]
fn test_addr_set_empty() {
    let addr_set = AddrSet::default();
    let aliases = AddressAliases::default();
    assert!(addr_set.addresses.is_empty() && addr_set.aliases.is_empty());
    assert!(!addr_set.contains(&Address::random(), &aliases));
}

#[test]
fn test_addr_set_direct_address() {
    let addr = Address::random();
    let mut addr_set = AddrSet::default();
    addr_set.addresses.push(addr);
    let aliases = AddressAliases::default();

    assert!(addr_set.contains(&addr, &aliases));
    assert!(!addr_set.contains(&Address::random(), &aliases));
}

#[test]
fn test_addr_set_alias_only() {
    let addr = Address::random();
    let mut aliases = AddressAliases::new();
    aliases.insert_group("test", vec![addr]);

    let mut addr_set = AddrSet::default();
    addr_set.aliases.push("test".into());

    assert!(addr_set.contains(&addr, &aliases));
    assert!(!addr_set.contains(&Address::random(), &aliases));
}

#[test]
fn test_addr_set_direct_and_alias() {
    let direct_addr = Address::random();
    let alias_addr = Address::random();
    let mut aliases = AddressAliases::new();
    aliases.insert_group("test", vec![alias_addr]);

    let mut addr_set = AddrSet::default();
    addr_set.addresses.push(direct_addr);
    addr_set.aliases.push("test".into());

    assert!(addr_set.contains(&direct_addr, &aliases));
    assert!(addr_set.contains(&alias_addr, &aliases));
    assert!(!addr_set.contains(&Address::random(), &aliases));
}

#[test]
fn test_ruleset_to_address_matching_with_create() {
    // Test that To matching only works for Call transactions, not Create
    let target_addr = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("to boost".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{target_addr:#x}")],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    // Create transaction should not match To rules
    let create_tx = MockFbTransaction {
        inner: MockTransaction::legacy()
            .with_sender(Address::random())
            .with_input(Bytes::new()),
        reverted_hashes: None,
        flashblock_number_min: None,
        flashblock_number_max: None,
    };

    if let MockTransaction::Legacy { to, .. } = &create_tx.inner {
        if matches!(to, TxKind::Create) {
            assert_eq!(ruleset.score_transaction(&create_tx), 0);
        }
    }
}

#[test]
fn test_ruleset_selector_short_input() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0x12345678".to_string()],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    // Inputs shorter than 4 bytes should not match
    let tx_short1 = make_mock_tx(Address::random(), Address::random(), &[0x12]);
    let tx_short2 = make_mock_tx(Address::random(), Address::random(), &[0x12, 0x34]);
    let tx_short3 = make_mock_tx(Address::random(), Address::random(), &[0x12, 0x34, 0x56]);
    let tx_empty = make_mock_tx(Address::random(), Address::random(), &[]);

    assert_eq!(ruleset.score_transaction(&tx_short1), 0);
    assert_eq!(ruleset.score_transaction(&tx_short2), 0);
    assert_eq!(ruleset.score_transaction(&tx_short3), 0);
    assert_eq!(ruleset.score_transaction(&tx_empty), 0);
}

#[test]
fn test_ruleset_version_preserved() {
    let mut ruleset = RuleSet::default();
    ruleset.version = 42;
    ruleset.rules.boost.push(BoostRule {
        name: Some("test".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec![],
        weight: 10,
        ..Default::default()
    });

    assert_eq!(ruleset.version, 42);
    let json = serde_json::to_string(&ruleset).unwrap();
    let decoded: RuleSet = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.version, 42);
}

// ==================== Additional Edge Case Tests ====================

#[test]
fn test_deny_match_reason_returns_correct_variant_for_sender() {
    let sender = Address::random();
    let receiver = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let result = ruleset.denied_match(&sender, &TxKind::Call(receiver));
    assert!(result.is_some());
    assert_eq!(
        result.unwrap(),
        crate::rules::types::DenyMatchReason::Sender(sender)
    );
}

#[test]
fn test_deny_match_reason_returns_correct_variant_for_receiver() {
    let sender = Address::random();
    let receiver = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny receiver".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![receiver],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let result = ruleset.denied_match(&sender, &TxKind::Call(receiver));
    assert!(result.is_some());
    assert_eq!(
        result.unwrap(),
        crate::rules::types::DenyMatchReason::Receiver(receiver)
    );
}

#[test]
fn test_deny_match_sender_takes_priority_over_receiver() {
    // When both sender and receiver are denied, sender should be the match reason
    let sender = Address::random();
    let receiver = Address::random();

    let mut ruleset = RuleSet::default();
    // Add single rule that denies both
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny both".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender, receiver],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    let result = ruleset.denied_match(&sender, &TxKind::Call(receiver));
    assert!(result.is_some());
    // Sender should be checked first
    assert_eq!(
        result.unwrap(),
        crate::rules::types::DenyMatchReason::Sender(sender)
    );
}

#[test]
fn test_deny_match_returns_none_for_create_receiver() {
    // Create transactions don't have a receiver, so only sender matching should work
    let sender = Address::random();
    let receiver_to_deny = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: Some("deny receiver only".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![receiver_to_deny],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    // Create transaction - receiver deny rule should not match
    let result = ruleset.denied_match(&sender, &TxKind::Create);
    assert!(result.is_none());

    // But sender deny should still work with Create
    let mut ruleset2 = RuleSet::default();
    ruleset2.rules.deny.push(DenyRule {
        name: Some("deny sender".into()),
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });
    let result2 = ruleset2.denied_match(&sender, &TxKind::Create);
    assert!(result2.is_some());
}

#[test]
fn test_external_deny_list_config_default_values() {
    let config = crate::rules::types::ExternalDenyListConfig::default();
    assert_eq!(config.endpoint, "https://www.google.com");
    assert!(config.allow_fail);
    assert_eq!(config.timeout, 1000);
}

#[test]
fn test_deny_rule_with_remote_endpoint_serialization() {
    use crate::rules::types::ExternalDenyListConfig;

    let rule = DenyRule {
        name: Some("external deny".into()),
        description: Some("External validation".into()),
        addrs: AddrSet {
            addresses: vec![Address::random()],
            aliases: vec!["blocked".into()],
        },
        remote_endpoint: Some(ExternalDenyListConfig {
            endpoint: "https://example.com/check".to_string(),
            allow_fail: false,
            timeout: 5000,
        }),
    };

    let json = serde_json::to_string(&rule).unwrap();
    let decoded: DenyRule = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.name, Some("external deny".into()));
    assert!(decoded.remote_endpoint.is_some());
    let endpoint = decoded.remote_endpoint.unwrap();
    assert_eq!(endpoint.endpoint, "https://example.com/check");
    assert!(!endpoint.allow_fail);
    assert_eq!(endpoint.timeout, 5000);
}

#[test]
fn test_boost_rule_matches_multiple_targets_in_single_rule() {
    let addr1 = Address::random();
    let addr2 = Address::random();
    let addr3 = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("multi target".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr1:#x}"), format!("{addr2:#x}")],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    let tx1 = make_mock_tx(addr1, Address::random(), []);
    let tx2 = make_mock_tx(addr2, Address::random(), []);
    let tx3 = make_mock_tx(addr3, Address::random(), []); // Not in target list

    assert_eq!(ruleset.score_transaction(&tx1), 100);
    assert_eq!(ruleset.score_transaction(&tx2), 100);
    assert_eq!(ruleset.score_transaction(&tx3), 0);
}

#[test]
fn test_boost_rule_to_match_type_with_multiple_targets() {
    let dest1 = Address::random();
    let dest2 = Address::random();
    let other_dest = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("multi dest".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{dest1:#x}"), format!("{dest2:#x}")],
        aliases: vec![],
        weight: 50,
        ..Default::default()
    });

    let tx1 = make_mock_tx(Address::random(), dest1, []);
    let tx2 = make_mock_tx(Address::random(), dest2, []);
    let tx3 = make_mock_tx(Address::random(), other_dest, []);

    assert_eq!(ruleset.score_transaction(&tx1), 50);
    assert_eq!(ruleset.score_transaction(&tx2), 50);
    assert_eq!(ruleset.score_transaction(&tx3), 0);
}

#[test]
fn test_invalid_address_in_target_is_ignored() {
    let valid_addr = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("mixed targets".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![
            "invalid_address".to_string(), // Invalid
            "0xnotanaddress".to_string(),  // Invalid
            format!("{valid_addr:#x}"),    // Valid
            "".to_string(),                // Empty/invalid
        ],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    let tx_valid = make_mock_tx(valid_addr, Address::random(), []);
    let tx_other = make_mock_tx(Address::random(), Address::random(), []);

    // Only valid address should match
    assert_eq!(ruleset.score_transaction(&tx_valid), 100);
    assert_eq!(ruleset.score_transaction(&tx_other), 0);
}

#[test]
fn test_nonexistent_alias_group_is_ignored() {
    let sender = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("with nonexistent alias".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["nonexistent_group".into()], // Group doesn't exist
        weight: 100,
        ..Default::default()
    });

    let tx = make_mock_tx(sender, Address::random(), []);
    // Should not match since alias group doesn't exist
    assert_eq!(ruleset.score_transaction(&tx), 0);
}

#[test]
fn test_empty_alias_group() {
    let sender = Address::random();

    let mut ruleset = RuleSet::default();
    // Insert an empty group
    ruleset
        .aliases
        .groups
        .insert("empty_group".into(), std::collections::HashSet::new());
    ruleset.rules.boost.push(BoostRule {
        name: Some("empty alias group".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["empty_group".into()],
        weight: 100,
        ..Default::default()
    });

    let tx = make_mock_tx(sender, Address::random(), []);
    // Empty group should not match anything
    assert_eq!(ruleset.score_transaction(&tx), 0);
}

#[test]
fn test_selector_input_longer_than_4_bytes() {
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0x12345678".to_string()],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    // Input with selector + additional data
    let tx_with_data = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb, 0xcc, 0xdd], // Extra bytes after selector
    );

    // Should still match on first 4 bytes
    assert_eq!(ruleset.score_transaction(&tx_with_data), 100);
}

#[test]
fn test_selector_matching_mixed_case_rule_target() {
    let mut ruleset = RuleSet::default();
    // Rule with mixed case selector
    ruleset.rules.boost.push(BoostRule {
        name: Some("mixed case selector".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec!["0xAbCdEf12".to_string()], // Mixed case
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    let tx = make_mock_tx(
        Address::random(),
        Address::random(),
        &[0xab, 0xcd, 0xef, 0x12],
    );

    // Should match case-insensitively
    assert_eq!(ruleset.score_transaction(&tx), 100);
}

#[test]
fn test_address_aliases_merge_extends_existing_group() {
    let addr1 = Address::random();
    let addr2 = Address::random();
    let addr3 = Address::random();

    let mut aliases1 = AddressAliases::new();
    aliases1.insert_group("group", vec![addr1, addr2]);

    let mut aliases2 = AddressAliases::new();
    aliases2.insert_group("group", vec![addr2, addr3]); // addr2 is duplicate

    aliases1.merge(&aliases2);

    let group = aliases1.groups.get("group").unwrap();
    assert!(group.contains(&addr1));
    assert!(group.contains(&addr2));
    assert!(group.contains(&addr3));
    assert_eq!(group.len(), 3);
}

#[test]
fn test_address_aliases_merge_adds_new_groups() {
    let addr1 = Address::random();
    let addr2 = Address::random();

    let mut aliases1 = AddressAliases::new();
    aliases1.insert_group("group1", vec![addr1]);

    let mut aliases2 = AddressAliases::new();
    aliases2.insert_group("group2", vec![addr2]);

    aliases1.merge(&aliases2);

    assert!(aliases1.groups.contains_key("group1"));
    assert!(aliases1.groups.contains_key("group2"));
}

#[test]
fn test_ruleset_merge_preserves_version_of_base() {
    let mut base = RuleSet::default();
    base.version = 5;

    let mut extra = RuleSet::default();
    extra.version = 10;
    extra.rules.boost.push(BoostRule {
        name: Some("extra rule".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec![],
        weight: 1,
        ..Default::default()
    });

    base.merge(&extra);

    // Version should remain from base (merge doesn't update version)
    assert_eq!(base.version, 5);
    assert_eq!(base.rules.boost.len(), 1);
}

#[test]
fn test_score_saturation_negative_overflow() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();

    // Add multiple rules with very negative weights that would underflow
    for _ in 0..10 {
        ruleset.rules.boost.push(BoostRule {
            name: Some("large negative".into()),
            description: None,
            match_type: MatchType::From,
            target: vec![format!("{sender:#x}")],
            aliases: vec![],
            weight: i64::MIN / 5, // Large negative
            ..Default::default()
        });
    }

    let tx = make_mock_tx(sender, Address::random(), []);
    let score = ruleset.score_transaction(&tx);

    // Should saturate to MIN, not underflow
    assert!(score >= i64::MIN);
    assert!(score < 0);
}

#[test]
fn test_addr_set_with_both_addresses_and_aliases() {
    let direct_addr = Address::random();
    let alias_addr = Address::random();
    let other_addr = Address::random();

    let mut aliases = AddressAliases::new();
    aliases.insert_group("vip", vec![alias_addr]);

    let addr_set = AddrSet {
        addresses: vec![direct_addr],
        aliases: vec!["vip".into()],
    };

    assert!(addr_set.contains(&direct_addr, &aliases));
    assert!(addr_set.contains(&alias_addr, &aliases));
    assert!(!addr_set.contains(&other_addr, &aliases));
}

#[test]
fn test_ruleset_yaml_deserialization() {
    let yaml = r#"
version: 3
aliases:
  vip_users:
    - "0x1234567890123456789012345678901234567890"
    - "0xabcdef0123456789abcdef0123456789abcdef01"
rules:
  deny:
    - name: "block bad actors"
      addresses:
        - "0xdeadbeef00000000000000000000000000000001"
  boost:
    - name: "vip boost"
      type: from
      aliases:
        - vip_users
      weight: 1000
"#;

    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.version, 3);
    assert_eq!(ruleset.rules.deny.len(), 1);
    assert_eq!(ruleset.rules.boost.len(), 1);
    assert!(ruleset.aliases.groups.contains_key("vip_users"));
    assert_eq!(ruleset.aliases.groups.get("vip_users").unwrap().len(), 2);
}

#[test]
fn test_ruleset_yaml_empty_rules_sections() {
    let yaml = r#"
version: 1
rules:
  deny: []
  boost: []
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.version, 1);
    assert!(ruleset.rules.deny.is_empty());
    assert!(ruleset.rules.boost.is_empty());
}

#[test]
fn test_ruleset_yaml_minimal() {
    // Minimal valid YAML - just empty
    let yaml = "";
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.version, 0);
    assert!(ruleset.rules.deny.is_empty());
    assert!(ruleset.rules.boost.is_empty());
}

#[test]
fn test_ruleset_yaml_only_version() {
    let yaml = "version: 42";
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.version, 42);
    assert!(ruleset.rules.deny.is_empty());
    assert!(ruleset.rules.boost.is_empty());
}

#[test]
fn test_ruleset_yaml_deny_rule_with_description() {
    let yaml = r#"
rules:
  deny:
    - name: "block spammers"
      description: "These addresses have been identified as spam sources"
      addresses:
        - "0x1111111111111111111111111111111111111111"
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.deny.len(), 1);
    assert_eq!(
        ruleset.rules.deny[0].name,
        Some("block spammers".to_string())
    );
    assert_eq!(
        ruleset.rules.deny[0].description,
        Some("These addresses have been identified as spam sources".to_string())
    );
}

#[test]
fn test_ruleset_yaml_boost_rule_all_match_types() {
    let yaml = r#"
rules:
  boost:
    - name: "from match"
      type: from
      target:
        - "0x1111111111111111111111111111111111111111"
      weight: 100
    - name: "to match"
      type: to
      target:
        - "0x2222222222222222222222222222222222222222"
      weight: 200
    - name: "selector match"
      type: selector
      target:
        - "0x12345678"
      weight: 300
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.boost.len(), 3);
    assert_eq!(ruleset.rules.boost[0].match_type, MatchType::From);
    assert_eq!(ruleset.rules.boost[1].match_type, MatchType::To);
    assert_eq!(ruleset.rules.boost[2].match_type, MatchType::Selector);
}

#[test]
fn test_ruleset_yaml_boost_rule_with_aliases_and_targets() {
    let yaml = r#"
aliases:
  group1:
    - "0x1111111111111111111111111111111111111111"
rules:
  boost:
    - name: "mixed"
      type: from
      target:
        - "0x2222222222222222222222222222222222222222"
      aliases:
        - group1
      weight: 50
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.boost.len(), 1);
    assert_eq!(ruleset.rules.boost[0].target.len(), 1);
    assert_eq!(ruleset.rules.boost[0].aliases.len(), 1);
}

#[test]
fn test_ruleset_yaml_negative_weight() {
    let yaml = r#"
rules:
  boost:
    - name: "penalize"
      type: from
      target:
        - "0x1111111111111111111111111111111111111111"
      weight: -500
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.boost[0].weight, -500);
}

#[test]
fn test_ruleset_yaml_multiple_aliases_groups() {
    let yaml = r#"
aliases:
  tier1:
    - "0x1111111111111111111111111111111111111111"
  tier2:
    - "0x2222222222222222222222222222222222222222"
    - "0x3333333333333333333333333333333333333333"
  empty_group: []
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.aliases.groups.len(), 3);
    assert_eq!(ruleset.aliases.groups.get("tier1").unwrap().len(), 1);
    assert_eq!(ruleset.aliases.groups.get("tier2").unwrap().len(), 2);
    assert_eq!(ruleset.aliases.groups.get("empty_group").unwrap().len(), 0);
}

#[test]
fn test_ruleset_yaml_deny_with_remote_endpoint() {
    let yaml = r#"
rules:
  deny:
    - name: "external check"
      addresses: []
      remote_endpoint:
        endpoint: "https://api.example.com/check"
        allow_fail: false
        timeout: 5000
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.deny.len(), 1);
    let endpoint = ruleset.rules.deny[0].remote_endpoint.as_ref().unwrap();
    assert_eq!(endpoint.endpoint, "https://api.example.com/check");
    assert!(!endpoint.allow_fail);
    assert_eq!(endpoint.timeout, 5000);
}

#[test]
fn test_ruleset_yaml_invalid_match_type_fails() {
    let yaml = r#"
rules:
  boost:
    - name: "invalid"
      type: invalid_type
      target: []
      weight: 0
"#;
    let result: Result<RuleSet, _> = serde_yaml::from_str(yaml);
    assert!(result.is_err());
}

#[test]
fn test_ruleset_yaml_addresses_with_checksummed_format() {
    // Test that checksummed addresses (mixed case) are handled
    let yaml = r#"
aliases:
  checksummed:
    - "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.aliases.groups.get("checksummed").unwrap().len(), 1);
}

#[test]
fn test_ruleset_yaml_selector_formats() {
    let yaml = r#"
rules:
  boost:
    - name: "with 0x"
      type: selector
      target:
        - "0x12345678"
      weight: 100
    - name: "without 0x"
      type: selector
      target:
        - "abcdef12"
      weight: 200
"#;
    let ruleset: RuleSet = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(ruleset.rules.boost.len(), 2);
    assert_eq!(ruleset.rules.boost[0].target[0], "0x12345678");
    assert_eq!(ruleset.rules.boost[1].target[0], "abcdef12");
}

#[test]
fn test_match_type_serialization() {
    let from_json = serde_json::to_string(&MatchType::From).unwrap();
    let to_json = serde_json::to_string(&MatchType::To).unwrap();
    let selector_json = serde_json::to_string(&MatchType::Selector).unwrap();

    assert_eq!(from_json, "\"from\"");
    assert_eq!(to_json, "\"to\"");
    assert_eq!(selector_json, "\"selector\"");

    let from: MatchType = serde_json::from_str("\"from\"").unwrap();
    let to: MatchType = serde_json::from_str("\"to\"").unwrap();
    let selector: MatchType = serde_json::from_str("\"selector\"").unwrap();

    assert_eq!(from, MatchType::From);
    assert_eq!(to, MatchType::To);
    assert_eq!(selector, MatchType::Selector);
}

#[test]
#[serial]
fn test_global_ruleset_persists_boost_rules() {
    reset_global_rules();
    let sender = Address::random();
    let mut initial_ruleset = RuleSet::default();
    initial_ruleset.rules.boost.push(BoostRule {
        name: Some("initial".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender:#x}")],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    set_global_ruleset(initial_ruleset);

    let tx = make_mock_tx(sender, Address::random(), []);
    assert_eq!(global_ruleset().score_transaction(&tx), 100);
}

#[test]
#[serial]
fn test_set_global_ruleset_replaces_entirely() {
    reset_global_rules();
    let sender1 = Address::random();
    let sender2 = Address::random();

    let mut initial = RuleSet::default();
    initial.rules.boost.push(BoostRule {
        name: Some("initial".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender1:#x}")],
        aliases: vec![],
        weight: 50,
        ..Default::default()
    });

    set_global_ruleset(initial);

    let mut updated = RuleSet::default();
    updated.rules.boost.push(BoostRule {
        name: Some("updated".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender2:#x}")],
        aliases: vec![],
        weight: 200,
        ..Default::default()
    });

    set_global_ruleset(updated);

    let tx1 = make_mock_tx(sender1, Address::random(), []);
    let tx2 = make_mock_tx(sender2, Address::random(), []);

    // Old sender should no longer match
    assert_eq!(global_ruleset().score_transaction(&tx1), 0);
    // New sender should match
    assert_eq!(global_ruleset().score_transaction(&tx2), 200);
}

#[test]
fn test_rule_fetcher_empty_registries() {
    let fetcher = RuleFetcher::new();
    let result = block_on(fetcher.fetch_all());
    assert!(result.is_success());
    assert!(result.ruleset.rules.deny.is_empty());
    assert!(result.ruleset.rules.boost.is_empty());
}

#[test]
fn test_rule_fetcher_default() {
    let fetcher = RuleFetcher::default();
    let result = block_on(fetcher.fetch_all());
    assert!(result.is_success());
    assert!(result.ruleset.rules.deny.is_empty());
}

#[test]
fn test_addr_set_default() {
    let addr_set = AddrSet::default();
    assert!(addr_set.addresses.is_empty());
    assert!(addr_set.aliases.is_empty());
}

#[test]
fn test_ruleset_new() {
    let ruleset = RuleSet::new();
    assert_eq!(ruleset.version, 0);
    assert!(ruleset.rules.deny.is_empty());
    assert!(ruleset.rules.boost.is_empty());
    assert!(ruleset.aliases.groups.is_empty());
}

#[test]
fn test_address_aliases_new() {
    let aliases = AddressAliases::new();
    assert!(aliases.groups.is_empty());
}

#[test]
fn test_address_aliases_get_group_nonexistent() {
    let aliases = AddressAliases::new();
    assert!(aliases.groups.get("nonexistent").is_none());
}

#[test]
fn test_address_aliases_contains_nonexistent_group() {
    let aliases = AddressAliases::new();
    assert!(!aliases.contains("nonexistent", &Address::random()));
}

#[test]
fn test_boost_rule_from_match_returns_early_on_first_target_match() {
    // Verifies short-circuit behavior - once a target matches, we don't check aliases
    let sender = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("target first".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender:#x}")],
        aliases: vec!["nonexistent".into()], // This alias doesn't exist but shouldn't matter
        weight: 100,
        ..Default::default()
    });

    let tx = make_mock_tx(sender, Address::random(), []);
    // Should still match because target is checked first
    assert_eq!(ruleset.score_transaction(&tx), 100);
}

#[test]
fn test_boost_rule_to_match_skips_create_transactions() {
    let target = Address::random();

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("to boost".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{target:#x}")],
        aliases: vec![],
        weight: 100,
        ..Default::default()
    });

    // Create a Create transaction using MockTransaction directly
    let mut inner =
        reth_transaction_pool::test_utils::MockTransaction::legacy().with_sender(Address::random());
    if let reth_transaction_pool::test_utils::MockTransaction::Legacy { to, .. } = &mut inner {
        *to = TxKind::Create;
    }
    let create_tx = MockFbTransaction {
        inner,
        reverted_hashes: None,
        flashblock_number_min: None,
        flashblock_number_max: None,
    };

    // To matching should not work on Create transactions
    assert_eq!(ruleset.score_transaction(&create_tx), 0);
}

#[test]
fn test_deny_rule_with_empty_addrs_denies_nothing() {
    let ruleset_with_empty_deny = RuleSet {
        version: 0,
        rules: crate::rules::Rules {
            deny: vec![DenyRule {
                name: Some("empty deny".into()),
                description: None,
                addrs: AddrSet::default(),
                remote_endpoint: None,
            }],
            boost: vec![],
        },
        aliases: AddressAliases::default(),
        hash: None,
    };

    // Should not deny any random address
    assert!(
        !ruleset_with_empty_deny.is_denied(&Address::random(), &TxKind::Call(Address::random()))
    );
    assert!(!ruleset_with_empty_deny.is_denied(&Address::random(), &TxKind::Create));
}

#[test]
fn test_is_restricted_fields_delegates_to_is_denied() {
    let sender = Address::random();
    let mut ruleset = RuleSet::default();
    ruleset.rules.deny.push(DenyRule {
        name: None,
        description: None,
        addrs: AddrSet {
            addresses: vec![sender],
            aliases: vec![],
        },
        remote_endpoint: None,
    });

    // is_restricted_fields should return true when is_denied returns true
    assert!(ruleset.is_restricted_fields(&sender, &TxKind::Call(Address::random()), &[]));
    // And false for non-denied
    assert!(!ruleset.is_restricted_fields(
        &Address::random(),
        &TxKind::Call(Address::random()),
        &[]
    ));
}

#[test]
#[serial]
fn test_validator_inserts_default_score_without_scoring_rules() {
    reset_global_rules();
    // No boost rules → has_scoring_rules() returns false

    let validator = RuleBasedValidator::new(PassthroughValidator::default());
    let tx = make_mock_tx(Address::random(), Address::random(), []);
    let tx_hash = *tx.hash();

    let outcome = block_on(validator.validate_transaction(TransactionOrigin::External, tx));
    assert!(
        matches!(outcome, TransactionValidationOutcome::Valid { .. }),
        "transaction should be valid"
    );

    // The new else branch should insert score 0 for valid txs without scoring rules
    assert_eq!(
        get_tx_score(&tx_hash),
        Some(0),
        "validator should insert score 0 when no scoring rules exist"
    );

    // Cleanup
    remove_tx_score(&tx_hash);
}
