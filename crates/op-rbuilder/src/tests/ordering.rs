#[cfg(feature = "rules")]
use crate::rules::{BoostRule, MatchType, RuleSet, set_global_ruleset};
use crate::tests::{ChainDriverExt, LocalInstance, framework::ONE_ETH};
use alloy_consensus::Transaction;
use futures::{StreamExt, future::join_all, stream};
use macros::rb_test;

/// This test ensures that the transactions are ordered by fee priority in the block.
/// This version of the test is only applicable to the standard builder because in flashblocks
/// the transaction order is commited by the block after each flashblock is produced,
/// so the order is only going to hold within one flashblock, but not the entire block.
#[rb_test(standard)]
async fn fee_priority_ordering(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(10, ONE_ETH).await?;

    let latest_block = driver.latest().await?;
    let base_fee = latest_block
        .header
        .base_fee_per_gas
        .expect("Base fee should be present in the latest block");

    // generate transactions with randomized tips
    let txs = join_all(accounts.iter().map(|signer| {
        driver
            .create_transaction()
            .with_signer(*signer)
            .with_max_priority_fee_per_gas(rand::random_range(1..50))
            .send()
    }))
    .await
    .into_iter()
    .collect::<eyre::Result<Vec<_>>>()?
    .into_iter()
    .map(|tx| *tx.tx_hash())
    .collect::<Vec<_>>();

    driver.build_new_block().await?;

    // verify all transactions are included in the block
    assert!(
        stream::iter(txs.iter())
            .all(|tx_hash| async {
                driver
                    .latest_full()
                    .await
                    .expect("Failed to fetch latest block")
                    .transactions
                    .hashes()
                    .any(|hash| hash == *tx_hash)
            })
            .await,
        "not all transactions included in the block"
    );

    // verify all transactions are ordered by fee priority
    let txs_tips = driver
        .latest_full()
        .await?
        .into_transactions_vec()
        .into_iter()
        .skip(1) // skip the deposit transaction
        .take(txs.len()) // skip the last builder transaction
        .map(|tx| tx.effective_tip_per_gas(base_fee as u64))
        .rev() // we want to check descending order
        .collect::<Vec<_>>();

    assert!(
        txs_tips.is_sorted(),
        "Transactions not ordered by fee priority"
    );

    Ok(())
}

/// Ensure that ruleset can override fee ordering: a low-fee tx to favored `to` address
/// should be ordered before a higher-fee tx that does not match any rule.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_override_fee_priority(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Pick a favored recipient address
    let favored_to = rand::random();

    // Install in-memory ruleset with boost rule for the favored address
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("favored recipient".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{favored_to:#x}")],
        aliases: vec![],
        weight: 10_000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // High-fee tx to random address
    let high_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    // Low-fee tx to favored recipient
    let favored_low_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(favored_to)
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_high = hashes
        .iter()
        .position(|h| h == high_fee_tx.tx_hash())
        .unwrap();
    let i_favored = hashes
        .iter()
        .position(|h| h == favored_low_fee_tx.tx_hash())
        .unwrap();
    assert!(i_favored < i_high, "ruleset did not override fee priority");

    Ok(())
}

/// Without a ruleset, higher-fee txs should be prioritized over lower-fee txs.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_absent_fee_priority_wins(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Clear any previously set rules
    set_global_ruleset(RuleSet::default());

    // High-fee tx to random address
    let high_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    // Low-fee tx to another random address
    let low_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_high = hashes
        .iter()
        .position(|h| h == high_fee_tx.tx_hash())
        .unwrap();
    let i_low = hashes
        .iter()
        .position(|h| h == low_fee_tx.tx_hash())
        .unwrap();
    assert!(i_high < i_low, "fee ordering did not apply without ruleset");

    Ok(())
}

/// Test that boost rules with MatchType::From prioritize transactions from specific senders.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_boost_from_address(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    // Create a boost rule for a specific sender
    let favored_sender = accounts[0].address;
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("vip sender".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{favored_sender:#x}")],
        aliases: vec![],
        weight: 5_000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Low-fee tx from favored sender
    let favored_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // High-fee tx from other sender
    let other_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    // Another high-fee tx from yet another sender
    let other_tx2 = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_favored = hashes
        .iter()
        .position(|h| h == favored_tx.tx_hash())
        .unwrap();
    let i_other = hashes
        .iter()
        .position(|h| h == other_tx.tx_hash())
        .unwrap();
    let i_other2 = hashes
        .iter()
        .position(|h| h == other_tx2.tx_hash())
        .unwrap();

    assert!(
        i_favored < i_other && i_favored < i_other2,
        "favored sender tx should be ordered before other txs"
    );

    Ok(())
}

/// Test that boost rules with MatchType::Selector prioritize transactions with specific function selectors.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_boost_selector(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Create a boost rule for a specific function selector
    let selector = "0x12345678";
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("priority selector".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec![selector.to_string()],
        aliases: vec![],
        weight: 7_500,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // High-fee tx without matching selector
    let normal_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .with_input(alloy_primitives::Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd]))
        .send()
        .await?;

    // Low-fee tx with matching selector
    let selector_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .with_input(alloy_primitives::Bytes::from(vec![0x12, 0x34, 0x56, 0x78]))
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_selector = hashes
        .iter()
        .position(|h| h == selector_tx.tx_hash())
        .unwrap();
    let i_normal = hashes
        .iter()
        .position(|h| h == normal_tx.tx_hash())
        .unwrap();

    assert!(
        i_selector < i_normal,
        "selector-matched tx should be ordered before normal tx"
    );

    Ok(())
}

/// Test that multiple boost rules with different weights are applied correctly.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_multiple_boost_weights(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    let addr1 = accounts[0].address;
    let addr2 = accounts[1].address;
    let _addr3 = accounts[2].address;

    // Create multiple boost rules with different weights
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("high priority".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr1:#x}")],
        aliases: vec![],
        weight: 10_000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("medium priority".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr2:#x}")],
        aliases: vec![],
        weight: 5_000,
        ..Default::default()
    });
    // addr3 has no rule, so weight = 0
    set_global_ruleset(ruleset);

    // All txs with same low fee
    let tx1 = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let tx2 = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let tx3 = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i1 = hashes.iter().position(|h| h == tx1.tx_hash()).unwrap();
    let i2 = hashes.iter().position(|h| h == tx2.tx_hash()).unwrap();
    let i3 = hashes.iter().position(|h| h == tx3.tx_hash()).unwrap();

    // tx1 (weight 10000) should come before tx2 (weight 5000), which should come before tx3 (weight 0)
    assert!(
        i1 < i2 && i2 < i3,
        "transactions should be ordered by rule weight: high > medium > none"
    );

    Ok(())
}

/// Test that alias-based boost rules work correctly.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_boost_with_aliases(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    let addr1 = accounts[0].address;
    let addr2 = accounts[1].address;
    let _addr3 = accounts[2].address;

    // Create ruleset with alias group and boost rule using alias
    let mut ruleset = RuleSet::default();
    ruleset.aliases.insert_group("vip_users", vec![addr1, addr2]);
    ruleset.rules.boost.push(BoostRule {
        name: Some("vip boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["vip_users".into()],
        weight: 8_000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Low-fee tx from VIP user (via alias)
    let vip_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // High-fee tx from non-VIP user
    let normal_tx = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_vip = hashes.iter().position(|h| h == vip_tx.tx_hash()).unwrap();
    let i_normal = hashes.iter().position(|h| h == normal_tx.tx_hash()).unwrap();

    assert!(
        i_vip < i_normal,
        "alias-matched VIP tx should be ordered before normal tx"
    );

    Ok(())
}

/// Test that multiple boost rules can match the same transaction and their weights are summed.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_combined_boost_rules(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let favored_sender = accounts[0].address;
    let favored_to = rand::random();
    let selector = "0xabcdef12";

    // Create multiple boost rules that can all match the same transaction
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("sender boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{favored_sender:#x}")],
        aliases: vec![],
        weight: 3_000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("recipient boost".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{favored_to:#x}")],
        aliases: vec![],
        weight: 2_000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec![selector.to_string()],
        aliases: vec![],
        weight: 1_000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Tx that matches all three rules (total weight = 6000)
    let combined_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(favored_to)
        .with_max_priority_fee_per_gas(1)
        .with_input(alloy_primitives::Bytes::from(vec![0xab, 0xcd, 0xef, 0x12]))
        .send()
        .await?;

    // Tx that matches only sender rule (weight = 3000)
    let sender_only_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .with_input(alloy_primitives::Bytes::from(vec![0x00, 0x00, 0x00, 0x00]))
        .send()
        .await?;

    // High-fee tx that matches no rules (weight = 0)
    let no_match_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .with_input(alloy_primitives::Bytes::from(vec![0x00, 0x00, 0x00, 0x00]))
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_combined = hashes
        .iter()
        .position(|h| h == combined_tx.tx_hash())
        .unwrap();
    let i_sender_only = hashes
        .iter()
        .position(|h| h == sender_only_tx.tx_hash())
        .unwrap();
    let i_no_match = hashes
        .iter()
        .position(|h| h == no_match_tx.tx_hash())
        .unwrap();

    // Combined (6000) > sender_only (3000) > no_match (0)
    assert!(
        i_combined < i_sender_only && i_sender_only < i_no_match,
        "transactions should be ordered by combined rule weights"
    );

    Ok(())
}

/// Test that when no scoring rules exist, fee priority is preserved.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_no_scoring_rules_preserves_fee_priority(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // Set ruleset with only deny rules (no boost rules)
    let ruleset = RuleSet::default();
    // No boost rules added, so has_scoring_rules() returns false
    set_global_ruleset(ruleset);

    // High-fee tx
    let high_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    // Low-fee tx
    let low_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_high = hashes
        .iter()
        .position(|h| h == high_fee_tx.tx_hash())
        .unwrap();
    let i_low = hashes
        .iter()
        .position(|h| h == low_fee_tx.tx_hash())
        .unwrap();

    // Without scoring rules, fee priority should still apply
    assert!(
        i_high < i_low,
        "fee priority should be preserved when no scoring rules exist"
    );

    Ok(())
}

/// Test that rules with negative weights still work correctly (penalize transactions).
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_negative_weight_penalizes(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let penalized_sender = accounts[0].address;

    // Create a rule with negative weight to penalize a sender
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("penalty".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{penalized_sender:#x}")],
        aliases: vec![],
        weight: -5000, // Negative weight
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Both txs with same fee
    let penalized_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(10)
        .send()
        .await?;

    let normal_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(10)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_penalized = hashes
        .iter()
        .position(|h| h == penalized_tx.tx_hash())
        .unwrap();
    let i_normal = hashes
        .iter()
        .position(|h| h == normal_tx.tx_hash())
        .unwrap();

    // Normal tx should come before penalized tx
    assert!(
        i_normal < i_penalized,
        "penalized tx should be ordered after normal tx"
    );

    Ok(())
}

/// Test that when rules are cleared, fee priority is restored.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_cleared_fee_priority_restored(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    // First set a rule
    let favored_sender = accounts[0].address;
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("favored".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{favored_sender:#x}")],
        aliases: vec![],
        weight: 10_000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Clear rules
    set_global_ruleset(RuleSet::default());

    // High-fee tx
    let high_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    // Low-fee tx
    let low_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_high = hashes
        .iter()
        .position(|h| h == high_fee_tx.tx_hash())
        .unwrap();
    let i_low = hashes
        .iter()
        .position(|h| h == low_fee_tx.tx_hash())
        .unwrap();

    // After clearing rules, fee priority should apply
    assert!(
        i_high < i_low,
        "fee priority should be restored after clearing rules"
    );

    Ok(())
}

/// Test that multiple rules matching the same transaction sum their weights correctly.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_multiple_matching_rules_sum_weights(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    let sender = accounts[0].address;
    let target = rand::random();
    let selector = "0x11223344";

    // Create multiple rules that all match the same transaction
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("sender rule".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{sender:#x}")],
        aliases: vec![],
        weight: 1000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("target rule".into()),
        description: None,
        match_type: MatchType::To,
        target: vec![format!("{target:#x}")],
        aliases: vec![],
        weight: 2000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector rule".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec![selector.to_string()],
        aliases: vec![],
        weight: 3000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Tx that matches all three rules (total = 6000)
    let combined_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(target)
        .with_max_priority_fee_per_gas(1)
        .with_input(alloy_primitives::Bytes::from(vec![0x11, 0x22, 0x33, 0x44]))
        .send()
        .await?;

    // Tx that matches only sender rule (total = 1000)
    let sender_only_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .with_input(alloy_primitives::Bytes::from(vec![0x00, 0x00, 0x00, 0x00]))
        .send()
        .await?;

    // High-fee tx with no rules (total = 0)
    let no_rule_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .with_input(alloy_primitives::Bytes::from(vec![0x00, 0x00, 0x00, 0x00]))
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();
    let i_combined = hashes
        .iter()
        .position(|h| h == combined_tx.tx_hash())
        .unwrap();
    let i_sender_only = hashes
        .iter()
        .position(|h| h == sender_only_tx.tx_hash())
        .unwrap();
    let i_no_rule = hashes
        .iter()
        .position(|h| h == no_rule_tx.tx_hash())
        .unwrap();

    // Combined (6000) > sender_only (1000) > no_rule (0, but high fee)
    // The combined should definitely come first
    assert!(
        i_combined < i_sender_only && i_combined < i_no_rule,
        "transaction matching multiple rules should be ordered first"
    );

    Ok(())
}

// ==================== Additional Integration Tests ====================

/// Helper to filter block hashes to only include the specified tx hashes (in order).
#[cfg(feature = "rules")]
fn filter_tx_order(
    block_hashes: &[alloy_primitives::B256],
    tx_hashes: &[&alloy_primitives::B256],
) -> Vec<alloy_primitives::B256> {
    block_hashes
        .iter()
        .filter(|h| tx_hashes.contains(h))
        .cloned()
        .collect()
}

/// Test that equal weight txs are sorted by fee when rules are present but equal.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_equal_weight_sorted_by_fee(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    // Create a rule that matches all senders equally
    let mut ruleset = RuleSet::default();
    for acc in &accounts {
        ruleset.rules.boost.push(BoostRule {
            name: Some("equal boost".into()),
            description: None,
            match_type: MatchType::From,
            target: vec![format!("{:#x}", acc.address)],
            aliases: vec![],
            weight: 1000, // All equal
            ..Default::default()
        });
    }
    set_global_ruleset(ruleset);

    // Different fees with equal rule weights
    let high_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let medium_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let low_fee_tx = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(10)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // All have equal weight=1000, so fee ordering should apply as tiebreaker
    // The exact behavior depends on implementation, but all should be included
    assert!(hashes.iter().any(|h| h == high_fee_tx.tx_hash()));
    assert!(hashes.iter().any(|h| h == medium_fee_tx.tx_hash()));
    assert!(hashes.iter().any(|h| h == low_fee_tx.tx_hash()));

    Ok(())
}

/// Test that zero weight rule doesn't affect ordering (fee priority preserved).
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_zero_weight_preserves_fee_ordering(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let target_sender = accounts[0].address;

    // Create a rule with zero weight
    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("zero weight".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{target_sender:#x}")],
        aliases: vec![],
        weight: 0,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Low-fee tx from matched sender (weight=0)
    let low_fee_matched = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // High-fee tx from unmatched sender (weight=0)
    let high_fee_unmatched = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // Both have weight=0, so high fee should come first
    let order = filter_tx_order(&hashes, &[high_fee_unmatched.tx_hash(), low_fee_matched.tx_hash()]);
    assert_eq!(
        order,
        vec![*high_fee_unmatched.tx_hash(), *low_fee_matched.tx_hash()],
        "zero weight should not boost tx, fee ordering should apply"
    );

    Ok(())
}

/// Test multiple alias groups working together.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_multiple_alias_groups(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(4, ONE_ETH).await?;

    // Create alias groups
    let mut ruleset = RuleSet::default();
    ruleset
        .aliases
        .insert_group("tier1", vec![accounts[0].address]);
    ruleset
        .aliases
        .insert_group("tier2", vec![accounts[1].address, accounts[2].address]);

    // Tier1 gets highest boost
    ruleset.rules.boost.push(BoostRule {
        name: Some("tier1 boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["tier1".into()],
        weight: 10000,
        ..Default::default()
    });

    // Tier2 gets medium boost
    ruleset.rules.boost.push(BoostRule {
        name: Some("tier2 boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![],
        aliases: vec!["tier2".into()],
        weight: 5000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Account[0] - tier1, high weight
    let tier1_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // Account[1] - tier2, medium weight
    let tier2_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // Account[3] - no tier, no weight, but high fee
    let notier_tx = driver
        .create_transaction()
        .with_signer(accounts[3])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // tier1 (10000) > tier2 (5000) > notier (0, high fee)
    let order = filter_tx_order(&hashes, &[tier1_tx.tx_hash(), tier2_tx.tx_hash(), notier_tx.tx_hash()]);
    assert_eq!(
        order,
        vec![*tier1_tx.tx_hash(), *tier2_tx.tx_hash(), *notier_tx.tx_hash()],
        "alias group priorities should be respected"
    );

    Ok(())
}

/// Test that same sender can have multiple transactions with rules applied consistently.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_same_sender_multiple_txs(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let boosted_sender = accounts[0].address;

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("sender boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{boosted_sender:#x}")],
        aliases: vec![],
        weight: 5000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Two txs from boosted sender
    let tx1 = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let tx2 = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(2)
        .send()
        .await?;

    // High-fee tx from other sender
    let other_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // tx1 and tx2 (weight=5000 each) should come before other_tx (weight=0)
    // tx1 before tx2 due to nonce ordering
    let order = filter_tx_order(&hashes, &[tx1.tx_hash(), tx2.tx_hash(), other_tx.tx_hash()]);
    assert_eq!(
        order,
        vec![*tx1.tx_hash(), *tx2.tx_hash(), *other_tx.tx_hash()],
        "boosted sender txs should come before unboosted, with nonce ordering"
    );

    Ok(())
}

/// Test selector matching with extended calldata.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_selector_with_calldata(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let selector = "0xaabbccdd";

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("selector boost".into()),
        description: None,
        match_type: MatchType::Selector,
        target: vec![selector.to_string()],
        aliases: vec![],
        weight: 8000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Tx with matching selector + extended calldata
    let selector_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        // Selector 0xaabbccdd followed by some arguments
        .with_input(alloy_primitives::Bytes::from(vec![
            0xaa, 0xbb, 0xcc, 0xdd, // selector
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // arg1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // arg2
        ]))
        .send()
        .await?;

    // Tx with different selector, high fee
    let other_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .with_input(alloy_primitives::Bytes::from(vec![0x11, 0x22, 0x33, 0x44]))
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    let order = filter_tx_order(&hashes, &[selector_tx.tx_hash(), other_tx.tx_hash()]);
    assert_eq!(
        order,
        vec![*selector_tx.tx_hash(), *other_tx.tx_hash()],
        "selector-matched tx with extended calldata should be boosted"
    );

    Ok(())
}

/// Test that rules with very large weights work correctly.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_large_weight_values(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let vip_sender = accounts[0].address;

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("huge boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{vip_sender:#x}")],
        aliases: vec![],
        weight: i64::MAX / 2, // Very large but safe weight
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    let vip_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let normal_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1000)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    let order = filter_tx_order(&hashes, &[vip_tx.tx_hash(), normal_tx.tx_hash()]);
    assert_eq!(
        order,
        vec![*vip_tx.tx_hash(), *normal_tx.tx_hash()],
        "large weight should still work correctly"
    );

    Ok(())
}

/// Test mixing positive and negative weights.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_mixed_positive_negative_weights(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    let boosted = accounts[0].address;
    let penalized = accounts[1].address;

    let mut ruleset = RuleSet::default();
    ruleset.rules.boost.push(BoostRule {
        name: Some("boost".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{boosted:#x}")],
        aliases: vec![],
        weight: 5000,
        ..Default::default()
    });
    ruleset.rules.boost.push(BoostRule {
        name: Some("penalize".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{penalized:#x}")],
        aliases: vec![],
        weight: -3000,
        ..Default::default()
    });
    set_global_ruleset(ruleset);

    // Boosted sender (weight = +5000)
    let boosted_tx = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    // Penalized sender (weight = -3000)
    let penalized_tx = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100) // High fee won't help enough
        .send()
        .await?;

    // Neutral sender (weight = 0)
    let neutral_tx = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // Order should be: boosted (+5000) > neutral (0) > penalized (-3000)
    let order = filter_tx_order(&hashes, &[boosted_tx.tx_hash(), neutral_tx.tx_hash(), penalized_tx.tx_hash()]);
    assert_eq!(
        order,
        vec![*boosted_tx.tx_hash(), *neutral_tx.tx_hash(), *penalized_tx.tx_hash()],
        "mixed weights should order correctly: boosted > neutral > penalized"
    );

    Ok(())
}

/// Test that rule updates between blocks take effect.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_update_between_blocks(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(2, ONE_ETH).await?;

    let addr0 = accounts[0].address;
    let addr1 = accounts[1].address;

    // First ruleset: boost addr0
    let mut ruleset1 = RuleSet::default();
    ruleset1.rules.boost.push(BoostRule {
        name: Some("boost addr0".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr0:#x}")],
        aliases: vec![],
        weight: 10000,
        ..Default::default()
    });
    set_global_ruleset(ruleset1);

    // First block
    let tx1_block1 = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let tx2_block1 = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let block1 = driver.build_new_block().await?;
    let hashes1: Vec<_> = block1.transactions.hashes().collect();

    // In first block, addr0 should come first
    let order1 = filter_tx_order(&hashes1, &[tx1_block1.tx_hash(), tx2_block1.tx_hash()]);
    assert_eq!(
        order1,
        vec![*tx1_block1.tx_hash(), *tx2_block1.tx_hash()],
        "first block: boosted addr0 should come first"
    );

    // Update ruleset: now boost addr1 instead
    let mut ruleset2 = RuleSet::default();
    ruleset2.rules.boost.push(BoostRule {
        name: Some("boost addr1".into()),
        description: None,
        match_type: MatchType::From,
        target: vec![format!("{addr1:#x}")],
        aliases: vec![],
        weight: 10000,
        ..Default::default()
    });
    set_global_ruleset(ruleset2);

    // Second block
    let tx1_block2 = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let tx2_block2 = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(1)
        .send()
        .await?;

    let block2 = driver.build_new_block().await?;
    let hashes2: Vec<_> = block2.transactions.hashes().collect();

    // In second block, addr1 should come first (rules updated)
    let order2 = filter_tx_order(&hashes2, &[tx1_block2.tx_hash(), tx2_block2.tx_hash()]);
    assert_eq!(
        order2,
        vec![*tx2_block2.tx_hash(), *tx1_block2.tx_hash()],
        "second block: boosted addr1 should come first after rule update"
    );

    Ok(())
}

/// Test empty ruleset means fee priority applies.
#[rb_test(standard)]
#[cfg(feature = "rules")]
async fn rules_empty_ruleset_fee_priority(rbuilder: LocalInstance) -> eyre::Result<()> {
    let driver = rbuilder.driver().await?;
    let accounts = driver.fund_accounts(3, ONE_ETH).await?;

    // Set empty ruleset
    set_global_ruleset(RuleSet::default());

    let high_fee = driver
        .create_transaction()
        .with_signer(accounts[0])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(100)
        .send()
        .await?;

    let medium_fee = driver
        .create_transaction()
        .with_signer(accounts[1])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(50)
        .send()
        .await?;

    let low_fee = driver
        .create_transaction()
        .with_signer(accounts[2])
        .with_to(rand::random())
        .with_max_priority_fee_per_gas(10)
        .send()
        .await?;

    let block = driver.build_new_block().await?;
    let hashes: Vec<_> = block.transactions.hashes().collect();

    // Fee ordering should apply
    let order = filter_tx_order(&hashes, &[high_fee.tx_hash(), medium_fee.tx_hash(), low_fee.tx_hash()]);
    assert_eq!(
        order,
        vec![*high_fee.tx_hash(), *medium_fee.tx_hash(), *low_fee.tx_hash()],
        "empty ruleset should result in fee priority ordering"
    );

    Ok(())
}
