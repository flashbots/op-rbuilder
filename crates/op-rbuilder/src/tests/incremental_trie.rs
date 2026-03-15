//! Tests for incremental trie state root calculation across flashblock boundaries.
//!
//! Compares three state root computation strategies:
//!
//! 1. **Full (ground truth)**: `state_root_with_updates` on cumulative hashed state.
//! 2. **Incremental**: uses cached trie nodes from fb1 with only fb2's prefix sets.
//!    Can produce wrong roots when reverted slots leave stale hashes in cached branch nodes.
//! 3. **Incremental with cumulative prefix sets**: uses cached trie nodes with cumulative
//!    prefix sets from all prior flashblocks, forcing the walker to re-visit every modified path.

use alloy_primitives::{B256, U256, keccak256};
use proptest::prelude::*;
use reth_db::{tables, transaction::DbTxMut};
use reth_primitives_traits::{Account, StorageEntry};
use reth_provider::{StorageTrieWriter, TrieWriter, test_utils::create_test_provider_factory};
use reth_trie::{HashedPostState, HashedStorage, StateRoot, StorageRoot, TrieInput};
use reth_trie_db::{DatabaseStateRoot, DatabaseStorageRoot};

type InitialAccount = (B256, Account, Vec<(B256, U256)>);

/// Helper: insert an account and its storage into the DB.
fn insert_account(
    tx: &impl DbTxMut,
    hashed_address: B256,
    account: Account,
    storage: &[(B256, U256)],
) {
    tx.put::<tables::HashedAccounts>(hashed_address, account)
        .unwrap();
    for &(key, value) in storage {
        tx.put::<tables::HashedStorages>(hashed_address, StorageEntry { key, value })
            .unwrap();
    }
}

/// Result of simulating two flashblocks with different state root strategies.
struct FlashblockRoots {
    full: B256,
    full_per_fb: B256,
    incremental: B256,
    incremental_with_cumulative_prefix_sets: B256,
}

/// Simulates two flashblocks with a populated trie (DB has branch nodes from prior blocks).
/// Computes full, incremental, and incremental-with-cumulative-prefix-sets state roots.
fn simulate_flashblocks_with_trie(
    initial_accounts: &[InitialAccount],
    fb1_state: HashedPostState,
    fb2_cumulative_state: HashedPostState,
) -> FlashblockRoots {
    let factory = create_test_provider_factory();
    let tx = factory.provider_rw().unwrap();

    for (hashed_address, account, storage) in initial_accounts {
        insert_account(tx.tx_ref(), *hashed_address, *account, storage);
    }

    // Populate storage trie tables
    for (hashed_address, _, _) in initial_accounts {
        let (_, _, storage_updates) = StorageRoot::from_tx_hashed(tx.tx_ref(), *hashed_address)
            .root_with_updates()
            .unwrap();
        let sorted_updates = storage_updates.into_sorted();
        tx.write_storage_trie_updates_sorted(core::iter::once((hashed_address, &sorted_updates)))
            .unwrap();
    }

    // Populate account trie table
    let (_initial_root, account_trie_updates) =
        StateRoot::from_tx(tx.tx_ref()).root_with_updates().unwrap();
    tx.write_trie_updates(account_trie_updates).unwrap();
    tx.commit().unwrap();

    let tx = factory.provider_rw().unwrap();

    // Full (ground truth)
    let fb2_sorted = fb2_cumulative_state.clone().into_sorted();
    let (full_root, _) = StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb2_sorted).unwrap();

    // Full per-flashblock
    let fb1_prefix_sets_for_fix = fb1_state.construct_prefix_sets();
    let fb1_sorted = fb1_state.into_sorted();
    let (full_per_fb_root, _) =
        StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb2_sorted).unwrap();
    assert_eq!(
        full_root, full_per_fb_root,
        "BUG: full-per-fb should always match ground truth"
    );

    // Incremental (only fb2 prefix sets)
    let (_, fb1_trie_updates) =
        StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb1_sorted).unwrap();
    let trie_input = TrieInput::new(
        fb1_trie_updates.clone(),
        fb2_cumulative_state.clone(),
        fb2_cumulative_state.construct_prefix_sets(),
    );
    let sorted_input = reth_trie::TrieInputSorted::from_unsorted(trie_input);
    let (incremental_root, _) =
        StateRoot::overlay_root_from_nodes_with_updates(tx.tx_ref(), sorted_input).unwrap();

    // Incremental with cumulative prefix sets
    let mut cumulative_prefix_sets = fb2_cumulative_state.construct_prefix_sets();
    cumulative_prefix_sets.extend(fb1_prefix_sets_for_fix);
    let trie_input = TrieInput::new(
        fb1_trie_updates,
        fb2_cumulative_state.clone(),
        cumulative_prefix_sets,
    );
    let sorted_input = reth_trie::TrieInputSorted::from_unsorted(trie_input);
    let (incremental_with_cumulative_prefix_sets_root, _) =
        StateRoot::overlay_root_from_nodes_with_updates(tx.tx_ref(), sorted_input).unwrap();

    FlashblockRoots {
        full: full_root,
        full_per_fb: full_per_fb_root,
        incremental: incremental_root,
        incremental_with_cumulative_prefix_sets: incremental_with_cumulative_prefix_sets_root,
    }
}

/// Simulates two flashblocks WITHOUT a populated trie.
fn simulate_flashblocks(
    initial_accounts: &[InitialAccount],
    fb1_state: HashedPostState,
    fb2_cumulative_state: HashedPostState,
) -> FlashblockRoots {
    let factory = create_test_provider_factory();
    let tx = factory.provider_rw().unwrap();

    for (hashed_address, account, storage) in initial_accounts {
        insert_account(tx.tx_ref(), *hashed_address, *account, storage);
    }
    tx.commit().unwrap();

    let tx = factory.provider_rw().unwrap();

    let fb2_sorted = fb2_cumulative_state.clone().into_sorted();
    let (full_root, _) = StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb2_sorted).unwrap();

    let fb1_prefix_sets_for_fix = fb1_state.construct_prefix_sets();
    let fb1_sorted = fb1_state.into_sorted();
    let (_fb1_full_root, _) =
        StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb1_sorted).unwrap();
    let (full_per_fb_root, _) =
        StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb2_sorted).unwrap();
    assert_eq!(
        full_root, full_per_fb_root,
        "BUG: full-per-fb should always match ground truth"
    );

    let (_, fb1_trie_updates) =
        StateRoot::overlay_root_with_updates(tx.tx_ref(), &fb1_sorted).unwrap();
    let trie_input = TrieInput::new(
        fb1_trie_updates.clone(),
        fb2_cumulative_state.clone(),
        fb2_cumulative_state.construct_prefix_sets(),
    );
    let sorted_input = reth_trie::TrieInputSorted::from_unsorted(trie_input);
    let (incremental_root, _) =
        StateRoot::overlay_root_from_nodes_with_updates(tx.tx_ref(), sorted_input).unwrap();

    let mut cumulative_prefix_sets = fb2_cumulative_state.construct_prefix_sets();
    cumulative_prefix_sets.extend(fb1_prefix_sets_for_fix);
    let trie_input = TrieInput::new(
        fb1_trie_updates,
        fb2_cumulative_state.clone(),
        cumulative_prefix_sets,
    );
    let sorted_input = reth_trie::TrieInputSorted::from_unsorted(trie_input);
    let (incremental_with_cumulative_prefix_sets_root, _) =
        StateRoot::overlay_root_from_nodes_with_updates(tx.tx_ref(), sorted_input).unwrap();

    FlashblockRoots {
        full: full_root,
        full_per_fb: full_per_fb_root,
        incremental: incremental_root,
        incremental_with_cumulative_prefix_sets: incremental_with_cumulative_prefix_sets_root,
    }
}

/// Asserts that the incremental path (without cumulative prefix sets) produces a WRONG
/// root, while the incremental path with cumulative prefix sets produces the CORRECT root.
fn assert_incremental_mismatch(roots: &FlashblockRoots) {
    assert_eq!(
        roots.full, roots.full_per_fb,
        "full-per-flashblock MUST match ground truth"
    );
    assert_ne!(
        roots.full, roots.incremental,
        "incremental should diverge from ground truth in this scenario, \
         but they matched. Full root: {:?}.",
        roots.full
    );
    assert_eq!(
        roots.full, roots.incremental_with_cumulative_prefix_sets,
        "incremental with cumulative prefix sets diverges from ground truth. \
         Full root: {:?}, Got: {:?}.",
        roots.full, roots.incremental_with_cumulative_prefix_sets
    );
}

/// Single contract with 20 storage slots (populated trie with branch nodes).
/// The branch node at 0xb has:
///   sub-nibble 1 (slots[0]): hash_mask NOT set (1 slot, leaf)
///   sub-nibble b (slots[13], slots[17]): hash_mask SET (2 slots = stored hash)
///
/// FB1 modifies slots[13] (in the hashed subtree). FB2 reverts it (absent from
/// cumulative state) and modifies slots[0] (same parent branch 0xb, different
/// sub-nibble). The walker descends into 0xb, gets the CACHED node from FB1,
/// and takes the stale hash for sub-nibble b → wrong root.
#[test]
fn test_storage_revert_to_original_with_populated_trie() {
    let hashed_address = keccak256([0x70; 20]);
    let slots: Vec<_> = (1u8..=20)
        .map(|i| keccak256(B256::with_last_byte(i)))
        .collect();

    let account = Account {
        nonce: 1,
        balance: U256::from(1000),
        bytecode_hash: Some(keccak256("contract")),
    };

    let initial_storage: Vec<_> = slots
        .iter()
        .enumerate()
        .map(|(i, s)| (*s, U256::from((i + 1) as u64 * 100)))
        .collect();
    let initial_accounts = vec![(hashed_address, account, initial_storage)];

    // FB1: Modify slots[13] (in the hashed subtree) from 1400→9999
    let mut fb1_state = HashedPostState::default();
    fb1_state.accounts.insert(hashed_address, Some(account));
    fb1_state.storages.insert(
        hashed_address,
        HashedStorage::from_iter(false, [(slots[13], U256::from(9999))]),
    );

    // FB2: slots[13] reverted (absent). slots[0] modified (same parent branch 0xb).
    let fb2_account = Account {
        nonce: 2,
        ..account
    };
    let mut fb2_cumulative = HashedPostState::default();
    fb2_cumulative
        .accounts
        .insert(hashed_address, Some(fb2_account));
    fb2_cumulative.storages.insert(
        hashed_address,
        HashedStorage::from_iter(false, [(slots[0], U256::from(777))]),
    );

    let roots = simulate_flashblocks_with_trie(&initial_accounts, fb1_state, fb2_cumulative);
    assert_incremental_mismatch(&roots);
}

// ---------------------------------------------------------------------------
// Fuzz tests: random flashblock states, full vs incremental
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Fuzz test: generate random two-flashblock scenarios and verify
    /// incremental state root matches full state root.
    #[test]
    fn fuzz_incremental_vs_full_state_root(
        seed in 0u64..100_000,
        num_accounts in 1usize..5,
        num_initial_slots in 0usize..6,
        num_fb1_changes in 1usize..4,
        num_fb2_changes in 1usize..4,
    ) {
        let mut rng_state = seed;
        let next = |s: &mut u64| -> u64 {
            *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *s >> 33
        };

        // Generate initial accounts
        let mut initial_accounts = Vec::new();
        let mut all_slots = Vec::new();
        for i in 0..num_accounts {
            let hashed_addr = keccak256(B256::with_last_byte(i as u8 + 1));
            let account = Account {
                nonce: next(&mut rng_state) % 100,
                balance: U256::from(next(&mut rng_state) % 100_000),
                bytecode_hash: if next(&mut rng_state) % 3 == 0 {
                    Some(keccak256(format!("code_{i}").as_bytes()))
                } else {
                    None
                },
            };
            let mut storage = Vec::new();
            let mut slots = Vec::new();
            for s in 0..num_initial_slots {
                let slot = keccak256(B256::from(U256::from(i * 100 + s)));
                slots.push(slot);
                storage.push((slot, U256::from(next(&mut rng_state) % 10_000 + 1)));
            }
            initial_accounts.push((hashed_addr, account, storage));
            all_slots.push(slots);
        }

        // Generate FB1 state changes
        let mut fb1_state = HashedPostState::default();
        for _ in 0..num_fb1_changes {
            let acct_idx = (next(&mut rng_state) as usize) % num_accounts;
            let (hashed_addr, account, _) = &initial_accounts[acct_idx];
            let new_account = Account {
                nonce: account.nonce + next(&mut rng_state) % 10 + 1,
                ..*account
            };
            fb1_state.accounts.insert(*hashed_addr, Some(new_account));
            if !all_slots[acct_idx].is_empty() {
                let slot_idx = (next(&mut rng_state) as usize) % all_slots[acct_idx].len();
                let slot = all_slots[acct_idx][slot_idx];
                fb1_state.storages.insert(
                    *hashed_addr,
                    HashedStorage::from_iter(
                        false,
                        [(slot, U256::from(next(&mut rng_state) % 50_000 + 1))],
                    ),
                );
            }
        }

        // Generate FB2 cumulative state (superset of FB1 with additional changes)
        let mut fb2_cumulative = fb1_state.clone();
        for _ in 0..num_fb2_changes {
            let acct_idx = (next(&mut rng_state) as usize) % num_accounts;
            let (hashed_addr, account, _) = &initial_accounts[acct_idx];
            let existing = fb2_cumulative
                .accounts
                .get(hashed_addr)
                .copied()
                .flatten()
                .unwrap_or(*account);
            let new_account = Account {
                nonce: existing.nonce + next(&mut rng_state) % 5 + 1,
                ..existing
            };
            fb2_cumulative
                .accounts
                .insert(*hashed_addr, Some(new_account));
            if !all_slots[acct_idx].is_empty() {
                let slot_idx = (next(&mut rng_state) as usize) % all_slots[acct_idx].len();
                let slot = all_slots[acct_idx][slot_idx];
                fb2_cumulative.storages.insert(
                    *hashed_addr,
                    HashedStorage::from_iter(
                        false,
                        [(slot, U256::from(next(&mut rng_state) % 50_000 + 1))],
                    ),
                );
            }
        }

        let roots = simulate_flashblocks(&initial_accounts, fb1_state, fb2_cumulative);

        // Full-per-fb must always match (already asserted inside simulate_flashblocks)
        // Incremental should match full (no populated trie = no stored hashes = no stale nodes)
        prop_assert_eq!(
            roots.full, roots.incremental,
            "Fuzz: incremental diverged from full (seed={})", seed
        );
        prop_assert_eq!(
            roots.full, roots.incremental_with_cumulative_prefix_sets,
            "Fuzz: incremental_with_cumulative_prefix_sets diverged from full (seed={})", seed
        );
    }
}
