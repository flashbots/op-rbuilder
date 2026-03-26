//! Tests for incremental trie state root calculation across flashblock boundaries.
//!
//! These tests call `compute_state_root` — the same function used in the production
//! payload builder — to ensure correctness of incremental state root calculation.
//!
//! Compares three state root computation strategies:
//!
//! 1. **Full (ground truth)**: `compute_state_root` with no prior trie / incremental disabled.
//! 2. **Incremental (buggy)**: `compute_state_root` with prior trie but only current prefix sets
//!    (simulated by discarding cumulative prefix sets between calls).
//! 3. **Incremental with cumulative prefix sets**: `compute_state_root` with cumulative prefix
//!    sets carried forward — the correct production path.

use alloy_primitives::{B256, U256, keccak256};
use proptest::prelude::*;
use reth_db::{tables, transaction::DbTxMut};
use reth_primitives_traits::{Account, StorageEntry};
use reth_provider::{
    DatabaseProviderFactory, LatestStateProvider, StorageTrieWriter, TrieWriter,
    test_utils::create_test_provider_factory,
};
use reth_trie::{HashedPostState, HashedStorage, StateRoot};
use reth_trie_db::{DatabaseStateRoot, DatabaseStorageRoot};

use crate::builder::state_root::compute_state_root;

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
    incremental_buggy: B256,
    incremental_fixed: B256,
}

/// Simulates two flashblocks with a populated trie (DB has branch nodes from prior blocks).
///
/// Uses `compute_state_root` for both full and incremental paths, exercising
/// the exact same code path as production.
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
        let (_, _, storage_updates) =
            reth_trie::StorageRoot::from_tx_hashed(tx.tx_ref(), *hashed_address)
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

    // Full (ground truth): compute with no prior trie
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let full_result =
        compute_state_root(&latest, fb2_cumulative_state.clone(), None, None, false).unwrap();

    // FB1 incremental: compute state root after first flashblock
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let fb1_result = compute_state_root(&latest, fb1_state, None, None, false).unwrap();

    // Incremental (buggy): use prior trie but discard cumulative prefix sets
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let buggy_result = compute_state_root(
        &latest,
        fb2_cumulative_state.clone(),
        Some(&fb1_result.trie_updates),
        None, // no cumulative prefix sets — this is the bug
        true,
    )
    .unwrap();

    // Incremental (fixed): use prior trie WITH cumulative prefix sets
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let fixed_result = compute_state_root(
        &latest,
        fb2_cumulative_state,
        Some(&fb1_result.trie_updates),
        Some(fb1_result.cumulative_prefix_sets),
        true,
    )
    .unwrap();

    FlashblockRoots {
        full: full_result.state_root,
        incremental_buggy: buggy_result.state_root,
        incremental_fixed: fixed_result.state_root,
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

    // Full (ground truth)
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let full_result =
        compute_state_root(&latest, fb2_cumulative_state.clone(), None, None, false).unwrap();

    // FB1
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let fb1_result = compute_state_root(&latest, fb1_state, None, None, false).unwrap();

    // Incremental (buggy)
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let buggy_result = compute_state_root(
        &latest,
        fb2_cumulative_state.clone(),
        Some(&fb1_result.trie_updates),
        None,
        true,
    )
    .unwrap();

    // Incremental (fixed)
    let provider = factory.database_provider_ro().unwrap();
    let latest = LatestStateProvider::new(provider);
    let fixed_result = compute_state_root(
        &latest,
        fb2_cumulative_state,
        Some(&fb1_result.trie_updates),
        Some(fb1_result.cumulative_prefix_sets),
        true,
    )
    .unwrap();

    FlashblockRoots {
        full: full_result.state_root,
        incremental_buggy: buggy_result.state_root,
        incremental_fixed: fixed_result.state_root,
    }
}

/// Asserts that the incremental path (without cumulative prefix sets) produces a WRONG
/// root, while the incremental path with cumulative prefix sets produces the CORRECT root.
fn assert_incremental_mismatch(roots: &FlashblockRoots) {
    assert_ne!(
        roots.full, roots.incremental_buggy,
        "incremental (buggy) should diverge from ground truth in this scenario, \
         but they matched. Full root: {:?}.",
        roots.full
    );
    assert_eq!(
        roots.full, roots.incremental_fixed,
        "incremental with cumulative prefix sets diverges from ground truth. \
         Full root: {:?}, Got: {:?}.",
        roots.full, roots.incremental_fixed
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

        // Without populated trie, incremental should match full
        // (no stored hashes = no stale nodes)
        prop_assert_eq!(
            roots.full, roots.incremental_buggy,
            "Fuzz: incremental diverged from full (seed={})", seed
        );
        prop_assert_eq!(
            roots.full, roots.incremental_fixed,
            "Fuzz: incremental_with_cumulative_prefix_sets diverged from full (seed={})", seed
        );
    }
}
