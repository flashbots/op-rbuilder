//! State root computation for flashblocks.
//!
//! [`StateRootCalculator`] manages state root computation across a sequence of
//! flashblocks. The first call computes from scratch; subsequent calls use the
//! cached trie for incremental computation.

use alloy_primitives::B256;
use reth_provider::{ProviderError, StateRootProvider};
use reth_trie::{HashedPostState, TrieInput, prefix_set::TriePrefixSetsMut, updates::TrieUpdates};
use std::sync::Arc;

/// Output of [`StateRootCalculator::compute`].
pub struct StateRootOutput {
    /// The computed state root hash.
    pub state_root: B256,
    /// Trie updates (shared with the calculator's internal cache).
    pub trie_updates: Arc<TrieUpdates>,
}

/// Manages state root computation across flashblocks.
///
/// When `incremental` is true, caches trie updates and cumulative prefix sets
/// so that each successive flashblock's state root can be computed
/// incrementally. The first call always computes from scratch; subsequent
/// calls reuse the cached trie.
///
/// When `incremental` is false, every call computes from scratch (no caching).
///
/// When computing incrementally, current prefix sets are extended with
/// cumulative prefix sets from all prior flashblocks so the trie walker
/// re-visits every previously modified path — preventing stale cached hashes
/// from reverted storage slots.
#[derive(Clone, Debug, Default)]
pub struct StateRootCalculator {
    incremental: bool,
    prev_trie_updates: Option<Arc<TrieUpdates>>,
    cumulative_prefix_sets: Option<TriePrefixSetsMut>,
}

impl StateRootCalculator {
    pub fn new(incremental: bool) -> Self {
        Self {
            incremental,
            prev_trie_updates: None,
            cumulative_prefix_sets: None,
        }
    }

    /// Whether the next [`Self::compute`] call will use cached trie state.
    pub fn has_cached_trie(&self) -> bool {
        self.prev_trie_updates.is_some()
    }

    /// Compute the state root, using the incremental path if a prior trie is cached.
    ///
    /// Updates internal state so the next call can build on this result.
    pub fn compute(
        &mut self,
        state_provider: &(impl StateRootProvider + ?Sized),
        hashed_state: HashedPostState,
    ) -> Result<StateRootOutput, ProviderError> {
        if !self.incremental {
            let (state_root, trie_updates) =
                state_provider.state_root_with_updates(hashed_state)?;
            return Ok(StateRootOutput {
                state_root,
                trie_updates: Arc::new(trie_updates),
            });
        }

        // Incremental path: build cumulative prefix sets (seed on the first
        // call, extend on subsequent calls) so reverted slots in a later
        // flashblock force the walker to re-visit previously modified
        // subtrees and invalidate their stale cached hashes.
        let mut prefix_sets = hashed_state.construct_prefix_sets();
        if let Some(prev_sets) = self.cumulative_prefix_sets.take() {
            prefix_sets.extend(prev_sets);
        }
        let cumulative = prefix_sets.clone();

        let (state_root, trie_updates) = if let Some(prev_trie) = &self.prev_trie_updates {
            let trie_input = TrieInput::new(prev_trie.as_ref().clone(), hashed_state, prefix_sets);
            state_provider.state_root_from_nodes_with_updates(trie_input)?
        } else {
            // First call: full computation that seeds the cache for subsequent calls.
            state_provider.state_root_with_updates(hashed_state)?
        };

        let trie_updates = Arc::new(trie_updates);
        self.prev_trie_updates = Some(Arc::clone(&trie_updates));
        self.cumulative_prefix_sets = Some(cumulative);

        Ok(StateRootOutput {
            state_root,
            trie_updates,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, keccak256};
    use proptest::prelude::*;
    use reth_db::{tables, transaction::DbTxMut};
    use reth_primitives_traits::{Account, StorageEntry};
    use reth_provider::{
        DatabaseProviderFactory, LatestStateProvider, StorageTrieWriter, TrieWriter,
        test_utils::create_test_provider_factory,
    };
    use reth_trie::{HashedStorage, StateRoot, StorageRoot};
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

    /// Simulates two flashblocks and returns (full_root, incremental_root).
    ///
    /// When `populate_trie` is true, the DB is seeded with branch nodes from a
    /// prior trie computation (mimicking a node that has been running for a
    /// while). When false, only hashed account/storage rows are inserted.
    fn simulate_flashblocks(
        initial_accounts: &[InitialAccount],
        fb1_state: HashedPostState,
        fb2_cumulative_state: HashedPostState,
        populate_trie: bool,
    ) -> (B256, B256) {
        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap();

        for (hashed_address, account, storage) in initial_accounts {
            insert_account(tx.tx_ref(), *hashed_address, *account, storage);
        }

        if populate_trie {
            for (hashed_address, _, _) in initial_accounts {
                let (_, _, storage_updates) =
                    StorageRoot::from_tx_hashed(tx.tx_ref(), *hashed_address)
                        .root_with_updates()
                        .unwrap();
                let sorted_updates = storage_updates.into_sorted();
                tx.write_storage_trie_updates_sorted(core::iter::once((
                    hashed_address,
                    &sorted_updates,
                )))
                .unwrap();
            }

            let (_initial_root, account_trie_updates) = StateRoot::from_tx(tx.tx_ref())
                .root_with_updates()
                .unwrap();
            tx.write_trie_updates(account_trie_updates).unwrap();
        }

        tx.commit().unwrap();

        // Full (ground truth): fresh calculator, single call
        let provider = factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        let full = StateRootCalculator::new(false)
            .compute(&latest, fb2_cumulative_state.clone())
            .unwrap();

        // Incremental: calculator across both flashblocks
        let mut calc = StateRootCalculator::new(true);

        let provider = factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        calc.compute(&latest, fb1_state).unwrap();

        let provider = factory.database_provider_ro().unwrap();
        let latest = LatestStateProvider::new(provider);
        let incremental = calc.compute(&latest, fb2_cumulative_state).unwrap();

        (full.state_root, incremental.state_root)
    }

    /// Single contract with 20 storage slots (populated trie with branch nodes).
    ///
    /// FB1 modifies slots[13] (in a hashed subtree under branch 0xb). FB2 reverts
    /// it (absent from cumulative state) and modifies slots[0] (same parent branch,
    /// different sub-nibble). Without cumulative prefix sets the walker would skip
    /// the reverted subtree and use the stale cached hash → wrong root.
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

        let (full, incremental) =
            simulate_flashblocks(&initial_accounts, fb1_state, fb2_cumulative, true);
        assert_eq!(
            full, incremental,
            "incremental state root diverges from ground truth. \
             Full: {:?}, Incremental: {:?}.",
            full, incremental
        );
    }

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

            let (full, incremental) =
                simulate_flashblocks(&initial_accounts, fb1_state, fb2_cumulative, false);
            prop_assert_eq!(
                full, incremental,
                "Fuzz: incremental diverged from full (seed={})", seed
            );
        }
    }
}
