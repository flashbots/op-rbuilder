//! Extracted state root computation for flashblocks.
//!
//! This module provides a single function that both the production payload builder
//! and tests/benchmarks call, ensuring they exercise the same code path.

use alloy_primitives::B256;
use reth_provider::{ProviderError, StateRootProvider};
use reth_trie::{HashedPostState, TrieInput, prefix_set::TriePrefixSetsMut, updates::TrieUpdates};

/// Result of a flashblock state root computation.
pub struct StateRootResult {
    /// The computed state root hash.
    pub state_root: B256,
    /// Trie updates produced (cached for the next flashblock).
    pub trie_updates: TrieUpdates,
    /// Cumulative prefix sets to carry forward to the next flashblock.
    pub cumulative_prefix_sets: TriePrefixSetsMut,
}

/// Computes the state root for a flashblock.
///
/// When `prev_trie_updates` is provided and `enable_incremental` is true,
/// performs an incremental calculation: current prefix sets are extended with
/// `prev_cumulative_prefix_sets` so the trie walker re-visits every path
/// modified in earlier flashblocks (preventing stale cached hashes from
/// reverted storage slots).
///
/// Otherwise falls back to a full state root calculation.
pub fn compute_state_root(
    state_provider: &(impl StateRootProvider + ?Sized),
    hashed_state: HashedPostState,
    prev_trie_updates: Option<&TrieUpdates>,
    prev_cumulative_prefix_sets: Option<TriePrefixSetsMut>,
    enable_incremental: bool,
) -> Result<StateRootResult, ProviderError> {
    if let Some(prev_trie) = prev_trie_updates
        && enable_incremental
    {
        // Incremental path: extend current prefix sets with cumulative sets
        // from all prior flashblocks so the walker re-visits every modified
        // path, even if a slot reverted.
        let mut prefix_sets = hashed_state.construct_prefix_sets();
        if let Some(prev_sets) = prev_cumulative_prefix_sets {
            prefix_sets.extend(prev_sets);
        }
        let cumulative_prefix_sets = prefix_sets.clone();

        let trie_input = TrieInput::new(prev_trie.clone(), hashed_state, prefix_sets);
        let (state_root, trie_updates) =
            state_provider.state_root_from_nodes_with_updates(trie_input)?;

        Ok(StateRootResult {
            state_root,
            trie_updates,
            cumulative_prefix_sets,
        })
    } else {
        // Full path: compute from scratch.
        let cumulative_prefix_sets = hashed_state.construct_prefix_sets();
        let (state_root, trie_updates) = state_provider.state_root_with_updates(hashed_state)?;

        Ok(StateRootResult {
            state_root,
            trie_updates,
            cumulative_prefix_sets,
        })
    }
}
