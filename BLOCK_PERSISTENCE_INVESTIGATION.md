# Block Storage Persistence Investigation

## Problem Statement

Test `test_flashtestations_permit_block_proof_flashblocks` fails with:
```
The tee key is not registered
```

This happens in Block 2, trying to access storage that was written in Block 1.

## Test Sequence

**Block 1** (number=1):
- Flashblock 1-4: Deploy and initialize contracts
- Sets up flashtestation registry and builder policy
- "Canonical chain committed number=1" - Block committed to chain
- Gas: 8.13Mgas total

**Block 2** (number=2):
- Flashblock 1-4: Try to use the contracts
- Expects storage from Block 1 to be present
- **FAILS**: "The tee key is not registered"

## Key Question

If Block 1 was committed to the canonical chain, why doesn't Block 2 see the storage?

## Hypothesis

The test might be running in both sequential AND parallel modes:
1. Sequential mode builds Block 1 → works
2. Sequential mode builds Block 2 → works (finds storage)
3. Parallel mode builds Block 1 → executes but storage?
4. Parallel mode builds Block 2 → **FAILS** (no storage)

This would explain why we see "build_block AFTER cleanup: bundle_state has 0 accounts" - in parallel mode, the bundle_state is empty after cleanup.

## CRITICAL FINDING: State Not Persisting Between Blocks

### Evidence from Test Output

The test DOES use Block-STM (parallel mode):
```
execute_txs{num_txns=5 num_threads=16}
Block-STM conflict detected...
```

### The Real Problem: Transaction Validation Errors

Transactions in Block 2 are FAILING validation:
```
Error executing transaction txn_idx=1 error=transaction validation error: nonce 1 too high, expected 0
Error executing transaction txn_idx=2 error=nonce 2 too high, expected 0
Error executing transaction txn_idx=3 error=nonce 3 too high, expected 0
```

**This means**: Transactions expect nonce 1, 2, 3... but the account nonce is still 0!

### Why Nonces Are Wrong

The account should have nonce > 0 after Block 1's transactions. But in Block 2, the nonce is 0, indicating:

**The account state from Block 1 is NOT in the database when Block 2 starts!**

This proves storage/state is not persisting between blocks in parallel mode.

### Additional Resource Limit Errors

```
Block DA footprint limit exceeded: 3488000 > 2500000
Gas limit exceeded: 642860 + 4368317 > 5000000
```

These suggest Block 2 is reading stale resource counters from Block 1, or the limits are being checked incorrectly against cumulative values from both blocks.

## Root Cause Hypothesis

When Block 1 is built with parallel execution:
1. Transactions execute successfully
2. State changes are in `bundle_state`
3. Block 1 is committed to chain ("Canonical chain committed")
4. **BUT**: The `bundle_state` is empty after cleanup (`bundle_state has 0 accounts`)
5. State changes never make it to the database
6. Block 2 starts with stale state (nonce=0, no storage)

The issue is in how `bundle_state` is managed in parallel mode vs sequential mode.

## THE BUG FOUND! (payload.rs:1100-1359)

### The Fatal Sequence

```rust
Line 1090: let untouched_transition_state = state.transition_state.clone();  // Save original

Line 1100: state.merge_transitions(BundleRetention::Reverts);  // Merge bundle → transition
          // bundle_state changes are now in transition_state ✓

Line 1357: state.take_bundle();  // Clean up bundle_state (expected)

Line 1359: state.transition_state = untouched_transition_state;  // ← RESET! Loses all changes!
```

### Why This Destroys State

1. `merge_transitions()` correctly merges bundle_state into transition_state
2. State changes are now in transition_state (which persists to DB)
3. Then `state.transition_state = untouched_transition_state` **RESETS** it
4. All state changes are **LOST**
5. Nothing gets committed to the database
6. Next block sees old state (nonce=0, no storage)

### Why Line 1090/1359 Exist

Comment says: "We use it to preserve state, so we run merge_transitions on transition state at most once"

This was meant to prevent duplicate merges, but it's DESTROYING the state instead!

### The Fix

We should NOT reset transition_state after merging! The merged state needs to persist.

Either:
1. Remove line 1359 entirely (don't reset transition_state)
2. Only reset for non-final flashblocks (to allow accumulation across flashblocks)
