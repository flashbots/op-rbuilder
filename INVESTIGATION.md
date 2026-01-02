# Block-STM Storage Persistence Investigation

## The Problem

Test `test_flashtestations_permit_block_proof_flashblocks` fails in parallel mode (Block-STM) with:
```
The tee key is not registered
```

This indicates storage from smart contracts is not persisting.

## Root Cause: Missing Storage for Specific Contracts

### Affected Addresses

Storage is missing for these two contracts in parallel mode:
- **`0xa15bb66138824a1c7167f5e85b957d04dd34e468`** = `FLASHTESTATION_REGISTRY_ADDRESS` (missing 7 storage slots)
- **`0x8ce361602b935680e8dec218b820ff5056beb7af`** = `BLOCK_BUILDER_POLICY_ADDRESS` (missing 7 storage slots)

### Transaction Sequence

The test setup performs:
1. **Deploy** flashtestation registry contract → creates contract at `0xa15bb...`
2. **Initialize** registry (`init_flashtestation_registry_contract()`) → writes ~7 storage slots
3. **Deploy** builder policy contract → creates contract at `0x8ce361...`
4. **Initialize** policy (`init_builder_policy_contract()`) → writes ~7 storage slots
5. **Build block** with all transactions

### Observable Behavior

**Sequential Mode (WORKING):**
- Registry init tx: writes 7 storage slots ✓
- Policy init tx: writes 7 storage slots ✓
- Total: Both contracts have storage after initialization

**Parallel Mode (BROKEN):**
- Registry init tx: writes 0 storage slots ✗
- Policy init tx: writes 0 storage slots ✗
- Total: Neither contract has storage after initialization

Note: Another contract `0x700b6a60ce7eaaea56f065753d8dcb9653dbad35` DOES get its 21 storage slots in both modes.

## Hypothesis: Contract Deployment Dependencies

The initialization transactions **depend on** the deployed contract bytecode from the previous transaction.

### Possible Root Causes in Block-STM

1. **Contract code not visible to dependent transaction**
   - Deploy tx creates contract with bytecode
   - Init tx tries to call the contract
   - If bytecode isn't visible via VersionedDatabase, init tx might fail

2. **Missing code-read dependency tracking**
   - Block-STM tracks storage/balance/nonce reads for conflict detection
   - But does it track CODE reads (via EXTCODECOPY, EXTCODEHASH, CALL)?
   - If not, init tx might execute with stale (empty) code

3. **Shared code cache not populated correctly**
   - Block-STM has a `shared_code_cache` for deployed contracts
   - If deploy tx doesn't populate it correctly
   - Init tx won't find the code and might fail silently

4. **Transaction execution errors not propagating**
   - Init tx might be failing during execution
   - Error gets caught but tx is marked as "executed"
   - Result: 0 storage writes but no visible failure

## Evidence from Logging

### EVM State Returns
```
Sequential: evm.transact() returns state with 6 accounts, some with storage
Parallel: evm.transact() returns state with 2 accounts, no storage for init txs
```

### Why This Matters

Each Block-STM transaction execution should produce complete, up-to-date state due to:
- Optimistic execution with conflict detection
- Re-execution when conflicts detected
- Final committed results are validated

So if init tx state has 0 storage, it's not because of missing dependency resolution.
It's because **the init transaction itself didn't write storage during execution**.

## Latest Findings (2026-01-02)

### CodeHash Dependency Tracking is Working

Added logging confirms:
1. Deploy transactions (TX 0) successfully add code to shared_code_cache
2. Init transactions (TX 1) successfully read `CodeHash` from MVHashMap with proper version tracking
3. Example: `TX 1: Read CodeHash for mystery addr 0xa15bb..., hash=0x4d6e..., version=(0, 0)`

This means **dependency tracking via CodeHash is working correctly** - the user was right!

### The Real Problem: Init Transactions Use Too Little Gas

Init transactions complete "successfully" but use only **23000 gas**:
- Expected: Several hundred thousand gas (to write ~7 storage slots)
- Actual: 23000 gas (barely above the 21000 base cost)
- Result: Success=true but 0 storage writes

This suggests init transactions are:
1. Finding the contract address (reads CodeHash successfully)
2. Starting to execute
3. Failing very early before actual contract execution
4. Returning "success" but with no state changes

### No code_by_hash Calls Observed

Despite init transactions reading the CodeHash, there are NO `code_by_hash()` calls in the logs. This suggests:
- Either the contract code isn't being accessed at all
- Or the code lookup is happening through a different path

### Hypothesis: Init Code vs Deployed Code Confusion

The user mentioned "init code issue" - this might mean:
- When deploying a contract, EVM executes the init code (constructor)
- Init code returns the deployed bytecode
- The deployed bytecode should be stored with the contract's code_hash
- But maybe we're caching the wrong code (init code instead of deployed code)?

## ROOT CAUSE FOUND AND FIXED! (db_adapter.rs:407)

### The Bug

In `db_adapter.rs` `basic()` function, when account info is partially in MVHashMap:

**Lines 392-409** - CodeHash read from MVHashMap:
```rust
match code_hash_result {
    ReadResult::Value { value: EvmStateValue::CodeHash(value), version } => {
        base_info.code_hash = value;  // ✓ Updated code_hash
        // ✗ MISSING: base_info.code not populated!
        did_exist = true;
    }
}
```

Compare to **lines 287-318** - All values from MVHashMap:
```rust
Ok(Some(AccountInfo {
    code_hash: h,
    code: self.code_cache.get(&h).map(|c| c.clone()),  // ✓ Populates code!
}))
```

### Why This Caused Silent Failure

1. Init transaction calls deployed contract address
2. `basic(address)` returns `AccountInfo { code_hash: <correct>, code: None }`
3. EVM sees code_hash (contract exists) but code=None (can't execute)
4. Treats as empty account call → succeeds with ~23k gas
5. No contract execution → **0 storage writes**

### The Fix (Line 411)

```rust
base_info.code_hash = value;
base_info.code = self.code_cache.get(&value).map(|c| c.clone());  // Added!
```

### Impact

Init transaction gas usage:
- **Before**: 23,000 gas (failed silently)
- **After**: 142,000 gas (contracts execute successfully!)

### Remaining Issue: Storage Persistence Across Blocks

The test still fails with "The tee key is not registered". Storage from contracts initialized in the first block doesn't persist to the second block. This is a separate issue related to how `bundle_state` is managed between blocks, not flashblocks.

The test builds 2 blocks with 4 flashblocks each:
- Block 1: Deploys and initializes contracts (now works!)
- Block 2: Tries to use the contracts (storage missing)

This is the original bundle_state persistence issue that needs investigation.
