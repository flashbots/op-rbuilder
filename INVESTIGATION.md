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

## Next Investigation Steps

1. **Check if init transactions are failing**
   - Add logging to see execution results for init txs
   - Check if they're silently erroring

2. **Verify contract code is accessible**
   - Check shared_code_cache after deploy tx
   - Verify init tx can read the deployed code

3. **Check dependency tracking for code reads**
   - Does VersionedDatabase track code_by_hash reads?
   - Are code reads causing conflicts and re-execution?

4. **Compare init tx execution between modes**
   - Log the full execution flow for an init tx in both modes
   - Identify where they diverge
