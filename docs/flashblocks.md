# Flashblock flow details

**FCU w/ attr - engine_forkchoiceUpdated with payloadAttributes**. This starts block building.

**FCU w/o attr - engine_forkchoiceUpdated without payloadAttributes**. This progresses the unsafe/safe/finalized head.

**newPayload - engine_newPayload**. This provides the execution client with new canonical block.
 
**getPayload - engine_getPayload**. Collects block building results. In flashblocks, this is only used to terminate block building as flashblocks are assembled on rollup-boost side. 

Flashblocks uses similar to canonical mechanism of block building, with the exception that it current implementation does not rely on getPayload.

It starts block building process on FCU w/ attr and try to time flashblocks, so all of them would be delivered before op-node issue getPayload to rollup-boost.

## build_payload Function Overview
This is the function that produces the block and contains all logic responsible for building the block and producing flashblocks
```pseudocode
function build_payload(build_arguments, best_payload_cell):  
    // 1. Set up the state for block building
    apply_pre_execution_changes()
    // === FALLBACK BLOCK CREATION ===
    // Produces deposits only block
    execute_sequencer_transactions()    
    // 2. Add builder transaction if we build block with txpool enabled (specified in FCU)
    if transaction_pool_enabled:
        add_builder_tx_after_deposits()
    
    // 3. Build and publish initial fallback block
    fallback_payload = build_block(state, context, execution_info)
    best_payload_cell.set(fallback_payload)
    // 4. Store the block in trie cache. This cache would be looked up on the next FCU w/ attr
    send_payload_to_engine(fallback_payload)
    // 5. Send fb via websocket
    publish_flashblock(fallback_payload)
    
    // 6. Return early if transaction pool is disabled
    if no_transaction_pool:
        record_metrics_and_return()
    
    // === FLASHBLOCKS TIMING CALCULATION ===
    // 7. Calculate flashblock timing based on remaining time until payload deadline.
    // The scheduler computes:
    //   - remaining_time = min(payload_timestamp - now, block_time)
    //   - first_offset = ((remaining_time - 1) % flashblock_interval) + 1
    //   - Subsequent flashblocks are sent at first_offset + N * flashblock_interval
    //   - The deadline (last flashblock) = remaining_time - end_buffer_ms
    //
    // The send_offset_ms parameter shifts all send times (positive = late, negative = early).
    // The end_buffer_ms parameter shifts the last sent time.
    // The number of triggers is clamped to target_flashblocks (block_time / flashblock_interval).
    //
    // Ex: If FCU arrives 400ms into a 1000ms slot:
    //   - remaining_time = 600ms, flashblock_interval = 200ms
    //   - first_offset = (600-1) % 200 + 1 = 200ms
    //   - With end_buffer_ms=30, deadline = 570ms
    //   - Triggers at: 200ms, 400ms, 570ms (3 flashblocks)
    scheduler = FlashblockScheduler::new(config, block_time, payload_timestamp)
    tokio::spawn(scheduler.run(..));
    
    // 8. Calculate resource limits per flashblock
    gas_per_flashblock = total_gas_limit / flashblocks_count
    da_per_flashblock = total_da_limit / flashblocks_count
    
    // === FLASHBLOCKS BUILDING LOOP ===
    
    // 9. Setup timing coordination. This timer task produces a cancel token that would be cancelled when it's time to 
    // send the flashblock. 
    setup_timer_task(first_offset, flashblock_interval)
    // 10. We use a custom wrapper around reth BestTransaction iterator. Our wrapper tracks committed transactions and skips 
    // them when we build a new flashblock.
    create_best_transactions_iterator()
    
    // 10. Main flashblock building loop
    loop:
        // Wait for next flashblock timing signal
        flashblock_cancel_token = wait_for_next_flashblock_signal()
        
        if flashblock_cancel_token is None:
            break  // All flashblocks completed or parent cancelled
        
        if reached_target_flashblock_count():
            continue  // Skip if we've built enough flashblocks
        
        // === SINGLE FLASHBLOCK BUILDING ===
        
        // 11. Provide a fresh BestTransaction iterator that would contain all transactions in mempool that could be 
        // included in the flashblock
        refresh_transaction_iterator_for_current_flashblock()
        
        // 12. Execute transactions within limits
        execute_best_transactions():
            while has_transactions() and within_limits():
                transaction = get_next_best_transaction()
                if can_execute(transaction, gas_limit, da_limit):
                    execute_transaction(transaction)
                    update_cumulative_usage()
                else:
                    skip_transaction()
                    // If we cannot fit a transaction, we will remove this tx and its ancestors from this round of 
                    // flashblock building
                    mark_invalid()
        
        // 13. Add builder transaction to last flashblock
        if is_last_flashblock():
            add_builder_tx_to_block()
        
        // 14. Build block and create flashblock payload
        (new_payload, flashblock_payload) = build_block(state, context, info)
        
        // 15. Wait for timing coordination
        wait_for_flashblock_timing_completion()
        
        if parent_build_cancelled():
            break  // If the main cancel token is cancelled we must start a new block building job and all previous
            // results are obsolete.
        
        // 16. Publish flashblock and update state
        publish_flashblock(flashblock_payload)
        best_payload_cell.set(new_payload)
        send_payload_to_engine(new_payload)
        
        // 17. Update limits for next flashblock
        increment_flashblock_index()
        increase_gas_and_da_limits_for_next_flashblock()
        mark_committed_transactions()
        
    // === CLEANUP PHASE ===
    
    // 18. Record final metrics and cleanup
    record_flashblocks_metrics()
    return success
```

### Timing Coordination

The `FlashblockScheduler` handles timing coordination for flashblock production:

- **Scheduler**: Pre-computes all send times at initialization based on remaining time until the payload deadline
- **Offset**: Applied to interval timings to ensure evenly spaced flashblocks
- **Trigger Clamping**: The number of triggers is set from the target_flashblocks count, which is computed based on remaining time and the configured flashblocks interval
- **Cancellation Tokens**: When a flashblock trigger fires, the current flashblock building is cancelled and published

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `flashblocks.block-time` | Flashblock interval in milliseconds | 250 |
| `flashblocks.send-offset-ms` | Shifts all send times. Positive = late, negative = early | 0 |
| `flashblocks.end-buffer-ms` | Time reserved at end of slot for final processing | 0 |

### Caveats
- If the payload timestamp is in the past or remaining time is 0, the scheduler will not trigger any flashblocks.
- Late FCU arrivals result in fewer flashblocks being produced (proportional to remaining time)

## Block building flow
These are sequence diagrams for flashblock building flow, rollup-boost, op-node and fallback sequencer interaction.

There are 2 separate cases: for regular blocks and for blocks with the no-txpool flag. When building no-txpool blocks we are using only the fallback EL to construct the block.
This is done to rely on the canonical implementation for such blocks as they are not compute intensive.

### Regular Block Building Flow (Mermaid)

```mermaid
sequenceDiagram
    participant OR as op-rbuilder
    participant OG as op-geth
    participant RB as rollup-boost
    participant ON as op-node
    participant WP as websocket-proxy

    rect rgba(230, 240, 250, 0.2)
        note over ON, WP: Block building process
        
        ON->>RB: FCU w/ attr
        RB->>OG: FCU w/ attr
        RB->>OR: FCU w/ attr
        OG->>RB: VALID/SYNCING
        OR->>RB: VALID/SYNCING
        RB->>RB: Mark that op-rbuilder is building this block
        RB->>ON: op-geth VALID/SYNCING
        OR->>OR: Start block building
        OG->>OG: Build regular block
        OR->>RB: Base flashblock
        OR->>RB: FB 1
        RB->>WP: Propagate FB 1
        OR->>RB: ...
        RB->>WP: ...
        OR->>RB: FB N
        RB->>WP: Propagate FB N
        ON->>RB: getPayload
        
        alt There is in-mem flashblock
            RB->>RB: Build payload from locally stored FBs
            RB->>ON: Payload from local FBs
            RB-->>OR: getPayload to stop building, without waiting for a response
        else There is no in-mem flashblocks, but builder is marked as building payload
            RB->>OG: getPayload
            RB->>OR: getPayload
            RB->>ON: op-rbuilder payload, if present, op-geth otherwise. Selection policy may be used if present
        else There is no in-mem flashblocks, but builder is not marked as building payload
            RB->>OG: getPayload
            RB->>ON: op-geth payload
        end
    end

    rect rgba(240, 250, 240, 0.2)
        note over ON, OR: Chain progression
        
        ON->>RB: FCU w/o attr
        RB->>OG: FCU w/o attr
        RB->>OR: FCU w/o attr
        ON->>RB: newPayload
        RB->>OG: newPayload
        RB->>OR: newPayload
    end
```

### No-Txpool Block Building Flow (Mermaid)

```mermaid
sequenceDiagram
    participant OR as op-rbuilder
    participant OG as op-geth
    participant RB as rollup-boost
    participant ON as op-node

    rect rgba(255, 245, 230, 0.2)
        note over ON, OR: Block building
        
        ON->>RB: FCU w/ attr
        RB->>OG: FCU w/ attr
        OG->>RB: VALID/SYNCING
        RB->>ON: VALID/SYNCING
        OG->>OG: Build block with deposit transaction only
        ON->>RB: getPayload
        RB->>OG: getPayload
        OG->>RB: Payload
        RB->>ON: Payload
    end

    rect rgba(240, 250, 240, 0.2)
        note over ON, OR: Chain progression
        
        ON->>RB: FCU w/o attr
        RB->>OG: FCU w/o attr
        ON->>RB: newPayload
        RB->>OG: newPayload
    end
```