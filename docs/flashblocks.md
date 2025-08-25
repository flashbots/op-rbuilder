## Flashblock flow details
This is sequence diagram for flashblock building flow, rollup-boost, op-node and fallback sequencer interaction.

There is 2 separate cases, for regular block and for block with no-txpool flag. When building no-txpool block we are using only fallback EL to construct the block. 
This is done to rely on canonical implementation for such block as they are not compute intensive.  
## Regular block building flow
```mermaid

participant op-rbuilder
participant op-geth
participant rollup-boost
participant op-node
participant websocket-proxy

group Block building process
op-node -> rollup-boost: FCU w/ attr
rollup-boost -> op-geth: FCU w/ attr
rollup-boost -> op-rbuilder: FCU w/ attr
op-geth -> rollup-boost: VALID/SYNCING
op-rbuilder -> rollup-boost: VALID/SYNCING
rollup-boost -> rollup-boost: Set that op-rbuilder is building this block
rollup-boost -> op-node: op-geth VALID/SYNCING
op-rbuilder -> op-rbuilder: Start block building
op-geth -> op-geth: Build regular block
op-rbuilder -> rollup-boost: Base flashblock
op-rbuilder -> rollup-boost: FB 1
rollup-boost -> websocket-proxy: Propagate FB 1
op-rbuilder -> rollup-boost: ...
rollup-boost -> websocket-proxy: ...
op-rbuilder -> rollup-boost: FB N
rollup-boost -> websocket-proxy: Propagate FB N
op-node -> rollup-boost: getPayload
group There is in-mem flashblock
rollup-boost -> rollup-boost: Build payload from locally stored FBs
rollup-boost -> op-node: Payload from local FBs
rollup-boost --> op-rbuilder: getPayload to stop building, without waiting for an answer
end
group There is no in-mem flashblocks, by builder marked as building payload
rollup-boost -> op-geth: getPayload
rollup-boost -> op-rbuilder: getPayload
rollup-boost -> op-node: op-rbuilder payload, if present, op-geth otherwise. Selection policy may be used if present
end
group There is no in-mem flashblocks, by builder is not marked as building payload
rollup-boost -> op-geth: getPayload
rollup-boost -> op-node: op-geth payload
end
end
group Chain progression
op-node -> rollup-boost: FCU w/o attr
rollup-boost -> op-geth: FCU w/o attr
rollup-boost -> op-rbuilder: FCU w/o attr
op-node -> rollup-boost: newPayload
rollup-boost -> op-geth: newPayload
rollup-boost -> op-rbuilder: newPayload
end
```

## Basic no-txpool flow
```mermaid

participant op-rbuilder
participant op-geth
participant rollup-boost
participant op-node
group Block building
op-node -> rollup-boost: FCU w/ attr
rollup-boost -> op-geth: FCU w/ attr
op-geth -> rollup-boost: VALID/SYNCING
rollup-boost -> op-node: VALID/SYNCING
op-geth -> op-geth: Build block with deposit transaction only
op-node -> rollup-boost: getPayload
rollup-boost -> op-geth: getPayload
op-geth -> rollup-boost: Payload
rollup-boost -> op-node: Payload
end
group Chain progression
op-node -> rollup-boost: FCU w/o attr
rollup-boost -> op-geth: FCU w/o attr
op-node -> rollup-boost: newPayload
rollup-boost -> op-geth: newPayload
end
```