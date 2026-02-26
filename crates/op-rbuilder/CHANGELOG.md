# Changelog

All notable changes to this project will be documented in this file.
## [0.3.2] - 2026-02-26

### Bug Fixes

- Don't miss blocks on batcher updates ([#529](https://github.com/flashbots/op-rbuilder/pull/529))
- Don't build flashblocks with more gas than block gas limit ([#567](https://github.com/flashbots/op-rbuilder/pull/567))
- Set an address for authrpc to the op-rbuilder readme ([#581](https://github.com/flashbots/op-rbuilder/pull/581))
- Add default-run to the op-rbuilder's manifest ([#162](https://github.com/flashbots/op-rbuilder/pull/162))
- Record missing flashblocks ([#225](https://github.com/flashbots/op-rbuilder/pull/225))
- Record num txs built with flashblocks enabled ([#227](https://github.com/flashbots/op-rbuilder/pull/227))
- Override clap long version envs ([#235](https://github.com/flashbots/op-rbuilder/pull/235))
- Gracefull cancellation on payload build failure ([#239](https://github.com/flashbots/op-rbuilder/pull/239))
- Flashblock contraints in bundle api ([#259](https://github.com/flashbots/op-rbuilder/pull/259))
- Check per-address gas limit before checking if the tx reverted ([#266](https://github.com/flashbots/op-rbuilder/pull/266))
- Jovian hardfork tests & fixes ([#320](https://github.com/flashbots/op-rbuilder/pull/320))
- **wspub:** Add flashblocks payload subscriber count limit ([#373](https://github.com/flashbots/op-rbuilder/pull/373))
- Separate flashblocks payloads handling and full built payloads in handler ([#354](https://github.com/flashbots/op-rbuilder/pull/354))
- Attempt to send one flashblock if payload deadline is in the past ([#386](https://github.com/flashbots/op-rbuilder/pull/386))

### Bundles

- Ensure that the min block number is inside the MAX_BLOCK_RANGE_BLOCKS ([#128](https://github.com/flashbots/op-rbuilder/pull/128))

### Documentation

- Eth_sendBundle ([#243](https://github.com/flashbots/op-rbuilder/pull/243))

### Features

- Add a feature to activate otlp telemetry ([#31](https://github.com/flashbots/op-rbuilder/pull/31))
- Add transaction gas limit ([#214](https://github.com/flashbots/op-rbuilder/pull/214))
- Address gas limiter ([#253](https://github.com/flashbots/op-rbuilder/pull/253))
- Add commit message and author in version metrics ([#236](https://github.com/flashbots/op-rbuilder/pull/236))
- Overwrite reth default cache directory ([#238](https://github.com/flashbots/op-rbuilder/pull/238))
- Implement p2p layer and broadcast flashblocks ([#275](https://github.com/flashbots/op-rbuilder/pull/275))
- Implement flashblock sync over p2p ([#288](https://github.com/flashbots/op-rbuilder/pull/288))
- Publish synced flashblocks to ws ([#310](https://github.com/flashbots/op-rbuilder/pull/310))
- Integrate downstream changes (Jovian hardfork + miner_setGasLimit + reth 1.9.1) ([#316](https://github.com/flashbots/op-rbuilder/pull/316))
- **tests:** Add BuilderTxValidation utility for validating builder transactions ([#347](https://github.com/flashbots/op-rbuilder/pull/347))
- **o11y:** Add tokio metrics ([#367](https://github.com/flashbots/op-rbuilder/pull/367))
- **logs:** Flashblock target and events with payload_id ([#365](https://github.com/flashbots/op-rbuilder/pull/365))
- Ignore unrecognized cli flags ([#409](https://github.com/flashbots/op-rbuilder/pull/409))

### Miscellaneous

- Workspace wide package settings ([#390](https://github.com/flashbots/op-rbuilder/pull/390))
- Fix op-rbuilder devnet docs ([#562](https://github.com/flashbots/op-rbuilder/pull/562))
- Add unused_async lint, deny unreachable_pub ([#299](https://github.com/flashbots/op-rbuilder/pull/299))
- **deps/reth:** Bump reth to 1.9.2 ([#318](https://github.com/flashbots/op-rbuilder/pull/318))
- **deps:** Bump reth ([#321](https://github.com/flashbots/op-rbuilder/pull/321))
- Set builder name in reth_builder_info ([#352](https://github.com/flashbots/op-rbuilder/pull/352))
- **op-rbuilder:** Release v0.2.14 ([#359](https://github.com/flashbots/op-rbuilder/pull/359))
- **log:** Add log targets for better explicit logs filtering ([#371](https://github.com/flashbots/op-rbuilder/pull/371))
- Rename bundle fields for consistency (no api change) ([#402](https://github.com/flashbots/op-rbuilder/pull/402))

### Performance

- Remove unnecessary clones in payload building ([#392](https://github.com/flashbots/op-rbuilder/pull/392))

### Refactor

- Add `unreachable_pub` warning and autofix warnings ([#263](https://github.com/flashbots/op-rbuilder/pull/263))
- Clean up and improve flashblocks `build_payload` ([#260](https://github.com/flashbots/op-rbuilder/pull/260))
- Clean up flashblocks context in payload builder ([#297](https://github.com/flashbots/op-rbuilder/pull/297))
- Use task executor in payload handler ([#377](https://github.com/flashbots/op-rbuilder/pull/377))
- Extract flashblock timing code and test it ([#380](https://github.com/flashbots/op-rbuilder/pull/380))
- Remove ExtraCtx generic param ([#404](https://github.com/flashbots/op-rbuilder/pull/404))

### Deps

- Reth v1.3.4 ([#507](https://github.com/flashbots/op-rbuilder/pull/507))
- Reth v1.3.8 ([#553](https://github.com/flashbots/op-rbuilder/pull/553))
- Use op-alloy types instead of rollup-boost ([#344](https://github.com/flashbots/op-rbuilder/pull/344))

### Op-rbuilder

- Update Documentation / CI Script ([#575](https://github.com/flashbots/op-rbuilder/pull/575))



## [0.2.14] - 2026-01-17

### Bug Fixes

- Don't miss blocks on batcher updates ([#529](https://github.com/flashbots/op-rbuilder/pull/529))
- Don't build flashblocks with more gas than block gas limit ([#567](https://github.com/flashbots/op-rbuilder/pull/567))
- Set an address for authrpc to the op-rbuilder readme ([#581](https://github.com/flashbots/op-rbuilder/pull/581))
- Add default-run to the op-rbuilder's manifest ([#162](https://github.com/flashbots/op-rbuilder/pull/162))
- Record missing flashblocks ([#225](https://github.com/flashbots/op-rbuilder/pull/225))
- Record num txs built with flashblocks enabled ([#227](https://github.com/flashbots/op-rbuilder/pull/227))
- Override clap long version envs ([#235](https://github.com/flashbots/op-rbuilder/pull/235))
- Gracefull cancellation on payload build failure ([#239](https://github.com/flashbots/op-rbuilder/pull/239))
- Flashblock contraints in bundle api ([#259](https://github.com/flashbots/op-rbuilder/pull/259))
- Check per-address gas limit before checking if the tx reverted ([#266](https://github.com/flashbots/op-rbuilder/pull/266))
- Jovian hardfork tests & fixes ([#320](https://github.com/flashbots/op-rbuilder/pull/320))

### Bundles

- Ensure that the min block number is inside the MAX_BLOCK_RANGE_BLOCKS ([#128](https://github.com/flashbots/op-rbuilder/pull/128))

### Documentation

- Eth_sendBundle ([#243](https://github.com/flashbots/op-rbuilder/pull/243))

### Features

- Add a feature to activate otlp telemetry ([#31](https://github.com/flashbots/op-rbuilder/pull/31))
- Add transaction gas limit ([#214](https://github.com/flashbots/op-rbuilder/pull/214))
- Address gas limiter ([#253](https://github.com/flashbots/op-rbuilder/pull/253))
- Add commit message and author in version metrics ([#236](https://github.com/flashbots/op-rbuilder/pull/236))
- Overwrite reth default cache directory ([#238](https://github.com/flashbots/op-rbuilder/pull/238))
- Implement p2p layer and broadcast flashblocks ([#275](https://github.com/flashbots/op-rbuilder/pull/275))
- Implement flashblock sync over p2p ([#288](https://github.com/flashbots/op-rbuilder/pull/288))
- Publish synced flashblocks to ws ([#310](https://github.com/flashbots/op-rbuilder/pull/310))
- Integrate downstream changes (Jovian hardfork + miner_setGasLimit + reth 1.9.1) ([#316](https://github.com/flashbots/op-rbuilder/pull/316))
- **tests:** Add BuilderTxValidation utility for validating builder transactions ([#347](https://github.com/flashbots/op-rbuilder/pull/347))

### Miscellaneous

- Workspace wide package settings ([#390](https://github.com/flashbots/op-rbuilder/pull/390))
- Fix op-rbuilder devnet docs ([#562](https://github.com/flashbots/op-rbuilder/pull/562))
- Add unused_async lint, deny unreachable_pub ([#299](https://github.com/flashbots/op-rbuilder/pull/299))
- **deps/reth:** Bump reth to 1.9.2 ([#318](https://github.com/flashbots/op-rbuilder/pull/318))
- **deps:** Bump reth ([#321](https://github.com/flashbots/op-rbuilder/pull/321))
- Set builder name in reth_builder_info ([#352](https://github.com/flashbots/op-rbuilder/pull/352))

### Refactor

- Add `unreachable_pub` warning and autofix warnings ([#263](https://github.com/flashbots/op-rbuilder/pull/263))
- Clean up and improve flashblocks `build_payload` ([#260](https://github.com/flashbots/op-rbuilder/pull/260))
- Clean up flashblocks context in payload builder ([#297](https://github.com/flashbots/op-rbuilder/pull/297))

### Deps

- Reth v1.3.4 ([#507](https://github.com/flashbots/op-rbuilder/pull/507))
- Reth v1.3.8 ([#553](https://github.com/flashbots/op-rbuilder/pull/553))
- Use op-alloy types instead of rollup-boost ([#344](https://github.com/flashbots/op-rbuilder/pull/344))

### Op-rbuilder

- Update Documentation / CI Script ([#575](https://github.com/flashbots/op-rbuilder/pull/575))


