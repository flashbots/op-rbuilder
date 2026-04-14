# Changelog

All notable changes to this project will be documented in this file.
## [0.4.2] - 2026-04-13

### Features

- Skip re-simulation of reverted txs between flashblocks ([#462](https://github.com/flashbots/op-rbuilder/pull/462))
- Metrics: record fcu delay ([#443](https://github.com/flashbots/op-rbuilder/pull/443))

### Chore

- Upgrade reth to 2.0 ([#459](https://github.com/flashbots/op-rbuilder/pull/459))
- Standardize logging ([#456](https://github.com/flashbots/op-rbuilder/pull/456))
- Add enable_tx_tracking_debug_logs flag to not check env vars during runtime ([#452](https://github.com/flashbots/op-rbuilder/pull/452))
- Use derive_more::Deref for WithFlashbotsMetadata ([#453](https://github.com/flashbots/op-rbuilder/pull/453))
- Remove reth_basic_payload_builder::PayloadBuilder impl ([#454](https://github.com/flashbots/op-rbuilder/pull/454))
- Remove unused file ([#455](https://github.com/flashbots/op-rbuilder/pull/455))
- Enable redundant_clone clippy lint ([#460](https://github.com/flashbots/op-rbuilder/pull/460))
- Create BlockEvmFactory abstraction ([#457](https://github.com/flashbots/op-rbuilder/pull/457))
- Add signer to revert log message ([#461](https://github.com/flashbots/op-rbuilder/pull/461))
- Accumulate reverted gas as u64 for payload metrics ([#451](https://github.com/flashbots/op-rbuilder/pull/451))

## [0.4.1] - 2026-03-30

### Bug Fixes

- Cache env var lookup ([#449](https://github.com/flashbots/op-rbuilder/pull/449))
- Gate incremental trie behind flag ([#446](https://github.com/flashbots/op-rbuilder/pull/446))

### Features

- Builder-playground dev ([#440](https://github.com/flashbots/op-rbuilder/pull/440))
- Per-transaction trace log specification ([#447](https://github.com/flashbots/op-rbuilder/pull/447))

### Chore

- Deprecate flashblocks.enabled flag ([#436](https://github.com/flashbots/op-rbuilder/pull/436))
- Add limit to uncompressed block size ([#437](https://github.com/flashbots/op-rbuilder/pull/437))
- Organize dependencies and delete unused ones ([#439](https://github.com/flashbots/op-rbuilder/pull/439))
- Update rust stable 1.94 ([#441](https://github.com/flashbots/op-rbuilder/pull/441))
- Testcontainers/reth-test behind testing feature ([#442](https://github.com/flashbots/op-rbuilder/pull/442))
- Bump reth to v1.11.2 ([#444](https://github.com/flashbots/op-rbuilder/pull/444))
- Deprecate flashblocks.enabled flag ([#448](https://github.com/flashbots/op-rbuilder/pull/448))

## [0.4.0] - 2026-03-09

### ⚠️ BREAKING CHANGES

Standard building mode is now deprecated, flashblocks building mode will always be on. The `--flashblocks.enabled` flag will be removed in the next release.

### Bug Fixes

- Update testcontainers to v0.27.0 to remediate CVE-2025-62518 ([#396](https://github.com/flashbots/op-rbuilder/pull/396))
- Cleanup address gas limiter buckets properly ([#425](https://github.com/flashbots/op-rbuilder/pull/425))

### Features

- Replace BlockCell with watch channel ([#397](https://github.com/flashbots/op-rbuilder/pull/397))
- Async PayloadBuilder::try_build ([#394](https://github.com/flashbots/op-rbuilder/pull/394))
- Add strict priority fee ordering mode for backrun bundles ([#410](https://github.com/flashbots/op-rbuilder/pull/410))
- Add explicit backrun bundle cancellation via 0-tx submissions ([#423](https://github.com/flashbots/op-rbuilder/pull/423))
- Local observability playground ([#430](https://github.com/flashbots/op-rbuilder/pull/430))
- Async-orchestrated payload builder with isolated blocking phases ([#398](https://github.com/flashbots/op-rbuilder/pull/398))

### Miscellaneous

- Rename bundle fields for consistency (no api change) ([#402](https://github.com/flashbots/op-rbuilder/pull/402))
- Remove the standard builder [breaking-change] ([#424](https://github.com/flashbots/op-rbuilder/pull/424))
- Lints all targets ([#426](https://github.com/flashbots/op-rbuilder/pull/426))
- Use counters instead of histograms for a couple metrics ([#428](https://github.com/flashbots/op-rbuilder/pull/428))

### Refactor

- Remove ExtraCtx generic param ([#404](https://github.com/flashbots/op-rbuilder/pull/404))

### Testing

- Use nextest test runner ([#422](https://github.com/flashbots/op-rbuilder/pull/422))

### Performance

- Add incremental trie cache optimization for flashblocks state root calculation ([#427](https://github.com/flashbots/op-rbuilder/pull/427))

### Chore

- Standardize releases ([#421](https://github.com/flashbots/op-rbuilder/pull/421))
- Remove unused custom-engine-api feature flag ([#420](https://github.com/flashbots/op-rbuilder/pull/420))
- Fix reproducible builds ([#403](https://github.com/flashbots/op-rbuilder/pull/403))
- Re-add flashblocks.enabled flag with deprecation warning ([#432](https://github.com/flashbots/op-rbuilder/pull/432))
- Feature gate macos fix ([#431](https://github.com/flashbots/op-rbuilder/pull/431))

### Revert

- Async payload builder ([#434](https://github.com/flashbots/op-rbuilder/pull/434))



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


