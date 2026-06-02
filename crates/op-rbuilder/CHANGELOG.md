# Changelog

All notable changes to this project will be documented in this file.
## [0.4.7] - 2026-06-02

### Bug Fixes

- [`6ae8f55`](https://github.com/flashbots/op-rbuilder/commit/6ae8f553413d85b0d93db7e89de4525d681b5367) Fix flashblock uncompressed limit check and presim error handling ([#524](https://github.com/flashbots/op-rbuilder/pull/524))

### Features

- [`c2e80b6`](https://github.com/flashbots/op-rbuilder/commit/c2e80b67c94d867a630e2d7627c84693f6166119) Limit max concurrency ([#522](https://github.com/flashbots/op-rbuilder/pull/522))

### Miscellaneous

- [`b537a2d`](https://github.com/flashbots/op-rbuilder/commit/b537a2d1e1a12a6e164b707f844b017ad6ff5e6b) Update rust to version 1.96 ([#529](https://github.com/flashbots/op-rbuilder/pull/529))
- [`ee245e5`](https://github.com/flashbots/op-rbuilder/commit/ee245e592967adccb443a283977ee5c1422f793a) Bump Cargo version to 0.4.7

### Refactor

- [`55edd74`](https://github.com/flashbots/op-rbuilder/commit/55edd746e9e73ab295b10b3d91de8b6f4e9e597c) Canonical + overlay design with epoch tag ([#488](https://github.com/flashbots/op-rbuilder/pull/488))

## [0.4.6] - 2026-05-18

### Bug Fixes

- [`0d63bd8`](https://github.com/flashbots/op-rbuilder/commit/0d63bd84072d17e0321dbeda05af565c6d68013d) Update Cargo.lock file in release script ([#510](https://github.com/flashbots/op-rbuilder/pull/510))

### Documentation

- [`1162908`](https://github.com/flashbots/op-rbuilder/commit/116290840c36b71cecaa549b8a2e58d60fb57087) Require signed commits in CONTRIBUTING ([#515](https://github.com/flashbots/op-rbuilder/pull/515))

### Miscellaneous

- [`376a060`](https://github.com/flashbots/op-rbuilder/commit/376a060142178a8e75fa47d3c28ba471fec6f018) Add flashblock cancel token ([#517](https://github.com/flashbots/op-rbuilder/pull/517))
- [`a53d0da`](https://github.com/flashbots/op-rbuilder/commit/a53d0dae685c8960f3ea64bc373c1bd8c4468f75) Bump Cargo version to 0.4.6

### Performance

- [`369b538`](https://github.com/flashbots/op-rbuilder/commit/369b538ac2d1d510d5d7c1a5567717e28818ed13) Wake poll on cancellation ([#508](https://github.com/flashbots/op-rbuilder/pull/508))

### Refactor

- [`b01741e`](https://github.com/flashbots/op-rbuilder/commit/b01741e8e6f69472912467e46451e92601bb26ef) Extract build_block into another module ([#506](https://github.com/flashbots/op-rbuilder/pull/506))
- [`5579a76`](https://github.com/flashbots/op-rbuilder/commit/5579a763c0465b3274c069464dc163461165f1dc) Move state root computation into its module ([#512](https://github.com/flashbots/op-rbuilder/pull/512))
- [`2710d66`](https://github.com/flashbots/op-rbuilder/commit/2710d66aef74c6aec08476b95bcd39ed3400e9d8) Add commit_tx fn to ExecutionInfo ([#511](https://github.com/flashbots/op-rbuilder/pull/511))
- [`f233b5b`](https://github.com/flashbots/op-rbuilder/commit/f233b5b0feafe95a2f732aefd7d1eb9523c2b10a) Remove backrun pool from config type ([#516](https://github.com/flashbots/op-rbuilder/pull/516))
- [`c468d8a`](https://github.com/flashbots/op-rbuilder/commit/c468d8a0da51db3739f3a63a859d564005c726c7) Make job ctx fields private ([#519](https://github.com/flashbots/op-rbuilder/pull/519))

## [0.4.5] - 2026-05-12

### Bug Fixes

- [`a977594`](https://github.com/flashbots/op-rbuilder/commit/a977594b7324f749cd886e852242b1ba85e6029b) Use git-cliff instead of release-plz for changelog ([#502](https://github.com/flashbots/op-rbuilder/pull/502))
- [`4ff9429`](https://github.com/flashbots/op-rbuilder/commit/4ff94298d4074a1e1f3e86449e0266a5cdd16128) Fix checking reverted hashes ([#498](https://github.com/flashbots/op-rbuilder/pull/498))
- [`1dd1313`](https://github.com/flashbots/op-rbuilder/commit/1dd131349ce845f8ce07119353a3cbdd2028a581) Execute_flashblock directly on blocking thread ([#504](https://github.com/flashbots/op-rbuilder/pull/504))

### Features

- [`8366c3e`](https://github.com/flashbots/op-rbuilder/commit/8366c3ec7228d4ff3f4f182999dbd0643030202f) Per-sender simulation time limiting ([#487](https://github.com/flashbots/op-rbuilder/pull/487))

### Miscellaneous

- [`ca6b585`](https://github.com/flashbots/op-rbuilder/commit/ca6b585470fd33095ca811ab8c6a5adc1d6704f5) Remove ci step to install foundry toolchain ([#497](https://github.com/flashbots/op-rbuilder/pull/497))
- [`bd1eca7`](https://github.com/flashbots/op-rbuilder/commit/bd1eca70cdc8ed11c646c731eb7d814d29fa37e6) Use `ActiveHardforks` a bit more widely ([#496](https://github.com/flashbots/op-rbuilder/pull/496))
- [`da1dabb`](https://github.com/flashbots/op-rbuilder/commit/da1dabbf477af75429845cae9b1c0cec5a26b24b) Create reth pool wrapper ([#495](https://github.com/flashbots/op-rbuilder/pull/495))
- [`d6c90fa`](https://github.com/flashbots/op-rbuilder/commit/d6c90fad8f059be558505ed307eedc4c8870a3ed) Remove unused testing code ([#500](https://github.com/flashbots/op-rbuilder/pull/500))
- [`32f630b`](https://github.com/flashbots/op-rbuilder/commit/32f630bbf914b42c58bfca92f14f429c08811f69) Drop redundant Box::pin on payload builder spawns ([#505](https://github.com/flashbots/op-rbuilder/pull/505))
- [`0fa2bad`](https://github.com/flashbots/op-rbuilder/commit/0fa2badf34e03f2a5bf43ee8fbbf3c1be759e959) Bump version to 0.4.5

### Refactor

- [`7b33ac1`](https://github.com/flashbots/op-rbuilder/commit/7b33ac1ccf962548d6fa768d09aabc46cfc0abbc) Extract receipt and hardforks code ([#493](https://github.com/flashbots/op-rbuilder/pull/493))
- [`d89d5e7`](https://github.com/flashbots/op-rbuilder/commit/d89d5e787ba88cf2be339c6868fb5e4054089e93) Wire presim through flashpool ([#499](https://github.com/flashbots/op-rbuilder/pull/499))
- [`a377b4d`](https://github.com/flashbots/op-rbuilder/commit/a377b4d60a5a7551201da41ffed7db60d063e419) Use oncelock for payload cancel reason ([#507](https://github.com/flashbots/op-rbuilder/pull/507))

## [0.4.4] - 2026-05-06

### Bug Fixes

- [`a9240e5`](https://github.com/flashbots/op-rbuilder/commit/a9240e5d65afdb07b4bc818240fa5b8aef10ebb0) Propagate eth_api errors instead of panicking ([#486](https://github.com/flashbots/op-rbuilder/pull/486))
- [`508bf56`](https://github.com/flashbots/op-rbuilder/commit/508bf56f224f7c97a5eaa091bdf2bde049546b22) Add back schedule times to log ([#491](https://github.com/flashbots/op-rbuilder/pull/491))

### Miscellaneous

- [`c510223`](https://github.com/flashbots/op-rbuilder/commit/c510223631f5e2492908492947510e929d36966f) Downgrade reth to v1.11.3 ([#484](https://github.com/flashbots/op-rbuilder/pull/484))
- [`805490e`](https://github.com/flashbots/op-rbuilder/commit/805490e2cf3d9b49167327fc93faa9f5acf8ad41) Prepare v0.4.4 release ([#494](https://github.com/flashbots/op-rbuilder/pull/494))

### Refactor

- [`77425d2`](https://github.com/flashbots/op-rbuilder/commit/77425d22800e629579aacda799cbe1eb8777446c) Rename FlashblockTxCache to FlashblockTxTracker ([#490](https://github.com/flashbots/op-rbuilder/pull/490))
- [`8d49662`](https://github.com/flashbots/op-rbuilder/commit/8d49662866ca5e7e95e1e613d913075c255b46d1) Split payload builder context into static and per-job ([#489](https://github.com/flashbots/op-rbuilder/pull/489))

## [0.4.3] - 2026-04-27

### Bug Fixes

- [`8e4e234`](https://github.com/flashbots/op-rbuilder/commit/8e4e2341cb4887d1f5c10282ccf602daa2e82b5f) Remove Box::leak in TEE metrics recording ([#469](https://github.com/flashbots/op-rbuilder/pull/469))
- [`cd2b5ff`](https://github.com/flashbots/op-rbuilder/commit/cd2b5fff32a02860262130927913790816f822f7) Avoid double-recording bundle_pre_simulation_duration on revert ([#474](https://github.com/flashbots/op-rbuilder/pull/474))
- [`5c58b81`](https://github.com/flashbots/op-rbuilder/commit/5c58b814f994ee6b54fc77ef5527b489fb0a9106) Only simulate bundles with revert protection ([#472](https://github.com/flashbots/op-rbuilder/pull/472))
- [`dc45b53`](https://github.com/flashbots/op-rbuilder/commit/dc45b53d04daa13a6668b38f5d0b96a3bf4f7052) Use cumulative prefix sets for incremental trie state root ([#445](https://github.com/flashbots/op-rbuilder/pull/445))

### Features

- [`1c17bc3`](https://github.com/flashbots/op-rbuilder/commit/1c17bc3bed89181bacf7edd434f58bfc2f0ddba8) Async payload builder ([#438](https://github.com/flashbots/op-rbuilder/pull/438))
- [`6763721`](https://github.com/flashbots/op-rbuilder/commit/6763721d1cd2020f3ec9c7b2eac1dcfad88789e7) Add flashblock publish timing metric ([#464](https://github.com/flashbots/op-rbuilder/pull/464))
- [`3577fd4`](https://github.com/flashbots/op-rbuilder/commit/3577fd4e4f9cb78fe90568cb43e74acda6e233eb) Top-of-block pre-simulation to filter reverting tx spam ([#466](https://github.com/flashbots/op-rbuilder/pull/466))
- [`6cb031b`](https://github.com/flashbots/op-rbuilder/commit/6cb031b9e0b58f2cc94b71a45a45855b41027ca5) Reshape log levels ([#470](https://github.com/flashbots/op-rbuilder/pull/470))

### Miscellaneous

- [`33d47e6`](https://github.com/flashbots/op-rbuilder/commit/33d47e6febc52d5d7a54a4f1c221b5ced031a7b7) Follow-up log reshape across builder/flashtestations ([#471](https://github.com/flashbots/op-rbuilder/pull/471))
- [`041c4d8`](https://github.com/flashbots/op-rbuilder/commit/041c4d8c4ef4a32abf4d5a7d16728975587124cc) Rename `reverted_hashes` to `allowed_revert_hashes` for clarity ([#468](https://github.com/flashbots/op-rbuilder/pull/468))
- [`d7a85ab`](https://github.com/flashbots/op-rbuilder/commit/d7a85abe01f601b6903252b1a6c04792e92c5ec8) Remove unused `interop` feature ([#475](https://github.com/flashbots/op-rbuilder/pull/475))
- [`abc46df`](https://github.com/flashbots/op-rbuilder/commit/abc46df87ac6ecadf1934b41eb0c2cb05e371910) Point to op-reth fork for payload id mismatch ([#473](https://github.com/flashbots/op-rbuilder/pull/473))
- [`790480f`](https://github.com/flashbots/op-rbuilder/commit/790480f0bbb8492380dc302f67bb3807884ee8f9) Release v0.4.3 ([#482](https://github.com/flashbots/op-rbuilder/pull/482))

### Refactor

- [`41c8024`](https://github.com/flashbots/op-rbuilder/commit/41c8024924262040b9c7d1b46074e3814615e773) Extract `FlashblocksState::next_after_seal` ([#477](https://github.com/flashbots/op-rbuilder/pull/477))
- [`973ed86`](https://github.com/flashbots/op-rbuilder/commit/973ed8643caddcacb32dc3ffa60f2bfa38586197) Extract `reserve_builder_tx_budget` helper ([#476](https://github.com/flashbots/op-rbuilder/pull/476))
- [`fba5d16`](https://github.com/flashbots/op-rbuilder/commit/fba5d16619b945cea97c5c39bdb28a4f347579b7) Move state root flags from FlashblocksState to OpPayloadBuilderCtx ([#478](https://github.com/flashbots/op-rbuilder/pull/478))
- [`667a564`](https://github.com/flashbots/op-rbuilder/commit/667a564d8ec5b672b8fa619289690d8837526f42) Drop dead config and tidy module ([#479](https://github.com/flashbots/op-rbuilder/pull/479))
- [`1fb5ec5`](https://github.com/flashbots/op-rbuilder/commit/1fb5ec52999fa13bfb351708a4aed27d0840ab5f) Behaviour fixes for new_payload_job and best_payload ([#480](https://github.com/flashbots/op-rbuilder/pull/480))

## [0.4.2] - 2026-04-14

### Bug Fixes

- [`293b0de`](https://github.com/flashbots/op-rbuilder/commit/293b0ded628a915250b6f82eb0ad9de10b8a74d4) Accumulate reverted gas as u64 for payload metrics ([#451](https://github.com/flashbots/op-rbuilder/pull/451))

### Features

- [`d764971`](https://github.com/flashbots/op-rbuilder/commit/d76497154da99f7c2b454520d51e81e7e98fa0be) Skip re-simulation of reverted txs between flashblocks ([#462](https://github.com/flashbots/op-rbuilder/pull/462))

### Miscellaneous

- [`f0b1928`](https://github.com/flashbots/op-rbuilder/commit/f0b192855f4eff8ebfcf53356f708f382a7cd174) Remove unused file ([#455](https://github.com/flashbots/op-rbuilder/pull/455))
- [`f79719f`](https://github.com/flashbots/op-rbuilder/commit/f79719f3476ea6a1fe47bf4e03790bac4eba3feb) Remove reth_basic_payload_builder::PayloadBuilder impl ([#454](https://github.com/flashbots/op-rbuilder/pull/454))
- [`c09a0de`](https://github.com/flashbots/op-rbuilder/commit/c09a0de377ae6ec47a024734cd21c033ab4d2a30) Use derive_more::Deref for WithFlashbotsMetadata ([#453](https://github.com/flashbots/op-rbuilder/pull/453))
- [`48f9a07`](https://github.com/flashbots/op-rbuilder/commit/48f9a0789ba5ad89513bc65283f5dc730169daf0) Add enable_tx_tracking_debug_logs flag to not check env vars during runtime ([#452](https://github.com/flashbots/op-rbuilder/pull/452))
- [`8dce09b`](https://github.com/flashbots/op-rbuilder/commit/8dce09bd30573dfd880fd7395d33178fa17adea3) Standardize logging ([#456](https://github.com/flashbots/op-rbuilder/pull/456))
- [`edb57f3`](https://github.com/flashbots/op-rbuilder/commit/edb57f3b0f80e145b0e68d829e5f0de069ee7d09) Enable redundant_clone clippy lint ([#460](https://github.com/flashbots/op-rbuilder/pull/460))
- [`21152c3`](https://github.com/flashbots/op-rbuilder/commit/21152c3eddfbddf646cc0eff0a29d266f2a97de4) Record fcu delay ([#443](https://github.com/flashbots/op-rbuilder/pull/443))
- [`cacbb42`](https://github.com/flashbots/op-rbuilder/commit/cacbb420c63d8c72d6a2d39c2bb9c4358a80c191) Upgrade reth to 2.0 ([#459](https://github.com/flashbots/op-rbuilder/pull/459))
- [`899ca1a`](https://github.com/flashbots/op-rbuilder/commit/899ca1ac3395c8085afce2af9f004f1f0f47ed38) Add signer to revert log message ([#461](https://github.com/flashbots/op-rbuilder/pull/461))
- [`1cb30fb`](https://github.com/flashbots/op-rbuilder/commit/1cb30fbd9d8c43912c97d652e00827d8fad88cf9) Release v0.4.2 ([#463](https://github.com/flashbots/op-rbuilder/pull/463))

### Refactor

- [`1f6f93a`](https://github.com/flashbots/op-rbuilder/commit/1f6f93a2207adf6af717641d468f1a6996f2061b) Create BlockEvmFactory abstraction ([#457](https://github.com/flashbots/op-rbuilder/pull/457))

## [0.4.1] - 2026-04-01

### Bug Fixes

- [`9d94256`](https://github.com/flashbots/op-rbuilder/commit/9d94256b9db145b02f0a9eb141da58f8df35b900) Gate incremental trie behind flag  ([#446](https://github.com/flashbots/op-rbuilder/pull/446))
- [`f30ee24`](https://github.com/flashbots/op-rbuilder/commit/f30ee2444c088d4dab8331097d176a1564fc7639) Cache env var lookup ([#449](https://github.com/flashbots/op-rbuilder/pull/449))

### Features

- [`0cae21f`](https://github.com/flashbots/op-rbuilder/commit/0cae21f90dee64a20cbc232b57b9935b1d545986) Builder-playground dev ([#440](https://github.com/flashbots/op-rbuilder/pull/440))

### Miscellaneous

- [`84386d6`](https://github.com/flashbots/op-rbuilder/commit/84386d663449ca3088818911eb61e70502f57864) Deprecate flashblocks.enabled flag ([#436](https://github.com/flashbots/op-rbuilder/pull/436))
- [`153a596`](https://github.com/flashbots/op-rbuilder/commit/153a5967813edc2b0356a227468952c13abdb58a) Add limit to uncompressed block size  ([#437](https://github.com/flashbots/op-rbuilder/pull/437))
- [`926e237`](https://github.com/flashbots/op-rbuilder/commit/926e237c0c6eec26adbcc61cfdffb20bc37fa16b) Organize dependencies and delete unused ones ([#439](https://github.com/flashbots/op-rbuilder/pull/439))
- [`aa3d8d2`](https://github.com/flashbots/op-rbuilder/commit/aa3d8d2c707be5a344e668a7f5bc7761fd20a591) Testcontainers/reth-test behind testing feature ([#442](https://github.com/flashbots/op-rbuilder/pull/442))
- [`d44c9a5`](https://github.com/flashbots/op-rbuilder/commit/d44c9a5a3b85fbcde2251a8ca8a36dbf816ca3c4) Update rust stable 1.94 ([#441](https://github.com/flashbots/op-rbuilder/pull/441))
- [`34405d8`](https://github.com/flashbots/op-rbuilder/commit/34405d89f83225a5ee7e15b32c72aedc93841b35) Bump reth to v1.11.2 ([#444](https://github.com/flashbots/op-rbuilder/pull/444))
- [`c2d0700`](https://github.com/flashbots/op-rbuilder/commit/c2d0700ff38a22e1dadd6f021f31685830a8fe3d) Per-transaction trace log specification ([#447](https://github.com/flashbots/op-rbuilder/pull/447))
- [`45ea24d`](https://github.com/flashbots/op-rbuilder/commit/45ea24dd9e5fd6d39bb9ad98e1a445c865f5d4c3) Deprecate flashblocks.enabled flag ([#448](https://github.com/flashbots/op-rbuilder/pull/448))
- [`f7cf833`](https://github.com/flashbots/op-rbuilder/commit/f7cf833a8e3272133e32ad96c47333537040cfac) Release v0.4.1 ([#450](https://github.com/flashbots/op-rbuilder/pull/450))

## [0.4.0] - 2026-03-09

### ⚠️ BREAKING CHANGES

Standard building mode is now deprecated, flashblocks building mode will always be on. The `--flashblocks.enabled` flag will be removed in the next release.

### Bug Fixes

- [`b9fbc9e`](https://github.com/flashbots/op-rbuilder/commit/b9fbc9e4adc8bf024937674f04baa094e119a419) Cleanup address gas limiter buckets properly ([#425](https://github.com/flashbots/op-rbuilder/pull/425))

### Features

- [`0de1a59`](https://github.com/flashbots/op-rbuilder/commit/0de1a59485b8261ddc463bfbdf14f29c6c3e89ce) Async PayloadBuilder::try_build ([#394](https://github.com/flashbots/op-rbuilder/pull/394))
- [`d0997a3`](https://github.com/flashbots/op-rbuilder/commit/d0997a3ce7b5e8ad9500eaa05559fdfd8911e5e7) Use nextest test runner ([#422](https://github.com/flashbots/op-rbuilder/pull/422))
- [`895158a`](https://github.com/flashbots/op-rbuilder/commit/895158abc6460bcfc18ef39b2728a25b4415895d) Add strict priority fee ordering mode for backrun bundles ([#410](https://github.com/flashbots/op-rbuilder/pull/410))
- [`b2326e8`](https://github.com/flashbots/op-rbuilder/commit/b2326e8000c4cb90a7209d018a814af667d83c7f) Add explicit backrun bundle cancellation via 0-tx submissions ([#423](https://github.com/flashbots/op-rbuilder/pull/423))
- [`dd09d24`](https://github.com/flashbots/op-rbuilder/commit/dd09d246c835f233ebfac1c308eb0d73267e513a) Local env ([#430](https://github.com/flashbots/op-rbuilder/pull/430))

### Miscellaneous

- [`c990ef7`](https://github.com/flashbots/op-rbuilder/commit/c990ef7eba5f097ab843a2bcc884ad57f033e681) Remove unused custom-engine-api feature flag ([#420](https://github.com/flashbots/op-rbuilder/pull/420))
- [`5270e9c`](https://github.com/flashbots/op-rbuilder/commit/5270e9ce9718a7762e715106450deb17faf3b107) Standardize releases ([#421](https://github.com/flashbots/op-rbuilder/pull/421))
- [`d95fa03`](https://github.com/flashbots/op-rbuilder/commit/d95fa0350d4646cacc4128ccde608e4580e92cb0) Replace BlockCell with watch channel ([#397](https://github.com/flashbots/op-rbuilder/pull/397))
- [`a4d8444`](https://github.com/flashbots/op-rbuilder/commit/a4d84446a0b8a5840c3747d25e93ccb66c43579d) Move tasks executor in payload builder ([#398](https://github.com/flashbots/op-rbuilder/pull/398))
- [`6a54a71`](https://github.com/flashbots/op-rbuilder/commit/6a54a71bfa83d0445bcb1c2206dab5a3f493b21d) Remove the standard builder [breaking-change] ([#424](https://github.com/flashbots/op-rbuilder/pull/424))
- [`28745e7`](https://github.com/flashbots/op-rbuilder/commit/28745e7541eb77581ed85feff9e7f60831aa4933) Fix repoducible builds ([#403](https://github.com/flashbots/op-rbuilder/pull/403))
- [`47b04f5`](https://github.com/flashbots/op-rbuilder/commit/47b04f5cd027c7c45cf1e09eab45568037b83428) Add incremental trie cache optimization for flashblocks state root calculation ([#427](https://github.com/flashbots/op-rbuilder/pull/427))
- [`53873f9`](https://github.com/flashbots/op-rbuilder/commit/53873f9d73af76f3f905674358e8fe34da3acb06) Lints all targets ([#426](https://github.com/flashbots/op-rbuilder/pull/426))
- [`d27c1fd`](https://github.com/flashbots/op-rbuilder/commit/d27c1fd7a7ef0ddfc70d44d5bbbd45b904b857d0) Use counters instead of histograms for a couple metrics ([#428](https://github.com/flashbots/op-rbuilder/pull/428))
- [`a72e017`](https://github.com/flashbots/op-rbuilder/commit/a72e0176ba836a88b5fc675536c3197382fb8908) Feature gate macos fix ([#431](https://github.com/flashbots/op-rbuilder/pull/431))
- [`0979b7c`](https://github.com/flashbots/op-rbuilder/commit/0979b7c509550f7e68fc20e64c29b6e8ef2464b7) Re-add flashblocks.enabled flag with deprecation warning ([#432](https://github.com/flashbots/op-rbuilder/pull/432))
- [`959dd28`](https://github.com/flashbots/op-rbuilder/commit/959dd28794af975a3ed10350922e16e38fb4f877) Async payload builder ([#434](https://github.com/flashbots/op-rbuilder/pull/434))
- [`64727e2`](https://github.com/flashbots/op-rbuilder/commit/64727e2cf7425d04cde84622a76dc82b91b51056) Release v0.4.0 ([#435](https://github.com/flashbots/op-rbuilder/pull/435))

## [0.3.3] - 2026-03-02

### Bug Fixes

- [`5fa7375`](https://github.com/flashbots/op-rbuilder/commit/5fa7375236d878a8212468218a54bcf9b3ae1f7e) Fix rb_test macro so default args are always produced ([#407](https://github.com/flashbots/op-rbuilder/pull/407))
- [`11796e7`](https://github.com/flashbots/op-rbuilder/commit/11796e73b0050dad2bb6a4bc9c2f1eed954ef216) Update testcontainers to v0.27.0 to remediate CVE-2025-62518 ([#396](https://github.com/flashbots/op-rbuilder/pull/396))

### Features

- [`4d41412`](https://github.com/flashbots/op-rbuilder/commit/4d41412343139f0b2ab58582e55a61778e4b8b1c) Ignore unrecognized cli flags ([#409](https://github.com/flashbots/op-rbuilder/pull/409))

### Miscellaneous

- [`14632d2`](https://github.com/flashbots/op-rbuilder/commit/14632d2eb4ef8cab3580015b248765aa402d714a) Backrun bundles ([#389](https://github.com/flashbots/op-rbuilder/pull/389))
- [`f2c6bc8`](https://github.com/flashbots/op-rbuilder/commit/f2c6bc84b1e13692e0e249a4c475624e085f8a3b) Clean up FBPoolTransaction trait ([#411](https://github.com/flashbots/op-rbuilder/pull/411))
- [`fbe1e26`](https://github.com/flashbots/op-rbuilder/commit/fbe1e26d808696f3ca40242278f7a67fc0907634) Revert ci toolchain version pin ([#412](https://github.com/flashbots/op-rbuilder/pull/412))
- [`7884f2c`](https://github.com/flashbots/op-rbuilder/commit/7884f2c0ba8861afbb4a6e645445510a225292f8) Remove builder-playground test ([#415](https://github.com/flashbots/op-rbuilder/pull/415))
- [`4658b42`](https://github.com/flashbots/op-rbuilder/commit/4658b425148330588437e9f58afc0c116e0b023a) Remove builder_signer from OpPayloadBuilderCtx because it wasn't doing anything ([#414](https://github.com/flashbots/op-rbuilder/pull/414))
- [`e3a7137`](https://github.com/flashbots/op-rbuilder/commit/e3a7137bf3172fcbff3cac0007c8242aac19356f) 0.3.3 ([#417](https://github.com/flashbots/op-rbuilder/pull/417))

### Refactor

- [`3916220`](https://github.com/flashbots/op-rbuilder/commit/39162200fd5152f6ee6e64eb183ab9624534227e) Remove ExtraCtx generic param ([#404](https://github.com/flashbots/op-rbuilder/pull/404))

## [0.3.2] - 2026-02-24

### Bug Fixes

- [`937612b`](https://github.com/flashbots/op-rbuilder/commit/937612bcf52a9df9f8c7a1abbf9db2ac08ba0b59) Separate flashblocks payloads handling and full built payloads in handler ([#354](https://github.com/flashbots/op-rbuilder/pull/354))
- [`bff17c4`](https://github.com/flashbots/op-rbuilder/commit/bff17c43be6097ccb6daed6b7b0118d0bda84804) Use rust:1.92-bookworm and debian:bookworm-slim for runtime ([#379](https://github.com/flashbots/op-rbuilder/pull/379))
- [`3b2217f`](https://github.com/flashbots/op-rbuilder/commit/3b2217f855d4f4f71a12d485f93e101b093591c7) Attempt to send one flashblock if payload deadline is in the past ([#386](https://github.com/flashbots/op-rbuilder/pull/386))
- [`b63a563`](https://github.com/flashbots/op-rbuilder/commit/b63a563d2428d44b7b13abe756ed75a53ffa3355) Fix release candidate workflow ([#387](https://github.com/flashbots/op-rbuilder/pull/387))

### Features

- [`7d7bb71`](https://github.com/flashbots/op-rbuilder/commit/7d7bb71b3d90805abdfa4677614054c194dbd7d9) Flashblock target and events with payload_id ([#365](https://github.com/flashbots/op-rbuilder/pull/365))

### Miscellaneous

- [`459bc4b`](https://github.com/flashbots/op-rbuilder/commit/459bc4bf6022ebbb7fae7dca852ae2b3cd4b9856) Add github action to automatically create release candidates ([#382](https://github.com/flashbots/op-rbuilder/pull/382))
- [`7db898d`](https://github.com/flashbots/op-rbuilder/commit/7db898d117e55f8efbd6b3d360c7635a29ec251a) Remove `git push origin` and use a precompiled binary ([#383](https://github.com/flashbots/op-rbuilder/pull/383))
- [`90772fa`](https://github.com/flashbots/op-rbuilder/commit/90772faefb5da3eff6cca52b7f8641e80dbb0a6c) Remove .claude ([#390](https://github.com/flashbots/op-rbuilder/pull/390))
- [`f63a443`](https://github.com/flashbots/op-rbuilder/commit/f63a443003f19969a482e17ec1b3eb32d0d2734d) Update builder-playground usage for local devnet runs and testing ([#395](https://github.com/flashbots/op-rbuilder/pull/395))
- [`1bfa5f9`](https://github.com/flashbots/op-rbuilder/commit/1bfa5f9d79b7da05a7fe8560b558b4ea17c6052d) Pin nightly version to resolve str::as_str() regression ([#401](https://github.com/flashbots/op-rbuilder/pull/401))
- [`dc0f032`](https://github.com/flashbots/op-rbuilder/commit/dc0f03225f7294790091840a55554df4b560df6c) Rename bundle fields for consistency (no api change) ([#402](https://github.com/flashbots/op-rbuilder/pull/402))
- [`fac3e6f`](https://github.com/flashbots/op-rbuilder/commit/fac3e6f573778b0218fe1975af81a41e72c2822f) 0.3.2 ([#400](https://github.com/flashbots/op-rbuilder/pull/400))

### Performance

- [`1d701d2`](https://github.com/flashbots/op-rbuilder/commit/1d701d26b0e81d08ee82af5daf6d5d0b2a4257bc) Remove unnecessary clones in payload building ([#392](https://github.com/flashbots/op-rbuilder/pull/392))

### Refactor

- [`329be9a`](https://github.com/flashbots/op-rbuilder/commit/329be9ac79eea8b201f8a03af14ac58de5c96e5c) Extract flashblock timing code and test it ([#380](https://github.com/flashbots/op-rbuilder/pull/380))

## [0.3.1] - 2026-02-04

### Bug Fixes

- [`8863dad`](https://github.com/flashbots/op-rbuilder/commit/8863dad5dec0418a5bedc18d9a8cbadddb5c8a3b) Add flashblocks payload subscriber count limit ([#373](https://github.com/flashbots/op-rbuilder/pull/373))

### Miscellaneous

- [`9cb3fc7`](https://github.com/flashbots/op-rbuilder/commit/9cb3fc76f456a013136ec88201cf308faa468efb) Update version to 0.3.0 ([#368](https://github.com/flashbots/op-rbuilder/pull/368))
- [`898ec7a`](https://github.com/flashbots/op-rbuilder/commit/898ec7a7099ef78d426ec4e57243b9da8fe0b76e) Upgrade reth to 1.10.2 ([#374](https://github.com/flashbots/op-rbuilder/pull/374))
- [`a708137`](https://github.com/flashbots/op-rbuilder/commit/a708137e9917864e11e101fa24c217edd41622ef) Fix external payload validation logic, resolve txs execution logic bug and add pre-exec validation ([#341](https://github.com/flashbots/op-rbuilder/pull/341))
- [`ed8eec4`](https://github.com/flashbots/op-rbuilder/commit/ed8eec449dab6e8eaab5be7ff26e97791d8b149e) Fix flashblocks builder p2p DNS resolution ([#372](https://github.com/flashbots/op-rbuilder/pull/372))
- [`c7a51ba`](https://github.com/flashbots/op-rbuilder/commit/c7a51baa5013c296798cc2999ee540f3ad6a3d29) Fix error handling on flashblock payload builder, do not panic node ([#364](https://github.com/flashbots/op-rbuilder/pull/364))
- [`1d8e0cd`](https://github.com/flashbots/op-rbuilder/commit/1d8e0cd5868f42c9055ecd310d6c074f65ece078) Support reconnection on disconnected static peers ([#340](https://github.com/flashbots/op-rbuilder/pull/340))
- [`f5c6312`](https://github.com/flashbots/op-rbuilder/commit/f5c63129edde9bd6db35254835edc19b74873413) Add log targets for better explicit logs filtering ([#371](https://github.com/flashbots/op-rbuilder/pull/371))
- [`c549377`](https://github.com/flashbots/op-rbuilder/commit/c549377293764257a9dd372f7e4a0728c61518ba) V0.3.1 ([#378](https://github.com/flashbots/op-rbuilder/pull/378))

### Refactor

- [`6873bbf`](https://github.com/flashbots/op-rbuilder/commit/6873bbf691d0b3300f2e28a2a9bfb0822045c0d8) Use task executor in payload handler ([#377](https://github.com/flashbots/op-rbuilder/pull/377))

## [0.3.0] - 2026-01-21

### Bug Fixes

- [`9362421`](https://github.com/flashbots/op-rbuilder/commit/93624218aa148f9f8ac4bc3b6c6a10db035c62a7) Fix external flashblock payload validation from p2p builders after jovian fork ([#343](https://github.com/flashbots/op-rbuilder/pull/343))
- [`d975705`](https://github.com/flashbots/op-rbuilder/commit/d975705288db59f4fbd6d39f11c9e8fd3fbfa864) Fix docker build ([#362](https://github.com/flashbots/op-rbuilder/pull/362))

### Features

- [`48ede7b`](https://github.com/flashbots/op-rbuilder/commit/48ede7ba3322452d78f93625eb93fd0ab8e335c4) Add release-plz automation ([#353](https://github.com/flashbots/op-rbuilder/pull/353))
- [`d4b36b5`](https://github.com/flashbots/op-rbuilder/commit/d4b36b50418cfff84569327ec020f8ece3824350) Add tokio metrics ([#367](https://github.com/flashbots/op-rbuilder/pull/367))

### Miscellaneous

- [`7687bc4`](https://github.com/flashbots/op-rbuilder/commit/7687bc42aaaafe63ce98d257264573ebd5f92f17) Fix div zero panic from zero fb calculation ([#35](https://github.com/flashbots/op-rbuilder/pull/35)) ([#342](https://github.com/flashbots/op-rbuilder/pull/342))
- [`215c9f1`](https://github.com/flashbots/op-rbuilder/commit/215c9f1146982eb6ce56e197858e15ba1bc76f1d) Update to reth 1.10.0 ([#355](https://github.com/flashbots/op-rbuilder/pull/355))
- [`af37149`](https://github.com/flashbots/op-rbuilder/commit/af371494a11735e3d44eaeb71c219e4919944644) Fix release pls workflow ([#356](https://github.com/flashbots/op-rbuilder/pull/356))
- [`cb9fca8`](https://github.com/flashbots/op-rbuilder/commit/cb9fca8f1793e070c1e1de8d9aef4a7abe4449a4) Don't publish to cargo.io ([#357](https://github.com/flashbots/op-rbuilder/pull/357))
- [`0bdc215`](https://github.com/flashbots/op-rbuilder/commit/0bdc215f185730144db046201f054dd3422ab075) Create release on stable tag ([#358](https://github.com/flashbots/op-rbuilder/pull/358))
- [`5df4c1b`](https://github.com/flashbots/op-rbuilder/commit/5df4c1b41b67f15f31285e413380027dffe64653) Create tag on release bot pr merge ([#360](https://github.com/flashbots/op-rbuilder/pull/360))
- [`5978155`](https://github.com/flashbots/op-rbuilder/commit/59781557c02441d3e4afa45a7a0c634386838788) Update toolchain to latest stable version of rust ([#361](https://github.com/flashbots/op-rbuilder/pull/361))
- [`9923cee`](https://github.com/flashbots/op-rbuilder/commit/9923cee7f53d8ef7724bbbb3a6d8076bc095cccc) Release v0.2.14 ([#359](https://github.com/flashbots/op-rbuilder/pull/359))
- [`5d45e7e`](https://github.com/flashbots/op-rbuilder/commit/5d45e7ec6c850257ade779184d54b7fa8417ba34) Fix zero div panic issue on new calc flashblocks timing func ([#363](https://github.com/flashbots/op-rbuilder/pull/363))

## [0.2.14] - 2026-01-08

### Features

- [`feed8bc`](https://github.com/flashbots/op-rbuilder/commit/feed8bcd7d2dca3c0a464e6f6668d324395b8391) Add BuilderTxValidation utility for validating builder transactions ([#347](https://github.com/flashbots/op-rbuilder/pull/347))

### Miscellaneous

- [`33c825a`](https://github.com/flashbots/op-rbuilder/commit/33c825a9e51d68b18eee6d6d32f173c77974ff0b) Update to use op-alloy flashblock types ([#328](https://github.com/flashbots/op-rbuilder/pull/328))
- [`7749480`](https://github.com/flashbots/op-rbuilder/commit/7749480e680a8da13dfa8e45c3f39ab9c9add0e4) Use op-alloy types instead of rollup-boost ([#344](https://github.com/flashbots/op-rbuilder/pull/344))
- [`73053fd`](https://github.com/flashbots/op-rbuilder/commit/73053fd499fdb737afa616da1b3ef55c9d2023c8) Add flashblock timing configuration options ([#348](https://github.com/flashbots/op-rbuilder/pull/348))
- [`7cb93f8`](https://github.com/flashbots/op-rbuilder/commit/7cb93f8b9c0675c9e4cc248f3377a279b5259d62) Set builder name in reth_builder_info ([#352](https://github.com/flashbots/op-rbuilder/pull/352))
- [`8e9e9b1`](https://github.com/flashbots/op-rbuilder/commit/8e9e9b1aaf875f34ccd432c0d60c2c44e19d1361) 0.2.14 ([#350](https://github.com/flashbots/op-rbuilder/pull/350))

## [0.2.13] - 2025-12-01

### Miscellaneous

- [`c119be1`](https://github.com/flashbots/op-rbuilder/commit/c119be14fa20351e4a7cbc8c03c385baf5989587) Update flashtestation logic to use new workload ID computation ([#331](https://github.com/flashbots/op-rbuilder/pull/331))
- [`c678f28`](https://github.com/flashbots/op-rbuilder/commit/c678f28a63f61f6b779d166b7ba547101d19bc02) Add cumulative da of builder tx da size ([#322](https://github.com/flashbots/op-rbuilder/pull/322))
- [`54413cd`](https://github.com/flashbots/op-rbuilder/commit/54413cd0a3fa80ec89c31eeca7074efb27b3b758) Update Cargo.toml ([#335](https://github.com/flashbots/op-rbuilder/pull/335))
- [`f1ed254`](https://github.com/flashbots/op-rbuilder/commit/f1ed25414ed597898b3b9a19212b581c6e098755) Fix deps ([#336](https://github.com/flashbots/op-rbuilder/pull/336))
- [`272d462`](https://github.com/flashbots/op-rbuilder/commit/272d462d980a43e7caf568df0fbbc0c2e0066207) 0.2.13 ([#337](https://github.com/flashbots/op-rbuilder/pull/337))

## [0.2.12] - 2025-11-19

### Miscellaneous

- [`6cd30b1`](https://github.com/flashbots/op-rbuilder/commit/6cd30b126be87bb38d7ae15bf1d517f430bfc412) Update version for jovian hardfork ([#323](https://github.com/flashbots/op-rbuilder/pull/323))
- [`6abc5ae`](https://github.com/flashbots/op-rbuilder/commit/6abc5aee23d4fb13a6e982531ecff5334c143092) Add blob gas used to flashblocks delta ([#325](https://github.com/flashbots/op-rbuilder/pull/325))
- [`dcab1ed`](https://github.com/flashbots/op-rbuilder/commit/dcab1ed689e7f06bea0d91f1af373ac9b77005ba) V0.2.12 op-rbuilder release ([#326](https://github.com/flashbots/op-rbuilder/pull/326))

## [0.2.11] - 2025-11-18

### Bug Fixes

- [`e335539`](https://github.com/flashbots/op-rbuilder/commit/e335539d8c44b4fe85cb9ef3ebbcfaf23144b812) Jovian hardfork tests & fixes ([#320](https://github.com/flashbots/op-rbuilder/pull/320))

### Miscellaneous

- [`e95a48f`](https://github.com/flashbots/op-rbuilder/commit/e95a48fcb1e8cddc24b750ce697193e154055b0d) Bump reth ([#321](https://github.com/flashbots/op-rbuilder/pull/321))

## [0.2.10] - 2025-11-13

### Miscellaneous

- [`afcf96b`](https://github.com/flashbots/op-rbuilder/commit/afcf96b0f27556e73399a3714e8e6a41434adb05) Bump reth to 1.9.2 ([#318](https://github.com/flashbots/op-rbuilder/pull/318))
- [`f1d2a80`](https://github.com/flashbots/op-rbuilder/commit/f1d2a80fba8136ae58975c663d9a63854dc47a4d) Op-rbuilder 0.2.10 release ([#319](https://github.com/flashbots/op-rbuilder/pull/319))

## [0.2.9] - 2025-11-10

### Documentation

- [`e6d72ad`](https://github.com/flashbots/op-rbuilder/commit/e6d72ad46bb94ae7a94adcd7bae06649ba7c9191) Clarify bundle block + fb number param interaction ([#307](https://github.com/flashbots/op-rbuilder/pull/307))

### Features

- [`440183b`](https://github.com/flashbots/op-rbuilder/commit/440183bd564dce309179153fb144ba93ee8c7d98) Implement flashblock sync over p2p ([#288](https://github.com/flashbots/op-rbuilder/pull/288))
- [`21046aa`](https://github.com/flashbots/op-rbuilder/commit/21046aaa1a5b382bcdda2b20969da1341fa28965) Publish synced flashblocks to ws ([#310](https://github.com/flashbots/op-rbuilder/pull/310))
- [`04c4d78`](https://github.com/flashbots/op-rbuilder/commit/04c4d78b25a59469c07206ef68307afcda63260a) Integrate downstream changes (Jovian hardfork + miner_setGasLimit + reth 1.9.1) ([#316](https://github.com/flashbots/op-rbuilder/pull/316))

### Miscellaneous

- [`23f503d`](https://github.com/flashbots/op-rbuilder/commit/23f503d76b9a021f8a068cc47d7ccf150a2385f6) Reth bump ([#306](https://github.com/flashbots/op-rbuilder/pull/306))
- [`0019a7b`](https://github.com/flashbots/op-rbuilder/commit/0019a7b93aca1c604fd6ff898e1639ce873c8122) Add permit functions for flashblocks number contract ([#287](https://github.com/flashbots/op-rbuilder/pull/287))
- [`b473f4e`](https://github.com/flashbots/op-rbuilder/commit/b473f4e791fc081416f7dcc128ff7b85476b6fcb) Remove ws publishing from synced flashblocks ([#312](https://github.com/flashbots/op-rbuilder/pull/312))
- [`f13be70`](https://github.com/flashbots/op-rbuilder/commit/f13be70aa4f2484ce65e41d18f831b2dcb297a72) [breaking-change] Fix arg for calculating state root ([#314](https://github.com/flashbots/op-rbuilder/pull/314))
- [`592ddad`](https://github.com/flashbots/op-rbuilder/commit/592ddad6f2ede3015ed9752628ec24aee015d84d) Add workload id as metric to builder ([#315](https://github.com/flashbots/op-rbuilder/pull/315))
- [`af0e74e`](https://github.com/flashbots/op-rbuilder/commit/af0e74e23ba92db24f88b672304410cca21ffa6b) 0.2.9 ([#317](https://github.com/flashbots/op-rbuilder/pull/317))

## [0.2.8] - 2025-10-27

### Bug Fixes

- [`4b934e4`](https://github.com/flashbots/op-rbuilder/commit/4b934e45b500bbcd6a0472c55ae5b29cb15dd62a) Remove incomplete step ([#301](https://github.com/flashbots/op-rbuilder/pull/301))

### Features

- [`8f08b2e`](https://github.com/flashbots/op-rbuilder/commit/8f08b2ececf93c6b2236c282626cc2e99e20b796) Implement p2p layer and broadcast flashblocks ([#275](https://github.com/flashbots/op-rbuilder/pull/275))

### Miscellaneous

- [`3665398`](https://github.com/flashbots/op-rbuilder/commit/3665398bc5c9fba9bc1d7843b97ba5e2de52fd80) Add codeowner ([#296](https://github.com/flashbots/op-rbuilder/pull/296))
- [`5cd19de`](https://github.com/flashbots/op-rbuilder/commit/5cd19de0eac9e4cd688be015cc23e79df2abc1e0) Add flashtestation builder tx and registration in block ([#282](https://github.com/flashbots/op-rbuilder/pull/282))
- [`012577e`](https://github.com/flashbots/op-rbuilder/commit/012577ed0c9b0a8dba315075e35538267549be86) Add flashtestations integration tests ([#283](https://github.com/flashbots/op-rbuilder/pull/283))
- [`fa24368`](https://github.com/flashbots/op-rbuilder/commit/fa24368a67751d57c22f5161f5cab05920342c20) Add unused_async lint, deny unreachable_pub ([#299](https://github.com/flashbots/op-rbuilder/pull/299))
- [`ab3278d`](https://github.com/flashbots/op-rbuilder/commit/ab3278d81f9f2848526890b4105a7c231f359ae2) 0.2.7 ([#300](https://github.com/flashbots/op-rbuilder/pull/300))
- [`663b981`](https://github.com/flashbots/op-rbuilder/commit/663b98101bd5ae2ca8535753af956d6802c9214f) Add permit flashtestations tx calls from builder ([#285](https://github.com/flashbots/op-rbuilder/pull/285))
- [`b601bcd`](https://github.com/flashbots/op-rbuilder/commit/b601bcda0e0527a5be0007b4ed138ceae0de863a) Remove non permit flashtestation calls ([#302](https://github.com/flashbots/op-rbuilder/pull/302))
- [`ceaf1c7`](https://github.com/flashbots/op-rbuilder/commit/ceaf1c730bd3c9c603b6741f8e06cb131b79e0ce) 0.2.8 ([#304](https://github.com/flashbots/op-rbuilder/pull/304))

### Refactor

- [`a3ff8ea`](https://github.com/flashbots/op-rbuilder/commit/a3ff8ea7ad1e5d439a919b016bcf5ee8023edff4) Clean up flashblocks context in payload builder ([#297](https://github.com/flashbots/op-rbuilder/pull/297))

## [0.2.6] - 2025-10-10

### Bug Fixes

- [`0bc3637`](https://github.com/flashbots/op-rbuilder/commit/0bc3637804e44d86301b3b90535a6303bf028c75) Fix docker build ([#292](https://github.com/flashbots/op-rbuilder/pull/292))
- [`28f8cac`](https://github.com/flashbots/op-rbuilder/commit/28f8cac5364ebef94b8f9f35aa1b565e10d3c758) Publish correct container index ([#293](https://github.com/flashbots/op-rbuilder/pull/293))

### Miscellaneous

- [`ea81432`](https://github.com/flashbots/op-rbuilder/commit/ea81432940c4e200f5b39ad6579c3e7e117e1a68) Flag to save tee key to local file ([#286](https://github.com/flashbots/op-rbuilder/pull/286))
- [`ab2fb51`](https://github.com/flashbots/op-rbuilder/commit/ab2fb516e1096bb19cc5dc1ae51cd89c8e2aece7) Bump reth to 1.8.2 ([#294](https://github.com/flashbots/op-rbuilder/pull/294))
- [`8ad2a94`](https://github.com/flashbots/op-rbuilder/commit/8ad2a94a6d0d9dd11801390e069849e4ba5e17b2) Release 0.2.6 ([#295](https://github.com/flashbots/op-rbuilder/pull/295))

## [0.2.5] - 2025-10-07

### Bug Fixes

- [`cfd1cf0`](https://github.com/flashbots/op-rbuilder/commit/cfd1cf07125a104875bf8fc477ca7e10b062bfd7) Dont mangle artifact binary name ([#289](https://github.com/flashbots/op-rbuilder/pull/289))

### Features

- [`7f58812`](https://github.com/flashbots/op-rbuilder/commit/7f588125a5a590cd2d0ee1b6af014965ecdf80ae) Push multi-platform container images ([#290](https://github.com/flashbots/op-rbuilder/pull/290))

### Miscellaneous

- [`220878f`](https://github.com/flashbots/op-rbuilder/commit/220878f84f5d459ff2fc5e887ddfed3cd9eb7dd5) Automatically build containers on release ([#279](https://github.com/flashbots/op-rbuilder/pull/279))
- [`f708634`](https://github.com/flashbots/op-rbuilder/commit/f7086347e083a8e6d589ce8aa527e4b68d9ec3a9) Fix readme ([#271](https://github.com/flashbots/op-rbuilder/pull/271))
- [`4cd0be6`](https://github.com/flashbots/op-rbuilder/commit/4cd0be6b7483c06b6baa56bb20d6864a9028a29a) Add metrics to track gas used by reverting txs ([#273](https://github.com/flashbots/op-rbuilder/pull/273))
- [`445c108`](https://github.com/flashbots/op-rbuilder/commit/445c10802fe2c7558712876a096ed7eca002bdc3) Add reproducible builds ([#233](https://github.com/flashbots/op-rbuilder/pull/233))
- [`1da7c00`](https://github.com/flashbots/op-rbuilder/commit/1da7c001051d469f9a59783dc11428686f3dce64) Add flashblocks number integration tests ([#277](https://github.com/flashbots/op-rbuilder/pull/277))
- [`ccdd1b1`](https://github.com/flashbots/op-rbuilder/commit/ccdd1b12f99c8e074fb8a01e6c9665990a457fc9) Update flashtestation service with latest contracts ([#281](https://github.com/flashbots/op-rbuilder/pull/281))
- [`eec8276`](https://github.com/flashbots/op-rbuilder/commit/eec827686b5daff283a5eaa81577bd63c8cb16df) 0.2.5 ([#291](https://github.com/flashbots/op-rbuilder/pull/291))

## [0.2.4] - 2025-09-29

### Features

- [`36260c6`](https://github.com/flashbots/op-rbuilder/commit/36260c66b6e3e5b863795dee846ba38d9f71a52d) Overwrite reth default cache directory ([#238](https://github.com/flashbots/op-rbuilder/pull/238))

### Miscellaneous

- [`95b420a`](https://github.com/flashbots/op-rbuilder/commit/95b420a6e9a91f61fd265801967dcf88e37cfb96) Bump reth to 1.8.1 ([#274](https://github.com/flashbots/op-rbuilder/pull/274))
- [`83f9cee`](https://github.com/flashbots/op-rbuilder/commit/83f9ceefc060558dc0fed1a4d6c7732811c1390d) Add remote quote provider arg for flashtestations ([#276](https://github.com/flashbots/op-rbuilder/pull/276))
- [`af00d1f`](https://github.com/flashbots/op-rbuilder/commit/af00d1f5709789bdb6d770822acd69541149e5a4) 0.2.4 ([#278](https://github.com/flashbots/op-rbuilder/pull/278))

## [0.2.3] - 2025-09-22

### Bug Fixes

- [`fa9924e`](https://github.com/flashbots/op-rbuilder/commit/fa9924e2fff889862b968e76cacf9f284f9f6e37) Check per-address gas limit before checking if the tx reverted ([#266](https://github.com/flashbots/op-rbuilder/pull/266))

### Miscellaneous

- [`fed74d1`](https://github.com/flashbots/op-rbuilder/commit/fed74d10512e6abb0e71e891233b623932d8102f) Flag to determine if calculating state root ([#241](https://github.com/flashbots/op-rbuilder/pull/241))
- [`265ebc2`](https://github.com/flashbots/op-rbuilder/commit/265ebc2477bc340e658cf9132890a368bdda14f8) Fix release artifacts ([#262](https://github.com/flashbots/op-rbuilder/pull/262))
- [`6b1752f`](https://github.com/flashbots/op-rbuilder/commit/6b1752f5b752263c3f3b40480511f641011dcfe1) Refactor payload builder to accept generic builder tx ([#217](https://github.com/flashbots/op-rbuilder/pull/217))
- [`e1893d7`](https://github.com/flashbots/op-rbuilder/commit/e1893d78ca0ceb36b886e902137c07a1c091c652) Add support for flashblocks number contract builder tx ([#256](https://github.com/flashbots/op-rbuilder/pull/256))
- [`6267095`](https://github.com/flashbots/op-rbuilder/commit/6267095f51bfe5c40da655f8faa40f360413c7f1) 0.2.3 ([#270](https://github.com/flashbots/op-rbuilder/pull/270))

### Refactor

- [`192d8b4`](https://github.com/flashbots/op-rbuilder/commit/192d8b4ba1392566dda0ecf791952850cf050f47) Add `unreachable_pub` warning and autofix warnings ([#263](https://github.com/flashbots/op-rbuilder/pull/263))
- [`c92a924`](https://github.com/flashbots/op-rbuilder/commit/c92a924839dbab5d6860770567ea070cb1ebb591) Clean up and improve flashblocks `build_payload` ([#260](https://github.com/flashbots/op-rbuilder/pull/260))

## [0.2.2] - 2025-09-12

### Bug Fixes

- [`7403f95`](https://github.com/flashbots/op-rbuilder/commit/7403f951a3a3f165f4db5860016d5dc4a83a4487) Gracefull cancellation on payload build failure ([#239](https://github.com/flashbots/op-rbuilder/pull/239))
- [`abff43f`](https://github.com/flashbots/op-rbuilder/commit/abff43f81a02ec68acb955f9c9094404150e5334) Flashblock contraints in bundle api ([#259](https://github.com/flashbots/op-rbuilder/pull/259))

### Features

- [`8b19955`](https://github.com/flashbots/op-rbuilder/commit/8b19955b594fc2e8da46f98cec32f2e867783370) Add commit message and author in version metrics ([#236](https://github.com/flashbots/op-rbuilder/pull/236))

### Miscellaneous

- [`e863882`](https://github.com/flashbots/op-rbuilder/commit/e863882855674c12dcf971aaab5a5025d1075b7c) Bump reth to 1.7.0 ([#258](https://github.com/flashbots/op-rbuilder/pull/258))
- [`5640d8c`](https://github.com/flashbots/op-rbuilder/commit/5640d8c7fb6f5722648c4cada09e99f9e78d12d1) 0.2.2 ([#261](https://github.com/flashbots/op-rbuilder/pull/261))

## [0.2.1] - 2025-09-09

### Features

- [`d0f1aad`](https://github.com/flashbots/op-rbuilder/commit/d0f1aadc4eacafd41b0fb63ce530bf29858434b1) Address gas limiter ([#253](https://github.com/flashbots/op-rbuilder/pull/253))

### Miscellaneous

- [`6abfa98`](https://github.com/flashbots/op-rbuilder/commit/6abfa98101968b481ccf15822c194675a32841f2) Release op-rbuilder 0.2.1 ([#255](https://github.com/flashbots/op-rbuilder/pull/255))

## [0.2.0] - 2025-08-29

### Documentation

- [`ba86ac4`](https://github.com/flashbots/op-rbuilder/commit/ba86ac4ec00a8f14b42bc33b29a850726f91d1ed) Eth_sendBundle ([#243](https://github.com/flashbots/op-rbuilder/pull/243))

### Miscellaneous

- [`f135052`](https://github.com/flashbots/op-rbuilder/commit/f135052f6cd0ad40c696f3545d08b061dac6376f) Update rust edition to 2024 ([#244](https://github.com/flashbots/op-rbuilder/pull/244))
- [`00a3a7c`](https://github.com/flashbots/op-rbuilder/commit/00a3a7ccd52bcbcb7268a12d082ded28d829d571) Add flashblocks sequence diagram ([#252](https://github.com/flashbots/op-rbuilder/pull/252))
- [`9e4b327`](https://github.com/flashbots/op-rbuilder/commit/9e4b3279a01e4e3013876204be350e8265119776) Bump version to 0.2.0 ([#250](https://github.com/flashbots/op-rbuilder/pull/250))

## [0.0.2] - 2025-08-25

### Bug Fixes

- [`ae2f8b9`](https://github.com/flashbots/op-rbuilder/commit/ae2f8b9e0295cbe756b69ca40046c6d76285e8d1) Tg invite link ([#9](https://github.com/flashbots/op-rbuilder/pull/9))
- [`460bd7a`](https://github.com/flashbots/op-rbuilder/commit/460bd7afd07b7eaeb4fcf955ac701131d58606cb) Parameter change ([#16](https://github.com/flashbots/op-rbuilder/pull/16))
- [`0896e31`](https://github.com/flashbots/op-rbuilder/commit/0896e315cf7e3ff87762217568f2b0a0906f74fa) Delete unused features of alloy-chains ([#66](https://github.com/flashbots/op-rbuilder/pull/66))
- [`ef783e4`](https://github.com/flashbots/op-rbuilder/commit/ef783e42aed6a9558290370bf1a6189cb2f8441f) Fix token permissions
- [`00ab95e`](https://github.com/flashbots/op-rbuilder/commit/00ab95e477bc20bfa3b2c35267aa3142cf93d7fe) Fix beginner setup/instructions for playground config ([#232](https://github.com/flashbots/op-rbuilder/pull/232))
- [`004e6fc`](https://github.com/flashbots/op-rbuilder/commit/004e6fc8a96e6d1c4c4920a515438d9a221bc7d9) Bump rust version in Dockerfile ([#257](https://github.com/flashbots/op-rbuilder/pull/257))
- [`1ef890f`](https://github.com/flashbots/op-rbuilder/commit/1ef890f0a78d8f1b7c80f7cd393980924cc95e7b) Bench ci ([#357](https://github.com/flashbots/op-rbuilder/pull/357))
- [`d60466b`](https://github.com/flashbots/op-rbuilder/commit/d60466b9d52c64833fe2bc935b90c9ae96b6cce5) Fixed variable name mismatch in for loop ([#408](https://github.com/flashbots/op-rbuilder/pull/408))
- [`b7fa7ed`](https://github.com/flashbots/op-rbuilder/commit/b7fa7edd3b22d4d763a1392bcb6979669c8e3bcd) Update to reth 1.2.2 for eip6110::parse_deposits_from_receipts ([#467](https://github.com/flashbots/op-rbuilder/pull/467))
- [`be0ae83`](https://github.com/flashbots/op-rbuilder/commit/be0ae83269bacaa68e5d3523ca4b4c68e8a6f335) Payout gas limit estimation ([#523](https://github.com/flashbots/op-rbuilder/pull/523))
- [`258351f`](https://github.com/flashbots/op-rbuilder/commit/258351f10df7949f443838bc4d45faac3f71a025) Don't miss blocks on batcher updates ([#529](https://github.com/flashbots/op-rbuilder/pull/529))
- [`82a0be3`](https://github.com/flashbots/op-rbuilder/commit/82a0be3225a54ca0adc4b0bf151c8b7c2ad09ee6) Don't build flashblocks with more gas than block gas limit ([#567](https://github.com/flashbots/op-rbuilder/pull/567))
- [`da259cd`](https://github.com/flashbots/op-rbuilder/commit/da259cdcb8434b16fed5b0e55935cf8a3688184f) Set an address for authrpc to the op-rbuilder readme ([#581](https://github.com/flashbots/op-rbuilder/pull/581))
- [`f71f346`](https://github.com/flashbots/op-rbuilder/commit/f71f34672ac570a629b0d8bb50ddc59c52e8fb26) Update features flags ([#103](https://github.com/flashbots/op-rbuilder/pull/103))
- [`102a5fb`](https://github.com/flashbots/op-rbuilder/commit/102a5fb4c0b95e6ff5e17450e670c70191739daa) Add default-run to the op-rbuilder's manifest ([#162](https://github.com/flashbots/op-rbuilder/pull/162))
- [`8909ca1`](https://github.com/flashbots/op-rbuilder/commit/8909ca1d3d3c6e1ca5b2e7c58a582bc2e5d10d49) Fix op-rbuilder release workflow ([#216](https://github.com/flashbots/op-rbuilder/pull/216))
- [`bb31c69`](https://github.com/flashbots/op-rbuilder/commit/bb31c69d63d9e59e81d8454f67b22c08f38c5ad8) Record missing flashblocks ([#225](https://github.com/flashbots/op-rbuilder/pull/225))
- [`784ad05`](https://github.com/flashbots/op-rbuilder/commit/784ad0581a93760c2ea4e44674519b5cedd17457) Record num txs built with flashblocks enabled ([#227](https://github.com/flashbots/op-rbuilder/pull/227))
- [`0f276ed`](https://github.com/flashbots/op-rbuilder/commit/0f276edc53925aa7db117479d50a4b71a781096e) README.md deadlinks ([#237](https://github.com/flashbots/op-rbuilder/pull/237))
- [`6d6763e`](https://github.com/flashbots/op-rbuilder/commit/6d6763ef850261703a74b57c6ab07f765df6de94) Override clap long version envs ([#235](https://github.com/flashbots/op-rbuilder/pull/235))
- [`b60ae07`](https://github.com/flashbots/op-rbuilder/commit/b60ae0773c80a777db8ddb2ba449b074bf9ce29d) Unquoted square brackets in gh workflows ([#247](https://github.com/flashbots/op-rbuilder/pull/247))
- [`021beff`](https://github.com/flashbots/op-rbuilder/commit/021beff607c14a9424ccf4315ec20e9e50084af9) Release name ([#248](https://github.com/flashbots/op-rbuilder/pull/248))

### Documentation

- [`44f8086`](https://github.com/flashbots/op-rbuilder/commit/44f808692be502fad22b8f54e6edeb65a6896153) Add stability and release info ([#28](https://github.com/flashbots/op-rbuilder/pull/28))
- [`3a575fd`](https://github.com/flashbots/op-rbuilder/commit/3a575fd05eca6ea35c22c9572bd42be5c91d6b22) More readme for builder-playground ([#99](https://github.com/flashbots/op-rbuilder/pull/99))
- [`8cb365a`](https://github.com/flashbots/op-rbuilder/commit/8cb365a097b529d3fd02843ceddf5940bd54a257) Pin ci badge to develop branch ([#157](https://github.com/flashbots/op-rbuilder/pull/157))
- [`5aea8aa`](https://github.com/flashbots/op-rbuilder/commit/5aea8aaacd97ab8101833220ef9c324b8e1a16fd) Reproducible builds ([#181](https://github.com/flashbots/op-rbuilder/pull/181))

### Features

- [`017e6a1`](https://github.com/flashbots/op-rbuilder/commit/017e6a1ef3b397914340c89388ac988d3d3359a8) Badges for the readme ([#11](https://github.com/flashbots/op-rbuilder/pull/11))
- [`76898d2`](https://github.com/flashbots/op-rbuilder/commit/76898d23d27ea7baa17a6f16e172cd5bf9a895ff) Add BuiltBlockTracerError ([#21](https://github.com/flashbots/op-rbuilder/pull/21))
- [`a4cd916`](https://github.com/flashbots/op-rbuilder/commit/a4cd91601f8503819960aaa60ea5f2570b646c2c) Add a vec of trait datasources to historical data fetcher ([#13](https://github.com/flashbots/op-rbuilder/pull/13))
- [`31467ca`](https://github.com/flashbots/op-rbuilder/commit/31467ca85b02e60ea4e28cb8f68d07e70e04642e) Add abstraction for the beacon api client ([#34](https://github.com/flashbots/op-rbuilder/pull/34))
- [`fce98e1`](https://github.com/flashbots/op-rbuilder/commit/fce98e1277307036b4fdd9ed97bc4c1262a655b2) Use alloy types for mevboost client ([#15](https://github.com/flashbots/op-rbuilder/pull/15))
- [`3c4c506`](https://github.com/flashbots/op-rbuilder/commit/3c4c5065738ff2981fcc9a17a366a7b9cb4c7fb4) Pectra ([#183](https://github.com/flashbots/op-rbuilder/pull/183))
- [`fc5e990`](https://github.com/flashbots/op-rbuilder/commit/fc5e99002e87480c46e41b98bf3b82e8accd4074) Add parallel builder ([#219](https://github.com/flashbots/op-rbuilder/pull/219))
- [`b39f17c`](https://github.com/flashbots/op-rbuilder/commit/b39f17c09b3c7343e3f47ef187dd905de04a6157) Add build arg RBUILDER_BIN to dockerfile ([#237](https://github.com/flashbots/op-rbuilder/pull/237))
- [`2397b4f`](https://github.com/flashbots/op-rbuilder/commit/2397b4f62c0e473d31ee53e9ebd3baa7a495f1bc) Add a justfile to run tests ([#106](https://github.com/flashbots/op-rbuilder/pull/106))
- [`cd9684c`](https://github.com/flashbots/op-rbuilder/commit/cd9684cfbbb15c3c4b93dbfa6d3fe2a88cf17702) Add a feature to activate otlp telemetry ([#31](https://github.com/flashbots/op-rbuilder/pull/31))
- [`0524dac`](https://github.com/flashbots/op-rbuilder/commit/0524dacd3b7b3f8bbead41c7b858d928326de43b) Add transaction gas limit ([#214](https://github.com/flashbots/op-rbuilder/pull/214))

### Miscellaneous

- [`c07d89d`](https://github.com/flashbots/op-rbuilder/commit/c07d89dd4601dafd70ed7d9b01495231e50991a0) Initial commit
- [`a7ccd58`](https://github.com/flashbots/op-rbuilder/commit/a7ccd583d62c3613d9a54d1558b2d2ddbb02a1ad) Use develop as default branch ([#6](https://github.com/flashbots/op-rbuilder/pull/6))
- [`f735cd7`](https://github.com/flashbots/op-rbuilder/commit/f735cd76306fb08267db76f9752d6156546afd82) Add license files ([#7](https://github.com/flashbots/op-rbuilder/pull/7))
- [`93b173e`](https://github.com/flashbots/op-rbuilder/commit/93b173e2811a29ecf7dabb1629b569217ea87ca4) Minor readme updates ([#19](https://github.com/flashbots/op-rbuilder/pull/19))
- [`e03571e`](https://github.com/flashbots/op-rbuilder/commit/e03571ec0c2513124dde3cc5b2fbdc6f3dfd10ce) Adds a high level description of the block building algorithm. ([#22](https://github.com/flashbots/op-rbuilder/pull/22))
- [`39f3659`](https://github.com/flashbots/op-rbuilder/commit/39f36598ef55a583fa4a7212526699f0829191e8) Upload benchmark report from separate workflow ([#23](https://github.com/flashbots/op-rbuilder/pull/23))
- [`2114e07`](https://github.com/flashbots/op-rbuilder/commit/2114e07a268fa27532a6ae60c0d0f13d214d7839) Add proc macros to ignore tests if env or http not set ([#36](https://github.com/flashbots/op-rbuilder/pull/36))
- [`f5a4366`](https://github.com/flashbots/op-rbuilder/commit/f5a43660a41e9966ca782ae20d5326c0c5ff21b2) Bump alloy to 0.2 ([#71](https://github.com/flashbots/op-rbuilder/pull/71))
- [`e755b68`](https://github.com/flashbots/op-rbuilder/commit/e755b68faa42a25e30255ec9c17d7cefbb223292) Bump reth to v1.0.3 ([#51](https://github.com/flashbots/op-rbuilder/pull/51))
- [`a2fac81`](https://github.com/flashbots/op-rbuilder/commit/a2fac81db0c6b3b98c9d285d365aab2be9f967b5) Add playground integration ([#69](https://github.com/flashbots/op-rbuilder/pull/69))
- [`f60de7d`](https://github.com/flashbots/op-rbuilder/commit/f60de7dcdaa11e6ae15881ea2206b9515fb99f0c) Doc explaining reorg losses. ([#102](https://github.com/flashbots/op-rbuilder/pull/102))
- [`a8f0a52`](https://github.com/flashbots/op-rbuilder/commit/a8f0a52c9f7c40b113cd37f4fd5726d9ee35f4e7) Add a safety check to benchmark uploads ([#105](https://github.com/flashbots/op-rbuilder/pull/105))
- [`8bbde5f`](https://github.com/flashbots/op-rbuilder/commit/8bbde5f434339be363dee53e41ad7da0c1b9d42f) Use webhook for notif
- [`ef09967`](https://github.com/flashbots/op-rbuilder/commit/ef099679e5d0924ec68ad6038791b1ddb168c5ff) Enable lint, integration with cache ([#103](https://github.com/flashbots/op-rbuilder/pull/103))
- [`28c907c`](https://github.com/flashbots/op-rbuilder/commit/28c907c54e4e9099304ed3410e3a3141510cc02a) Shell expand the reth data dir ([#114](https://github.com/flashbots/op-rbuilder/pull/114))
- [`c9da194`](https://github.com/flashbots/op-rbuilder/commit/c9da194f09f23183e12c495f85cd98c727d042df) Cleanup example config: comment internal blocks_processor_url ([#98](https://github.com/flashbots/op-rbuilder/pull/98))
- [`92d1283`](https://github.com/flashbots/op-rbuilder/commit/92d1283df17bd44e0ca2c613cc55ed7aa7d15ff5) Replace ethers usage with alloy ([#142](https://github.com/flashbots/op-rbuilder/pull/142))
- [`76601fe`](https://github.com/flashbots/op-rbuilder/commit/76601fe5cad5984fbe81097ae4c7c78ce9674f31) Pin alloy ([#153](https://github.com/flashbots/op-rbuilder/pull/153))
- [`d91aa87`](https://github.com/flashbots/op-rbuilder/commit/d91aa872b4b944bee8e2e08b29904c60b01f06e6) Disable dependabot ([#150](https://github.com/flashbots/op-rbuilder/pull/150))
- [`aec01c6`](https://github.com/flashbots/op-rbuilder/commit/aec01c6899f902302ab56367b939e71875a608cb) Remove dependabot yaml file ([#155](https://github.com/flashbots/op-rbuilder/pull/155))
- [`db6d87c`](https://github.com/flashbots/op-rbuilder/commit/db6d87c1298b3c472e3c9d4c3171abfe919ce07a) Add @ferranbt to codeowners ([#158](https://github.com/flashbots/op-rbuilder/pull/158))
- [`f0b56aa`](https://github.com/flashbots/op-rbuilder/commit/f0b56aa8ca1d842b48d49036614926192df96fae) Add benchmark for txfetcher ([#134](https://github.com/flashbots/op-rbuilder/pull/134))
- [`b01e15f`](https://github.com/flashbots/op-rbuilder/commit/b01e15fbc9987791d2e90a23d413bc48773b4deb) Improve metrics developer experience ([#170](https://github.com/flashbots/op-rbuilder/pull/170))
- [`b631b1c`](https://github.com/flashbots/op-rbuilder/commit/b631b1c12bd5505cc7acbfcc50c87bdb883040d8) Use root playgroung config toml file ([#173](https://github.com/flashbots/op-rbuilder/pull/173))
- [`79f6bc2`](https://github.com/flashbots/op-rbuilder/commit/79f6bc263f082ab5cf53d2591799d95df8976ba8) Reth v1.0.6 ([#165](https://github.com/flashbots/op-rbuilder/pull/165))
- [`f1fc7d7`](https://github.com/flashbots/op-rbuilder/commit/f1fc7d7bbd1e0a395222086a6dc4e9cd87f2fa10) Redact_sensitive feature flag ([#176](https://github.com/flashbots/op-rbuilder/pull/176))
- [`cfd872e`](https://github.com/flashbots/op-rbuilder/commit/cfd872e1a8301f60d060e4512447db00c62c2c26) Add sample Lighthouse config ([#179](https://github.com/flashbots/op-rbuilder/pull/179))
- [`1d3e4b5`](https://github.com/flashbots/op-rbuilder/commit/1d3e4b599e68c3eceaf0155b03d9078204c5ba34) Sparse trie ([#174](https://github.com/flashbots/op-rbuilder/pull/174))
- [`936dc21`](https://github.com/flashbots/op-rbuilder/commit/936dc2184120ec4867a60c86658d8df6c1d3f6ae) Bump rust version to 1.81 ([#197](https://github.com/flashbots/op-rbuilder/pull/197))
- [`ba70142`](https://github.com/flashbots/op-rbuilder/commit/ba701429787c10ad37b9063b2bd483febd55b854) Bump keccak-asm, sha3-asm ([#198](https://github.com/flashbots/op-rbuilder/pull/198))
- [`7174680`](https://github.com/flashbots/op-rbuilder/commit/71746807ae4fa8202af81885393ef173f31d71ee) Root hash prefetcher + small things ([#204](https://github.com/flashbots/op-rbuilder/pull/204))
- [`30e2d69`](https://github.com/flashbots/op-rbuilder/commit/30e2d69fa6e86cf1d204824f4060a103bc79897e) In-process rbuilder ([#228](https://github.com/flashbots/op-rbuilder/pull/228))
- [`6c05693`](https://github.com/flashbots/op-rbuilder/commit/6c056934de7c041217850177f81fd206838cbb76) Move flashbots/eth-sparse-mpt to a workspace crate ([#248](https://github.com/flashbots/op-rbuilder/pull/248))
- [`b29b747`](https://github.com/flashbots/op-rbuilder/commit/b29b747ad2ecc302af20db9e912babbb49665954) Op-rbuilder ([#244](https://github.com/flashbots/op-rbuilder/pull/244))
- [`3d7567e`](https://github.com/flashbots/op-rbuilder/commit/3d7567e837e2b20b98fe67db8a4e557be6c80607) Add --package=${RBUILDER_BIN} to fix reth-rbuilder container ([#250](https://github.com/flashbots/op-rbuilder/pull/250))
- [`fe1f9f8`](https://github.com/flashbots/op-rbuilder/commit/fe1f9f819e5e320dc68861b6408838bcd223f7c9) Op-rbuilder telemetry ([#252](https://github.com/flashbots/op-rbuilder/pull/252))
- [`902acdb`](https://github.com/flashbots/op-rbuilder/commit/902acdba6f0eba501d7ac2f9ba9d57e91e57cb7c) Add `reth-rbuilder` crate to default-members ([#251](https://github.com/flashbots/op-rbuilder/pull/251))
- [`31ccc87`](https://github.com/flashbots/op-rbuilder/commit/31ccc878ee428ddefb9cbe09a597aa4f73cb0837) Reth v1.1.1 ([#255](https://github.com/flashbots/op-rbuilder/pull/255))
- [`71dc18d`](https://github.com/flashbots/op-rbuilder/commit/71dc18d3fe4616b424dfc777d5808d773b4d7b63) Update CODEOWNERS ([#259](https://github.com/flashbots/op-rbuilder/pull/259))
- [`0e6c121`](https://github.com/flashbots/op-rbuilder/commit/0e6c121ac15b6b4988546c2f3bafc58812d13a41) Add docker build step to CI ([#258](https://github.com/flashbots/op-rbuilder/pull/258))
- [`0d1c66d`](https://github.com/flashbots/op-rbuilder/commit/0d1c66d14eaace79db76c8331d369fc98c9ac7c5) Docker build time and CI ([#261](https://github.com/flashbots/op-rbuilder/pull/261))
- [`d92fa83`](https://github.com/flashbots/op-rbuilder/commit/d92fa83193eeb3fc4bef2696df9a58bbc93123d1) Add `reth-rbuilder` as an artifact target in CI ([#262](https://github.com/flashbots/op-rbuilder/pull/262))
- [`56d904a`](https://github.com/flashbots/op-rbuilder/commit/56d904aa8dc14f53e5d101e3dc80b552c78e91f4) Label artifact version and feature selection in CI ([#264](https://github.com/flashbots/op-rbuilder/pull/264))
- [`9284e46`](https://github.com/flashbots/op-rbuilder/commit/9284e4694f57062a7d9a054d5950da2a64ab5d4a) Rm redundant arc ([#268](https://github.com/flashbots/op-rbuilder/pull/268))
- [`70bd802`](https://github.com/flashbots/op-rbuilder/commit/70bd802e0bc744212d170e90f7c3d89268df38ca) Replace std mutex with parking lot ([#269](https://github.com/flashbots/op-rbuilder/pull/269))
- [`644e063`](https://github.com/flashbots/op-rbuilder/commit/644e0636a9fd5d87ed106ec94c9aadbc21fca6a9) Bump Reth to 1.1.2 ([#288](https://github.com/flashbots/op-rbuilder/pull/288))
- [`0562c1d`](https://github.com/flashbots/op-rbuilder/commit/0562c1d00a63dbbe41eb46793e71707633df57ff) Run all benchmarks in `make bench` and CI ([#292](https://github.com/flashbots/op-rbuilder/pull/292))
- [`d7e59c4`](https://github.com/flashbots/op-rbuilder/commit/d7e59c4f5e585023a332106c3b63f7eeca979fcc) Validate builder configs in CI ([#294](https://github.com/flashbots/op-rbuilder/pull/294))
- [`117e73e`](https://github.com/flashbots/op-rbuilder/commit/117e73ee2d08aebd346e3a8c51d84991e1f6b9d7) Add sysperf command ([#289](https://github.com/flashbots/op-rbuilder/pull/289))
- [`b00cc7b`](https://github.com/flashbots/op-rbuilder/commit/b00cc7bdd21475456b5347c8c28502cae3cecc21) Add System Information to sysperf command ([#308](https://github.com/flashbots/op-rbuilder/pull/308))
- [`29acb6b`](https://github.com/flashbots/op-rbuilder/commit/29acb6b22219c72b290020dba2866e63665ff7b9) Move bundle merger ([#298](https://github.com/flashbots/op-rbuilder/pull/298))
- [`4aa0e7d`](https://github.com/flashbots/op-rbuilder/commit/4aa0e7d2f204fe0de6d3160d63e8acd6ca2c2823) Do not run redact sensitive integration test ([#332](https://github.com/flashbots/op-rbuilder/pull/332))
- [`20a1239`](https://github.com/flashbots/op-rbuilder/commit/20a1239ea5e07b355531977b92cd7760d68c91fb) Update workflows ([#345](https://github.com/flashbots/op-rbuilder/pull/345))
- [`1568696`](https://github.com/flashbots/op-rbuilder/commit/1568696e4d04213058d687bd898584758c83f79e) Add StateProviderFactory custom trait ([#331](https://github.com/flashbots/op-rbuilder/pull/331))
- [`3d9c089`](https://github.com/flashbots/op-rbuilder/commit/3d9c08957b1b7d0591d6465b0d8856acb70624dc) Add builder tx at end of block in op-rbuilder ([#346](https://github.com/flashbots/op-rbuilder/pull/346))
- [`d915d23`](https://github.com/flashbots/op-rbuilder/commit/d915d237208a545e55bc7cae198b817d64734b67) In-process rbuilder orderpool <> reth transaction-pool connection ([#339](https://github.com/flashbots/op-rbuilder/pull/339))
- [`678a07f`](https://github.com/flashbots/op-rbuilder/commit/678a07f0d6a83569475b9bfdbea3515d26048233) Backtesting fixed ([#360](https://github.com/flashbots/op-rbuilder/pull/360))
- [`1ac1572`](https://github.com/flashbots/op-rbuilder/commit/1ac157219af170629c8e0db0f728d6743d4d383b) Add flashblocks payload builder ([#352](https://github.com/flashbots/op-rbuilder/pull/352))
- [`a19e366`](https://github.com/flashbots/op-rbuilder/commit/a19e3662b9d5e24caccc71090604a7b87f9bfb97) Fix error message for KeyNotFound variant ([#367](https://github.com/flashbots/op-rbuilder/pull/367))
- [`1050e10`](https://github.com/flashbots/op-rbuilder/commit/1050e10282a55112ff9920b0817e7aa3d89a4ce2) Update dep to reth115 ([#368](https://github.com/flashbots/op-rbuilder/pull/368))
- [`c406368`](https://github.com/flashbots/op-rbuilder/commit/c4063685bfda2e8d4377b69106865411a65a8828) Add builder tx to new op-rbuilder ([#361](https://github.com/flashbots/op-rbuilder/pull/361))
- [`ffe533a`](https://github.com/flashbots/op-rbuilder/commit/ffe533a96e2141479d48a6ab014bb4165db14500) Add monitoring exex for op-rbuilder ([#365](https://github.com/flashbots/op-rbuilder/pull/365))
- [`c5f2c1d`](https://github.com/flashbots/op-rbuilder/commit/c5f2c1d9af3d95dcf34c54a600df0e18e1ad3d1a) Add op-rbuilder metrics ([#378](https://github.com/flashbots/op-rbuilder/pull/378))
- [`5205a79`](https://github.com/flashbots/op-rbuilder/commit/5205a79c9f3de404432e3960660d55ae3b616380) Rename payload generator ([#382](https://github.com/flashbots/op-rbuilder/pull/382))
- [`49287ff`](https://github.com/flashbots/op-rbuilder/commit/49287ff9d821a88ae0d1b17ff6f749bbdbe73943) Add integration test for op-rbuilder ([#381](https://github.com/flashbots/op-rbuilder/pull/381))
- [`dee01b6`](https://github.com/flashbots/op-rbuilder/commit/dee01b6b2eca5aceb47c890fe5c92f3c21a91cf8) Add op-rbuilder README ([#383](https://github.com/flashbots/op-rbuilder/pull/383))
- [`ded3ced`](https://github.com/flashbots/op-rbuilder/commit/ded3cedd919491cb7f320b0b69f26b69b887f591) Add deposit command for op-rbuilder tester ([#384](https://github.com/flashbots/op-rbuilder/pull/384))
- [`860a2c5`](https://github.com/flashbots/op-rbuilder/commit/860a2c5f45b523f438499b261883efe5ec23ea02) Add `rust-toolchain.toml` ([#391](https://github.com/flashbots/op-rbuilder/pull/391))
- [`abc68bc`](https://github.com/flashbots/op-rbuilder/commit/abc68bc099b026f07711d5cf533751be7b614edd) Workspace wide package settings ([#390](https://github.com/flashbots/op-rbuilder/pull/390))
- [`e6cdbaa`](https://github.com/flashbots/op-rbuilder/commit/e6cdbaa0a908848e25ca28081b9619df0559beb1) Blocklist integration tests ([#396](https://github.com/flashbots/op-rbuilder/pull/396))
- [`9dafcb2`](https://github.com/flashbots/op-rbuilder/commit/9dafcb2dc7b8847135b8c8f0bdd464bab65eaf6f) Root hash thread pool, new trie benches. ([#404](https://github.com/flashbots/op-rbuilder/pull/404))
- [`15c7d1b`](https://github.com/flashbots/op-rbuilder/commit/15c7d1bc3342f95dd1c02f20bc1618ed82b7067c) Add tests to paylaod generator ([#409](https://github.com/flashbots/op-rbuilder/pull/409))
- [`33f2ddc`](https://github.com/flashbots/op-rbuilder/commit/33f2ddcd487358ace2f49f152821259c06081c00) Use payload attributes timestamp to calculate op payload deadline ([#416](https://github.com/flashbots/op-rbuilder/pull/416))
- [`21f0fbf`](https://github.com/flashbots/op-rbuilder/commit/21f0fbfbd8a6a9eb6f9b2eafdac888a97eee80c0) Validate rbuilder with op-reth ([#410](https://github.com/flashbots/op-rbuilder/pull/410))
- [`7107a0d`](https://github.com/flashbots/op-rbuilder/commit/7107a0d7b23b22e2eccc4637d47fc30266f3c19a) Spawn a task with the Op builder txn monitoring instead of ExEx ([#417](https://github.com/flashbots/op-rbuilder/pull/417))
- [`9ebdc8d`](https://github.com/flashbots/op-rbuilder/commit/9ebdc8d35c51d8915687dd6b6fbea2e19979fbb9) Add Op L1 block info txn in op CL tester ([#420](https://github.com/flashbots/op-rbuilder/pull/420))
- [`80e2b40`](https://github.com/flashbots/op-rbuilder/commit/80e2b40c89c025fe13b695b92500ce14ab1c7f64) Remove broken benchmark CI ([#422](https://github.com/flashbots/op-rbuilder/pull/422))
- [`364534b`](https://github.com/flashbots/op-rbuilder/commit/364534b0f300708f967887d604cff9d585870cce) Replace dry run mode with a test relay ([#421](https://github.com/flashbots/op-rbuilder/pull/421))
- [`a64ebbb`](https://github.com/flashbots/op-rbuilder/commit/a64ebbbee294296eb93df3c804f4f423d133ed7a) Add cancellation token + fb-rb integration ([#424](https://github.com/flashbots/op-rbuilder/pull/424))
- [`0f1fce6`](https://github.com/flashbots/op-rbuilder/commit/0f1fce67557eb6fe24e8cebb79bbd85bbd25f205) Make PayloadServiceBuilder work with a Builder trait ([#425](https://github.com/flashbots/op-rbuilder/pull/425))
- [`877f998`](https://github.com/flashbots/op-rbuilder/commit/877f99834b8385b1eec0e394672ee46f88ecc622) Tidy unused variables from op payload builder ([#427](https://github.com/flashbots/op-rbuilder/pull/427))
- [`ad6c74c`](https://github.com/flashbots/op-rbuilder/commit/ad6c74c15fbbd6f00646e1f86bf1d47d6270e246) Fix docker ([#433](https://github.com/flashbots/op-rbuilder/pull/433))
- [`cdcb72f`](https://github.com/flashbots/op-rbuilder/commit/cdcb72f5a1a149f0660cd4f9b4df3605c215b25e) Add op-rbuilder release ci action ([#432](https://github.com/flashbots/op-rbuilder/pull/432))
- [`d7a407a`](https://github.com/flashbots/op-rbuilder/commit/d7a407ace431ef0e00234e8cc743e1ccc34741fc) Revert "Add op-rbuilder release ci action ([#432](https://github.com/flashbots/op-rbuilder/pull/432))" ([#450](https://github.com/flashbots/op-rbuilder/pull/450))
- [`578988d`](https://github.com/flashbots/op-rbuilder/commit/578988d3d9cb2227740267f15e0e96fd78f7b607) Reth 1.2.0 ([#429](https://github.com/flashbots/op-rbuilder/pull/429))
- [`c45fc1d`](https://github.com/flashbots/op-rbuilder/commit/c45fc1d16d3f95dabb35026fc5d8ce8658ce8195) Add metrics for reverted transactions and builder balance in exex ([#451](https://github.com/flashbots/op-rbuilder/pull/451))
- [`6c27eb2`](https://github.com/flashbots/op-rbuilder/commit/6c27eb2d2b9604ecb7ec09e2fbbf5af511871728) Flashblocks with incremental blocks + support in tester ([#454](https://github.com/flashbots/op-rbuilder/pull/454))
- [`a6d9969`](https://github.com/flashbots/op-rbuilder/commit/a6d996913a674bb8e70bad91fde90f4cc4905503) Bump Reth to 1.1.2 ([#461](https://github.com/flashbots/op-rbuilder/pull/461))
- [`7463c58`](https://github.com/flashbots/op-rbuilder/commit/7463c584f3bb97e17f00917e93a0198976ed639f) Performance micro-optimizations ([#457](https://github.com/flashbots/op-rbuilder/pull/457))
- [`557578a`](https://github.com/flashbots/op-rbuilder/commit/557578a79a69ef39c97223e0a78f9931cf43899d) Improved readme and config-live-example ([#458](https://github.com/flashbots/op-rbuilder/pull/458))
- [`77a4b7a`](https://github.com/flashbots/op-rbuilder/commit/77a4b7a0cacc37beb2df633b35d6f12a4c978e90) Remove reverting transactions from pool in op-rbuilder ([#456](https://github.com/flashbots/op-rbuilder/pull/456))
- [`d8f7f08`](https://github.com/flashbots/op-rbuilder/commit/d8f7f0867f571d1a87b4f684a914ddce90c82324) Fix deposit command to right address ([#468](https://github.com/flashbots/op-rbuilder/pull/468))
- [`6e5114a`](https://github.com/flashbots/op-rbuilder/commit/6e5114ace999090dcd51e384fa75a6cce4272f01) Add priority fee integration test ([#463](https://github.com/flashbots/op-rbuilder/pull/463))
- [`f0ec47c`](https://github.com/flashbots/op-rbuilder/commit/f0ec47cbf8cae58a4ed5f5c717d8b4ddd95a8fe8) Make flashblock ws url as a flag and add more data ([#442](https://github.com/flashbots/op-rbuilder/pull/442))
- [`d497ce8`](https://github.com/flashbots/op-rbuilder/commit/d497ce8100c12d36370ce319f6dc335f48ee0d50) Make block times dynamic in flashblock builder ([#482](https://github.com/flashbots/op-rbuilder/pull/482))
- [`99065c9`](https://github.com/flashbots/op-rbuilder/commit/99065c919b8d9403d58ef9057879012b1caad6e2) Fix flashblocks receipt index ([#494](https://github.com/flashbots/op-rbuilder/pull/494))
- [`2d4961b`](https://github.com/flashbots/op-rbuilder/commit/2d4961b912237bb30ed96f6da8c9057b0fe14065) Download sccache manually in Dockerfile ([#485](https://github.com/flashbots/op-rbuilder/pull/485))
- [`4f6807b`](https://github.com/flashbots/op-rbuilder/commit/4f6807bfb9cf6e0acff8770e8401c071bf35e1cf) Refactor ExecutedPayload and ExecutionInfo ([#477](https://github.com/flashbots/op-rbuilder/pull/477))
- [`9499572`](https://github.com/flashbots/op-rbuilder/commit/9499572316509a348a180fa19a46ec506fd756af) Update rust to 1.85 ([#495](https://github.com/flashbots/op-rbuilder/pull/495))
- [`3874196`](https://github.com/flashbots/op-rbuilder/commit/38741960469c355777829be84a8bb87814211301) Add docker cicd for optimism ([#480](https://github.com/flashbots/op-rbuilder/pull/480))
- [`5bbc3cb`](https://github.com/flashbots/op-rbuilder/commit/5bbc3cb614e4dc44f84cd106a61f64fb42e72701) Remove prints in op-rbuilder ([#502](https://github.com/flashbots/op-rbuilder/pull/502))
- [`8602518`](https://github.com/flashbots/op-rbuilder/commit/8602518af555780aaed7770285787c5dc9ea94db) Add txn monitoring in op-rbuilder pool ([#500](https://github.com/flashbots/op-rbuilder/pull/500))
- [`23085c5`](https://github.com/flashbots/op-rbuilder/commit/23085c521906184c044fd9370076ff2444860a4c) Interop support ([#462](https://github.com/flashbots/op-rbuilder/pull/462))
- [`5650e50`](https://github.com/flashbots/op-rbuilder/commit/5650e50f02c0139799ae09e51297f3e3f59e3556) Fixed grammatical errors for improved readability ([#511](https://github.com/flashbots/op-rbuilder/pull/511))
- [`d6b8c92`](https://github.com/flashbots/op-rbuilder/commit/d6b8c921346a4661b8206887a22f30f8736b028b) Reth v1.3.4 ([#507](https://github.com/flashbots/op-rbuilder/pull/507))
- [`217153f`](https://github.com/flashbots/op-rbuilder/commit/217153ff2ec7aff422cc232375c97ef7867d9d27) IPC state provider ([#489](https://github.com/flashbots/op-rbuilder/pull/489))
- [`af6c20e`](https://github.com/flashbots/op-rbuilder/commit/af6c20e31159269b46d97a03c2219d8adb9e655f) Remove previous interop impl ([#526](https://github.com/flashbots/op-rbuilder/pull/526))
- [`d83d872`](https://github.com/flashbots/op-rbuilder/commit/d83d8720ae6bf5e0beab83744c9fe32f4c13e2c1) Lock builder playground version ([#527](https://github.com/flashbots/op-rbuilder/pull/527))
- [`5b0a9ac`](https://github.com/flashbots/op-rbuilder/commit/5b0a9ac4c94ec3d31516cde73e63b890e00ff98e) Remove unused ([#537](https://github.com/flashbots/op-rbuilder/pull/537))
- [`a72e98f`](https://github.com/flashbots/op-rbuilder/commit/a72e98f139289c84fcd91bb93dc9dbfe746d8466) Update `dev` profile ([#538](https://github.com/flashbots/op-rbuilder/pull/538))
- [`be8c61d`](https://github.com/flashbots/op-rbuilder/commit/be8c61d53ab3d15f557c548d51ac05e11d84c035) Fix integration tests ([#536](https://github.com/flashbots/op-rbuilder/pull/536))
- [`e9f293a`](https://github.com/flashbots/op-rbuilder/commit/e9f293a30c6ce859810f5abe48e4a36fbdfc0cce) Fix op-rbuilder release action ([#541](https://github.com/flashbots/op-rbuilder/pull/541))
- [`e2d1c3a`](https://github.com/flashbots/op-rbuilder/commit/e2d1c3a8dc4bbee435753c2f31a73b3f77ba2c9c) Try to fix CI ([#545](https://github.com/flashbots/op-rbuilder/pull/545))
- [`6563faa`](https://github.com/flashbots/op-rbuilder/commit/6563faab1de45784f7b10592135ce475608ee28b) Add metrics for flashblock and message tracking in OpRBuilder ([#543](https://github.com/flashbots/op-rbuilder/pull/543))
- [`0dc2253`](https://github.com/flashbots/op-rbuilder/commit/0dc22532dfaee7e71bde6c5d60924399d956aa9a) Reth v1.3.8 ([#553](https://github.com/flashbots/op-rbuilder/pull/553))
- [`0eea8b3`](https://github.com/flashbots/op-rbuilder/commit/0eea8b30b4993cd23a7aa29e025b9d488e8b21f0) Fix Isthmus request hash; support reth 1.3.11 ([#564](https://github.com/flashbots/op-rbuilder/pull/564))
- [`fa8670a`](https://github.com/flashbots/op-rbuilder/commit/fa8670a242a1c35c414c7b6f4cdf499b7feba84c) Fix op-rbuilder devnet docs ([#562](https://github.com/flashbots/op-rbuilder/pull/562))
- [`0da7ad0`](https://github.com/flashbots/op-rbuilder/commit/0da7ad0c1fa64e6fc74df1dc8b67811e5c52b3d1) Use latest reth for op-rbuilder ([#570](https://github.com/flashbots/op-rbuilder/pull/570))
- [`d431350`](https://github.com/flashbots/op-rbuilder/commit/d43135070c2b4052b0ad3938453be032b6307dc3) New configuration doc! ([#578](https://github.com/flashbots/op-rbuilder/pull/578))
- [`a0a4364`](https://github.com/flashbots/op-rbuilder/commit/a0a4364056206c67e33f00b73991accbc5325612) Fix isthmus withdrawals hash on payload builder vanilla ([#571](https://github.com/flashbots/op-rbuilder/pull/571))
- [`88b4253`](https://github.com/flashbots/op-rbuilder/commit/88b425301321152d1bb592514ac8c65e9edbb559) Remove dynamic logging to improve performance ([#587](https://github.com/flashbots/op-rbuilder/pull/587))
- [`60ee921`](https://github.com/flashbots/op-rbuilder/commit/60ee921fc1bb7734872b78be9c52169a1524d428) Fix resource usage in monitoring task ([#588](https://github.com/flashbots/op-rbuilder/pull/588))
- [`6b66a71`](https://github.com/flashbots/op-rbuilder/commit/6b66a71dff6973e4455ead9e73320a0930192538) Update Documentation / CI Script ([#575](https://github.com/flashbots/op-rbuilder/pull/575))
- [`c393e2f`](https://github.com/flashbots/op-rbuilder/commit/c393e2f46651444bb451849b4d838598c6517bcd) Add flashblocks feature to ci ([#595](https://github.com/flashbots/op-rbuilder/pull/595))
- [`3903b9d`](https://github.com/flashbots/op-rbuilder/commit/3903b9d3682b9319ab20b6b94b1cec6c73726cf2) Revert revert protection in op-rbuilder ([#602](https://github.com/flashbots/op-rbuilder/pull/602))
- [`e9e13ad`](https://github.com/flashbots/op-rbuilder/commit/e9e13ad607db7dcb9c4cecd539ecf43f588e5d3f) Finish block building process even when cancel request is found ([#606](https://github.com/flashbots/op-rbuilder/pull/606))
- [`abb5131`](https://github.com/flashbots/op-rbuilder/commit/abb51314fc065532dc2b282848407a5412dcb848) Add usage of jemalloc in op-rbuilder when feature is enabled + improve debug-fast profile ([#617](https://github.com/flashbots/op-rbuilder/pull/617))
- [`c9bab69`](https://github.com/flashbots/op-rbuilder/commit/c9bab6976d393ffe341518e7995f04e2c749b9d1) Clean up the repo
- [`82280d2`](https://github.com/flashbots/op-rbuilder/commit/82280d2438240d679cfdf3ccbf700f15637db4a5) More
- [`dade529`](https://github.com/flashbots/op-rbuilder/commit/dade52974a7d282120dc7dce4ef219b81cf1419c) More stuff
- [`606c0e9`](https://github.com/flashbots/op-rbuilder/commit/606c0e9c4f8cd53aab016d8c35a62a6ab9f4e7d4) More
- [`2302ca2`](https://github.com/flashbots/op-rbuilder/commit/2302ca21d6b90f890118a74e514d62f7c366b674) Remove unnecessary step
- [`111f8be`](https://github.com/flashbots/op-rbuilder/commit/111f8beaf55f07da4e5bf6e5c49274f22769ab90) Merge pull request #1 from flashbots/feat/clean
- [`94dc734`](https://github.com/flashbots/op-rbuilder/commit/94dc734df4b24f14b13c1bd60077f0eedb2a5eb2) Add info log for reverting tx hashes
- [`7b58a1a`](https://github.com/flashbots/op-rbuilder/commit/7b58a1ab0cd787d16e9711992ab81214fc1b4642) Remove unecessary import
- [`1e3c873`](https://github.com/flashbots/op-rbuilder/commit/1e3c873d4593b5d43a141b34a686901393945790) Merge pull request #2 from flashbots/reverting-hashes
- [`5a9201a`](https://github.com/flashbots/op-rbuilder/commit/5a9201a59a8d40856467c51f02dffd486a97e214) Removed op- prefix for tags, because we are in op-rbuilder repo now
- [`035262a`](https://github.com/flashbots/op-rbuilder/commit/035262ae1abaa071e1805dcbbc27b13664605994) Merge pull request #4 from SozinM/msozin/fix-docker-build-times-and-ci-action
- [`12a09e2`](https://github.com/flashbots/op-rbuilder/commit/12a09e2a735b1df53bcddd25cd74918b33ffa9e9) Fix issue in release cicd ([#5](https://github.com/flashbots/op-rbuilder/pull/5))
- [`ff00720`](https://github.com/flashbots/op-rbuilder/commit/ff007207564c5cb2533df461a4e0c3634da8c4f1) Remove monitoring tx task
- [`5a8cdb0`](https://github.com/flashbots/op-rbuilder/commit/5a8cdb0bdf6bccf374c6d71013697344956957ea) Remove more things
- [`c70f096`](https://github.com/flashbots/op-rbuilder/commit/c70f09617e0f22e2403482a3b2cd2b0be63a2c28) Remove more stuff
- [`6156e74`](https://github.com/flashbots/op-rbuilder/commit/6156e74069065ec4bfe23118eff6678333e329a3) Last clean
- [`cabd0b8`](https://github.com/flashbots/op-rbuilder/commit/cabd0b8dc51f3c6d1867a8d0a83611a2c95bb364) More cleaning
- [`519b157`](https://github.com/flashbots/op-rbuilder/commit/519b1573bc22bcee4c7a2998d868ffd7b9f40ff6) Merge pull request #3 from flashbots/feat/remove-monitoring-tx-task
- [`3757e64`](https://github.com/flashbots/op-rbuilder/commit/3757e64416535140aab72ff9a82a7a70409323ef) Add variable builder deadline
- [`570c233`](https://github.com/flashbots/op-rbuilder/commit/570c233fb0f964acb2227404787f791bc353addd) Fix lint
- [`1658c1d`](https://github.com/flashbots/op-rbuilder/commit/1658c1d4e7896ab8710a10863597f6f0e143c311) Fix on FB
- [`a310353`](https://github.com/flashbots/op-rbuilder/commit/a31035385fdb8ec5c6dc820fdb0b681f916a6b1c) Remove dep
- [`907b06e`](https://github.com/flashbots/op-rbuilder/commit/907b06e5231b4e3fb04978733346ada1e2eac963) Merge pull request #28 from flashbots/feat/arg-deadline
- [`28feb36`](https://github.com/flashbots/op-rbuilder/commit/28feb36d11a465d5ab261d0c96a9bcd302673d8e) Use nightly clippy
- [`1fa2d4a`](https://github.com/flashbots/op-rbuilder/commit/1fa2d4a2d9cd7c995e7b14f523cf93a4f99fb892) Merge pull request #27 from flashbots/msozin/clippy-and-fmt-nightly
- [`c7526f6`](https://github.com/flashbots/op-rbuilder/commit/c7526f61635a7e5b30452aeac21d994aab43a717) Change to info
- [`a393138`](https://github.com/flashbots/op-rbuilder/commit/a3931386930e7afb3e6d8d418cf6ea68d8a9c3ac) Update
- [`ba10ddb`](https://github.com/flashbots/op-rbuilder/commit/ba10ddbc2b9dd0c91e2ae0fad3db57928896b6cb) Merge pull request #30 from flashbots/fix/monitoring-info
- [`84e3dc2`](https://github.com/flashbots/op-rbuilder/commit/84e3dc24f47ecc706252ec453352795219faa1aa) Add flag to enable revert protection
- [`dbd0416`](https://github.com/flashbots/op-rbuilder/commit/dbd0416cb9ebb039d229b00df75648af31972169) Add metric
- [`272fdd3`](https://github.com/flashbots/op-rbuilder/commit/272fdd33672185c4cede5504e92d608a91e354d5) Fix
- [`3e8a108`](https://github.com/flashbots/op-rbuilder/commit/3e8a1081ceabe31e8397c4c39e180bb884345dc8) Fix lint
- [`b609c17`](https://github.com/flashbots/op-rbuilder/commit/b609c17dd480f834b48b5777e6198b52f11be0b1) Merge pull request #32 from flashbots/feat/add-flag-to-enable-revert-protection
- [`d903b47`](https://github.com/flashbots/op-rbuilder/commit/d903b479bb01a8f31cee8f0ef9175be9ef2c7a6d) Remove print statement
- [`09e6f0c`](https://github.com/flashbots/op-rbuilder/commit/09e6f0cbe82e9d2951ff15cae48afdbe90e70039) Remove print
- [`2a7ae1d`](https://github.com/flashbots/op-rbuilder/commit/2a7ae1d564a64e778e759ca94e908eebe5cf659b) Merge pull request #33 from flashbots/fix-remove-print
- [`fef7b1e`](https://github.com/flashbots/op-rbuilder/commit/fef7b1e16498218ffc6b9a40b8d687da2ea412bc) Add e2e test for monitor txn
- [`6a7252e`](https://github.com/flashbots/op-rbuilder/commit/6a7252ef4e2263d490a331e1c9cb58869dbbffc8) Partial
- [`5f49111`](https://github.com/flashbots/op-rbuilder/commit/5f49111f6e4c4f643ba0ebc908b2c18fbba51f7e) Add test
- [`5544143`](https://github.com/flashbots/op-rbuilder/commit/5544143928134bfad3938ffdb91497fbd40c5307) Fix lint
- [`d0d4882`](https://github.com/flashbots/op-rbuilder/commit/d0d4882e5a236d6b8d29cd94317f80aeaaf5c85c) Merge pull request #34 from flashbots/e2e/monitor-txn
- [`6206e26`](https://github.com/flashbots/op-rbuilder/commit/6206e266b5c2648b912503f19c149004dbff1f75) Test new generator
- [`0735e3e`](https://github.com/flashbots/op-rbuilder/commit/0735e3ee450d0187a672f14fd7ded5bb2a732889) More changes
- [`24d0c5c`](https://github.com/flashbots/op-rbuilder/commit/24d0c5cfe750b27bc4475738197c2afbe37ad2b5) Add integration tet
- [`95c2409`](https://github.com/flashbots/op-rbuilder/commit/95c2409055bbaa75823ec1e5d021358ecc0b1e7b) Merge pull request #50 from flashbots/test-new-gen
- [`68a5690`](https://github.com/flashbots/op-rbuilder/commit/68a56906261626f7d7469889e665788112bcc5a8) Was using wrong static for jemalloc ([#51](https://github.com/flashbots/op-rbuilder/pull/51))
- [`bb2284a`](https://github.com/flashbots/op-rbuilder/commit/bb2284a45b16e75c72fcdaf21a31e4498605d1b7) Add version metric to op-rbuilder ([#52](https://github.com/flashbots/op-rbuilder/pull/52))
- [`55d1007`](https://github.com/flashbots/op-rbuilder/commit/55d1007330e4a69f4f3d30d18de6404af3f89d78) Add a --playground flag on op-rbuilder to start with the flags required to run the builder on playground ([#49](https://github.com/flashbots/op-rbuilder/pull/49))
- [`5d5e944`](https://github.com/flashbots/op-rbuilder/commit/5d5e944ba718d15703f15e0e8b74113c3df0c83e) Integration test uses genesis file ([#44](https://github.com/flashbots/op-rbuilder/pull/44))
- [`77df514`](https://github.com/flashbots/op-rbuilder/commit/77df5147cfb56c3971c851771c1f19acf0b3af1e) Issue #36: Migrate the rest of the test to the new test utility ([#53](https://github.com/flashbots/op-rbuilder/pull/53))
- [`1254093`](https://github.com/flashbots/op-rbuilder/commit/12540933c8a2ea1416fcc440e6516821d54c4522) Fix withdrawals root ([#56](https://github.com/flashbots/op-rbuilder/pull/56))
- [`c7b2f6a`](https://github.com/flashbots/op-rbuilder/commit/c7b2f6a8dbbe2cf7a92b2c8a21c74e5ccc9131dd) Bump reth to 1.4.1 ([#54](https://github.com/flashbots/op-rbuilder/pull/54))
- [`98ada65`](https://github.com/flashbots/op-rbuilder/commit/98ada6561fe1b4ef87654679e3079fb6b0191661) Add helper utility to check for block inclusion in e2e tests ([#60](https://github.com/flashbots/op-rbuilder/pull/60))
- [`3bc0aff`](https://github.com/flashbots/op-rbuilder/commit/3bc0affe2bf54f1cf148a95b44a180a14009354e) Add opt-in revert protection ([#59](https://github.com/flashbots/op-rbuilder/pull/59))
- [`6a6215e`](https://github.com/flashbots/op-rbuilder/commit/6a6215e9af34c1c8b6edcb0698ace4699f08f202) Fix bundle result ([#66](https://github.com/flashbots/op-rbuilder/pull/66))
- [`92b8f6a`](https://github.com/flashbots/op-rbuilder/commit/92b8f6a2f4f27007257f2f6823e0ba0ed7714042) Remove flashblocks conditional compilation ([#67](https://github.com/flashbots/op-rbuilder/pull/67))
- [`99c69f4`](https://github.com/flashbots/op-rbuilder/commit/99c69f4fcf69ba22d937ccb5823a8dd874c8f389) Use correct DA transaction compression ([#61](https://github.com/flashbots/op-rbuilder/pull/61))
- [`9c34744`](https://github.com/flashbots/op-rbuilder/commit/9c34744950450e42a199045433b6f50d6bfe0e5d) Remove op-integration workflow ([#73](https://github.com/flashbots/op-rbuilder/pull/73))
- [`ee63878`](https://github.com/flashbots/op-rbuilder/commit/ee6387805465ce4aeb98988dbc8b159da36f044e) Modity flashblocks ws bind/port flags ([#71](https://github.com/flashbots/op-rbuilder/pull/71))
- [`c9f5aea`](https://github.com/flashbots/op-rbuilder/commit/c9f5aeaab33afddf7f2a817126fad12c06b8f717) Migrate e2e tests to Isthmus ([#45](https://github.com/flashbots/op-rbuilder/pull/45))
- [`e76909a`](https://github.com/flashbots/op-rbuilder/commit/e76909ae9bc166fd20e835166344c2f9a3eccde6) Update CODEOWNERS ([#74](https://github.com/flashbots/op-rbuilder/pull/74))
- [`4aee498`](https://github.com/flashbots/op-rbuilder/commit/4aee4988fea0d61d8efda83087132f247f9aa74e) Add total_block_built_duration metric back to vanilla builder ([#77](https://github.com/flashbots/op-rbuilder/pull/77))
- [`d5e89ff`](https://github.com/flashbots/op-rbuilder/commit/d5e89ff0eb8b9f01fce78b92313b667bb0dad2ee) Feat/revert protection status endpoint ([#76](https://github.com/flashbots/op-rbuilder/pull/76))
- [`161baee`](https://github.com/flashbots/op-rbuilder/commit/161baee8011e0e8dd500d993b8b38d3bb76459ae) Fix da scaling ([#81](https://github.com/flashbots/op-rbuilder/pull/81))
- [`95accfe`](https://github.com/flashbots/op-rbuilder/commit/95accfe4daf3df313ed0ec23cc4a6d52b063fad2) Add logs for da limits ([#86](https://github.com/flashbots/op-rbuilder/pull/86))
- [`7cd15e1`](https://github.com/flashbots/op-rbuilder/commit/7cd15e14e0ba3cb3518d1892d750033f44d8897e) Add log for the block building execution  ([#87](https://github.com/flashbots/op-rbuilder/pull/87))
- [`fa22d5c`](https://github.com/flashbots/op-rbuilder/commit/fa22d5c91c0abf9fea731b919371c83c02261ee5) Add builder txn to Flashblocks ([#89](https://github.com/flashbots/op-rbuilder/pull/89))
- [`10de3b5`](https://github.com/flashbots/op-rbuilder/commit/10de3b5e7358f666658e70b161ea57acad2e32df) Use original function with manual scaling ([#96](https://github.com/flashbots/op-rbuilder/pull/96))
- [`7a02bbf`](https://github.com/flashbots/op-rbuilder/commit/7a02bbfc17adbed09a72881081a84f03ed499e99) Add error log in case builder tx da size sets max_da_block_size to 0 ([#97](https://github.com/flashbots/op-rbuilder/pull/97))
- [`26989ba`](https://github.com/flashbots/op-rbuilder/commit/26989ba5dc8a9d722501fd9963c9044027fe9adf) Add replacement for default reth version ([#98](https://github.com/flashbots/op-rbuilder/pull/98))
- [`d28a45c`](https://github.com/flashbots/op-rbuilder/commit/d28a45c9875907254992221dd459807486c40571) Add changes to local devnet instructions ([#102](https://github.com/flashbots/op-rbuilder/pull/102))
- [`e1984d8`](https://github.com/flashbots/op-rbuilder/commit/e1984d86e12dcf0be2a3b58139bad2a0751405aa) Added feature-gated interop ([#93](https://github.com/flashbots/op-rbuilder/pull/93))
- [`0df5b08`](https://github.com/flashbots/op-rbuilder/commit/0df5b0873925773662576f96218b17b35a8f7063) Use Gauge for da size limits ([#105](https://github.com/flashbots/op-rbuilder/pull/105))
- [`503eb2d`](https://github.com/flashbots/op-rbuilder/commit/503eb2d8b618e2011865f4bcae0b86758c1df657) Account for DA and gas limit in flashblocks ([#104](https://github.com/flashbots/op-rbuilder/pull/104))
- [`19bd39c`](https://github.com/flashbots/op-rbuilder/commit/19bd39c2da3f68b49901df6797fc350fef617296) Upgrade to reth 1.4.7 and main rollup-boost branch ([#112](https://github.com/flashbots/op-rbuilder/pull/112))
- [`d325dbd`](https://github.com/flashbots/op-rbuilder/commit/d325dbd196b9762d03e356c789f0c9995322e9ce) Add block number and DA used to logging ([#107](https://github.com/flashbots/op-rbuilder/pull/107))
- [`81cae28`](https://github.com/flashbots/op-rbuilder/commit/81cae28d740d843562ea34ef22089b671ad109d2) Add gas limit and DA transaction results for tracing ([#110](https://github.com/flashbots/op-rbuilder/pull/110))
- [`6f2f7fb`](https://github.com/flashbots/op-rbuilder/commit/6f2f7fbefd83c14ea89d751744302ba6bf3dd858) Use block number as hex ([#116](https://github.com/flashbots/op-rbuilder/pull/116))
- [`3e9ffeb`](https://github.com/flashbots/op-rbuilder/commit/3e9ffebeb01ef2b4ee0ab3588ea0b8f171c56c99) Add another builder tx after the first flashblock ([#121](https://github.com/flashbots/op-rbuilder/pull/121))
- [`7e24aba`](https://github.com/flashbots/op-rbuilder/commit/7e24aba9d8c305624e87c2804c167f10e6f9f6c7) Add reverting hashes + min block number to Bundle ([#115](https://github.com/flashbots/op-rbuilder/pull/115))
- [`1dcac5f`](https://github.com/flashbots/op-rbuilder/commit/1dcac5fc5614ddcf2a8ac54310ef87ea477aa5ca) Ensure that the min block number is inside the MAX_BLOCK_RANGE_BLOCKS ([#128](https://github.com/flashbots/op-rbuilder/pull/128))
- [`0c59cb7`](https://github.com/flashbots/op-rbuilder/commit/0c59cb769ed93644815b1fa286c7f4082930a421) Fix bundle type reverting hashes optional param ([#126](https://github.com/flashbots/op-rbuilder/pull/126))
- [`726089a`](https://github.com/flashbots/op-rbuilder/commit/726089ae919c39bb306fdc260658a381479f3582) Remove toml and add feature gate ([#117](https://github.com/flashbots/op-rbuilder/pull/117))
- [`0320e89`](https://github.com/flashbots/op-rbuilder/commit/0320e899db0d7577187877c82f00f76b18f0774c) Move bundle validation to primitives folder ([#129](https://github.com/flashbots/op-rbuilder/pull/129))
- [`8c5737a`](https://github.com/flashbots/op-rbuilder/commit/8c5737a0a5a0fd598f39be90f4e48f931de402b6) Split op-rbuilder in lib and main ([#138](https://github.com/flashbots/op-rbuilder/pull/138))
- [`046a730`](https://github.com/flashbots/op-rbuilder/commit/046a730ec74a44daba98262a94c72103550cac03) In-process tests, optional dockerized validation node  ([#132](https://github.com/flashbots/op-rbuilder/pull/132))
- [`68ded82`](https://github.com/flashbots/op-rbuilder/commit/68ded82c0879e479e10ba90febc0e594666fcd78) Fmt ([#142](https://github.com/flashbots/op-rbuilder/pull/142))
- [`75db54f`](https://github.com/flashbots/op-rbuilder/commit/75db54fa29643db300af372f565da9274b7504d0) Add minTimestamp and maxTimestamp as optional fields to bundle ([#141](https://github.com/flashbots/op-rbuilder/pull/141))
- [`c527f74`](https://github.com/flashbots/op-rbuilder/commit/c527f746a104664f6eef4fc70955d93f5bf36517) Add metric for bundles received ([#149](https://github.com/flashbots/op-rbuilder/pull/149))
- [`a1b9bb8`](https://github.com/flashbots/op-rbuilder/commit/a1b9bb8240a4077c97d9f29e9f3e9a1615e68f16) Add metric to count reverted bundles ([#151](https://github.com/flashbots/op-rbuilder/pull/151))
- [`b248d3b`](https://github.com/flashbots/op-rbuilder/commit/b248d3b86f253ebca15037137a8f068661305b25) Remove extra generic param ([#152](https://github.com/flashbots/op-rbuilder/pull/152))
- [`05b3171`](https://github.com/flashbots/op-rbuilder/commit/05b317107b440db0744ae1f2900ef3cb7b7731fa) Add pingpong and closing frame handle ([#154](https://github.com/flashbots/op-rbuilder/pull/154))
- [`98d3374`](https://github.com/flashbots/op-rbuilder/commit/98d33746803d2658c876d47ca706acf0d2024216) Supress infallible clippy error ([#155](https://github.com/flashbots/op-rbuilder/pull/155))
- [`5b34904`](https://github.com/flashbots/op-rbuilder/commit/5b3490445d28508504ef97e541cfa4af3cc0e6e7) Use tungstenite provided ping handling ([#156](https://github.com/flashbots/op-rbuilder/pull/156))
- [`30bf302`](https://github.com/flashbots/op-rbuilder/commit/30bf302d6471de26c602ac7f42ead2af66d2d69b) Avoid boxing for the txlogging task ([#153](https://github.com/flashbots/op-rbuilder/pull/153))
- [`12078ff`](https://github.com/flashbots/op-rbuilder/commit/12078fff505f93759d3b76e336cc288a8bbbadf6) Fix regression tester command ([#160](https://github.com/flashbots/op-rbuilder/pull/160))
- [`a87b1ba`](https://github.com/flashbots/op-rbuilder/commit/a87b1ba87c6a11937f19a4b5290b2ccf7b27c84f) Genesis command outputs genesis file ([#159](https://github.com/flashbots/op-rbuilder/pull/159))
- [`1afc698`](https://github.com/flashbots/op-rbuilder/commit/1afc698ff574decedb341fbd25dcdf5d9323837f) Update docs ([#161](https://github.com/flashbots/op-rbuilder/pull/161))
- [`19b271d`](https://github.com/flashbots/op-rbuilder/commit/19b271d9df1545f20fac342c00b9638e4af4cd61) Account for flashblocks time drift ([#123](https://github.com/flashbots/op-rbuilder/pull/123))
- [`90123e5`](https://github.com/flashbots/op-rbuilder/commit/90123e5306bcdad2bb068c29a55f456e0eada41c) Run the vanilla tests using both the flashblocks builder and the vanilla builder ([#145](https://github.com/flashbots/op-rbuilder/pull/145))
- [`9ceeb68`](https://github.com/flashbots/op-rbuilder/commit/9ceeb68e83cc5123ec1d35dbc43d15dc22c10975) Add ci workflow to build independent docker images + nightly ([#163](https://github.com/flashbots/op-rbuilder/pull/163))
- [`0670aa3`](https://github.com/flashbots/op-rbuilder/commit/0670aa3864b4c631253384ee369c9058efb70b82) Flashtestions ([#137](https://github.com/flashbots/op-rbuilder/pull/137))
- [`4f1931b`](https://github.com/flashbots/op-rbuilder/commit/4f1931b46a786b4de0c371e8a051fca147e46f6d) Flashtestations flag ([#165](https://github.com/flashbots/op-rbuilder/pull/165))
- [`408840b`](https://github.com/flashbots/op-rbuilder/commit/408840b5fe21dbc76c6d3f15a06a435eb3a7a29b) Add some telemetry for `eth_sendBundle` ([#176](https://github.com/flashbots/op-rbuilder/pull/176))
- [`a62d35e`](https://github.com/flashbots/op-rbuilder/commit/a62d35e19027cd47141a9dbdc0af0fadac67aba6) Review ([#170](https://github.com/flashbots/op-rbuilder/pull/170))
- [`255d50b`](https://github.com/flashbots/op-rbuilder/commit/255d50b78539784fb57e871ea844e4858284ce2c) Add cli flag for funding key ([#168](https://github.com/flashbots/op-rbuilder/pull/168))
- [`e1a445f`](https://github.com/flashbots/op-rbuilder/commit/e1a445f418fc97940c00ce7e6a3fa29bc72ea848) Move builder tx right after deposits and put it into base flashblock ([#178](https://github.com/flashbots/op-rbuilder/pull/178))
- [`2ecd976`](https://github.com/flashbots/op-rbuilder/commit/2ecd976dd6b0078484fd753af5fc5dd59d8b680b) Implement correct flashblocks time cutoff ([#172](https://github.com/flashbots/op-rbuilder/pull/172))
- [`13802c3`](https://github.com/flashbots/op-rbuilder/commit/13802c303419df0df16a8825ee5a95e4bf16beeb) Change default leeway-time + add handing for block cancellation ([#185](https://github.com/flashbots/op-rbuilder/pull/185))
- [`8459271`](https://github.com/flashbots/op-rbuilder/commit/845927189407039cb79831df6e6605c03c2295ea) Bump reth 1.5.0 ([#186](https://github.com/flashbots/op-rbuilder/pull/186))
- [`69a58d8`](https://github.com/flashbots/op-rbuilder/commit/69a58d811d8968276bcbaf0908c00b1a5024cfdc) Add simple logging to timer task ([#191](https://github.com/flashbots/op-rbuilder/pull/191))
- [`dc1b00c`](https://github.com/flashbots/op-rbuilder/commit/dc1b00cc2f55874e0f16f72160fd076c556cda48) Improve metrics so we could better plot them ([#193](https://github.com/flashbots/op-rbuilder/pull/193))
- [`4664acb`](https://github.com/flashbots/op-rbuilder/commit/4664acbad2b54517511a03e293ebcb0f5543776e) Bump reth to 1.5.1 ([#192](https://github.com/flashbots/op-rbuilder/pull/192))
- [`6888235`](https://github.com/flashbots/op-rbuilder/commit/6888235f87be34d4e6d4b21e66e2779a1af2ad17) Fix ordering issue by not including arriving txs into the best transaction iterator ([#195](https://github.com/flashbots/op-rbuilder/pull/195))
- [`eba783d`](https://github.com/flashbots/op-rbuilder/commit/eba783d3b7f7993e35d3459d006bdf633c99c20f) Remove without_updates for flashblocks ([#198](https://github.com/flashbots/op-rbuilder/pull/198))
- [`990ba53`](https://github.com/flashbots/op-rbuilder/commit/990ba53f1a30c669448fdbaf444ee67b111c94c3) Add a test to validate that no-tx-pool works ([#199](https://github.com/flashbots/op-rbuilder/pull/199))
- [`f0636ba`](https://github.com/flashbots/op-rbuilder/commit/f0636ba6a6efbac3ac75bec3d06183630ef16315) Add TDX quote provider service ([#200](https://github.com/flashbots/op-rbuilder/pull/200))
- [`d987794`](https://github.com/flashbots/op-rbuilder/commit/d987794f167d73064eb194f647350137ddaae8f5) Add gauge metrics for block building steps ([#205](https://github.com/flashbots/op-rbuilder/pull/205))
- [`183311e`](https://github.com/flashbots/op-rbuilder/commit/183311e69cf0e5c20c26cf1ae5f828c3f54aa9af) Remove redundant account initialization ([#208](https://github.com/flashbots/op-rbuilder/pull/208))
- [`6b0f5aa`](https://github.com/flashbots/op-rbuilder/commit/6b0f5aac094536833d779492e13af5b78acdc598) Add flashblocks index to payload building context ([#210](https://github.com/flashbots/op-rbuilder/pull/210))
- [`591b08a`](https://github.com/flashbots/op-rbuilder/commit/591b08a5d6871ee2cc49262d80512832212e6db7) Add tdx-quote-provider to release workflow ([#204](https://github.com/flashbots/op-rbuilder/pull/204))
- [`65938aa`](https://github.com/flashbots/op-rbuilder/commit/65938aafdd701a0f72e8da4c657c1459913abf79) Gauge metrics to inspect flag settings ([#207](https://github.com/flashbots/op-rbuilder/pull/207))
- [`9b62aab`](https://github.com/flashbots/op-rbuilder/commit/9b62aabc423da55f0576b849241906555e8a5a51) Fix tdx-quote-provider release workflow ([#211](https://github.com/flashbots/op-rbuilder/pull/211))
- [`c08025b`](https://github.com/flashbots/op-rbuilder/commit/c08025b831dbf0d007fdebdb7f0ae8a3f8e35d48) Bump reth to 1.6 ([#215](https://github.com/flashbots/op-rbuilder/pull/215))
- [`ef159dd`](https://github.com/flashbots/op-rbuilder/commit/ef159dd3a86e4eda9b5f63861c4dda6562d7c223) Less confusing naming, state is called db and db is called state ([#219](https://github.com/flashbots/op-rbuilder/pull/219))
- [`c5c46f3`](https://github.com/flashbots/op-rbuilder/commit/c5c46f3f35ffe00032ecb0c5dd533abb752d2900) Add flashblock number filters to eth_sendBundle ([#213](https://github.com/flashbots/op-rbuilder/pull/213))
- [`daab741`](https://github.com/flashbots/op-rbuilder/commit/daab7418c4982585423a2df61a8085dd845eb144) Add reproducibility flags ([#218](https://github.com/flashbots/op-rbuilder/pull/218))
- [`3e3ead7`](https://github.com/flashbots/op-rbuilder/commit/3e3ead7faff3b5dd69cb365b1fc0ac77ac32dfc3) Fix bundle state and produce executed block ([#223](https://github.com/flashbots/op-rbuilder/pull/223))
- [`0ec0644`](https://github.com/flashbots/op-rbuilder/commit/0ec06442a3ca9066eef0ab207f7781cc66b2cb83) Add caching to generator ([#221](https://github.com/flashbots/op-rbuilder/pull/221))
- [`d9d33d2`](https://github.com/flashbots/op-rbuilder/commit/d9d33d2c864d1b8b680c9c2e4f5f42a41669f4af) Combine eth api modifications ([#231](https://github.com/flashbots/op-rbuilder/pull/231))
- [`9d4ce99`](https://github.com/flashbots/op-rbuilder/commit/9d4ce9920eb1cc9f1f8f76ddaef53b42b522c769) Add correct metric value ([#234](https://github.com/flashbots/op-rbuilder/pull/234))
- [`13a16d5`](https://github.com/flashbots/op-rbuilder/commit/13a16d52474f6cabd9aee21ce8421f9e0c2800b2) Update README.md ([#201](https://github.com/flashbots/op-rbuilder/pull/201))
- [`d4bcb67`](https://github.com/flashbots/op-rbuilder/commit/d4bcb6723c29afaa8eda03a8837c4f6056733f04) Update CODEOWNERS ([#242](https://github.com/flashbots/op-rbuilder/pull/242))
- [`5c60db4`](https://github.com/flashbots/op-rbuilder/commit/5c60db42826da3f233f24cb2ecabca83ac99da68) Add fix to preserve all executed blocks for flashblocks ([#229](https://github.com/flashbots/op-rbuilder/pull/229))
- [`92b22b4`](https://github.com/flashbots/op-rbuilder/commit/92b22b40848dd5d3b5f04109efc2183d485ae00d) Improve best tx wrapper ([#245](https://github.com/flashbots/op-rbuilder/pull/245))
- [`5a92b90`](https://github.com/flashbots/op-rbuilder/commit/5a92b90a47d01d627549fe80f281e26ff4de19e9) Update op-rbuilder ci for prefixed tagging ([#246](https://github.com/flashbots/op-rbuilder/pull/246))

### Refactor

- [`b804276`](https://github.com/flashbots/op-rbuilder/commit/b8042760a698508355553c5edc8ae7102fe03b9f) `TransactionSignedEcRecoveredWithBlobs` constructor api ([#347](https://github.com/flashbots/op-rbuilder/pull/347))

### Testing

- [`8a3c714`](https://github.com/flashbots/op-rbuilder/commit/8a3c714f7d231f6865ab4cfa18ac775d6f226d97) Add unit tests + ci to test the txfetcher ([#12](https://github.com/flashbots/op-rbuilder/pull/12))
