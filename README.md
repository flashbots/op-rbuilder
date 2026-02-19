# op-rbuilder

[![CI status](https://github.com/flashbots/op-rbuilder/actions/workflows/op_rbuilder_checks.yaml/badge.svg)](https://github.com/flashbots/op-rbuilder/actions)

`op-rbuilder` is a Rust-based block builder designed to build blocks for the Optimism stack.

## Running op-rbuilder

To run op-rbuilder with the op-stack, you need:

-   CL node to sync the op-rbuilder with the canonical chain
-   Sequencer with the [rollup-boost](https://github.com/flashbots/rollup-boost) setup

To run the op-rbuilder, run:

```bash
cargo run -p op-rbuilder --bin op-rbuilder -- node \
    --chain /path/to/chain-config.json \
    --http \
    --authrpc.port 9551 \
    --authrpc.jwtsecret /path/to/jwt.hex
```

To build the op-rbuilder, run:

```bash
cargo build -p op-rbuilder --bin op-rbuilder
```

### Flashblocks

To run op-rbuilder with flashblocks:

```bash
cargo run -p op-rbuilder --bin op-rbuilder -- node \
    --chain /path/to/chain-config.json \
    --http \
    --authrpc.port 9551 \
    --authrpc.jwtsecret /path/to/jwt.hex \
    --flashblocks.enabled \
    --flashblocks.port 1111 \ # port to bind ws that provides flashblocks 
    --flashblocks.addr 127.0.0.1 # address to bind the ws that provides flashblocks
```

#### Flashblocks Number Contract

To enable builder tranctions to the [flashblocks number contract](https://github.com/Uniswap/flashblocks_number_contract) for contracts to integrate with flashblocks onchain, specify the address in the CLI args:

```bash
cargo run -p op-rbuilder --bin op-rbuilder -- node \
    --chain /path/to/chain-config.json \
    --http \
    --authrpc.port 9551 \
    --authrpc.jwtsecret /path/to/jwt.hex \
    --flashblocks.enabled \
    --flashblocks.number-contract-address 0xFlashblocksNumberAddress
```

This will increment the flashblock number before the start of every flashblock and replace the builder tx at the end of the block.

### Flashtestations 

To run op-rbuilder with flashtestations:

```bash
cargo run -p op-rbuilder --bin op-rbuilder -- node \
    --chain /path/to/chain-config.json \
    --http \
    --authrpc.port 9551 \
    --authrpc.jwtsecret /path/to/jwt.hex \
    --flashtestations.enabled \
    --flashtestations.rpc-url your-rpc-url \ # rpc to submit the attestation transaction to
    --flashtestations.funding-amount 0.01 \ # amount in ETH to fund the TEE generated key
    --flashtestations.funding-key secret-key \ # funding key for the TEE key
    --flashtestations.registry-address 0xFlashtestationsRegistryAddress \
    --flashtestations.builder-policy-address 0xBuilderPolicyAddress
```

Note that `--rollup.builder-secret-key` must be set and funded in order for the flashtestations key to be funded and submit the attestation on-chain.

## Observability

To verify whether a builder block has landed on-chain, you can add the `--rollup.builder-secret-key` flag or `BUILDER_SECRET_KEY` environment variable.
This will add an additional transaction to the end of the block from the builder key. The transaction will have `Block Number: {}` in the input data as a transfer to the zero address. Ensure that the key has sufficient balance to pay for the transaction at the end of the block.

To enable metrics, set the `--metrics` flag like in [reth](https://reth.rs/run/monitoring) which will expose reth metrics in addition to op-rbuilder metrics. op-rbuilder exposes on-chain metrics via [reth execution extensions](https://reth.rs/exex/overview) such as the number of blocks landed and builder balance. Note that the accuracy of the on-chain metrics will be dependent on the sync status of the builder node. There are also additional block building metrics such as:

-   Block building latency
-   State root calculation latency
-   Transaction fetch latency
-   Transaction simulation latency
-   Number of transactions included in the built block

To see the full list of op-rbuilder metrics, see [`src/metrics.rs`](./crates/op-rbuilder/src/metrics.rs).

Default `debug` level trace logs can be found at:

- `~/.cache/op-rbuilder/logs` on Linux
- `~/Library/Caches/op-rbuilder/logs` on macOS
- `%localAppData%/op-rbuilder/logs` on Windows

## Integration Testing

op-rbuilder has an integration test framework that runs the builder against mock engine api payloads and ensures that the builder produces valid blocks.

You can run the tests using the command

```bash
just run-tests
```

or the following sequence:

```bash
# Ensure you have op-reth installed in your path,
# you can download it with the command below and move it to a location in your path
./scripts/ci/download-op-reth.sh

# Generate a genesis file
cargo run -p op-rbuilder --features="testing" --bin tester -- genesis --output genesis.json

# Build the op-rbuilder binary
cargo build -p op-rbuilder --bin op-rbuilder

# Run the integration tests
cargo test --package op-rbuilder --lib
```

## Local Devnet

1. Install [flashbots/builder-playground](https://github.com/flashbots/builder-playground).

2. `builder-playground start playground.yaml` (use `--skip-setup` if you need to skip `cargo build` every time).

3. Run `contender`:

```bash
cargo run -- spam --tps 10 -r http://localhost:2222 --optimism --min-balance 0.14
```

And you should start to see blocks being built and landed on-chain with `contender` transactions.

Alternatively, you can send a single test transaction like:

```bash
builder-playground test http://localhost:2222 --timeout 30s --retries 10
```

op-rbuilder will automatically try to detect all settings and ports from the currently running playground thanks to the `--builder.playground` flag.

Make sure to check out `playground.yaml` if you need to inspect or modify the configuration for your local test environment!

## Running GitHub actions locally

To verify that CI will allow your PR to be merged before sending it please make sure that our GitHub `checks.yaml` action passes locall by calling:

```
act -W .github/workflows/checks.yaml
```

More instructions on installing and configuring `act` can be found on [their website](https://nektosact.com).

### Known issues

-   Running actions locally require a Github Token. You can generate one by following instructions on [Github Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). After generating a token you will need to pass it to `act` either through the command line using `-s GITHUB_TOKEN=<your token>` or by adding it to the `~/.config/act/actrc` file.
-   You might get an error about missing or incompatible `warp-ubuntu-latest-x64-32x` platform. This can be mitigated by adding `-P warp-ubuntu-latest-x64-32x=ghcr.io/catthehacker/ubuntu:act-latest` on the command line when calling `act` or appending this flag to `~/.config/act/actrc`
