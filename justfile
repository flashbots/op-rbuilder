# Build and run op-rbuilder in playground mode for testing
run-playground:
  cargo run -p op-rbuilder --bin op-rbuilder -- node \
      --chain $HOME/.playground/devnet/l2-genesis.json \
      --flashblocks.enabled \
      --builder.enable-resource-metering \
      --datadir ~/.playground/devnet/op-rbuilder \
      -vv \
      --http --http.port 2222 \
      --authrpc.addr 0.0.0.0 --authrpc.port 4444 --authrpc.jwtsecret $HOME/.playground/devnet/jwtsecret \
      --port 30333 --disable-discovery \
      --metrics 127.0.0.1:9011 \
      --rollup.builder-secret-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
      --trusted-peers enode://79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8@127.0.0.1:30304

# Run the complete test suite (genesis generation, build, and tests)
run-tests:
  just generate-test-genesis
  just build-op-rbuilder
  just run-tests-op-rbuilder

# Download `op-reth` binary
download-op-reth:
  ./scripts/ci/download-op-reth.sh

# Generate a genesis file (for tests)
generate-test-genesis:
  cargo run -p op-rbuilder --features="testing" --bin tester -- genesis --output genesis.json


# Build the op-rbuilder binary
build-op-rbuilder:
  cargo build -p op-rbuilder --bin op-rbuilder

# Run the integration tests
run-tests-op-rbuilder:
  PATH=$PATH:$(pwd) cargo test --package op-rbuilder --lib
