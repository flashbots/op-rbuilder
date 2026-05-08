# Build and run op-rbuilder in playground mode for testing
run-playground:
    cargo build --bin op-rbuilder -p op-rbuilder
    ./target/debug/op-rbuilder node --builder.playground
