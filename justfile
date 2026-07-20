# Build the profiling op-rbuilder binary and start the decker local devnet
# (see local-testing/README.md; requires the `decker` CLI on PATH)
devnet:
    make op-rbuilder-profiling FEATURES=telemetry,loki
    decker start

# Build and run op-rbuilder in playground mode for testing
run-playground:
    cargo build --bin op-rbuilder -p op-rbuilder
    ./target/debug/op-rbuilder node --builder.playground
