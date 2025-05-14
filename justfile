run-playground:
  cargo build --features flashblocks --bin op-rbuilder -p op-rbuilder
  ./target/debug/op-rbuilder node --builder.playground