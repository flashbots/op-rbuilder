#!/usr/bin/env bash
set -euo pipefail

# Run optimism acceptance tests against an op-rbuilder binary
# built from this repository checkout.
#
# This script is intended for both local iteration and CI use.
# For rapid local reruns, disable expensive setup/build steps with:
#   BUILD_OP_RBUILDER=0 PREP_OPTIMISM=0 BUILD_CONTRACTS=0 BUILD_ROLLUP_BOOST=0 BUILD_CANNON_PRESTATES=0

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/.ci-work}"
OPTIMISM_DIR="${OPTIMISM_DIR:-$WORK_DIR/optimism}"
OPTIMISM_REPO="${OPTIMISM_REPO:-https://github.com/ethereum-optimism/optimism.git}"
OPTIMISM_REF="${OPTIMISM_REF:-develop}"

# Canonical package selection is provided by CI through GATE.
GATE="${GATE:-}"

BUILD_OP_RBUILDER="${BUILD_OP_RBUILDER:-1}"
OP_RBUILDER_FEATURES="${FEATURES:-}"
PREP_OPTIMISM="${PREP_OPTIMISM:-1}"
BUILD_CONTRACTS="${BUILD_CONTRACTS:-1}"
BUILD_ROLLUP_BOOST="${BUILD_ROLLUP_BOOST:-1}"
BUILD_CANNON="${BUILD_CANNON:-1}"
BUILD_OP_PROGRAM="${BUILD_OP_PROGRAM:-1}"
BUILD_CANNON_PRESTATES="${BUILD_CANNON_PRESTATES:-1}"
DISABLE_RUSTC_WRAPPER="${DISABLE_RUSTC_WRAPPER:-1}"

RBUILDER_BIN="${RBUILDER_BIN:-$ROOT_DIR/target/release/op-rbuilder}"
ROLLUP_BOOST_BIN="${ROLLUP_BOOST_BIN:-$OPTIMISM_DIR/rollup-boost/target/release/rollup-boost}"
CANNON_BIN="${CANNON_BIN:-$OPTIMISM_DIR/cannon/bin/cannon}"
OP_PROGRAM_BIN="${OP_PROGRAM_BIN:-$OPTIMISM_DIR/op-program/bin/op-program}"

ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT_DIR/.ci-artifacts/acceptance}"
mkdir -p "$ARTIFACTS_DIR"

log() {
  printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

resolve_tool_bin() {
  local tool="$1"
  local bin="$2"

  if command -v mise >/dev/null 2>&1; then
    local root
    root="$(mise where "$tool" 2>/dev/null || true)"
    if [[ -n "$root" ]]; then
      if [[ -x "$root/bin/$bin" ]]; then
        printf '%s\n' "$root/bin/$bin"
        return 0
      fi
      if [[ -x "$root/$bin" ]]; then
        printf '%s\n' "$root/$bin"
        return 0
      fi
    fi
  fi

  command -v "$bin"
}

run_tool() {
  local tool="$1"
  local bin="$2"
  shift 2
  local exe
  exe="$(resolve_tool_bin "$tool" "$bin")"
  "$exe" "$@"
}

setup_mise() {
  if ! command -v mise >/dev/null 2>&1; then
    log "Installing mise"
    curl https://mise.run | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
  # shellcheck disable=SC1091
  eval "$(mise activate bash)"
  # Ensure shims are available in non-interactive CI shells.
  export PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$PATH"
  if mise env -s bash >/dev/null 2>&1; then
    eval "$(mise env -s bash)"
  fi
}

prepare_optimism_checkout() {
  mkdir -p "$(dirname "$OPTIMISM_DIR")"

  if [[ ! -d "$OPTIMISM_DIR/.git" ]]; then
    log "Cloning optimism repository: $OPTIMISM_REPO"
    git clone --depth=1 "$OPTIMISM_REPO" "$OPTIMISM_DIR"
  fi

  log "Checking out optimism ref: $OPTIMISM_REF"
  (
    cd "$OPTIMISM_DIR"
    git fetch origin "$OPTIMISM_REF" --depth=1
    git checkout FETCH_HEAD
  )

  log "Syncing optimism submodules"
  (
    cd "$OPTIMISM_DIR"
    git submodule sync
    git submodule update --init --recursive --single-branch -j 8
  )
}

build_op_rbuilder() {
  if [[ "$BUILD_OP_RBUILDER" != "1" ]]; then
    return
  fi
  log "Building op-rbuilder release binary"
  log "op-rbuilder features: $OP_RBUILDER_FEATURES"
  (
    cd "$ROOT_DIR"
    if [[ -n "$OP_RBUILDER_FEATURES" ]]; then
      run_tool rust cargo build --release -p op-rbuilder --bin op-rbuilder --features "$OP_RBUILDER_FEATURES"
    else
      run_tool rust cargo build --release -p op-rbuilder --bin op-rbuilder
    fi
  )
}

build_contract_artifacts() {
  if [[ "$BUILD_CONTRACTS" != "1" ]]; then
    return
  fi
  log "Building optimism contracts-bedrock artifacts"
  (
    cd "$OPTIMISM_DIR/packages/contracts-bedrock"
    run_tool just just install
    run_tool just just build-no-tests
  )
}

build_rollup_boost() {
  if [[ "$BUILD_ROLLUP_BOOST" != "1" ]]; then
    return
  fi
  log "Building rollup-boost release binary"
  (
    cd "$OPTIMISM_DIR/rollup-boost"
    run_tool rust cargo build --release -p rollup-boost --bin rollup-boost
  )
}

build_cannon() {
  if [[ "$BUILD_CANNON" != "1" ]]; then
    return
  fi
  log "Building cannon binary"
  (
    cd "$OPTIMISM_DIR"
    mkdir -p "$(dirname "$CANNON_BIN")"
    run_tool go go build -o "$CANNON_BIN" ./cannon
  )
}

build_op_program() {
  if [[ "$BUILD_OP_PROGRAM" != "1" ]]; then
    return
  fi
  log "Building op-program binary"
  (
    cd "$OPTIMISM_DIR"
    mkdir -p "$(dirname "$OP_PROGRAM_BIN")"
    run_tool go go build -o "$OP_PROGRAM_BIN" ./op-program/host/cmd/main.go
  )
}

build_cannon_prestates() {
  if [[ "$BUILD_CANNON_PRESTATES" != "1" ]]; then
    return
  fi
  log "Building cannon prestates"
  (
    cd "$OPTIMISM_DIR"
    make cannon-prestates
  )
}

run_acceptance_tests() {
  log "Running acceptance tests for gate: ${GATE}"
  export RUST_BINARY_PATH_OP_RBUILDER="$RBUILDER_BIN"
  export RUST_BINARY_PATH_ROLLUP_BOOST="$ROLLUP_BOOST_BIN"
  export DEVSTACK_ORCHESTRATOR="${DEVSTACK_ORCHESTRATOR:-sysgo}"
  export GATE="${GATE:-flashblocks}"
  if [[ -n "${DISABLE_OP_E2E_LEGACY:-}" ]]; then
    export DISABLE_OP_E2E_LEGACY
  fi
  export LOG_LEVEL="${LOG_LEVEL:-info}"

  (
    cd "$OPTIMISM_DIR"/op-acceptance-tests
    BINARY_PATH=$(mise which op-acceptor)

    # Gate mode - use go run with acceptor binary
    CMD_ARGS=(
        "go" "run" "cmd/main.go"
        "--gate" "$GATE"
        "--testdir" "$OPTIMISM_DIR"
        "--validators" "$ROOT_DIR/tests/acceptance-tests.yaml"
        "--acceptor" "$BINARY_PATH"
        "--log.level" "$LOG_LEVEL"
        "--orchestrator" "$DEVSTACK_ORCHESTRATOR"
        "--show-progress"
    )
    echo "${CMD_ARGS[@]}"
    "${CMD_ARGS[@]}"

    # Copy logs to artifacts dir
    cp -R $OPTIMISM_DIR/op-acceptance-tests/logs/testrun-* $ARTIFACTS_DIR
  ) 2>&1 | tee "$ARTIFACTS_DIR/go-test.log"
}

main() {
  need_cmd git
  need_cmd curl
  need_cmd make

  # Some environments export RUSTC_WRAPPER=sccache globally.
  # Disable by default for deterministic CI/runtime behavior.
  if [[ "$DISABLE_RUSTC_WRAPPER" == "1" ]]; then
    if [[ -n "${RUSTC_WRAPPER:-}" ]]; then
      log "Disabling RUSTC_WRAPPER for this run (was: $RUSTC_WRAPPER)"
    fi
    unset RUSTC_WRAPPER
    export CARGO_BUILD_RUSTC_WRAPPER=
    export SCCACHE_DISABLE=1
  fi

  if [[ "$PREP_OPTIMISM" == "1" ]]; then
    prepare_optimism_checkout
  fi

  setup_mise
  (
    cd "$OPTIMISM_DIR"
    mise install
  )

  build_op_rbuilder
  [[ -x "$RBUILDER_BIN" ]] || { echo "op-rbuilder binary missing: $RBUILDER_BIN" >&2; exit 1; }

  build_contract_artifacts
  build_rollup_boost
  build_cannon
  build_op_program
  build_cannon_prestates
  [[ -x "$ROLLUP_BOOST_BIN" ]] || { echo "rollup-boost binary missing: $ROLLUP_BOOST_BIN" >&2; exit 1; }
  [[ -x "$CANNON_BIN" ]] || { echo "cannon binary missing: $CANNON_BIN" >&2; exit 1; }
  [[ -x "$OP_PROGRAM_BIN" ]] || { echo "op-program binary missing: $OP_PROGRAM_BIN" >&2; exit 1; }

  run_acceptance_tests
  log "Completed successfully"
}

main "$@"
