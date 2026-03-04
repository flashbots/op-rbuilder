#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JOB_NAME="${JOB_NAME:-acceptance-local}"
CONFIG_PATH="${CONFIG_PATH:-$ROOT_DIR/.circleci/local-acceptance.yml}"

log() {
  printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

main() {
  need_cmd circleci
  need_cmd docker

  if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not running" >&2
    exit 1
  fi

  if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "missing local CircleCI config: $CONFIG_PATH" >&2
    exit 1
  fi

  # Default to a sibling optimism checkout when available.
  if [[ -z "${OPTIMISM_DIR:-}" && -d "$ROOT_DIR/../optimism-1/.git" ]]; then
    OPTIMISM_DIR="$(cd "$ROOT_DIR/../optimism-1" && pwd)"
    export OPTIMISM_DIR
  fi

  if [[ -n "${OPTIMISM_DIR:-}" && -z "${PREP_OPTIMISM+x}" ]]; then
    export PREP_OPTIMISM=0
  fi

  mkdir -p \
    "$HOME/.cargo" \
    "$HOME/.cache/go-build" \
    "$HOME/go/pkg/mod" \
    "$HOME/.cache/mise" \
    "$HOME/.local/share/mise"

  local -a env_flags
  local -a pass_envs=(
    OPTIMISM_DIR OPTIMISM_REPO OPTIMISM_REF TEST_PKGS TEST_RUN TEST_TIMEOUT
    BUILD_OP_RBUILDER PREP_OPTIMISM BUILD_CONTRACTS BUILD_ROLLUP_BOOST BUILD_CANNON BUILD_OP_PROGRAM BUILD_CANNON_PRESTATES
    DISABLE_RUSTC_WRAPPER RBUILDER_BIN ROLLUP_BOOST_BIN CANNON_BIN OP_PROGRAM_BIN ARTIFACTS_DIR
    DEVSTACK_ORCHESTRATOR DISABLE_OP_E2E_LEGACY LOG_LEVEL
  )
  local var
  for var in "${pass_envs[@]}"; do
    if [[ -n "${!var+x}" ]]; then
      env_flags+=( -e "$var=${!var}" )
    fi
  done

  local -a volume_flags
  volume_flags+=( -v "$HOME/.cargo:/home/circleci/.cargo" )
  volume_flags+=( -v "$HOME/.cache/go-build:/home/circleci/.cache/go-build" )
  volume_flags+=( -v "$HOME/go/pkg/mod:/home/circleci/go/pkg/mod" )
  volume_flags+=( -v "$HOME/.cache/mise:/home/circleci/.cache/mise" )
  volume_flags+=( -v "$HOME/.local/share/mise:/home/circleci/.local/share/mise" )
  if [[ -n "${OPTIMISM_DIR:-}" && -d "$OPTIMISM_DIR" ]]; then
    volume_flags+=( -v "$OPTIMISM_DIR:$OPTIMISM_DIR" )
  fi

  log "Executing CircleCI local job '$JOB_NAME'"
  circleci local execute "$JOB_NAME" \
    --config "$CONFIG_PATH" \
    "${env_flags[@]}" \
    "${volume_flags[@]}" \
    "$@"
}

main "$@"
