# Local Dev Environment

Local devnet configuration for `op-rbuilder`, powered by [decker](https://github.com/flashbots/decker) (`decker.ts` at the repo root runs the `opstack` recipe with a host-process `op-rbuilder`). [builder-playground](https://github.com/flashbots/builder-playground) (`local-testing/playground.yaml`) is kept working as a deprecated fallback for the rest of this migration — see the [Legacy appendix](#legacy-builder-playground-deprecated).

## Prerequisites

- **podman**, with its (rootless) API socket running. Prefer Docker? Install **docker** instead and uncomment the `target: { pods: "docker-compose" }` line at the bottom of `decker.ts`.
- **decker** CLI:
  ```bash
  curl -sSfL https://raw.githubusercontent.com/flashbots/decker/main/install.sh | bash
  ```
- **process-compose** — `op-rbuilder` runs as a host process here (not a container), which decker drives through its `process-compose` renderer: `brew install process-compose` (macOS) or see the [process-compose install docs](https://github.com/F1bonacc1/process-compose#installation) (Linux).
- [flashbots/contender](https://github.com/flashbots/contender), for traffic generation.

## Quickstart

From the repository root:

```bash
just devnet
```

This builds the profiling `op-rbuilder` binary (`make op-rbuilder-profiling FEATURES=telemetry,loki` — the binary `decker.ts` points `builderBinary` at) and then runs `decker start`, which clones the pinned decker source into `.decker/` on first use and brings the whole stack up in the foreground (Ctrl+C tears it down).

Equivalent, one step at a time:

```bash
make op-rbuilder-profiling FEATURES=telemetry,loki
decker pull    # clone the pinned decker source into .decker/ (skips an existing clone)
decker start   # foreground, Ctrl+C to stop; use `decker up` + `decker down` to detach instead
```

See `decker.ts` for the exact recipe options in use (fork, L2 block time, flashblocks tuning, chain-monitor); `decker up`/`start` print every pod/process and its port right before the run starts.

## Generate Local Traffic

```bash
contender spam --tps 50 -r http://localhost:9645 --optimism --min-balance 0.14eth --forever
```

You should start to see blocks being built and landed on-chain with `contender` transactions.

## Send a Test Transaction

```bash
decker test --rpc 9645
```

(`--rpc` accepts a bare port as shorthand for `http://localhost:<port>`, or a full URL.)

> The obvious legacy-style equivalent, `builder-playground test http://localhost:2222 --timeout 30s --retries 10`, was actually silently broken: `test` ignores positional arguments and requires `--rpc`, so that invocation really exercised the command's *default* target (`:8545`), never the builder. See the [Legacy appendix](#legacy-builder-playground-deprecated) for the corrected form.

## Services

| Service | Port | Notes |
|---|---|---|
| op-rbuilder (builder) RPC | `9645` | decker's fixed port — **not** builder-playground's old `:2222` (see `decker.ts`) |
| op-rbuilder authrpc | `9651` | rollup-boost's engine-API target |
| op-rbuilder metrics | `6062` | |
| op-rbuilder flashblocks (ws) | `1111` | `ws://localhost:1111` |
| chain-monitor | `8087` | `http://localhost:8087/metrics` |
| L1 EL (`el-1`) RPC | `8545` | |
| L2 sequencer EL RPC | `9545` | fallback target rollup-boost uses if the builder is down |
| L1 explorer (Blockscout) | `3002` | `http://localhost:3002` |
| L2 explorer (Blockscout) | `3003` | `http://localhost:3003` |
| Pod logs (Dozzle) | `18080` | podman only; under `docker-compose` use `decker attach` for logs |

## Builder-Only Restart Loop

To iterate on `op-rbuilder` itself without tearing down the rest of the devnet: stop decker's own builder process (it holds `:9645`/`:9651`), rebuild, then run the binary directly from the repository root — it auto-detects the running devnet's artifacts:

```bash
make op-rbuilder-profiling FEATURES=telemetry,loki
./target/profiling/op-rbuilder node --builder.playground
```

A bare `--builder.playground` (no path) resolves `./.decker/runtime/artifacts` first, falling back to the legacy `$HOME/.local/state/builder-playground/devnet` if that doesn't exist. It fixes `authrpc` at `:9651` (so rollup-boost keeps working unchanged) and trusted-peers the sequencer EL directly; its own RPC prefers `:2222` but falls back to a random free port if that's taken — check the startup logs for the actual one. This auto-detection requires the decker-aware `--builder.playground` rewrite (`feat/decker-devnet-detection`); on an older `op-rbuilder` build, pass the directory explicitly instead: `--builder.playground .decker/runtime/artifacts`.

## Karst

The devnet defaults to the `karst` L2 fork, which requires the `op-reth` v2.3.x dependency line — `main` is already on it, but older branches will not produce valid Karst blocks. Testing an older branch: override the fork via `decker.ts`'s `options.l2Fork` (e.g. `"jovian"` or `"isthmus"`), which also switches the sequencer EL back to `op-geth`.

## Legacy: builder-playground (deprecated)

Kept working during the migration to decker above; do not add anything new here.

1. [flashbots/builder-playground](https://github.com/flashbots/builder-playground).
1. [flashbots/contender](https://github.com/flashbots/contender).

From the repository root:

```bash
builder-playground start local-testing/playground.yaml
```

Use `--skip-setup` to skip `cargo build` on repeated runs:

```bash
builder-playground start local-testing/playground.yaml --skip-setup
```

Services:
- Grafana:       http://localhost:3000
- Tempo:         http://localhost:3200 (via Grafana Explore)
- Prometheus:    http://localhost:9090
- Loki:          http://localhost:3100
- RPC:           http://localhost:2222
- Chain Monitor: http://localhost:8087/metrics

Logs can be found at `$HOME/.local/state/builder-playground/sessions/latest/logs/`

Generate local traffic with `contender`:

```bash
contender spam --tps 50 -r http://localhost:2222 --optimism --min-balance 0.14eth --forever
```

Send a single test transaction (note the `--rpc` flag — a bare target URL is silently ignored):

```bash
builder-playground test --rpc http://localhost:2222 --timeout 30s --retries 10
```

`op-rbuilder` automatically detects settings and ports from the running playground via `--builder.playground`.
