# Local Dev Environment

Local devnet configuration for `op-rbuilder`, powered by [decker](https://github.com/flashbots/decker). [builder-playground](https://github.com/flashbots/builder-playground) (`local-testing/playground.yaml`) is kept working as a legacy fallback, see [Legacy appendix](#legacy-builder-playground-deprecated).

## Prerequisites

- **podman**, with its (rootless) API socket running. For docker instead, uncomment the `target: { pods: "docker-compose" }` line at the bottom of `decker.ts`.
- **decker** CLI:
  ```bash
  curl -sSfL https://raw.githubusercontent.com/flashbots/decker/main/install.sh | bash
  ```
- **process-compose**: `op-rbuilder` runs as a host process here, which decker drives through its `process-compose` renderer.
- [flashbots/contender](https://github.com/flashbots/contender), for traffic generation.

## Quickstart

**First time only**: clone decker into `.decker/` before anything else:

```bash
git clone https://github.com/flashbots/decker.git .decker
```

From the repository root:

```bash
just devnet
```

This builds the profiling `op-rbuilder` binary and runs `decker start` against the `.decker/` clone above, bringing the whole stack up.

Or alternatively:

```bash
make op-rbuilder-profiling FEATURES=telemetry,loki
decker start   # fg, Ctrl+C to stop; use `decker up` + `decker down` to detach
```

See `decker.ts` for the exact recipe options (fork, L2 block time, flashblocks config, chain-monitor, observability).

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

## Services

| Service | Port | Notes |
|---|---|---|
| op-rbuilder RPC | `9645` | decker's fixed port |
| op-rbuilder authrpc | `9651` | rollup-boost engine-API |
| op-rbuilder metrics | `6062` | |
| op-rbuilder flashblocks (ws) | `1111` | `ws://localhost:1111` |
| chain-monitor | `8087` | `http://localhost:8087/metrics` |
| Prometheus | `9009` | scrapes op-rbuilder + chain-monitor metrics |
| Grafana | `3000` | `http://localhost:3000`, anonymous Admin (no login) |
| L1 EL (`el-1`) RPC | `8545` | |
| L2 sequencer EL RPC | `9545` | fallback target rollup-boost |
| L1 explorer (Blockscout) | `3002` | `http://localhost:3002` |
| L2 explorer (Blockscout) | `3003` | `http://localhost:3003` |
| Pod logs (Dozzle) | `18080` | podman only; under `docker-compose` use `decker attach` for logs |

## Observability

Provisioned by `local-testing/decker/obs.ts`:

- **Prometheus** (`:9009`) scrapes `op-rbuilder`'s metrics.
- **Grafana** (`:3000`) provisioned with op-rbuilder local dashboard.

**Deferred**: Loki, Tempo and Alloy. decker has no container prototypes for them yet.

## Builder-Only Restart Loop

To iterate on `op-rbuilder` itself without tearing down the rest of the devnet: stop decker's own builder process (it holds `:9645`/`:9651`), rebuild, then run the binary directly from the repository root; it auto-detects the running devnet's artifacts:

```bash
make op-rbuilder-profiling FEATURES=telemetry,loki
./target/profiling/op-rbuilder node --builder.playground
```

A bare `--builder.playground` resolves `./.decker/runtime/artifacts` first, falling back to the legacy `$HOME/.local/state/builder-playground/devnet` if that doesn't exist.

## Karst

The devnet defaults to the `karst` L2 fork, which requires `op-reth` v2.3.x dependency.

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
