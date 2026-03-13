# Local Dev Environment

This directory contains local development environment configuration for `op-rbuilder`.

## Prerequisites

1. [flashbots/builder-playground](https://github.com/flashbots/builder-playground).
1. [flashbots/contender](https://github.com/flashbots/contender).

## Start Local Devnet

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

## Generate Local Traffic

Run `contender`:

```bash
contender spam --tps 50 -r http://localhost:2222 --optimism --min-balance 0.14eth --forever
```

You should start to see blocks being built and landed on-chain with `contender` transactions.

Alternatively, send a single test transaction:

```bash
builder-playground test http://localhost:2222 --timeout 30s --retries 10
```

`op-rbuilder` automatically detects settings and ports from the running playground via `--builder.playground`.
