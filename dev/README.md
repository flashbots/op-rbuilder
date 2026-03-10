# Local Dev Environment

This directory contains local development environment configuration for `op-rbuilder`.

## Prerequisites

1. [flashbots/builder-playground](https://github.com/flashbots/builder-playground).
1. [flashbots/contender](https://github.com/flashbots/contender).

## Start Local Devnet

From the repository root:

```bash
builder-playground start dev/playground.yaml
```

Use `--skip-setup` to skip `cargo build` on repeated runs:

```bash
builder-playground start dev/playground.yaml --skip-setup
```

Services:
- Grafana:    http://localhost:3000
- Jaeger:     http://localhost:16686
- Prometheus: http://localhost:9090
- RPC:        http://localhost:2222

Logs can be found at `$HOME/.local/state/builder-playground/sessions/latest/logs/`

## Generate Local Traffic

Run `contender`:

```bash
contender spam --tps 10 -r http://localhost:2222 --optimism --min-balance 0.14
```

You should start to see blocks being built and landed on-chain with `contender` transactions.

Alternatively, send a single test transaction:

```bash
builder-playground test http://localhost:2222 --timeout 30s --retries 10
```

`op-rbuilder` automatically detects settings and ports from the running playground via `--builder.playground`.
