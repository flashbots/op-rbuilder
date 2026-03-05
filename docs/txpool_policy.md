# Txpool Policy Configuration

`op-rbuilder` now configures ingress filtering and transaction ordering via a
single policy file passed with `--rules.config-path` (or `RULES_CONFIG_PATH`).

## Top-Level Schema

```yaml
ingress:
  type: allow_all | deny_rules
  # only for deny_rules
  sources:
    refresh_interval: 60
    file:
      - path: /path/to/deny-rules.yaml
        name: optional
        enabled: true

ordering:
  type: priority_fee | priority_fee_with_boost
  # only for priority_fee_with_boost
  unscored_score: 0
  sources:
    refresh_interval: 60
    file:
      - path: /path/to/boost-rules.yaml
```

## Regimes

- `ingress.type = allow_all`
  - No ingress deny filtering is applied.
- `ingress.type = deny_rules`
  - Ingress deny filtering is enabled.
  - Rules are loaded from configured `sources`.

- `ordering.type = priority_fee`
  - Transactions are ordered by effective priority fee.
  - Boost scoring is disabled.
- `ordering.type = priority_fee_with_boost`
  - Transactions are ordered by `(boost_score, effective_priority_fee)`.
  - Boost scores are loaded from configured `sources`.

## Source List Semantics

For each regime (`ingress.sources` and `ordering.sources`) the `file` list is:

1. Processed in listed order.
2. Skips entries with `enabled: false`.
3. Merged additively:
   - `deny` rules are appended.
   - `boost` rules are appended.
   - alias groups are union-merged by group name.

This is not an override model; it is an additive composition model.

## Minimal Examples

Priority-fee only, no deny rules:

```yaml
ingress:
  type: allow_all
ordering:
  type: priority_fee
```

Deny filtering + boost ordering:

```yaml
ingress:
  type: deny_rules
  sources:
    refresh_interval: 30
    file:
      - path: /etc/op-rbuilder/rules/deny.yaml

ordering:
  type: priority_fee_with_boost
  sources:
    refresh_interval: 30
    file:
      - path: /etc/op-rbuilder/rules/boost.yaml
```
