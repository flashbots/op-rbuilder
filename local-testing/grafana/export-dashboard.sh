#!/bin/sh
# Export the current op-rbuilder dashboard from Grafana back to the local file.
# Usage: ./dev/grafana/export-dashboard.sh [grafana_url]
#
# Run this after editing the dashboard in Grafana's UI to persist changes.

GRAFANA_URL="${1:-http://localhost:3000}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/dashboards/op-rbuilder.json"

curl -sf "$GRAFANA_URL/api/dashboards/uid/op-rbuilder-dev" \
  | jq '.dashboard' > "$OUT.tmp" \
  && mv "$OUT.tmp" "$OUT" \
  && echo "Exported dashboard to $OUT" \
  || { rm -f "$OUT.tmp"; echo "Failed to export dashboard" >&2; exit 1; }
