#!/bin/sh
# Wait for the L2 RPC endpoint to be reachable before starting chain-monitor.
# chain-monitor has no retry logic at startup — it fatally exits if the RPC
# is not available when NewBlockInspector dials it.

RPC_URL="${CHAIN_MONITOR_L2_RPC:-http://host.docker.internal:2222}"
RPC_HOST=$(echo "${RPC_URL}" | sed 's|.*://||; s|/.*||; s|:.*||')
RPC_PORT=$(echo "${RPC_URL}" | sed 's|.*://||; s|/.*||; s|.*:||')

echo "Waiting for L2 RPC at ${RPC_HOST}:${RPC_PORT}..."
while ! nc -z "${RPC_HOST}" "${RPC_PORT}" 2>/dev/null; do
    sleep 1
done
echo "L2 RPC is ready."

exec ./chain-monitor "$@"
