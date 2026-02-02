#!/bin/bash
set -e

CONFIG_FILE="/app/bob.json"

# Patch bob.json with environment variables using jq
# Only overrides values when the corresponding env var is set

# --- String parameters ---
if [ -n "$NODE_SEED" ]; then
    jq --arg v "$NODE_SEED" '.["node-seed"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$LOG_LEVEL" ]; then
    jq --arg v "$LOG_LEVEL" '.["log-level"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$ARBITRATOR_IDENTITY" ]; then
    jq --arg v "$ARBITRATOR_IDENTITY" '.["arbitrator-identity"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$NODE_ALIAS" ]; then
    jq --arg v "$NODE_ALIAS" '.["node-alias"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$TICK_STORAGE_MODE" ]; then
    jq --arg v "$TICK_STORAGE_MODE" '.["tick-storage-mode"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$TX_STORAGE_MODE" ]; then
    jq --arg v "$TX_STORAGE_MODE" '.["tx-storage-mode"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$KEYDB_URL" ]; then
    jq --arg v "$KEYDB_URL" '.["keydb-url"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$KVROCKS_URL" ]; then
    jq --arg v "$KVROCKS_URL" '.["kvrocks-url"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

# --- Unsigned integer parameters ---
if [ -n "$RPC_PORT" ]; then
    jq --argjson v "$RPC_PORT" '.["rpc-port"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$SERVER_PORT" ]; then
    jq --argjson v "$SERVER_PORT" '.["server-port"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$REQUEST_CYCLE_MS" ]; then
    jq --argjson v "$REQUEST_CYCLE_MS" '.["request-cycle-ms"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$REQUEST_LOGGING_CYCLE_MS" ]; then
    jq --argjson v "$REQUEST_LOGGING_CYCLE_MS" '.["request-logging-cycle-ms"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$FUTURE_OFFSET" ]; then
    jq --argjson v "$FUTURE_OFFSET" '.["future-offset"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$MAX_THREAD" ]; then
    jq --argjson v "$MAX_THREAD" '.["max-thread"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$SPAM_QU_THRESHOLD" ]; then
    jq --argjson v "$SPAM_QU_THRESHOLD" '.["spam-qu-threshold"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$TX_TICK_TO_LIVE" ]; then
    jq --argjson v "$TX_TICK_TO_LIVE" '.["tx_tick_to_live"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$LAST_N_TICK_STORAGE" ]; then
    jq --argjson v "$LAST_N_TICK_STORAGE" '.["last_n_tick_storage"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$KVROCKS_TTL" ]; then
    jq --argjson v "$KVROCKS_TTL" '.["kvrocks_ttl"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

# --- Boolean parameters ---
if [ -n "$RUN_SERVER" ]; then
    jq --argjson v "$RUN_SERVER" '.["run-server"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$IS_TESTNET" ]; then
    jq --argjson v "$IS_TESTNET" '.["is-testnet"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$ENABLE_ADMIN_ENDPOINTS" ]; then
    jq --argjson v "$ENABLE_ADMIN_ENDPOINTS" '.["enable-admin-endpoints"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$ALLOW_CHECK_IN_QUBIC_GLOBAL" ]; then
    jq --argjson v "$ALLOW_CHECK_IN_QUBIC_GLOBAL" '.["allow-check-in-qubic-global"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

if [ -n "$ALLOW_RECEIVE_LOG_FROM_INCOMING" ]; then
    jq --argjson v "$ALLOW_RECEIVE_LOG_FROM_INCOMING" '.["allow-receive-log-from-incoming-connections"] = $v' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

# --- Array parameters ---
# P2P_NODES: comma-separated list, e.g. "1:1.2.3.4:21841,2:5.6.7.8:21841"
if [ -n "$P2P_NODES" ]; then
    jq --arg v "$P2P_NODES" '.["p2p-node"] = ($v | split(",") | map(. | ltrimstr(" ") | rtrimstr(" ")))' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
fi

echo "=== Bob configuration ==="
# Print config but redact the node-seed for security
jq 'if .["node-seed"] then .["node-seed"] = "***REDACTED***" else . end' "$CONFIG_FILE"
echo "========================="

# Execute the original CMD (supervisord)
exec "$@"
