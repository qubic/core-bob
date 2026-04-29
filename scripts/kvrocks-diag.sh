#!/usr/bin/env bash
# kvrocks-diag.sh — gather kvrocks size / compaction diagnostics from a bob container.
#
# Usage:
#   kvrocks-diag.sh [-c CONTAINER] [-p PORT] [-d DATA_DIR] [-l LOG_FILE]
#
# Defaults:
#   container: qubic-bob          (use -c to use a different container name)
#   port:      6666               (kvrocks)
#   data dir:  /data/kvrocks      (path inside the container)
#   log file:  /app/logs/kvrocks.INFO  (glog INFO file; .log is just stdout)
set -euo pipefail

CONTAINER="qubic-bob"
PORT=6666
DATA_DIR="/data/kvrocks"
LOG_FILE="/app/logs/kvrocks.INFO"

while getopts ":c:p:d:l:h" opt; do
    case "$opt" in
        c) CONTAINER="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        d) DATA_DIR="$OPTARG" ;;
        l) LOG_FILE="$OPTARG" ;;
        h) sed -n '2,12p' "$0"; exit 0 ;;
        *) sed -n '2,12p' "$0"; exit 1 ;;
    esac
done

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "ERROR: container '$CONTAINER' is not running." >&2
    exit 1
fi

CLI="redis-cli"
if docker exec "$CONTAINER" sh -c 'command -v keydb-cli >/dev/null 2>&1'; then
    CLI="keydb-cli"
fi

hr() { printf '\n=== %s ===\n' "$1"; }

hr "Container & client"
echo "container: $CONTAINER"
echo "client:    $CLI"
echo "port:      $PORT"
echo "data dir:  $DATA_DIR"
echo "log file:  $LOG_FILE"

hr "Disk usage on host (Docker volume)"
# Best-effort: try to find the host path of the kvrocks bind/volume mount
HOST_MOUNT=$(docker inspect "$CONTAINER" \
    --format '{{ range .Mounts }}{{ if eq .Destination "'"$DATA_DIR"'" }}{{ .Source }}{{ end }}{{ end }}')
if [ -n "$HOST_MOUNT" ]; then
    echo "host path: $HOST_MOUNT"
    df -h "$HOST_MOUNT" || true
    du -sh "$HOST_MOUNT" 2>/dev/null || true
else
    echo "(could not resolve host mount for $DATA_DIR — skipping host df/du)"
fi

hr "Container view of kvrocks data directory"
docker exec "$CONTAINER" sh -c "df -h $DATA_DIR 2>/dev/null; echo; du -sh $DATA_DIR/* 2>/dev/null | sort -h | tail -20"

hr "Compaction state (INFO rocksdb)"
docker exec "$CONTAINER" $CLI -p "$PORT" INFO rocksdb 2>/dev/null \
    | grep -iE "num_running_compactions|num_running_flushes|pending_compaction_bytes|num_files_at_level|level_sizes|estimate_live_data_size|estimate_table_readers_mem|total_sst_files_size|background_errors" \
    || echo "(no relevant fields found)"

hr "Server INFO (selected)"
docker exec "$CONTAINER" $CLI -p "$PORT" INFO server 2>/dev/null \
    | grep -iE "kvrocks_version|uptime_in_days|role" || true
docker exec "$CONTAINER" $CLI -p "$PORT" INFO keyspace 2>/dev/null || true

hr "Key-prefix sample (heavy hitters)"
echo "(scanning ~10000 keys, may take a moment)"
docker exec "$CONTAINER" $CLI -p "$PORT" --scan --count 1000 2>/dev/null \
    | head -10000 \
    | awk -F: 'NF>=2{print $1":"$2; next}{print $0}' \
    | sort | uniq -c | sort -rn | head -15 \
    || echo "(scan failed or empty)"

hr "Recent compaction log lines"
docker exec "$CONTAINER" sh -c "
    for f in $LOG_FILE /app/logs/kvrocks.INFO /app/logs/kvrocks.WARNING /app/logs/kvrocks.log; do
        if [ -f \"\$f\" ]; then
            echo \"--- \$f ---\"
            tail -n 2000 \"\$f\" | grep -iE 'compact|flush|stall|slowdown|error' | tail -30 || true
        fi
    done"

hr "Config (kvrocks.conf — selected)"
docker exec "$CONTAINER" sh -c "grep -nE 'compression|ttl|compact|write_buffer|max_open_files|block_cache' /etc/kvrocks/kvrocks.conf 2>/dev/null || true"

hr "Config (bob.json — TTL/retention knobs)"
docker exec "$CONTAINER" sh -c "grep -nE 'kvrocks_ttl|tx_tick_to_live|tick-storage-mode|indexer-max-activities-per-key|spam-qu-threshold|n_tickdata_to_store' /app/bob.json 2>/dev/null || true"

hr "Done"
echo "Tip: re-run after the next compaction cycle to see whether pending_compaction_bytes and total_sst_files_size are shrinking."
