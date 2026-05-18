# Docker Environment Variables

Complete reference for environment variables supported by the
`qubiccore/bob` Docker image. Each variable is translated into the
corresponding config-file setting at container startup by
[`docker/entrypoint.sh`](../docker/entrypoint.sh).

Three configuration files are produced:

| File | What it controls | How env vars patch it |
|---|---|---|
| `/app/bob.json` | bob's runtime config | `jq` rewrites the matching key |
| `/etc/redis/redis.conf` | bundled KeyDB | `sed` replaces the matching line |
| `/etc/kvrocks/kvrocks.conf` | bundled Kvrocks | `sed` replaces the matching line |

You can also mount your own `bob.json` and skip env vars entirely — see
the [example compose file](../docker/examples/docker-compose.yml).

---

## Identity & networking

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `NODE_SEED` | `node-seed` | (built-in default) | 55-char lowercase a–z seed used to derive the node identity. The default works for read-only indexers; set your own if you want a stable, unique identity. |
| `NODE_ALIAS` | `node-alias` | `Big fat bob` | Human-readable name reported by `/status` and other endpoints. |
| `ARBITRATOR_IDENTITY` | `arbitrator-identity` | (built-in) | 60-char uppercase Qubic identity used to validate the computor set. |
| `P2P_NODES` | `p2p-node` | `[]` (auto-discover) | Comma-separated peer list. Example: `BM:157.180.10.49:21841:0-0-0-0,BM:65.109.122.174:21841:0-0-0-0`. Format per entry: `BM:IP:PORT[:P0-P1-P2-P3]` for trusted peers or `IP:PORT` for plain peers. |
| `RUN_SERVER` | `run-server` | `true` | If `true`, serve P2P data to other peers on `SERVER_PORT`. |
| `SERVER_PORT` | `server-port` | `21842` | P2P listening port. |
| `RPC_PORT` | `rpc-port` | `40420` | REST + JSON-RPC + WebSocket port. |
| `IS_TESTNET` | `is-testnet` | `false` | Testnet vs mainnet mode. |
| `LOG_LEVEL` | `log-level` | `info` | One of `trace`, `debug`, `info`, `warn`, `error`, `fatal`. |

## Storage backend connections

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `KEYDB_URL` | `keydb-url` | `tcp://127.0.0.1:6379` | URL of the Redis/KeyDB instance. Override to point at an external server (and disable the bundled one — see [docker/README.md](../docker/README.md)). |
| `KVROCKS_URL` | `kvrocks-url` | `tcp://127.0.0.1:6666` | URL of the Kvrocks instance. |

## Sync pacing

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `REQUEST_CYCLE_MS` | `request-cycle-ms` | `100` | Interval (ms) between tick-data requests to peers. Lower = more aggressive sync, higher = lighter on peers. |
| `REQUEST_LOGGING_CYCLE_MS` | `request-logging-cycle-ms` | `100` | Interval (ms) between log-event requests. |
| `FUTURE_OFFSET` | `future-offset` | `3` | How many ticks ahead of the current tip bob will pre-fetch. Too high overloads peers; too low slows sync recovery. |
| `MAX_THREAD` | `max-thread` | `0` (auto) | Cap on worker threads; `0` uses the number of CPU cores. |

## Storage retention & sizing

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `TICK_STORAGE_MODE` | `tick-storage-mode` | `kvrocks` | One of `lastNTick`, `kvrocks`, `free`. `kvrocks` migrates old ticks to disk; `lastNTick` deletes them; `free` keeps everything in KeyDB. |
| `TX_STORAGE_MODE` | `tx-storage-mode` | `kvrocks` | One of `lastNTick`, `kvrocks`, `free`. Same semantics for `transaction:*` blobs. |
| `LAST_N_TICK_STORAGE` | `last_n_tick_storage` | `1000` | (`lastNTick` mode only) Number of recent ticks to keep in KeyDB before deletion. |
| `TX_TICK_TO_LIVE` | `tx_tick_to_live` | `10000` (Config.h) / `3000` (docker default) | (`kvrocks` mode only) How many ticks of `transaction:*` blobs stay in KeyDB before migration to kvrocks. |
| `KVROCKS_TTL` | `kvrocks_ttl` | `1209600` (14 days, ~2 epochs) | TTL applied to every key bob writes to Kvrocks: `transaction:*`, `itx:*`, `vtick:*`, `log:*`, indexed entries. Set to `0` for no expiration. |
| `INDEXER_MAX_ACTIVITIES_PER_KEY` | `indexer-max-activities-per-key` | `100000` (Config.h) / `10000` (docker default) | Cap on entries in each `indexed:*` topic zset. Oldest entries get popped via `ZPOPMIN` when the cap is hit. |
| `WAIT_AT_EPOCH_END` | `wait-at-epoch-end` | `1800` (seconds) | After receiving END_EPOCH, how long to keep serving slower peers before shutting down. |

## Indexer behavior

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `SPAM_QU_THRESHOLD` | `spam-qu-threshold` | `0` | Minimum QU amount to index a transfer. `0` disables filtering. Historically used to suppress dust txs from the indexer; current default keeps everything so receipts/balances are always correct. |
| `PERSIST_ORACLE_TX` | `persist-oracle-tx` | `true` | Persist oracle reply transactions (`destinationPublicKey=0`, `inputType ∈ {6,7,10}`). |

## API surface

| Env var | bob.json key | Default | Description |
|---|---|---|---|
| `ENABLE_ADMIN_ENDPOINTS` | `enable-admin-endpoints` | `false` | Expose `/_admin/*` routes (e.g. `/_admin/checkTransactions`). Keep `false` in public deployments. |
| `ALLOW_CHECK_IN_QUBIC_GLOBAL` | `allow-check-in-qubic-global` | `true` | Allow bob to register itself with `qubic.global` for peer discovery. Disable if you run isolated. |
| `ALLOW_RECEIVE_LOG_FROM_INCOMING` | `allow-receive-log-from-incoming-connections` | `false` | Accept log-event packets from non-trusted incoming peers. Off by default since malformed payloads can pollute the local DB. |

## Bundled KeyDB (`/etc/redis/redis.conf`)

These do **not** apply if you point `KEYDB_URL` at an external server.

| Env var | redis.conf line | Default | Description |
|---|---|---|---|
| `REDIS_PORT` | `port` | `6379` | KeyDB listening port. |
| `REDIS_MAXMEMORY` | `maxmemory` | `2gb` | Memory cap. Increase for high-throughput nodes; OOM on writes (`Failed to add log ... OOM command not allowed`) usually means the cleaner is falling behind — raise this or lower `n_tickdata_to_store` / `TX_TICK_TO_LIVE`. |
| `REDIS_MAXMEMORY_POLICY` | `maxmemory-policy` | `noeviction` | **Keep `noeviction`**. Any eviction policy will silently drop keys bob needs and corrupt the index. |
| `REDIS_LOGLEVEL` | `loglevel` | `notice` | One of `debug`, `verbose`, `notice`, `warning`. |

## Bundled Kvrocks (`/etc/kvrocks/kvrocks.conf`)

These do **not** apply if you point `KVROCKS_URL` at an external server.

| Env var | kvrocks.conf line | Default | Description |
|---|---|---|---|
| `KVROCKS_PORT` | `port` | `6666` | Kvrocks listening port. |
| `KVROCKS_WORKERS` | `workers` | `4` | Number of worker threads. |
| `KVROCKS_LOGLEVEL` | `log-level` | `info` | One of `debug`, `info`, `notice`, `warning`, `error`, `fatal`. |
| `KVROCKS_BLOCK_CACHE_SIZE` | `rocksdb.block_cache_size` | `4096` (MB) | RocksDB block cache, in MB. Bigger speeds reads, costs RAM. Rule of thumb: leave ~2 GB for redis and ~2 GB for OS/app overhead; give the rest to this. |
| `KVROCKS_WRITE_BUFFER_SIZE` | `rocksdb.write_buffer_size` | `256` (MB) | Per-memtable size, in MB. Larger = fewer L0 flushes. |
| `KVROCKS_MAX_WRITE_BUFFER_NUMBER` | `rocksdb.max_write_buffer_number` | `4` | Max in-memory memtables. |
| `KVROCKS_MAX_OPEN_FILES` | `rocksdb.max_open_files` | `4096` | File descriptor cap. |
| `KVROCKS_ROCKSDB_TTL` | `rocksdb.ttl` | `1296000` (15 days) | RocksDB-level secondary TTL safety net. Should be **slightly above** `KVROCKS_TTL` so the app-level TTL fires first. |

---

## Tips

- **Start with defaults**, override only what you need. The image ships with a sensible bob.json + redis.conf + kvrocks.conf.
- **`NODE_SEED`** is optional but recommended if you want a stable, unique node identity (e.g. for guardian setups or peer-reputation tracking).
- **High-load tuning**: when KeyDB OOMs under high load, raise `REDIS_MAXMEMORY`; if migration to kvrocks lags, lower `last_n_tick_storage` (LastNTick mode) or `n_tickdata_to_store` (Kvrocks mode).
- **Mount a custom config file** if you outgrow env vars — see the `volumes:` block in [docker/examples/docker-compose.yml](../docker/examples/docker-compose.yml).
- **Inspect the effective config** at container start: the entrypoint logs `=== Bob configuration ===`, `=== Redis configuration ===`, and `=== Kvrocks configuration ===` (with `node-seed` redacted) so you can verify your overrides took effect.

For the bob.json reference (every config key, including ones not exposed via env), see [CONFIG_FILE.MD](CONFIG_FILE.MD).
