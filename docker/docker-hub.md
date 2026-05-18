# Qubic Bob

[![Latest version](https://img.shields.io/docker/v/qubiccore/bob?label=version&sort=semver)](https://hub.docker.com/r/qubiccore/bob/tags)
[![Image size](https://img.shields.io/docker/image-size/qubiccore/bob/latest)](https://hub.docker.com/r/qubiccore/bob)

**Qubic Bob** is a high-performance indexer for the [Qubic network](https://qubic.org).
It syncs tick data from peers, verifies integrity via quorum & log events,
indexes blockchain state, and exposes it through:

- 🔌 **JSON-RPC 2.0 API** (HTTP & WebSocket) — Ethereum-like, designed for exchanges, dApps, and explorers.
- 🌐 **REST API** — for tooling that prefers plain HTTP.
- 📡 **WebSocket subscriptions** — real-time `tickStream`, `newTicks`, `logs`, `transfers`.

This image ships **bob + KeyDB + Kvrocks** in a single container — no extra services to install.

---

## 🚀 Quick start

### One-liner

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -e NODE_SEED=your_55_char_lowercase_seed_a_z_only_padded_to_55chars \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

### Docker Compose

```yaml
services:
  qubic-bob:
    image: qubiccore/bob:latest
    container_name: qubic-bob
    restart: unless-stopped
    ports:
      - "21842:21842"     # P2P
      - "40420:40420"     # JSON-RPC / REST / WebSocket
    environment:
      NODE_SEED: your_55_char_lowercase_seed_a_z_only_padded_to_55chars
      NODE_ALIAS: my-bob-node
      # See the full list at docs/DOCKER_ENV.md
    volumes:
      - qubic-bob-redis:/data/redis
      - qubic-bob-kvrocks:/data/kvrocks
      - qubic-bob-data:/data/bob

volumes:
  qubic-bob-redis:
  qubic-bob-kvrocks:
  qubic-bob-data:
```

### Verify it's running

```bash
# Wait ~30s after start, then:
curl -s http://localhost:40420/status | jq
curl -s -X POST http://localhost:40420/qubic \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'
```

---

## 📦 Available tags

| Tag | What it is |
|---|---|
| `latest` | Latest stable release. Recommended for production. |
| `vX.Y.Z` (e.g. `v1.5.0`) | Pinned version. Recommended if you need reproducibility. |
| `nightly` | Daily build from `master`. May be unstable. |

See the [release notes](https://github.com/qubic/core-bob/blob/master/RELEASE_NOTES.md) for what changed in each version.

---

## 🖥️ System requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores (AVX2 required) | 8+ cores |
| RAM | 12 GB | 32 GB |
| Storage | 300 GB SSD/NVMe | 500 GB+ NVMe |
| Network | 100 Mbps | 1 Gbps |

Bob is memory-hungry on busy networks. KeyDB holds recent ticks in RAM
before migrating to Kvrocks on disk; if the network throughput exceeds
your `REDIS_MAXMEMORY`, you'll see `OOM command not allowed when used
memory > maxmemory` errors in the log. See [Tuning under load](#-tuning-under-load) below.

---

## 🔌 API endpoints

| Endpoint | Protocol | Purpose |
|---|---|---|
| `POST http://localhost:40420/qubic` | JSON-RPC 2.0 | Primary API |
| `ws://localhost:40420/ws/qubic` | WebSocket | Subscriptions + JSON-RPC |
| `GET http://localhost:40420/*` | REST | Convenience endpoints |
| `GET http://localhost:40420/swagger` | Swagger UI | REST API explorer |

### Common JSON-RPC methods

| Method | Description |
|---|---|
| `qubic_getTickNumber` | Latest tick |
| `qubic_getTickByNumber` | Full tick details (digests, votes, fees, log range) |
| `qubic_getBalance` | Identity's QU balance |
| `qubic_getAssetBalance` | Asset balance (ownership + possession) |
| `qubic_getTransactionByHash` | Transaction by hash |
| `qubic_getTransactionReceipt` | Receipt with `status: "success" \| "failed" \| "pending"` |
| `qubic_getLogs` | Filter logs by tick range, identity, log type |
| `qubic_broadcastTransaction` | Submit a signed transaction |
| `qubic_status` | Full node status |
| `qubic_subscribe` | WebSocket subscription (newTicks, logs, transfers, tickStream) |

Full reference: [JSON-RPC API Guide](https://github.com/qubic/core-bob/blob/master/docs/QUBIC_JSON_RPC.md) ·
[REST API Guide](https://github.com/qubic/core-bob/blob/master/docs/REST_API.md) ·
[Interactive playground](https://gistpreview.github.io/?6912d613bc27ae75126859447fca8acf)

---

## ⚙️ Configuration

Two ways to configure, in order of preference:

1. **Environment variables** (recommended) — see [docs/DOCKER_ENV.md](https://github.com/qubic/core-bob/blob/master/docs/DOCKER_ENV.md) for the complete reference of all 39 supported vars.
2. **Mount a custom `bob.json`** — for advanced cases where env vars aren't enough.

### Most-used env vars

| Env var | Purpose | Default |
|---|---|---|
| `NODE_SEED` | 55-char a–z seed identifying this node | - |
| `NODE_ALIAS` | Display name | `Big fat bob` |
| `P2P_NODES` | Comma-separated peer list | auto-discover |
| `LOG_LEVEL` | `trace`/`debug`/`info`/`warn`/`error` | `info` |
| `REDIS_MAXMEMORY` | KeyDB memory cap | `2gb` |
| `KVROCKS_TTL` | Data retention in kvrocks (seconds) | `1209600` (14 days) |

### Custom bob.json

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 -p 40420:40420 \
  -v ./bob.json:/app/bob.json \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

⚠️ **Do not use `:ro`** on the bob.json mount — the entrypoint patches the file at startup.

Full bob.json reference: [docs/CONFIG_FILE.MD](https://github.com/qubic/core-bob/blob/master/docs/CONFIG_FILE.MD).

---

## 💾 Volumes

| Path | What's in it | Persist? |
|---|---|---|
| `/data/redis` | KeyDB persistence (AOF + RDB) | yes |
| `/data/kvrocks` | Kvrocks (RocksDB-backed) data | yes |
| `/data/bob` | bob's snapshot files | yes |
| `/app/logs` | logs from supervisord-managed children | optional |

A fresh container with no volumes will start clean every restart — fine for dev, **not** for guardians or production indexers.

---

## 🛠️ Tuning under load

If you see `Failed to add log ... OOM command not allowed`:

| Symptom | Fix |
|---|---|
| Steady OOM under high tx volume | Increase `REDIS_MAXMEMORY` (e.g. `8gb`) |
| OOM after container restart | Wait for migration to drain, or lower `LAST_N_TICK_STORAGE` (lastNTick mode) / `n_tickdata_to_store` (kvrocks mode) |
| Disk usage growing fast | Lower `KVROCKS_TTL` (default 14 days). 7 days halves disk. |
| Cleaner falling behind | Check the `Current state:` log lines — the `GC: <a>/<b>` numbers should track the indexing cursor; if they drift, your machine can't keep up. |

bob logs a `KeyDB memory: <used> / <max> (XX%)` line roughly once per minute and immediately when usage crosses 85% — this is the cleanest signal for memory pressure.

---

## 🔧 Troubleshooting

| Issue | Check |
|---|---|
| Container exits immediately | `docker logs qubic-bob` — usually a config validation error (bad `NODE_SEED`, bad `P2P_NODES` format) |
| Stuck at "Waiting for new epoch info from peers" | Peer set unreachable. Verify outbound to port `21841` on the listed peers. Default uses `qubic.global` for auto-discovery. |
| `status: "failed"` for low-value txs | Should not happen on v1.4.0+ (the default `SPAM_QU_THRESHOLD` is now `0`). Upgrade if you see this. |
| `tick_data` endpoint returns zeros | The tick is older than your retention window. Check `TICK_STORAGE_MODE`: `lastNTick` deletes; `kvrocks` archives. |
| WebSocket subscription disconnects | Bob auto-disconnects idle WS connections. Re-subscribe on disconnect (this is expected). |

---

## 🧑‍💻 For developers

- **Source code**: [github.com/qubic/core-bob](https://github.com/qubic/core-bob)
- **Issue tracker**: [GitHub Issues](https://github.com/qubic/core-bob/issues)
- **Releases**: [Release notes](https://github.com/qubic/core-bob/blob/master/RELEASE_NOTES.md) · [GitHub Releases](https://github.com/qubic/core-bob/releases)
- **Build from source**: see [README on GitHub](https://github.com/qubic/core-bob/blob/master/README.md)

### Inside the container

```bash
# View the effective config
docker exec qubic-bob jq . /app/bob.json
docker exec qubic-bob cat /etc/redis/redis.conf
docker exec qubic-bob cat /etc/kvrocks/kvrocks.conf

# Talk to KeyDB / Kvrocks directly
docker exec qubic-bob redis-cli ping            # KeyDB on 6379
docker exec qubic-bob redis-cli -p 6666 ping    # Kvrocks on 6666

# Tail bob logs
docker logs -f qubic-bob
```

---

Built with ❤️ by the Qubic Bob team. Massive thanks to [@krypdkat](https://github.com/krypdkat) for the original qubicbob project this is based on.
