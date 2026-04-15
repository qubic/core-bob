# Docker Setup for Qubic Bob

All-in-one Docker image with Bob, Redis, and Kvrocks bundled together. If you already run your own KeyDB/Kvrocks instances, you can point Bob to them via the config file.

## Directory Structure

```
docker/
├── Dockerfile
├── bob.json              # Default config
├── redis.conf            # Redis settings
├── kvrocks.conf          # Kvrocks settings
├── supervisord.conf      # Process manager config
└── examples/
    ├── docker-compose.yml
    └── redis.conf        # Example Redis override
```

---

## Using the Pre-built Image

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

Or with Docker Compose:

```bash
cd docker/examples
docker compose up -d
```

### View Logs

```bash
docker logs -f qubic-bob
```

---

## Building from Source

```bash
# From repository root
docker build -t qubic-bob -f docker/Dockerfile .

docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubic-bob
```

---

## Exposed Ports

| Port | Description |
|------|-------------|
| 21842 | Bob P2P server |
| 40420 | REST API & JSON-RPC |

## Volumes

| Volume | Description |
|--------|-------------|
| `/data/redis` | Redis persistence data |
| `/data/kvrocks` | Kvrocks persistence data |
| `/data/bob` | Bob snapshot files (spectrum.*, universe.*) |

---

## Configuration

Mount your own `bob.json` to `/app/bob.json`:

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -v ./bob.json:/app/bob.json:ro \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

### bob.json Options

```json
{
  "p2p-node": [],
  "keydb-url": "tcp://127.0.0.1:6379",
  "kvrocks-url": "tcp://127.0.0.1:6666",
  "run-server": true,
  "server-port": 21842,
  "tick-storage-mode": "kvrocks",
  "tx-storage-mode": "kvrocks",
  "tx_tick_to_live": 10000,
  "log-level": "info",
  "spam-qu-threshold": 0
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `p2p-node` | P2P nodes to connect to | `[]` (auto-fetches) |
| `keydb-url` | Redis/KeyDB connection URL | `tcp://127.0.0.1:6379` |
| `kvrocks-url` | Kvrocks connection URL | `tcp://127.0.0.1:6666` |
| `run-server` | Enable P2P server | `true` |
| `server-port` | P2P server port | `21842` |
| `tick-storage-mode` | `kvrocks` or `lastNTick` | `kvrocks` |
| `tx-storage-mode` | `kvrocks` or `free` | `kvrocks` |
| `tx_tick_to_live` | Ticks to keep transaction data | `10000` |
| `log-level` | `debug`, `info`, `warn`, `error` | `info` |
| `spam-qu-threshold` | Min QU to index transfers (0 disables the filter) | `0` |

> To use external KeyDB/Kvrocks instances, update `keydb-url` and `kvrocks-url` to point to your hosts.

### P2P Node Format

```json
"p2p-node": [
  "BM:IP:PORT:P0-P1-P2-P3",
  "BM:157.180.10.49:21841:0-0-0-0"
]
```

- `BM:` prefix indicates a trusted node
- `0-0-0-0` Passcode from node (relevant for full node connection)

---

## Managing the Database

### Clean Up (Reset Everything)

```bash
docker stop qubic-bob
docker rm qubic-bob
docker volume rm qubic-bob-redis qubic-bob-kvrocks qubic-bob-data
```

### Clean While Running

```bash
docker exec -it qubic-bob bash

# Clear Redis
redis-cli FLUSHALL

# Clear Kvrocks
redis-cli -p 6666 FLUSHALL

# Remove snapshot files
rm -f /data/bob/spectrum.* /data/bob/universe.*

exit
docker restart qubic-bob
```

---

## Troubleshooting

### Check Service Status

```bash
docker exec -it qubic-bob supervisorctl status
```

### Common Issues

**"Cannot connect to Kvrocks"**
- Kvrocks hasn't started yet. Bob will retry automatically.

**"Peer certificate is not valid"**
- Missing CA certificates. Ensure `ca-certificates` is installed.

**"No persisted lastCleanTransactionTick found"**
- Normal on first startup or after database cleanup.

**Snapshot file errors**
- Database may be corrupted. Clean up and restart fresh.

---

## Building & Publishing

```bash
# From repository root
docker build -t qubiccore/bob:latest -f docker/Dockerfile .

# Tag with version from Version.h
docker tag qubiccore/bob:latest qubiccore/bob:v1.2.0

# Push all tags
docker push qubiccore/bob:latest
docker push qubiccore/bob:v1.2.0
```

### Tag Scheme

| Tag | When updated | Purpose |
|-----|-------------|---------|
| `:latest` | Each release | Default pull, always stable |
| `:vX.Y.Z` | Once, immutable | Pinned production deployments |
| `:nightly` | Daily / every push to master | Testing pre-release changes |
