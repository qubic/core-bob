# Qubic Bob

Qubic Bob is a high-performance indexer for the Qubic network that provides a **JSON-RPC 2.0 API** (similar to Ethereum's JSON-RPC) and WebSocket subscriptions for real-time blockchain data.

## Quick Start

### Standalone (Recommended)

All-in-one image with Bob, Redis, and Kvrocks included:

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

### With Docker Compose

```yaml
services:
  qubic-bob:
    image: qubiccore/bob:latest
    ports:
      - "21842:21842"
      - "40420:40420"
    volumes:
      - qubic-bob-redis:/data/redis
      - qubic-bob-kvrocks:/data/kvrocks
      - qubic-bob-data:/data/bob

volumes:
  qubic-bob-redis:
  qubic-bob-kvrocks:
  qubic-bob-data:
```

## Available Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `vX.Y.Z` (e.g. `v1.2.0`) | Pinned version |
| `nightly` | Daily build from master |

## JSON-RPC API

The primary interface is a **JSON-RPC 2.0 API** designed for exchange integration and dApp development. If you're familiar with Ethereum's JSON-RPC, you'll find similar patterns.

### Endpoints

| Endpoint | Protocol |
|----------|----------|
| `http://localhost:40420/qubic` | HTTP POST |
| `ws://localhost:40420/ws/qubic` | WebSocket |

### Example Request

```bash
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'
```

### Core Methods

| Method | Description |
|--------|-------------|
| `qubic_getTickNumber` | Get latest tick number |
| `qubic_getTickByNumber` | Get tick details |
| `qubic_getBalance` | Get identity balance |
| `qubic_getTransaction` | Get transaction by hash |
| `qubic_getTransactionReceipt` | Get transaction receipt with execution status |
| `qubic_getLogs` | Query logs with filters |
| `qubic_status` | Full node status |

### WebSocket Subscriptions

Real-time data streaming via WebSocket:

```json
{"jsonrpc":"2.0","method":"qubic_subscribe","params":["tickStream",{}],"id":1}
```

| Subscription | Description |
|--------------|-------------|
| `newTicks` | New tick notifications |
| `logs` | Log events matching filter |
| `transfers` | QU transfer events |
| `tickStream` | Full tick stream with transactions and logs |

## Ports

| Port | Description |
|------|-------------|
| 21842 | P2P server |
| 40420 | JSON-RPC & REST API |

## Volumes

| Path | Description |
|------|-------------|
| `/data/redis` | Redis persistence |
| `/data/kvrocks` | Kvrocks persistence |
| `/data/bob` | Bob snapshot files |

## Configuration

Mount a custom `bob.json` to `/app/bob.json`:

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
| `tick-storage-mode` | `kvrocks` or `lastNTick` | `kvrocks` |
| `tx-storage-mode` | `kvrocks` or `free` | `kvrocks` |
| `tx_tick_to_live` | Ticks to keep tx data | `10000` |
| `log-level` | `debug`, `info`, `warn`, `error` | `info` |
| `spam-qu-threshold` | Min QU to index transfers (0 disables the filter) | `0` |

## Links

- [GitHub Repository](https://github.com/qubic/core-bob)
- [JSON-RPC API Guide](https://github.com/qubic/core-bob/QUBIC_JSON_RPC.md)
- [RPC Playground](https://gistpreview.github.io/?6912d613bc27ae75126859447fca8acf)