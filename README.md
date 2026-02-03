# Qubic Bob

A high-performance indexer for the **Qubic blockchain network**. Bob syncs tick data, verifies integrity via logging events, indexes blockchain data, and exposes it through an Ethereum-style **JSON-RPC 2.0** API (HTTP & WebSocket) and a REST API.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
  - [Option 1: Docker Hub (Recommended)](#option-1-docker-hub-recommended)
  - [Option 2: Docker from Source](#option-2-docker-from-source)
  - [Option 3: Build from Source (No Docker)](#option-3-build-from-source-no-docker)
- [Configuration](#configuration)
- [Usage](#usage)
- [Useful Resources](#useful-resources)

---

## System Requirements

| Resource | Minimum |
|----------|---------|
| CPU | 4 cores (AVX2 support required) |
| RAM | 16 GB |
| Storage | 100 GB fast SSD / NVMe |

---

## Quick Start

Choose the method that best fits your setup. If you just want to get Bob running with minimal effort, **Option 1** is the way to go.

### Option 1: Docker Hub (Recommended)

The standalone image bundles Bob, Redis, and Kvrocks into a single container -- no extra services needed. If you already run your own KeyDB/Kvrocks instances, you can point Bob to them via the config file (see [Configuration](#configuration)).

```bash
docker run -d --name qubic-bob \
  -p 21842:21842 \
  -p 40420:40420 \
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubiccore/bob:latest
```

Check the logs to make sure everything is running:

```bash
docker logs -f qubic-bob
```

**Ports exposed:**

| Port | Purpose |
|------|---------|
| 21842 | P2P server |
| 40420 | REST API & JSON-RPC |

---

### Option 2: Docker from Source

If you want to build the Docker image yourself instead of pulling from Docker Hub:

```bash
git clone https://github.com/qubic/core-bob.git
cd qubicbob
docker build -t qubic-bob -f docker/Dockerfile .
docker compose -f docker/examples/docker-compose.yml up -d
```

Check the logs:

```bash
docker logs -f qubic-bob
```

---

### Option 3: Build from Source (No Docker)

#### 1. Install system dependencies

```bash
sudo apt-get update
sudo apt install -y vim net-tools tmux cmake git libjsoncpp-dev \
  build-essential uuid-dev libhiredis-dev zlib1g-dev unzip
```

#### 2. Install KeyDB

KeyDB is a Redis-compatible database required by Bob. Follow the [KeyDB installation guide](doc/KEYDB_INSTALL.md).

Optionally, install KVRocks for additional disk-based persistence: [KVRocks installation guide](doc/KVROCKS_INSTALL.MD).

#### 3. Build Bob

```bash
git clone https://github.com/qubic/core-bob.git
cd qubicbob
mkdir build && cd build
cmake ..
make bob -j$(nproc)
```

#### 4. Run

```bash
./bob <path-to-config.json>
```

For example, using the provided default config:

```bash
./bob ../default_config_bob.json
```

---

## Configuration

An example configuration file, `default_config_bob.json`, ships with the repository. Below is an annotated reference:

```json
{
  "trusted-node": ["BM:157.180.10.49:21841:0-0-0-0", "BM:65.109.122.174:21841:0-0-0-0"],
  "request-cycle-ms": 100,
  "request-logging-cycle-ms": 30,
  "future-offset": 3,
  "log-level": "info",
  "keydb-url": "tcp://127.0.0.1:6379",
  "run-server": false,
  "server-port": 21842,
  "arbitrator-identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ",
  "trusted-entities": ["QCTBOBEPDEZGBBCSOWGBYCAIZESDMEVRGLWVNBZAPBIZYEJFFZSPPIVGSCVL"],
  "tick-storage-mode": "kvrocks",
  "kvrocks-url": "tcp://127.0.0.1:6666",
  "tx-storage-mode": "kvrocks",
  "tx_tick_to_live": 3000,
  "max-thread": 8,
  "spam-qu-threshold": 100
}
```

**Key fields:**

| Field | Description |
|-------|-------------|
| `trusted-node` | Nodes to sync from. Format: `BM:IP:PORT:PASSCODE` or `BM:IP:PORT` |
| `request-cycle-ms` | Interval (ms) for tick data requests. Too low may overload the node |
| `future-offset` | How many ticks ahead to request. Too high may overload the node |
| `keydb-url` | Redis / KeyDB connection URL |
| `run-server` | Set to `true` to serve data to other nodes on `server-port` |
| `tick-storage-mode` | `"kvrocks"`, `"lastNTick"`, or `"free"` |
| `tx-storage-mode` | `"kvrocks"` or `"free"` |
| `log-level` | `"debug"`, `"info"`, `"warn"`, or `"error"` |
| `max-thread` | Max worker threads (`0` = auto) |
| `spam-qu-threshold` | Minimum QU amount to index a transfer |

---

## Usage

Once Bob is running you can interact with it via the JSON-RPC or REST API:

- **JSON-RPC (HTTP):** `POST http://localhost:40420/qubic`
- **JSON-RPC (WebSocket):** `ws://localhost:40420/ws/qubic`

Example JSON-RPC call:

```bash
curl -s -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'
```

---

## Useful Resources

### Using Bob
- [Ethereum-like JSON-RPC (HTTP/WS)](doc/QUBIC_JSON_RPC.md)
- [REST API Endpoints](doc/REST_API.md)
- [What is a Logging Event in Qubic?](doc/LOGGING_IN_QUBIC.MD)
- [Mastering the findlog Method](doc/FINDLOG.MD)
- [Dealing with Transactions and Logging](doc/DEAL_WITH_TX.MD)
- [Improve Stability via Kernel Buffer Size](doc/KERN_BUF_SIZE.MD)

### Inside Bob
- [Anatomy of Bob](doc/ANATOMY_OF_BOB.MD)
- [How the Indexer Indexes Qubic Data](doc/INDEXER_INDEXING_DATA.MD)
