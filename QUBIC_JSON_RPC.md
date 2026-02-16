# Qubic JSON-RPC API Guide

This guide is for exchange developers and integrators who want to connect to Qubic. If you're familiar with Ethereum's JSON-RPC API, this guide will help you understand the differences and map concepts between the two.


> [!NOTE]
> This documentation covers the Qubic JSON-RPC 2.0 API including WebSocket subscriptions.

To have a playground, you can open [rpc_playground.html](rpc_playground.html) in your browser. Or use the published version [here on github gist](https://gistpreview.github.io/?6912d613bc27ae75126859447fca8acf).

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Concept Mapping: Ethereum vs Qubic](#concept-mapping-ethereum-vs-qubic)
4. [API Endpoints](#api-endpoints)
5. [Method Reference](#method-reference)
6. [Code Examples](#code-examples)
7. [WebSocket Subscriptions](#websocket-subscriptions)

---

## Introduction

Qubic uses a JSON-RPC 2.0 API similar to Ethereum, but with terminology and data structures adapted to Qubic's unique architecture. Key differences:

- **Ticks** instead of blocks
- **Identities** (60-character strings) instead of 20-byte addresses
- **Epochs** as time periods (~7 days each)
- **Immediate finality** - no confirmation wait needed
- **No gas** - transactions are free

## Quick Start

### HTTP Endpoint
```
POST http://your-node:40420/qubic
```

### WebSocket Endpoint
```
ws://your-node:40420/ws/qubic
```

### Example: Get Current Tick
```bash
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": 12500000,
  "id": 1
}
```

### Example: Get Balance
```bash
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getBalance","params":["BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID"],"id":1}'
```

---

## Concept Mapping: Ethereum vs Qubic

| Ethereum Concept | Qubic Concept | Notes |
|-----------------|---------------|-------|
| Block | **Tick** | Atomic consensus unit, ~1 second interval |
| Block number | **Tick number** | Sequential 32-bit integer |
| Block hash | **Tick signature** | 64-byte Schnorr signature |
| Address (20 bytes, 0x...) | **Identity** (60 chars) | Encoded public key (A-Z) |
| Private key | **Seed** (55 lowercase letters) | Used to derive identity |
| wei/gwei/ether | **QU** | No decimals, raw integer units |
| Gas limit/price | N/A | Qubic has no gas fees |
| Confirmations | N/A | Ticks are immediately final |
| ERC-20 tokens | **Native assets** | Built-in asset support |
| Smart contracts | **Smart contracts** | Index 1-65535 |
| - | **Epoch** | ~7 day period, resets state |

### Identity Format

Qubic identities are 60-character uppercase strings:
```
BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFUDG
└──────────────────── 56 chars ────────────────────────┘└4─┘
                      address                           checksum
```

**Structure:**
- **56 characters**: The address derived from the 32-byte public key
- **4 characters**: Checksum (KangarooTwelve hash of public key)

**Encoding Algorithm:**
The 32-byte public key is split into 4 chunks of 8 bytes. Each chunk is treated as a 64-bit integer and converted to 14 characters by repeatedly dividing by 26 (remainder → A-Z). The checksum is derived from `KangarooTwelve(publicKey, 32)`, masked to 18 bits, and encoded as 4 characters.

**Checksum Validation:**
To validate an identity, recompute the checksum from the public key (decoded from the first 56 characters) and compare with the last 4 characters. Invalid checksums indicate a typo or corrupted address.

The API also accepts hex format (0x + 64 hex chars) for compatibility:
```
0x0000000000000000000000000000000000000000000000000000000000000000
```

Responses always return the 60-character Qubic identity format (uppercase).

### Transaction Hash Format

Transaction hashes are 60-character lowercase strings with the same structure:
```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh
└──────────────────── 56 chars ────────────────────────┘└4─┘
                      hash                              checksum
```

**Structure:**
- **56 characters**: The hash derived from 32 bytes (same algorithm as identity, but lowercase)
- **4 characters**: Checksum (KangarooTwelve hash, encoded as a-z)

**Key Difference:**
- Identities (addresses): **UPPERCASE** (A-Z)
- Transaction hashes: **lowercase** (a-z)

### Tick Tags

Similar to Ethereum block tags:

| Tag | Meaning |
|-----|---------|
| `"latest"` | Latest verified tick |
| `"earliest"` | First tick of current epoch |
| `"pending"` | Current fetching tick (not yet verified) |
| `12500000` | Specific tick number (decimal) |
| `"0xbebc20"` | Specific tick number (hex) |

---

## API Endpoints

| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `/qubic` | HTTP POST | JSON-RPC 2.0 requests |
| `/ws/qubic` | WebSocket | Real-time subscriptions |

---

## Method Reference

### Chain Info Methods

#### qubic_chainId
Returns chain identification info.

Chain IDs are derived deterministically from `keccak256("qubic:<network>")[-4:]`:

| Network | Chain ID (Decimal) | Chain ID (Hex) |
|---------|-------------------|----------------|
| mainnet | 788278422 | 0x2efc2c96 |
| testnet | 1997427496 | 0x770e5328 |
| devnet | 7948451 | 0x007948a3 |
| simnet | 3266082397 | 0xc2ac765d |

**Request:**
```json
{"jsonrpc":"2.0","method":"qubic_chainId","params":[],"id":1}
```

**Response:**
```json
{
  "result": {
    "chainId": "0x2efc2c96",
    "chainIdDecimal": 788278422,
    "network": "qubic-mainnet"
  }
}
```

| Ethereum Equivalent | Notes |
|---------------------|-------|
| `eth_chainId` | Returns more info in Qubic format |

---

#### qubic_clientVersion
Returns client version string.

**Response:** `"QubicBob/1.1.2"`

| Ethereum Equivalent |
|---------------------|
| `web3_clientVersion` |

---

#### qubic_syncing
Returns sync status with detailed tick progress.

**Response (syncing):**
```json
{
  "result": {
    "syncing": true,
    "epoch": 150,
    "initialTick": 12000000,
    "lastSeenNetworkTick": 12500000,
    "currentFetchingTick": 12490000,
    "currentFetchingLogTick": 12480000,
    "currentVerifyLoggingTick": 12450000,
    "currentIndexingTick": 12449999,
    "progress": 0.9
  }
}
```

**Response (synced):**
```json
{
  "result": {
    "syncing": false,
    "epoch": 150,
    "initialTick": 12000000,
    "lastSeenNetworkTick": 12500000,
    "currentFetchingTick": 12500000,
    "currentFetchingLogTick": 12500000,
    "currentVerifyLoggingTick": 12500000,
    "currentIndexingTick": 12499999
  }
}
```

**Tick Status Fields:**
| Field | Description |
|-------|-------------|
| `lastSeenNetworkTick` | Last seen tick of the Qubic network (omitted if unknown) |
| `currentFetchingTick` | Latest tick being fetched from network |
| `currentFetchingLogTick` | Latest tick with logs being fetched |
| `currentVerifyLoggingTick` | Latest tick with verified logs |
| `currentIndexingTick` | Latest tick indexed in database |

**Sync Determination:**
- If `lastSeenNetworkTick` is available: synced when `lastSeenNetworkTick - 10 <= currentVerifyLoggingTick`
- Fallback (network tick unknown): synced when `currentFetchingTick - 10 <= currentVerifyLoggingTick`

| Ethereum Equivalent |
|---------------------|
| `eth_syncing` |

---

#### qubic_status
Returns full node status including version info (same as `/status` REST endpoint).

**Response:**
```json
{
  "result": {
    "currentProcessingEpoch": 192,
    "currentFetchingTick": 41000000,
    "currentFetchingLogTick": 40999900,
    "currentVerifyLoggingTick": 40999800,
    "currentIndexingTick": 40999799,
    "initialTick": 39862000,
    "bobVersion": "1.2.3",
    "bobVersionGitHash": "abc1234",
    "bobCompiler": "GCC 13.2.0",
    "extraInfo": {
      "type": "bob",
      "version": "1.2.3",
      "alias": "My Bob Node",
      "uptime": 86400,
      "timestamp": 1704067200,
      "operator": "BAAAA...",
      "signature": "0x..."
    }
  }
}
```

| Ethereum Equivalent |
|---------------------|
| N/A (Qubic-specific) |

---

#### qubic_getCurrentEpoch
Returns current epoch info including tick range and log boundaries.

**Response:**
```json
{
  "result": {
    "epoch": 192,
    "currentTick": 39900000,
    "initialTick": 39862000,
    "endTick": 0,
    "endTickStartLogId": -1,
    "endTickEndLogId": -3
  }
}
```

**Fields:**
| Field | Description |
|-------|-------------|
| `epoch` | Current epoch number |
| `currentTick` | Latest verified tick |
| `initialTick` | First tick of this epoch |
| `endTick` | Last tick of this epoch (0 if epoch still active) |
| `endTickStartLogId` | Starting log ID for end-of-epoch events (-1 if not available) |
| `endTickEndLogId` | Ending log ID for end-of-epoch events |

| Ethereum Equivalent |
|---------------------|
| N/A (Qubic-specific) |

---

#### qubic_getEpochInfo
Returns epoch info for any epoch (current or historical).

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | number | Epoch number |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getEpochInfo",
  "params": [192],
  "id": 1
}
```

**Response:**
```json
{
  "result": {
    "epoch": 192,
    "initialTick": 39862000,
    "endTick": 40100000,
    "endTickStartLogId": 1234567890,
    "endTickEndLogId": 1234569000
  }
}
```

| Ethereum Equivalent |
|---------------------|
| N/A (Qubic-specific) |

---

#### qubic_getEndEpochLogs
Returns the logs from the end-of-epoch tick. These logs contain epoch-ending protocol events.

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | number | Epoch number |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getEndEpochLogs",
  "params": [192],
  "id": 1
}
```

**Response:**
```json
{
  "result": [
    {
      "logId": 1234567890,
      "tick": 40100000,
      "type": 6,
      "scIndex": 0,
      "data": "...",
      "extraData": "..."
    }
  ]
}
```

| Ethereum Equivalent |
|---------------------|
| N/A (Qubic-specific) |

---

### Tick Methods

#### qubic_getTickNumber
Returns latest verified tick number.

**Response:** `12500000`

| Ethereum Equivalent |
|---------------------|
| `eth_blockNumber` |

---

#### qubic_getTickByNumber
Returns tick data by number or tag.

**Params:** `[tickTag, includeTransactions]`
- `tickTag`: `"latest"`, `"earliest"`, `"pending"`, or numeric tick number
- `includeTransactions`: `true` for full transaction objects, `false` for hashes only

**Request (hashes only):**
```json
{"jsonrpc":"2.0","method":"qubic_getTickByNumber","params":["latest", false],"id":1}
```

**Response (includeTransactions=false):**
```json
{
  "result": {
    "tickNumber": 12500000,
    "epoch": 150,
    "computorIndex": 42,
    "signature": "0x...",
    "tickHash": "0x...",
    "timestamp": 1705312245,
    "timestampISO": "2025-01-15T10:30:45Z",
    "millisecond": 500,
    "timelock": "0x...",
    "transactionCount": 2,
    "transactions": [
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
      "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi"
    ],
    "previousTickHash": "0x..."
  }
}
```

**Request (full transactions):**
```json
{"jsonrpc":"2.0","method":"qubic_getTickByNumber","params":[12500000, true],"id":1}
```

**Response (includeTransactions=true):**
```json
{
  "result": {
    "tickNumber": 12500000,
    "epoch": 150,
    "computorIndex": 42,
    "signature": "0x...",
    "tickHash": "0x...",
    "timestamp": 1705312245,
    "timestampISO": "2025-01-15T10:30:45Z",
    "millisecond": 500,
    "timelock": "0x...",
    "transactionCount": 2,
    "transactions": [
      {
        "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
        "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "amount": 1000000,
        "inputType": 0,
        "inputSize": 0,
        "inputData": ""
      },
      {
        "hash": "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi",
        "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
        "amount": 5000000,
        "inputType": 1,
        "inputSize": 32,
        "inputData": "0x0102030405..."
      }
    ],
    "previousTickHash": "0x..."
  }
}
```

**Transaction Object Fields:**
| Field | Description |
|-------|-------------|
| `hash` | 60-char Qubic transaction hash (lowercase) |
| `from` | Sender identity (60 chars, uppercase) |
| `to` | Recipient identity (60 chars, uppercase) |
| `amount` | Transfer amount in QU (integer) |
| `inputType` | Transaction type (0=transfer, >0=SC call) |
| `inputSize` | Size of input data in bytes |
| `inputData` | Hex-encoded input data (empty string if none) |

| Ethereum Equivalent |
|---------------------|
| `eth_getBlockByNumber` |

---

#### qubic_getTickByHash

**Status: NOT AVAILABLE**

This method is currently disabled. Unlike Ethereum where block hashes are indexed, Qubic does not maintain a tick hash → tick number index. Implementing this would require scanning all ticks, which is inefficient.

Use `qubic_getTickByNumber` instead if you know the tick number.

| Ethereum Equivalent |
|---------------------|
| `eth_getBlockByHash` (no Qubic equivalent) |

---

### Transaction Methods

#### qubic_getTransactionByHash
Returns transaction by hash.

**Params:** `[txHash]` - Accepts 60-char Qubic hash (lowercase) or 0x hex format

**Response:**
```json
{
  "result": {
    "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
    "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "amount": 1000000000,
    "tick": 12500000,
    "inputType": 0,
    "inputSize": 0,
    "inputData": ""
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getTransactionByHash` |

---

#### qubic_getTransactionReceipt
Returns transaction receipt with logs.

**Params:** `[txHash]` - Accepts 60-char Qubic hash (lowercase) or 0x hex format

**Response:**
```json
{
  "result": {
    "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
    "tick": 12500000,
    "tickHash": "0x...",
    "transactionIndex": 3,
    "epoch": 150,
    "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "amount": 1000000000,
    "inputType": 0,
    "executed": true,
    "status": "success",
    "logs": [...],
    "logCount": 2
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getTransactionReceipt` |

---

### Balance & Transfer Methods

#### qubic_getBalance
Returns balance and transfer stats for an identity.

**Params:** `[identity]`

**Response:**
```json
{
  "result": {
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "publicKeyHex": "0x...",
    "balance": "1000000000000",
    "incomingAmount": "1500000000000",
    "outgoingAmount": "500000000000",
    "numberOfIncomingTransfers": 100,
    "numberOfOutgoingTransfers": 50,
    "latestIncomingTransferTick": 12499900,
    "latestOutgoingTransferTick": 12499500,
    "currentTick": 12500000
  }
}
```

| Ethereum Equivalent | Notes |
|---------------------|-------|
| `eth_getBalance` | Returns much more data |

---

#### qubic_getTransfers
Returns transfers/logs matching filter criteria. Uses the same filter format as the `/findLog` REST endpoint.

**Params:** `[filterObject]`

**Filter Object:**

The filter object follows the same format as the `/findLog` endpoint. See [FINDLOG.MD](FINDLOG.MD) for complete documentation on filter parameters, topic usage, and examples.

| Field | Type | Description |
|-------|------|-------------|
| `identity` | string | Optional. Filter by source or destination identity (JSON-RPC extension) |
| `fromTick` | number | Starting tick number |
| `toTick` | number | Ending tick number |
| `scIndex` | number | Smart contract index. 0 for protocol logs (default: 0) |
| `logType` | number | Log type filter |
| `topic1` | string | Topic filter 1 (source for protocol logs) |
| `topic2` | string | Topic filter 2 (destination for protocol logs) |
| `topic3` | string | Topic filter 3 (extra info) |

> **Wildcard Filter:** Use `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB` to match any value for topic filters.

**Log Types:**

> **Note:** Log types are derived from Qubic core. The latest version can be found at:
> https://github.com/qubic/core/blob/main/src/logging/logging.h

| Type | Name | Description |
|------|------|-------------|
| 0 | QU_TRANSFER | Native QU token transfer |
| 1 | ASSET_ISSUANCE | New asset created |
| 2 | ASSET_OWNERSHIP_CHANGE | Asset ownership transferred |
| 3 | ASSET_POSSESSION_CHANGE | Asset possession transferred |
| 4 | CONTRACT_ERROR_MESSAGE | Smart contract error log |
| 5 | CONTRACT_WARNING_MESSAGE | Smart contract warning log |
| 6 | CONTRACT_INFORMATION_MESSAGE | Smart contract info log |
| 7 | CONTRACT_DEBUG_MESSAGE | Smart contract debug log |
| 8 | BURNING | QU tokens burned |
| 9 | DUST_BURNING | Dust amounts burned |
| 10 | SPECTRUM_STATS | Spectrum statistics |
| 11 | ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE | Asset ownership managing contract changed |
| 12 | ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE | Asset possession managing contract changed |
| 13 | CONTRACT_RESERVE_DEDUCTION | Contract reserve deduction |
| 255 | CUSTOM_MESSAGE | Custom message (see subtypes below) |

**Custom Message Subtypes (opCode in log data):**
| OpCode | Name | Description |
|--------|------|-------------|
| 6217575821008262227 | STA_DDIV | Start distribute dividends |
| 6217575821008457285 | END_DDIV | End distribute dividends |
| 4850183582582395987 | STA_EPOC | Start epoch |
| 4850183582582591045 | END_EPOC | End epoch |

**Request (simple - QU transfers for identity):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "fromTick": 12490000,
    "toTick": 12500000
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": {
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "fromTick": 12490000,
    "toTick": 12500000,
    "transfers": [
      {
        "ok": true,
        "epoch": 150,
        "tick": 12495000,
        "type": 0,
        "logId": 12345678,
        "logDigest": "a1b2c3d4e5f60718",
        "bodySize": 72,
        "logTypename": "QU_TRANSFER",
        "timestamp": "25-01-11 14:30:45",
        "txHash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
        "body": {
          "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
          "amount": 1000000
        },
        "direction": "incoming"
      }
    ],
    "count": 1
  }
}
```

**Request (all protocol logs in tick range - no identity filter):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "fromTick": 12490000,
    "toTick": 12490010,
    "logType": 0
  }],
  "id": 1
}
```

**Request (smart contract logs with topic filters):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "fromTick": 12490000,
    "toTick": 12500000,
    "scIndex": 1,
    "logType": 6,
    "topic1": "FILTERIDENTITY1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }],
  "id": 1
}
```

**Response (smart contract logs):**
```json
{
  "result": {
    "fromTick": 12490000,
    "toTick": 12500000,
    "scIndex": 1,
    "logType": 6,
    "transfers": [
      {
        "tick": 12495000,
        "epoch": 150,
        "logId": 12345680,
        "logType": 6,
        "logTypeName": "CONTRACT_INFO",
        "contractIndex": 1,
        "contractLogType": 42,
        "rawData": "0x..."
      }
    ],
    "count": 1
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` with transfer event filter |

---

### Asset Methods

#### qubic_getAssetBalance
Returns asset balance for an identity.

**Params:** `[identity, issuer, assetName]`

**Response:**
```json
{
  "result": {
    "identity": "...",
    "issuer": "...",
    "assetName": "QFT",
    "ownershipBalance": "1000000",
    "possessionBalance": "1000000"
  }
}
```

| Ethereum Equivalent |
|---------------------|
| ERC-20 `balanceOf` call |

---

### Transfer History Methods

These methods provide transaction history filtering by identity.

#### qubic_getQuTransfers
Returns QU transfer history for an identity, separated into incoming and outgoing transfers.

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | object | Filter object with `identity`, `fromTick`, `toTick` |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getQuTransfers",
  "params": [{
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "fromTick": 41000000,
    "toTick": 41000100
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": {
    "in": [
      "bxlilwtegxfdwxzrqquxjfsctqqxltxskfexqqdrhrtlfqhvgbxugqrkhbrgsj"
    ],
    "out": [
      "ayrltrgxfdwxzrqquxjfsctqqxltxskfexqqdrhrtlfqhvgbxugqrkhbrgsk"
    ]
  }
}
```

**Constraints:**
- Maximum tick range: 1000 ticks
- Returns transaction hashes (60-char Qubic format)

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` with Transfer event filter for address |

---

#### qubic_getAssetTransfers
Returns asset transfer history for an identity and specific asset.

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | object | Filter object with `identity`, `issuer`, `assetName`, `fromTick`, `toTick` |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getAssetTransfers",
  "params": [{
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "issuer": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFUDG",
    "assetName": "QFT",
    "fromTick": 41000000,
    "toTick": 41000100
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": {
    "in": ["txhash1..."],
    "out": ["txhash2..."]
  }
}
```

**Constraints:**
- Maximum tick range: 1000 ticks
- `assetName` max 7 characters

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` with ERC-20 Transfer event filter |

---

#### qubic_getAllAssetTransfers
Returns all transfers for a specific asset (without identity filter).

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | object | Filter object with `issuer`, `assetName`, `fromTick`, `toTick` |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getAllAssetTransfers",
  "params": [{
    "issuer": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFUDG",
    "assetName": "QFT",
    "fromTick": 41000000,
    "toTick": 41000100
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": [
    "txhash1...",
    "txhash2...",
    "txhash3..."
  ]
}
```

**Constraints:**
- Maximum tick range: 1000 ticks
- Returns array of transaction hashes

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` with ERC-20 Transfer event (all transfers for token) |

---

### Log Methods

#### qubic_getLogs
Returns logs matching filter.

**Params:** Filter object:
```json
{
  "fromTick": "latest",
  "toTick": "latest",
  "identity": ["IDENTITY1...", "IDENTITY2..."],
  "logType": [0, 1, 2]
}
```

**Log Types:**

See the complete log types table in [qubic_getTransfers](#qubic_gettransfers) section above.

**Response:**
```json
{
  "result": [
    {
      "tick": 12500000,
      "epoch": 150,
      "logId": 12345678,
      "logIndex": 0,
      "transactionIndex": 3,
      "logType": 0,
      "logTypeName": "QU_TRANSFER",
      "transactionHash": "...",
      "source": "...",
      "destination": "...",
      "amount": "1000000",
      "rawData": "0x..."
    }
  ]
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` |

---

#### qubic_findLogIds
Returns only log IDs matching filter (same as `/findLog` REST endpoint). Useful for efficiently finding logs before fetching full details.

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | object | Filter object |

**Filter object:**
```json
{
  "scIndex": 0,
  "logType": 0,
  "topic1": "IDENTITY...",
  "topic2": "IDENTITY...",
  "topic3": "IDENTITY...",
  "fromTick": 41000000,
  "toTick": 41000100
}
```

**Required fields:** `scIndex`, `logType`, `fromTick`, `toTick`

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_findLogIds",
  "params": [{
    "scIndex": 0,
    "logType": 0,
    "fromTick": 41000000,
    "toTick": 41000100
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": [1234567890, 1234567891, 1234567892]
}
```

| Ethereum Equivalent |
|---------------------|
| N/A (returns only IDs for efficiency) |

---

#### qubic_getLogsByIdRange
Returns logs by ID range (same as `/log/{epoch}/{from_id}/{to_id}` REST endpoint).

**Parameters:**
| Position | Type | Description |
|----------|------|-------------|
| 0 | number | Epoch number |
| 1 | number | Starting log ID (inclusive) |
| 2 | number | Ending log ID (inclusive) |

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getLogsByIdRange",
  "params": [192, 1000000, 1000010],
  "id": 1
}
```

**Response:**
```json
{
  "result": [
    {
      "tick": 41000000,
      "epoch": 192,
      "logId": 1000000,
      "logType": 0,
      "source": "...",
      "destination": "...",
      "amount": "1000000",
      "txId": "...",
      "txOrderIndex": 0
    }
  ]
}
```

| Ethereum Equivalent |
|---------------------|
| N/A (direct log ID access) |

---

### Smart Contract Methods

#### qubic_querySmartContract

Query a smart contract function. This is an asynchronous operation - the first call enqueues the query, and subsequent calls with the same nonce retrieve the result.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_querySmartContract",
  "params": [{
    "nonce": 12345,
    "scIndex": 1,
    "funcNumber": 1,
    "data": "0x00000000"
  }],
  "id": 1
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nonce` | number | Yes | Unique identifier for this query (used for caching and retrieval) |
| `scIndex` | number | Yes | Smart contract index (1-based) |
| `funcNumber` | number | Yes | Function number to call |
| `data` | string | Yes | Hex-encoded input data (with or without 0x prefix) |

**Response (success - result available):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "nonce": 12345,
    "data": "0102030405060708..."
  },
  "id": 1
}
```

**Response (pending - query enqueued):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "nonce": 12345,
    "pending": true,
    "message": "Query enqueued; poll again with the same nonce to get the result"
  },
  "id": 1
}
```

**Response (error):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "nonce": 12345,
    "error": "Bob has no connection to any BM"
  },
  "id": 1
}
```

**Usage Pattern:**

1. Send initial query with a unique nonce
2. If response contains `pending: true`, poll again with the same nonce
3. Results are cached for ~60 seconds, so use the same nonce to retrieve cached results
4. Use unique nonces for different queries to avoid cache collisions

**Example - Query with polling:**
```javascript
async function querySmartContract(scIndex, funcNumber, inputData) {
  const nonce = Date.now(); // Use timestamp as unique nonce

  let result;
  for (let i = 0; i < 30; i++) { // Poll for up to 3 seconds
    const response = await rpc('qubic_querySmartContract', [{
      nonce,
      scIndex,
      funcNumber,
      data: inputData
    }]);

    if (response.data) {
      return response.data; // Success!
    }

    if (response.error && response.error !== 'pending') {
      throw new Error(response.error);
    }

    // Wait 100ms before next poll
    await new Promise(r => setTimeout(r, 100));
  }

  throw new Error('Query timeout');
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_call` |

---

## Code Examples

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const RPC_URL = 'http://localhost:40420/qubic';

async function rpc(method, params = []) {
  const response = await axios.post(RPC_URL, {
    jsonrpc: '2.0',
    method,
    params,
    id: 1
  });
  return response.data.result;
}

// Get balance
async function getBalance(identity) {
  return await rpc('qubic_getBalance', [identity]);
}

// Get latest tick
async function getLatestTick() {
  return await rpc('qubic_getTickNumber');
}

// Track deposits for an identity
async function trackDeposits(identity, fromTick) {
  const latestTick = await getLatestTick();
  const transfers = await rpc('qubic_getTransfers', [{
    identity: identity,
    fromTick: fromTick.toString(),
    toTick: latestTick.toString()
  }]);

  return transfers.transfers.filter(t => t.direction === 'incoming');
}

// Query smart contract logs with topic filters
async function getSCLogs(scIndex, logType, topic1, fromTick, toTick) {
  return await rpc('qubic_getTransfers', [{
    scIndex: scIndex,
    logType: logType,
    topic1: topic1,
    fromTick: fromTick,
    toTick: toTick
  }]);
}

// Example usage
(async () => {
  const identity = 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID';

  const balance = await getBalance(identity);
  console.log('Balance:', balance.balance);

  const deposits = await trackDeposits(identity, 12490000);
  console.log('Deposits:', deposits);
})();
```

### Python

```python
import requests
import json

RPC_URL = 'http://localhost:40420/qubic'

def rpc(method, params=None):
    payload = {
        'jsonrpc': '2.0',
        'method': method,
        'params': params or [],
        'id': 1
    }
    response = requests.post(RPC_URL, json=payload)
    return response.json()['result']

def get_balance(identity):
    return rpc('qubic_getBalance', [identity])

def get_latest_tick():
    return rpc('qubic_getTickNumber')

def get_transaction_receipt(tx_hash):
    return rpc('qubic_getTransactionReceipt', [tx_hash])

# Example: Track deposits
identity = 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID'
balance = get_balance(identity)
print(f"Balance: {balance['balance']} QU")
print(f"Incoming transfers: {balance['numberOfIncomingTransfers']}")
```

### cURL

```bash
# Get tick number
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'

# Get balance
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getBalance","params":["YOUR_IDENTITY"],"id":1}'

# Get transfers for identity
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTransfers","params":[{"identity":"YOUR_IDENTITY","fromTick":12490000,"toTick":12500000}],"id":1}'

# Get smart contract logs with topic filter
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTransfers","params":[{"scIndex":1,"logType":6,"fromTick":12490000,"toTick":12500000,"topic1":"FILTERIDENTITY..."}],"id":1}'
```

### WebSocket (JavaScript - tickStream)

```javascript
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:40420/ws/qubic');

ws.on('open', () => {
  console.log('Connected to Qubic RPC WebSocket');

  // Subscribe to tickStream with filters
  ws.send(JSON.stringify({
    jsonrpc: '2.0',
    method: 'qubic_subscribe',
    params: ['tickStream', {
      txFilters: [],      // Empty = all transactions
      logFilters: [],     // Empty = all logs
      skipEmptyTicks: false,
      includeInputData: true
    }],
    id: 1
  }));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data);

  // Handle subscription confirmation
  if (msg.id === 1 && msg.result) {
    console.log('Subscribed with ID:', msg.result);
    return;
  }

  // Handle tick stream notifications
  if (msg.method === 'qubic_subscription') {
    const tick = msg.params.result;
    console.log(`Tick ${tick.tick}: ${tick.filteredTxs} txs, ${tick.filteredLogs} logs`);

    // Process transactions
    for (const tx of tick.transactions) {
      console.log(`  TX: ${tx.hash.slice(0, 20)}... ${tx.from.slice(0, 10)} -> ${tx.to.slice(0, 10)} ${tx.amount} QU`);
      if (tx.executed) {
        console.log(`      Executed: logs ${tx.logIdFrom} - ${tx.logIdFrom + tx.logIdLength - 1}`);
      }
    }

    // Process logs
    for (const log of tick.logs) {
      if (log.logType === 0) {  // QU_TRANSFER
        console.log(`  LOG: ${log.source.slice(0, 10)} -> ${log.destination.slice(0, 10)} ${log.amount} QU`);
      }
    }
  }
});

ws.on('close', () => {
  console.log('Disconnected');
});
```

---

## WebSocket Subscriptions

Connect to `ws://your-node:40420/ws/qubic` for real-time updates.

### Available Subscription Types

| Type | Description | Catch-Up Support |
|------|-------------|------------------|
| `newTicks` | New tick notifications | No |
| `logs` | Log events matching filter | Yes (logId-based) |
| `transfers` | QU transfer events (specialized log filter) | Yes (logId-based) |
| `tickStream` | Full tick stream with transactions and logs | Yes (tick-based) |

---

### Subscribe to New Ticks

Subscribe to new tick notifications. This is a lightweight subscription that only sends basic tick metadata.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["newTicks"],
  "id": 1
}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_0","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_0",
    "result": {
      "tickNumber": 42100500,
      "epoch": 193,
      "computorIndex": 500,
      "signature": "0xa1b2c3d4...",
      "tickHash": "0xdeadbeef...",
      "timestamp": 1736860245,
      "timestampISO": "2025-01-14T10:30:45Z",
      "millisecond": 123,
      "timelock": "0x...",
      "transactionCount": 15,
      "previousTickHash": "0x..."
    }
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_subscribe` with `"newHeads"` |

---

### Subscribe to Transfers

Monitor QU transfers for specific identities. This is a specialized log subscription filtered to `QU_TRANSFER` events only.

**Request (basic):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["transfers", {"identity": ["YOUR_IDENTITY"]}],
  "id": 1
}
```

**Request (with catch-up):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["transfers", {
    "identity": ["BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID"],
    "startLogId": 1234567890,
    "startEpoch": 193
  }],
  "id": 1
}
```

**Filter Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `identity` | string or array | Filter by identity (source or destination) |
| `startLogId` | number | Optional. Start log ID for catch-up |
| `startEpoch` | number | Optional. Epoch for startLogId (defaults to current epoch) |

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_1","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_1",
    "result": {
      "ok": true,
      "epoch": 193,
      "tick": 42100500,
      "type": 0,
      "logId": 1234567900,
      "logDigest": "a1b2c3d4e5f60718",
      "bodySize": 72,
      "logTypename": "QU_TRANSFER",
      "timestamp": "25-01-14 10:30:45",
      "txHash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
      "body": {
        "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
        "amount": 5000000
      },
      "isCatchUp": false
    }
  }
}
```

> **Note:** The log format is identical to the `/ws/log` WebSocket endpoint format, making it easy to migrate between endpoints.

**Result Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | Always `true` for valid logs |
| `epoch` | number | Epoch of the log |
| `tick` | number | Tick number |
| `type` | number | Log type (always 0 for transfers) |
| `logId` | number | Unique log ID within the epoch |
| `logDigest` | string | 16-char hex digest of the log |
| `bodySize` | number | Size of log body in bytes |
| `logTypename` | string | Human-readable log type name |
| `timestamp` | string | Timestamp string (YY-MM-DD HH:MM:SS) |
| `txHash` | string | Transaction hash that generated this log |
| `body` | object | Parsed log body (from, to, amount for QU_TRANSFER) |
| `isCatchUp` | boolean | `true` if this is historical data from catch-up |

> **Catch-Up:** When `startLogId` is specified, historical events are replayed with `isCatchUp: true`. A `catchUpComplete` notification is sent when all historical data has been delivered (see [Subscribe to Logs](#subscribe-to-logs) for details).

| Ethereum Equivalent |
|---------------------|
| `eth_subscribe` with `"logs"` and Transfer event filter |

---

### Subscribe to Logs

Subscribe to log events with optional filters. Supports catch-up from a specific log ID.

**Request (basic):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["logs", {
    "identity": ["IDENTITY1...", "IDENTITY2..."],
    "logType": [0, 2]
  }],
  "id": 1
}
```

**Request (with catch-up):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["logs", {
    "identity": ["BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID"],
    "logType": [0, 1, 2],
    "startLogId": 1234567890,
    "startEpoch": 193
  }],
  "id": 1
}
```

**Filter Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `identity` | string or array | Filter by identity (source or destination) |
| `logType` | number or array | Filter by log type(s) |
| `startLogId` | number | Optional. Start log ID for catch-up |
| `startEpoch` | number | Optional. Epoch for startLogId (defaults to current epoch) |

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_2","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_2",
    "result": {
      "ok": true,
      "epoch": 193,
      "tick": 42100500,
      "type": 2,
      "logId": 1234567901,
      "logDigest": "b2c3d4e5f6071829",
      "bodySize": 120,
      "logTypename": "ASSET_OWNERSHIP_CHANGE",
      "timestamp": "25-01-14 10:30:46",
      "txHash": "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi",
      "body": {
        "sourcePublicKey": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "destinationPublicKey": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
        "assetName": "QFT",
        "numberOfShares": 1000
      },
      "isCatchUp": true
    }
  }
}
```

> **Note:** The log format is identical to the `/ws/log` WebSocket endpoint format, making it easy to migrate between endpoints.

**Catch-Up Behavior:**

When `startLogId` is specified:
1. The subscription is created immediately
2. Historical logs from `startLogId` to current are sent with `isCatchUp: true`
3. Real-time logs that arrive during catch-up are queued (up to 10,000 logs)
4. After catch-up completes, queued logs are delivered, then a `catchUpComplete` notification is sent
5. All subsequent events are real-time with `isCatchUp: false`

**Catch-Up Complete Notification:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_2",
    "result": {
      "catchUpComplete": true
    }
  }
}
```

**Queue Mode:**
- If the client is more than 10,000 logs behind, real-time logs are skipped (not queued) to prevent memory exhaustion
- Once within 10,000 logs of current, real-time logs start being queued
- This ensures efficient catch-up without unbounded memory growth

| Ethereum Equivalent |
|---------------------|
| `eth_subscribe` with `"logs"` |

---

### Subscribe to Tick Stream

The `tickStream` subscription provides a comprehensive real-time stream of ticks with full transaction and log data.

**newTicks vs tickStream Comparison:**

| Aspect | `newTicks` | `tickStream` |
|--------|-----------|--------------|
| **Purpose** | Lightweight tick notification | Comprehensive tick data stream |
| **Data included** | Basic tick metadata only | Full transactions + logs |
| **Filtering** | None | Transaction and log filters |
| **Catch-up** | No | Yes (via `startTick`) |
| **Use case** | Know when new tick arrives | Process all chain activity |

**When to use which:**

- **Use `newTicks`** when you just need to know a tick happened and will fetch specific data via HTTP calls afterward, or when you want minimal bandwidth.
- **Use `tickStream`** when you need all transactions and logs in real-time, are building an explorer or indexer, need transaction execution status immediately, or want historical data via catch-up.

This is ideal for:
- Building real-time block explorers
- Monitoring all chain activity
- Syncing external systems with the chain

**Request (basic - all ticks with all data):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["tickStream", {}],
  "id": 1
}
```

**Request (with filters):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["tickStream", {
    "txFilters": [
      {
        "from": "SOURCEIDENTITY...",
        "to": "DESTIDENTITY...",
        "minAmount": 1000000,
        "inputType": 0
      }
    ],
    "logFilters": [
      {
        "scIndex": 0,
        "logType": 0,
        "transferMinAmount": 1000000
      }
    ],
    "startTick": 12490000,
    "skipEmptyTicks": false,
    "includeInputData": true
  }],
  "id": 1
}
```

**Filter Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `txFilters` | array | `[]` | Transaction filters (empty = all transactions) |
| `logFilters` | array | `[]` | Log filters (empty = all logs) |
| `startTick` | number | `0` | Start tick for catch-up (0 = current tick only) |
| `skipEmptyTicks` | boolean | `false` | Skip ticks with no matching data (heartbeat every 120 ticks) |
| `includeInputData` | boolean | `true` | Include full inputData hex in transactions |

**Transaction Filter Fields (`txFilters`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `from` | string | `""` | Source identity filter (empty = any) |
| `to` | string | `""` | Destination identity filter (empty = any) |
| `minAmount` | number | `0` | Minimum transfer amount |
| `inputType` | number | `-1` | Input type filter (-1 = any, 0 = basic transfer, >0 = SC call) |

**Log Filter Fields (`logFilters`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scIndex` | number | `0` | Smart contract index (0 = protocol logs) |
| `logType` | number | `0` | Log type filter |
| `transferMinAmount` | number | `0` | Minimum amount for QU_TRANSFER events |

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_1","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_3",
    "result": {
      "tick": 42100500,
      "epoch": 193,
      "isCatchUp": false,
      "timestamp": "2025-01-14T10:30:45Z",
      "totalTxs": 15,
      "filteredTxs": 3,
      "totalLogs": 42,
      "filteredLogs": 5,
      "transactions": [
        {
          "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
          "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
          "amount": 5000000,
          "inputType": 0,
          "inputSize": 0,
          "inputData": "",
          "executed": true,
          "logIdFrom": 1234567900,
          "logIdLength": 1
        },
        {
          "hash": "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi",
          "from": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
          "to": "CFBMEMZOIDEXQAUXYYSZIURADQLAPWPMNJXQSNVQJADFYLJCRRTFPBQGIM",
          "amount": 1000000,
          "inputType": 1,
          "inputSize": 32,
          "inputData": "0x0102030405060708091011121314151617181920212223242526272829303132",
          "executed": true,
          "logIdFrom": 1234567901,
          "logIdLength": 2
        },
        {
          "hash": "cdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij",
          "from": "DDDIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "to": "EEEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "amount": 100,
          "inputType": 0,
          "inputSize": 0,
          "inputData": "",
          "executed": false,
          "logIdFrom": -1,
          "logIdLength": 0
        }
      ],
      "logs": [
        {
          "ok": true,
          "epoch": 193,
          "tick": 42100500,
          "type": 0,
          "logId": 1234567900,
          "logDigest": "a1b2c3d4e5f60718",
          "bodySize": 72,
          "logTypename": "QU_TRANSFER",
          "timestamp": "25-01-14 10:30:45",
          "txHash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
          "txIndex": 0,
          "body": {
            "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
            "amount": 5000000
          }
        },
        {
          "ok": true,
          "epoch": 193,
          "tick": 42100500,
          "type": 0,
          "logId": 1234567901,
          "logDigest": "b2c3d4e5f6071829",
          "bodySize": 72,
          "logTypename": "QU_TRANSFER",
          "timestamp": "25-01-14 10:30:45",
          "txHash": "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi",
          "txIndex": 1,
          "body": {
            "from": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
            "to": "CFBMEMZOIDEXQAUXYYSZIURADQLAPWPMNJXQSNVQJADFYLJCRRTFPBQGIM",
            "amount": 1000000
          }
        }
      ]
    }
  }
}
```

**Empty Tick Notification (when `skipEmptyTicks: false`):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_3",
    "result": {
      "tick": 42100501,
      "epoch": 193,
      "isCatchUp": false,
      "timestamp": "2025-01-14T10:30:46Z",
      "totalTxs": 0,
      "filteredTxs": 0,
      "totalLogs": 0,
      "filteredLogs": 0,
      "transactions": [],
      "logs": []
    }
  }
}
```

**Result Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `epoch` | number | Current epoch |
| `tick` | number | Tick number |
| `isCatchUp` | boolean | `true` if this is historical data from catch-up |
| `timestamp` | string | ISO 8601 timestamp of the tick |
| `totalLogs` | number | Total logs in tick (before filtering) |
| `filteredLogs` | number | Number of logs matching filter |
| `totalTxs` | number | Total transactions in tick (before filtering) |
| `filteredTxs` | number | Number of transactions matching filter |
| `transactions` | array | Filtered transactions |
| `logs` | array | Filtered logs |

**Transaction Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `hash` | string | 60-char transaction hash (lowercase) |
| `from` | string | Source identity |
| `to` | string | Destination identity |
| `amount` | number | Transfer amount in QU |
| `inputType` | number | Transaction type (0=transfer, >0=SC call) |
| `inputSize` | number | Size of input data in bytes |
| `inputData` | string | Hex-encoded input data (if `includeInputData` is true) |
| `executed` | boolean | Whether the transaction was executed |
| `logIdFrom` | number | Starting log ID for this transaction (-1 if no logs) |
| `logIdLength` | number | Number of logs generated by this transaction |

**Catch-Up Behavior:**

When `startTick` is specified and is less than the current tick:
1. The subscription is created immediately
2. Historical ticks from `startTick` to current are sent with `isCatchUp: true`
3. Real-time ticks that arrive during catch-up are queued and delivered in order
4. After catch-up completes, a `catchUpComplete` notification is sent
5. All subsequent ticks are real-time with `isCatchUp: false`

**Catch-Up Complete Notification:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_3",
    "result": {
      "catchUpComplete": true
    }
  }
}
```

**Heartbeat Ticks:**

When `skipEmptyTicks` is `true`, ticks with no matching transactions or logs are skipped. However, every 120th tick is always sent as a heartbeat to confirm the connection is alive.

---

### Unsubscribe

Cancel an active subscription.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_unsubscribe",
  "params": ["qubic_sub_0"],
  "id": 1
}
```

**Response (success):**
```json
{"jsonrpc":"2.0","result":true,"id":1}
```

**Response (not found):**
```json
{"jsonrpc":"2.0","result":false,"id":1}
```

| Ethereum Equivalent |
|---------------------|
| `eth_unsubscribe` |

---

## Method Mapping Quick Reference

| Ethereum Method | Qubic Method |
|-----------------|--------------|
| `eth_chainId` | `qubic_chainId` |
| `web3_clientVersion` | `qubic_clientVersion` |
| `eth_syncing` | `qubic_syncing` |
| `eth_blockNumber` | `qubic_getTickNumber` |
| `eth_getBlockByNumber` | `qubic_getTickByNumber` |
| `eth_getBlockByHash` | `qubic_getTickByHash` (disabled) |
| `eth_getTransactionByHash` | `qubic_getTransactionByHash` |
| `eth_getTransactionReceipt` | `qubic_getTransactionReceipt` |
| `eth_getBalance` | `qubic_getBalance` |
| `eth_getLogs` | `qubic_getLogs` |
| `eth_subscribe("newHeads")` | `qubic_subscribe("newTicks")` |
| `eth_subscribe("logs")` | `qubic_subscribe("logs")` |
| N/A | `qubic_subscribe("transfers")` |
| N/A | `qubic_subscribe("tickStream")` |
| `eth_unsubscribe` | `qubic_unsubscribe` |
| N/A | `qubic_status` |
| N/A | `qubic_getCurrentEpoch` |
| N/A | `qubic_getEpochInfo` |
| N/A | `qubic_getEndEpochLogs` |
| N/A | `qubic_getTransfers` |
| N/A | `qubic_findLogIds` |
| N/A | `qubic_getLogsByIdRange` |
| N/A | `qubic_getQuTransfers` |
| N/A | `qubic_getAssetTransfers` |
| N/A | `qubic_getAllAssetTransfers` |
| N/A | `qubic_getAssetBalance` |
| N/A | `qubic_getAssets` (not implemented) |
| `eth_sendRawTransaction` | `qubic_broadcastTransaction` |
| `eth_call` | `qubic_querySmartContract` |

---

## Error Codes

Standard JSON-RPC 2.0 error codes:

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Missing required fields |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Wrong parameter types |
| -32603 | Internal error | Server error |
| -32001 | Resource not found | Tick/transaction not found |
| -32002 | Resource unavailable | Node not synced |
| -32005 | Limit exceeded | Query range too large |

---

## Best Practices for Exchanges (Qubic, Qu)

1. **Track deposits by identity**: Use `qubic_getTransfers` with your deposit addresses, logType `QU_TRANSFER`
2. **Poll vs subscribe**: Use WebSocket subscriptions for real-time, HTTP for historical
3. **Real-time streaming**: Use `tickStream` subscription for comprehensive real-time chain monitoring with transaction execution status
4. **Resumable subscriptions**: Use `startLogId` parameter with `logs` or `transfers` subscriptions to resume from a known position after reconnection
5. **No confirmations needed**: Qubic ticks are immediately final
6. **Epoch awareness**: Balance/state resets at epoch boundaries; catch-up requires correct `startEpoch` parameter
7. **Rate limiting**: Limit log queries to 1000 ticks max per request
8. **Identity validation**: Verify identities (60 uppercase characters; checksum)
9. **Transaction execution**: Check `executed` field in tickStream transactions to verify successful execution
10. **Catch-up awareness**: Check `isCatchUp` field in subscription notifications to distinguish historical from real-time data
