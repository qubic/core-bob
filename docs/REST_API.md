# Qubic BOB Network REST API

This document describes the REST endpoints exposed by the server.

Base URL
- Host: 1.2.3.4
- Port: 40420
- Base: http://HOST:40420

General
- All responses are application/json.
- Errors are returned as JSON with fields:
  - ok: false
  - error: string message
- Exception: some failures detected after input validation return HTTP 200 with only `{"error": "..."}` (no `ok` field), e.g. `/balance` and `/tx` not found, `/log` negative range or batch > 500000, and the transfer endpoints when `toTick < fromTick`, `toTick - fromTick >= 1000`, or identity/assetName length is invalid.
- Numeric parameters using unsigned 32-bit range must be within 0..4294967295.
- Hex string parameters:
  - Optional 0x or 0X prefix is accepted.
  - Must contain only 0-9, a-f, A-F.
  - Must have even length after removing optional prefix.

## Response Data Structures

The following JSON bodies are returned by the endpoints below (field names as sent on the wire):

### BalanceInfo (`GET /balance`)
```json
{
    "incomingAmount": 0,
    "outgoingAmount": 0,
    "balance": 0,
    "numberOfIncomingTransfers": 0,
    "numberOfOutgoingTransfers": 0,
    "latestIncomingTransferTick": 0,
    "latestOutgoingTransferTick": 0,
    "currentBobTick": 0,
    "error": "null"
}
```
- `error` is the string `"null"` normally; it carries a message when the entity is still being processed (`currentBobTick` < latest transfer tick).
- Invalid or unknown identity: HTTP 200 with `{"error": "Wrong identity format"}` or `{"error": "Identity not found in spectrum"}`.

### AssetBalanceInfo (`GET /asset`)
```json
{
    "ownershipBalance": 0,
    "possessionBalance": 0
}
```
- Each balance is `-1` when the matching ownership/possession record is not found.

### TransactionInfo (`GET /tx`)
```json
{
    "hash": "",
    "from": "",
    "to": "",
    "amount": 0,
    "tick": 0,
    "logIdFrom": -1,
    "logIdTo": -1,
    "transactionIndex": -1,
    "executed": false,
    "status": "success",
    "timestamp": 0,
    "inputSize": 0,
    "inputType": 0,
    "inputData": ""
}
```
- `status` is `"pending"`, `"success"` or `"failed"`; `executed` is `null` while pending.
- If the tick is not yet indexed, only `hash`, `from`, `to`, `amount`, `tick`, `inputSize`, `inputType`, `inputData` are returned.
- Not found: HTTP 200 with `{"error": "..."}`.

### EpochInfo (`GET /epochinfo`)
```json
{
    "epoch": 0,
    "initialTick": 0,
    "endTick": 0,
    "endTickStartLogId": -1,
    "endTickEndLogId": -3,
    "lastIndexedTick": 0,
    "latestLogId": -1
}
```
- When the end-epoch log range is not available, `endTickStartLogId` is `-1` and `endTickEndLogId` is `-3`.

### SyncStatus (`GET /status`)
```json
{
    "currentProcessingEpoch": 0,
    "currentFetchingTick": 0,
    "currentFetchingLogTick": 0,
    "currentVerifyLoggingTick": 0,
    "currentIndexingTick": 0,
    "initialTick": 0,
    "targetTickVoteSignature": 613566,
    "computorListSignature": 14237492837401234567,
    "computorPacketSignature": 14237492837401234567,
    "bobVersion": "",
    "bobVersionGitHash": "",
    "bobCompiler": "",
    "extraInfo": {}
}
```
- `extraInfo` is a signed node-info object (`type`, `version`, `alias`, `uptime`, `timestamp`, `operator`, `messageHex`, `signature`); optional query `?challenge=<32 hex chars>` is included in the signed message.

Signature-related fields (also returned by `GET /status` and `qubic_syncing`):

| Field | Type | Description |
|-------|------|-------------|
| `targetTickVoteSignature` | uint32 | Vote signature-score difficulty threshold bob uses to filter tick votes (higher score = rejected as low-difficulty). Fixed constant. |
| `computorListSignature` | uint64 | Identifier of the current computor-list packet: the first 8 bytes of the arbitrator signature over the `Computors` struct, as a little-endian uint64. Changes when the computor list changes (detect mid-epoch updates). |
| `computorPacketSignature` | uint64 | Alias of `computorListSignature` (same value). |

> The full 64-byte arbitrator signature is available via the `qubic_getComputors` JSON-RPC method (`signature` field).

### BroadcastResult (`POST /broadcastTransaction`)
```json
{
    "txHash": ""
}
```

----------------------------------------------------------------

GET /balance/{identity}
- Description: Returns balance information for the provided identity.
- Path parameters:
  - identity: string
- Responses:
  - 200: JSON body containing BalanceInfo structure
  - 500: error JSON if an internal error occurs

----------------------------------------------------------------

GET /asset/{identity}/{issuer}/{asset_name}/{manageSCIndex}
- Description: Returns information about a specific asset for an identity and issuer.
- Path parameters:
  - identity: string
  - issuer: string
  - asset_name: string
  - manageSCIndex: uint32 managing contract index (0 is valid; e.g. 1 = QX)
- Validation:
  - manageSCIndex must be an integer and within uint32 range
- Responses:
  - 200: JSON body containing AssetBalanceInfo structure
  - 400: error JSON if manageSCIndex is invalid or out of range
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /epochinfo/{epoch}
- Description: Returns information about the specified epoch.
- Path parameters:
  - epoch: integer (uint16 range recommended)
- Validation:
  - epoch must be an integer and within valid range
- Responses:
  - 200: JSON body containing EpochInfo structure
  - 400: error JSON if epoch is invalid or out of range
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /tx/{tx_hash}
- Description: Returns transaction details by transaction hash.
- Path parameters:
  - tx_hash: string
- Responses:
  - 200: JSON body containing TransactionInfo structure
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /log/{epoch}/{from_id}/{to_id}
- Description: Returns log entries for a given epoch and id range.
- Path parameters:
  - epoch: integer (uint16 range recommended)
  - from_id: integer (64-bit signed)
  - to_id: integer (64-bit signed)
- Validation:
  - from_id and to_id must be integers
  - to_id must be greater than or equal to from_id
- Responses:
  - 200: JSON array of log event objects (missing IDs appear as `{"ok":false,"error":"not_found",...}`); negative range or batch > 500000 returns 200 with `{"error": "..."}`
  - 400: error JSON for invalid input or ranges
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /tick/{tick_number}
- Description: Returns information for a specific tick, including tick data, transactions, and the computor `votes[]` for the tick.
- Path parameters:
  - tick_number: unsigned 32-bit integer range (0..4294967295)
- Validation:
  - tick_number must be an integer and within uint32 range
- Responses:
  - 200: JSON body with tick data. The `votes[]` array contains each computor vote with: `computorIndex`, `epoch`, `tick`, timestamp fields, `prevResourceTestingDigest`, `saltedResourceTestingDigest`, `prevTransactionBodyDigest`, `saltedTransactionBodyDigest`, the prev/salted spectrum/universe/computer digests, `transactionDigest`, `expectedNextTickTransactionDigest`, and the raw `signature` (hex). A vote's signature score is filtered against `targetTickVoteSignature` (see `/status`).
  - 400: error JSON for invalid input or ranges
  - 500: error JSON on internal error

----------------------------------------------------------------

POST /findLog
- Description: Searches for logs matching topics and criteria in a tick window.
- Request body (JSON):
  - fromTick: uint32
  - toTick: uint32
  - scIndex: uint32
  - logType: uint32
  - topic1: string (required)
  - topic2: string (required)
  - topic3: string (required)
- Validation:
  - All numeric fields must be within uint32
  - topic1, topic2, topic3 must be strings and present; each must be a 60-char Qubic identity (any case), a 0x-prefixed 66-char hex public key, or a 64-char hex public key (empty is rejected; use `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB` as wildcard)
  - fromTick must be less than or equal to toTick
- Responses:
  - 200: JSON array of matching tick numbers, e.g. `[51000003, 51000042]`
  - 400: error JSON for invalid or missing fields
  - 500: error JSON on internal error

----------------------------------------------------------------

POST /getlogcustom
- Description: Retrieves logs for a given epoch and a single tick or tick range, filtered by scIndex/logType and optional topics.
- Request body (JSON):
  - epoch: uint32 (required)
  - scIndex: uint32 (required)
  - logType: uint32 (required)
  - tick: uint32 (single tick), OR
  - startTick + endTick: uint32 (inclusive range; endTick is clamped to startTick + 1000)
  - topic1, topic2, topic3: string (optional; omitted = wildcard)
- Validation:
  - All numeric fields must be within uint32
  - Either tick or both startTick and endTick must be present
  - A present topic must be a 60-char Qubic identity, a 0x-prefixed hex public key, or a 64-char hex public key
- Responses:
  - 200: JSON array of log event objects
  - 400: error JSON for invalid or missing fields
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /status
- Description: Returns node status information.
- Responses:
  - 200: JSON body with SyncStatus structure
  - 500: error JSON on internal error

----------------------------------------------------------------

POST /querySmartContract
- Description: Sends a smart contract query. The server will try to return a cached or completed result immediately; otherwise it enqueues the request and returns a pending response. The client should retry with the same nonce until data is returned.
- Request body (JSON):
  - nonce: uint32 (note: transmitted as unsigned 64 in JSON but constrained to uint32)
  - scIndex: uint32
  - funcNumber: uint32
  - data: hex string (optional 0x/0X prefix accepted; even length; hex only)
- Behavior:
  - The request is enqueued for processing.
  - The server polls for a ready response every 100ms, up to 20 times (about 2s), before returning 202.
- Responses:
  - 200: JSON with fields:
    - nonce: uint32
    - data: hex string of the response payload (no 0x prefix)
  - 202: JSON pending response if not ready within the short wait window:
    - error: "pending"
    - message: "Query enqueued; try again with the same nonce"
    - nonce: uint32
    - Connection may be closed after this response.
  - 400: error JSON for invalid inputs (e.g., non-hex data, odd-length hex)
  - 500: error JSON on internal error

Notes on data validation for this endpoint:
- data must be a valid hex string after removing optional 0x/0X prefix.
- data length must be even.
- nonce, scIndex, funcNumber must be within uint32 ranges.

----------------------------------------------------------------

POST /broadcastTransaction
- Description: Broadcasts a signed transaction to the network.
- Request body (JSON):
  - data: hex string containing the transaction payload (optional 0x/0X prefix accepted; even length; hex only)
- Validation:
  - data must be hex and even-length after removing optional prefix
- Responses:
  - 200: JSON body with BroadcastResult structure
  - 400: error JSON for invalid hex payload
  - 500: error JSON on internal error

## POST /getQuTransfersForIdentity

- Description: Returns QU (native token) transfer events involving a specific identity, within a tick range.
- Request body (JSON):
  - fromTick: uint32 (inclusive)
  - toTick: uint32 (inclusive)
  - identity: string
- Validation:
  - Request body must be valid JSON.
  - Required fields: fromTick, toTick, identity.
- Responses:
  - 200: `{"in": [txHash...], "out": [txHash...]}`
  - 400: error JSON for invalid JSON or missing required fields
  - 500: error JSON on internal error

### Example

```bash
curl -sS http://HOST:40420/getQuTransfersForIdentity \
-H "Content-Type: application/json" \
-d '{"fromTick":1000000,"toTick":1000100,"identity":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB"}'
```

---

## POST /getAssetTransfersForIdentity

- Description: Returns asset transfer events involving a specific identity (filtered by asset issuer + asset name), within a tick range.
- Request body (JSON):
  - fromTick: uint32 (inclusive)
  - toTick: uint32 (inclusive)
  - identity: string
  - assetIssuer: string
  - assetName: string
- Validation:
  - Request body must be valid JSON.
  - Required fields: fromTick, toTick, identity, assetIssuer, assetName.
- Responses:
  - 200: `{"in": [txHash...], "out": [txHash...]}`
  - 400: error JSON for invalid JSON or missing required fields
  - 500: error JSON on internal error

### Example

```bash
curl -sS http://HOST:40420/getAssetTransfersForIdentity \
-H "Content-Type: application/json" \
-d '{"fromTick":1000000,"toTick":1000100,"identity":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB","assetIssuer":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFXIB","assetName":"MYASSET"}'
```

---

## POST /getAllAssetTransfers

- Description: Returns all transfer events for a specific asset (filtered by asset issuer + asset name), within a tick range (not restricted to a single identity).
- Request body (JSON):
  - fromTick: uint32 (inclusive)
  - toTick: uint32 (inclusive)
  - assetIssuer: string
  - assetName: string
- Validation:
  - Request body must be valid JSON.
  - Required fields: fromTick, toTick, assetIssuer, assetName.
- Responses:
  - 200: JSON array of txHash strings
  - 400: error JSON for invalid JSON or missing required fields
  - 500: error JSON on internal error

### Example

```bash
curl -sS http://HOST:40420/getAllAssetTransfers \
-H "Content-Type: application/json" \
-d '{"fromTick":1000000,"toTick":1000100,"assetIssuer":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFXIB","assetName":"MYASSET"}'
```

## JSON-RPC Interface

The Qubic API also provides a JSON-RPC 2.0 interface accessible via HTTP and WebSocket connections. This interface supports all REST endpoints through equivalent methods with better parameter validation and enhanced functionality. 

[JSON-RPC document](QUBIC_JSON_RPC.md)