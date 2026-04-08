# Qubic Network REST API

This document describes the REST endpoints exposed by the server.

Base URL
- Host: 0.0.0.0
- Port: 40420
- Base: http://HOST:40420

General
- All responses are application/json.
- Errors are returned as JSON with fields:
  - ok: false
  - error: string message
- Numeric parameters using unsigned 32-bit range must be within 0..4294967295.
- Hex string parameters:
  - Optional 0x or 0X prefix is accepted.
  - Must contain only 0-9, a-f, A-F.
  - Must have even length after removing optional prefix.

----------------------------------------------------------------

GET /balance/{identity}
- Description: Returns balance information for the provided identity.
- Path parameters:
  - identity: string
- Responses:
  - 200: JSON body (format depends on backend)
  - 500: error JSON if an internal error occurs

----------------------------------------------------------------

GET /asset/{identity}/{issuer}/{asset_name}/{manageSCIndex}
- Description: Returns information about a specific asset for an identity and issuer.
- Path parameters:
  - identity: string
  - issuer: string
  - asset_name: string
  - manageSCIndex: [1..1024]
- Validation:
  - manageSCIndex must be an integer and within uint32 range
- Responses:
  - 200: JSON body (format depends on backend)
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
  - 200: JSON body (format depends on backend)
  - 400: error JSON if epoch is invalid or out of range
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /tx/{tx_hash}
- Description: Returns transaction details by transaction hash.
- Path parameters:
  - tx_hash: string
- Responses:
  - 200: JSON body (format depends on backend)
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
  - 200: JSON body (format depends on backend)
  - 400: error JSON for invalid input or ranges
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /tick/{tick_number}
- Description: Returns information for a specific tick.
- Path parameters:
  - tick_number: unsigned 32-bit integer range (0..4294967295)
- Validation:
  - tick_number must be an integer and within uint32 range
- Responses:
  - 200: JSON body (format depends on backend)
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
  - topic1, topic2, topic3 must be strings and present
  - fromTick must be less than or equal to toTick
- Responses:
  - 200: JSON result from the search
  - 400: error JSON for invalid or missing fields
  - 500: error JSON on internal error

----------------------------------------------------------------

POST /getlogcustom
- Description: Retrieves a custom log for a given epoch and tick.
- Request body (JSON):
  - epoch: uint32
  - tick: uint32
  - scIndex: uint32
  - logType: uint32
  - topic1: string (required)
  - topic2: string (required)
  - topic3: string (required)
- Validation:
  - All numeric fields must be within uint32
  - topic1, topic2, topic3 must be strings and present
- Responses:
  - 200: JSON result
  - 400: error JSON for invalid or missing fields
  - 500: error JSON on internal error

----------------------------------------------------------------

GET /status
- Description: Returns node status information.
- Responses:
  - 200: JSON body with status details
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
  - The server checks asynchronously for up to about 100ms for a ready response.
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
  - 200: JSON body with broadcast result (format depends on backend)
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
  - 200: JSON result (format depends on backend)
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
  - 200: JSON result (format depends on backend)
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
  - 200: JSON result (format depends on backend)
  - 400: error JSON for invalid JSON or missing required fields
  - 500: error JSON on internal error

### Example

```bash
curl -sS http://HOST:40420/getAllAssetTransfers \
-H "Content-Type: application/json" \
-d '{"fromTick":1000000,"toTick":1000100,"assetIssuer":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFXIB","assetName":"MYASSET"}'
```

----------------------------------------------------------------

HTTP Status Codes
- 200 OK: Successful request with JSON payload.
- 202 Accepted: Request accepted and pending (used by querySmartContract when result not ready).
- 400 Bad Request: Validation errors or malformed input.
- 500 Internal Server Error: Unexpected server-side error.

Content Types
- Requests: For POST endpoints, send Content-Type: application/json.
- Responses: application/json for all endpoints.

Timeouts and Connection Behavior
- Short-polling pattern on querySmartContract:
  - The server attempts to return the result within roughly 100ms. If not ready, it returns 202 with a pending message and may close the connection. Clients should retry with the same nonce until a 200 response with data is received.
