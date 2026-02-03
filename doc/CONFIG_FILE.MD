# Configuration Reference

This document describes the JSON configuration consumed by the application. It covers required and optional fields, types, defaults, validation rules, and how different options interact.

The configuration must be a single JSON object (root must be an object). Invalid JSON or incorrect types produce descriptive errors.

## Quick Start

- The root must be a JSON object.
- You must provide:
    - arbitrator-identity (string)
    - At least one of trusted-node (array of strings) or p2p-node (array of strings) must be present and non-empty.
- Other fields are optional and have sensible defaults (where applicable).

## Keys Overview

- Networking and peers
    - trusted-node: array of strings (optional, but at least one of this or p2p-node required)
    - p2p-node: array of strings (optional, but at least one of this or trusted-node required)
    - server-port: unsigned integer (optional)
    - is-trusted-node: boolean (optional)
    - node-seed: string (optional)
- Identity and trust
    - arbitrator-identity: string (required)
    - trusted-entities: array of uppercase 60-char strings (optional, strict validation)
- Execution and threading
    - max-thread: unsigned integer (optional; 0 means auto/unlimited)
- Logging and diagnostics
    - log-level: string (optional)
    - request-cycle-ms: unsigned integer (optional)
    - request-logging-cycle-ms: unsigned integer (optional)
    - spam-qu-threshold: unsigned integer (optional; default 0)
- Environment
    - is-testnet: boolean (optional)
    - keydb-url: string (optional)
- Tick storage
    - tick-storage-mode: string, one of "lastNTick", "kvrocks", "free" (optional; default "lastNTick")
    - last_n_tick_storage: unsigned integer (only for "lastNTick"; default 1000)
    - kvrocks-url: string (only for "kvrocks"; default "tcp://127.0.0.1:6666")

## Detailed Field Reference

### trusted-node
- Type: array of strings
- Required: No (but see rule below)
- Validation: Must be an array; each element must be a string.
- Notes: At least one of trusted-node or p2p-node must be present and have at least one element.

### p2p-node
- Type: array of strings
- Required: No (but see rule below)
- Validation: Must be an array; each element must be a string.
- Rule: At least one of trusted-node or p2p-node must be present and non-empty.

If both arrays are absent or empty, configuration is rejected with: “Either 'trusted-node' or 'p2p-node' array is required”.

### arbitrator-identity
- Type: string
- Required: Yes
- Validation: Must be a string (non-empty recommended).
- Error if missing: “string required for key 'arbitrator-identity'”.

### log-level
- Type: string
- Required: No

### keydb-url
- Type: string
- Required: No

### run-server
- Type: boolean
- Required: No

### is-testnet
- Type: boolean
- Required: No

### request-cycle-ms
- Type: unsigned integer
- Required: No
- Validation:
    - Accepts non-negative integers.
    - If provided as a signed integer, it must be >= 0.

### request-logging-cycle-ms
- Type: unsigned integer
- Required: No
- Validation: Same as request-cycle-ms.

### future-offset
- Type: unsigned integer
- Required: No
- Validation: Same as request-cycle-ms.

### server-port
- Type: unsigned integer
- Required: No
- Validation: Same as request-cycle-ms.

### max-thread
- Type: unsigned integer
- Required: No
- Meaning: Maximum threads the system can use.
- Special: 0 means auto/unlimited.

### spam-qu-threshold
- Type: unsigned integer
- Required: No
- Default: 0
- Meaning: Threshold for spam/junk QU transfer detection.

### is-trusted-node
- Type: boolean
- Required: No

### node-seed
- Type: string
- Required: No

### trusted-entities
- Type: array of strings
- Required: No
- Validation for each element:
    - Must be a string of exactly 60 characters.
    - All characters must be uppercase letters A–Z.
- Notes: Each valid identity is transformed to a public key and stored internally in a trusted map.

### tick-storage-mode
- Type: string
- Required: No
- Allowed values: "lastNTick", "kvrocks", "free"
- Default: "lastNTick"
- Behavior and related fields:
    - "lastNTick"
        - last_n_tick_storage (unsigned integer)
            - Required: No
            - Default: 1000 (if not previously set or set to zero)
            - Validation: Must be a non-negative integer.
    - "kvrocks"
        - kvrocks-url (string)
            - Required: No
            - Default: "tcp://127.0.0.1:6666" (if absent or empty)
    - "free"
        - No related options. Implies no garbage cleaner.
- Error if value is not one of the allowed: “Invalid value for 'tick-storage-mode': must be one of 'lastNTick', 'kvrocks', or 'free'”.

## Type and Range Rules

- Unsigned integer fields accept:
    - JSON unsigned numbers
    - JSON signed numbers if >= 0
    - Negative values are rejected with a specific error.
- Booleans must be JSON booleans (true/false), not strings.
- Strings must be JSON strings.
- Arrays must be JSON arrays containing elements of the documented type.

## Error Conditions Summary

- File cannot be opened: “cannot open file”
- JSON parse error: “invalid JSON: …”
- Root is not an object: “invalid JSON: root must be an object”
- Missing arbitrator-identity: “string required for key 'arbitrator-identity'”
- Both trusted-node and p2p-node absent or empty: “Either 'trusted-node' or 'p2p-node' array is required”
- Type mismatches: “Invalid type: … required for key '…'”
- Negative integer for unsigned fields: “Negative integer is invalid for key '…'”
- trusted-entities element length not 60: “Invalid trusted entity ID length: must be 60 characters”
- trusted-entities element not uppercase A–Z: “Invalid trusted entity ID format: must be uppercase letters only”
- tick-storage-mode invalid value: “Invalid value for 'tick-storage-mode': must be one of 'lastNTick', 'kvrocks', or 'free'”

## Minimal Example

~~~json
{
  "arbitrator-identity": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "trusted-node": ["node1.example.org:1234"]
}
~~~

- Provides required arbitrator-identity and at least one of the peer lists.

## Full Example

~~~json
{
  "arbitrator-identity": "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZAB",
  "trusted-node": ["node1.example.org:1234", "node2.example.org:5678"],
  "p2p-node": ["p2p1.example.org:7000"],
  "log-level": "info",
  "keydb-url": "redis://localhost:6379/0",
  "run-server": true,
  "is-testnet": false,
  "request-cycle-ms": 100,
  "request-logging-cycle-ms": 1000,
  "future-offset": 50,
  "server-port": 8080,
  "max-thread": 0,
  "spam-qu-threshold": 0,
  "is-trusted-node": false,
  "node-seed": "some-seed-string",
  "trusted-entities": [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZAB",
    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
  ],
  "tick-storage-mode": "kvrocks",
  "kvrocks-url": "tcp://127.0.0.1:6666"
}
~~~