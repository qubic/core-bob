## Qubic API: POST /findLog

### Overview

The `GET /findLog` endpoint is a powerful search feature that allows you to find all ticks within a specified range that contain log entries matching a specific filter.

Instead of iterating through every tick, you provide a tick range and filter criteria. The API returns a list of only the tick numbers that satisfy your filter, which you can then query individually for full details. This dramatically reduces server overhead and improves efficiency.

### Endpoint
`POST /findLog`

### Request Body

* `fromTick`: The starting tick number for the search range.
* `toTick`: The ending tick number for the search range.
* `scIndex`: The smart contract index.
    * Use `0` to search for protocol/system events, such as `QU_TRANSFER` and asset transfers.
* `logType`: The specific type of log to filter for.
    * For example, `0` may correspond to a `QU_TRANSFER` event. (Note: A full list of log types will be documented separately).
* `topic1`: The first topic filter.
* `topic2`: The second topic filter.
* `topic3`: The third topic filter.

> **Topic Filtering for System Events (scIndex = 0)**
>
> When searching for system events (`scIndex = 0`), the topics generally map as follows:
> * `topic1`: Source Address
> * `topic2`: Destination Address
> * `topic3`: Extra Info

> **Using a Wildcard ("null") Filter**
>
> To match *any* value for a topic parameter, use the "null" identity:
> `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib`

### Recommended Workflow

1.  Call `POST /findLog` with your desired range and filters to retrieve a list of matching tick numbers.
2.  For each tick number returned, call `GET /tick/{tick_number}` to fetch all transaction hashes for that specific tick.
3.  Process the logs from those transactions as needed.

### Example: Find all `QU_TRANSFER` events to QSWAP

This example searches for all ticks between `35917281` and `35918281` that contain a `QU_TRANSFER` log event sent *to* the QSWAP address.

#### Request

curl -s -X POST '91.99.221.77:40420/findLog' \
  -H 'Content-Type: application/json' \
  -d '{
    "fromTick": 35917281,
    "toTick": 35918281,
    "scIndex": 0,
    "logType": 0,
    "topic1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib",
    "topic2": "naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaamaml",
    "topic3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib"
  }'

#### Parameter Breakdown

* `fromTick`: `35917281`
* `toTick`: `35918281`
* `scIndex`: `0` (We are searching for a system event, `QU_TRANSFER`).
* `logType`: `0` (The type ID for `QU_TRANSFER`).
* `topic1`: `aaaaaaaa...fxib` (Wildcard: The source address can be *anything*).
* `topic2`: `naaaaaaa...maml` (The destination address *must* be the QSWAP address).
* `topic3`: `aaaaaaaa...fxib` (Wildcard: The extra info can be *anything*).

#### Response

```json
[35917462, 35917541]
```

This response indicates that only ticks `35917462` and `35917541` (within the specified range) contain logs matching the filter.

#### Use Cases
This method is ideal for backend services that need to build user-specific data logs on the fly. For example, QX or QSWAP can use this endpoint to find all relevant trading events for a specific user and then cache that data, rather than scanning the entire chain history.

- [Finding asset transfer (EASY)](FIND_LOG_ASSET_ADVANCED.MD)
- [Finding asset transfer (ADVANCED)](FIND_LOG_ASSET_ADVANCED.MD)