# WebSocket Log Streaming & Subscription Model
This document describes the real-time log streaming WebSocket and the subscription model used to deliver log events to clients. It focuses on the protocol, message formats, subscription keys, catch-up behavior, and operational considerations.
## 1) Overview
The system exposes a WebSocket endpoint that allows clients to:
- Subscribe to one or more categories of log events (by (scIndex, logType)).
- Receive real-time events as they are verified/processed.
- Optionally request catch-up delivery (historical events) so a client can resume from where it left off.
- Unsubscribe from a specific stream or from all streams.
- Send ping messages to validate connectivity and retrieve server tick/epoch metadata.

The model is topic-based: each log event is mapped to a subscription key, and only clients subscribed to that key receive the event.
## 2) Endpoint
- WebSocket path: GET /ws/logs
- Typical local dev URL: ws://localhost:40420/ws/logs

Clients must open a WebSocket connection, then send JSON text frames to manage subscriptions.
## 3) Key Concepts
### 3.1 Subscription Key: (scIndex, logType)
A subscription is defined by a pair:
- scIndex: smart contract index
    - 0 is reserved for core/system events (e.g., transfers, asset events).
    - Non-zero values represent a specific smart contract.

- logType: numeric log type identifier
    - Core events use well-known IDs.
    - Custom/indexed contract events are typically high values (e.g., >= 100000).

A client can subscribe to multiple keys simultaneously.
### 3.2 Real-time vs Catch-up
There are two delivery modes:
- Real-time: events streamed as they occur.
- Catch-up: events sent from a client-provided cursor up to “now”, then real-time continues.

Catch-up can be expressed using either:
- lastTick (tick-based cursor), or
- lastLogId (log-id-based cursor; takes priority if provided)

## 4) Protocol: Client → Server Messages
All client messages are JSON objects and must include an action field.
### 4.1 Subscribe (single)
{"action":"subscribe","scIndex":1,"logType":100001}
### 4.2 Subscribe with catch-up (tick cursor)
{"action":"subscribe","scIndex":1,"logType":100001,"lastTick":12345678}
Interpretation: “I have processed events up through lastTick; send me what I missed and then continue streaming new events.”
### 4.3 Subscribe with catch-up (log-id cursor)
{"action":"subscribe","scIndex":1,"logType":100001,"lastLogId":987654321}
Interpretation: “I have processed events up through log id lastLogId; catch me up from the next log id.”
Priority rule: if both lastLogId and lastTick are present, lastLogId wins.
### 4.4 Batch subscribe
{
"action":"subscribe",
"lastTick":12345678,
"subscriptions":[
{"scIndex":1,"logType":100001},
{"scIndex":2,"logType":100002}
]
}
Batch subscription is useful to reduce round trips and to perform catch-up once after registering multiple keys.
### 4.5 Unsubscribe (single)
{"action":"unsubscribe","scIndex":1,"logType":100001}
### 4.6 Unsubscribe all
{"action":"unsubscribeAll"}
### 4.7 Ping (application-level)
{"action":"ping"}
This is separate from WebSocket protocol ping/pong frames; it returns a JSON pong message with server metadata.
## 5) Protocol: Server → Client Messages
### 5.1 Welcome (sent immediately on connect)
{"type":"welcome","currentVerifiedTick":12345678,"currentEpoch":152}
Use this to quickly learn the server’s current state and decide whether catch-up is needed.
### 5.2 Acknowledgment (ack)
Sent in response to subscribe/unsubscribe actions.
Single subscribe/unsubscribe commonly includes the key:
{"type":"ack","action":"subscribe","success":true,"scIndex":1,"logType":100001}
Batch subscribe returns an aggregate count:
{"type":"ack","action":"subscribe","success":true,"subscriptionsAdded":2}
### 5.3 Log event message
{
"type":"log",
"scIndex":1,
"logType":100001,
"isCatchUp":false,
"message": { ... }
}
- isCatchUp
    - true means the server is replaying historical events during catch-up.
    - false means the event is a live real-time push.

- message is the parsed log payload (intended to match the REST log representation).

### 5.4 Catch-up completion marker
Tick-based:
{"type":"catchUpComplete","fromTick":12345679,"toTick":12345700,"logsDelivered":42}
Log-id-based:
{"type":"catchUpComplete","fromLogId":987654322,"toLogId":987655000,"logsDelivered":42}
This message indicates the server has finished replaying historical events up to the requested boundary. After this point, the client should treat subsequent isCatchUp:false messages as the live stream.
### 5.5 Pong (application-level)
{"type":"pong","serverTick":12345678,"serverEpoch":152}
### 5.6 Error
{"type":"error","message":"...","code":"ERROR_CODE"}
Errors are returned for invalid JSON, missing fields, unsupported message types, and unknown actions.
## 6) Subscription Semantics
### 6.1 Multiple subscriptions per connection
A single WebSocket connection can hold many subscriptions. The server routes each eligible log event to all connections subscribed to that event’s key.
### 6.2 Idempotency
- Subscribing to an already-subscribed key is treated as successful (idempotent behavior is expected).
- Unsubscribing from a key that is not currently subscribed may return success:false.

### 6.3 Non-subscribable events
Not every log event is intended to be subscribable. Only events that can be mapped to a stable (scIndex, logType) key are routed via this system. Events outside the indexed set are ignored for subscription delivery.
## 7) Catch-up Behavior (Important Details)
### 7.1 When catch-up runs
Catch-up is triggered after subscription(s) are registered (single or batch). This ensures only the requested keys are replayed.
### 7.2 Cursor meaning
- With lastTick: the server replays events for ticks after lastTick up to (roughly) the current verified tick at the time catch-up starts.
- With lastLogId: the server replays events with IDs after lastLogId up to the current latest log id.

### 7.3 Ordering and duplication considerations
During catch-up, the server may suppress real-time pushes to a client to avoid out-of-order or duplicate delivery while history is being replayed. Clients should still implement defensive handling:
- Treat (epoch, tick, logId) (or equivalent fields inside message) as the canonical ordering/cursor.
- Deduplicate if needed (e.g., if a reconnect overlaps ranges).

### 7.4 Recommended client cursor strategy
For robust resumption:
1. Persist the highest processed logId (preferred if available) or tick.
2. On reconnect, subscribe with lastLogId/lastTick.
3. Process log messages, updating your stored cursor.
4. When you receive catchUpComplete, you know you are live.

## 8) Typical Client Flows
### 8.1 Start live only
1. Connect → receive welcome
2. Send subscribe without lastTick/lastLogId
3. Receive only new logs going forward

### 8.2 Resume from last seen logId
1. Connect → receive welcome
2. Send subscribe with lastLogId
3. Receive log messages with isCatchUp:true
4. Receive catchUpComplete
5. Continue receiving real-time log messages with isCatchUp:false

### 8.3 Manage subscriptions dynamically
- Subscribe to additional keys at runtime (optionally with catch-up).
- Unsubscribe from noisy keys to reduce bandwidth.
- Use unsubscribeAll before switching to a new set of subscriptions.

## 9) Core Event Types (scIndex = 0)
Core events use scIndex = 0 and fixed logType IDs (examples commonly supported):

| logType | Meaning |
| --- | --- |
| 0 | QU_TRANSFER |
| 1 | ASSET_ISSUANCE |
| 2 | ASSET_OWNERSHIP_CHANGE |
| 3 | ASSET_POSSESSION_CHANGE |
| 8 | BURNING |
| 11 | ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE |
| 12 | ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE |
Custom contract events typically use scIndex != 0 and logType >= 100000.
## 10) Operational Notes
- Message format: JSON text frames only.
- Keep-alive: you may use {"action":"ping"} on an interval and/or native WebSocket ping frames depending on your client.
- Backpressure: if a client can’t keep up, it should reduce subscription breadth, process asynchronously, and persist cursor frequently to minimize replay on reconnect.
- Reconnect strategy: on any disconnect, reconnect and re-subscribe with your persisted cursor.
