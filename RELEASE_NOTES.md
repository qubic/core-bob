# Release Notes

Reverse-chronological log of user-visible changes. Entries cover JSON-RPC, REST,
WebSocket subscriptions, docker/config, and indexer behavior. Internal
refactors and test additions are summarized only when they affect runtime
behavior.

For exact commit boundaries, see `git log v<a>..v<b>`.
---
## 1.5.14

**END_EPOCH events now reach WebSocket subscribers automatically.** The end-epoch log batch lives on a virtual tick (`lastQuorumTick+1`) that never gets quorum tick data or votes; previously it was silently dropped on every live path.

- **Live `logs`/`transfers` subscriptions**: verified logs on ticks without tick data (the END_EPOCH virtual tick, quorum-empty ticks with logs) are now delivered instead of dropped. Their `timestamp` is backfilled from the previous tick (matching the REST `/epochLogs` convention) instead of `0`.
- **Live `tickStream` subscriptions**: the indexer now pushes the virtual end-epoch tick's log batch (zeroed tick data, `hasNoTickData: true`, real `timestamp`) before exiting at epoch end. The batch carries the ending epoch's number; the same tick number later re-appears as the next epoch's init tick with the new epoch's number — clients deduplicating across the boundary should key on `(epoch, tick)`, not `tick` alone.
- **`tickStream` catch-up**: recovered end-epoch logs (backup keys) are now actually merged into the boundary tick's message (previously collected but never emitted), deduplicated against live keys, with `timestamp` backfilled. Catch-up during the 30-minute end-epoch serving window no longer hangs waiting on the exited indexer and now covers the virtual end-epoch tick.
- **`logs`/`transfers` catch-up**: END_EPOCH events crossing an epoch boundary now resolve `txHash` to `SC_END_EPOCH_TX_<tick>` via the backed-up end-epoch log ranges instead of misattributing them to an unrelated transaction of the reused tick number.

## 1.5.13

**Improve log accessing.**
- **Fix bug** when accessing END_EPOCH events from previous epoch.

---
## 1.5.12

- Fix several memory bugs
- Update fourq verify

---
## 1.5.11

- **Faster catch-up**: `future-offset` default raised to **10**. The docker image previously shipped `3`, which throttled sync to ~3 ticks of look-ahead pipelining; it is now consistent across the code default, [docker/bob.json](docker/bob.json), [default_config_bob.json](default_config_bob.json), and docs. Raise via `FUTURE_OFFSET` to accelerate large initial syncs.
- **Configurable log-event chunk size**: `LOG_EVENT_CHUNK_SIZE` / `log-event-chunk-size` controls how many log IDs are requested per `RequestLog` (default **1000**).
- **Log-range integrity (misalignment fix)**: `db_insert_log_range` now writes the range blob and its summary **atomically** (SETNX blob + conditional summary), and corrupt/garbage summaries are rejected and refetched. This eliminates the non-deterministic state-digest **misalignment crashes / restart loops** caused by inconsistent (start, length) reads across restarts.
- **Connection resilience**: an always-on peer watchdog disconnects peers idle for 30s; bootstrap and rescue waits are now bounded so an unresponsive peer can't stall startup indefinitely; the redundant `EXCHANGE_PUBLIC_PEERS` handshake was dropped from the bootstrap sequence.
- **Diagnostics**: per-cycle request/response traffic counters and a "Blocked-on" snapshot in the periodic state line; an optional `DIAGNOSTIC_MODE` for deeper per-tick / per-log auditing; per-log source attribution to investigate "wrong tick" reports.
- **New tool**: `tools/bob_probe` — a standalone CLI to probe a BM node's handshake / tick-info / log-range / log-event responses for connectivity debugging.

---
## 1.5.10

- **Database validation**: Added validation rules to discard garbage log range data (prevents corrupted data storage)
- **Bug fix**: Fixed log range validation to correctly handle non-contiguous log slots
- **Logging**: Added detailed warning logs for database validation failures to aid debugging

---

## 1.5.6

**Default `tx_tick_to_live` lowered to 1000** (was 3000) in both
[docker/bob.json](docker/bob.json) and the documented example in
[README.md](README.md). With the post-cutover 4096-tx-per-tick ceiling
the previous 3000-tick window kept a lot of `transaction:*` blobs in
KeyDB; 1000 keeps roughly 30 minutes of recent tx data resident and
migrates the rest to kvrocks faster, easing memory pressure on
guardian hosts.

Operators that rely on instant lookups of older recent txs from KeyDB
can revert to the previous value via `TX_TICK_TO_LIVE=3000`.

---

## 1.5.5

**Config key normalization** — `bob.json` keys are now lowercased and `-` is converted to `_` before parsing, so mixed naming styles (e.g. `log-level`, `Log_Level`) all resolve to the same canonical key.

**Enhanced computor verification** — Added `TARGET_TICK_VOTE_SIGNATURE`, `computorListSignature`, and arbitrator signature to status/computor endpoints for fast signature verification.

---

## 1.5.4

**TickStream catch-up: epoch-boundary jump**

Previously, when catch-up spanned the numerical gap between one epoch's
last tick and the next epoch's `initTick`, bob iterated every tick in
that gap and emitted a placeholder for each — potentially hundreds of
thousands of empty messages over a slow WebSocket.

Catch-up now detects the boundary via the persisted `end_epoch_tick:<e>`
and `init_tick:<e+1>` keys, emits **one** synthetic event:

```json
{
  "type": "epochBoundary",
  "fromEpoch": 214,
  "toEpoch":   215,
  "lastEpochEndTick": 52500000,
  "newEpochInitTick": 52800000,
  "skippedTicks": 299999
}
```

…and jumps the cursor directly to the next epoch's `initTick`. The
`sub.lastTick` is updated so a reconnect-during-catch-up doesn't replay
the gap.

If the cutover is contiguous (no numerical gap), no boundary event is
emitted — the existing tick events carry the transition naturally
(including the SC_END_EPOCH log merge from 1.5.3).

Multiple epoch transitions in a single catch-up range are handled
iteratively — each gap fires its own boundary event.

**End-epoch logs are still delivered before the jump**

The catch-up loop still visits the prior epoch's `endTick` first and
emits its tick event including the merged SC_END_EPOCH log batch. Only
the empty numerical range after that endTick is jumped.

The 1.5.3 end-epoch-log merge looked up `end_epoch_tick:<td.epoch - 1>`,
which was based on a stale assumption that the new epoch's `initTick`
could equal the prior epoch's `endTick`. In practice an epoch's `endTick`
is always strictly less than the next epoch's `initTick`, so at the
endTick `td.epoch` is always the *ending* epoch — the previous logic
looked one epoch too far back and missed the merge. The lookup now
checks both `td.epoch` and `td.epoch - 1` against `end_epoch_tick:<e>`
so the SC_END_EPOCH batch is delivered correctly.

---

## 1.5.3

**Special-event log delivery fixes for TickStream catch-up**

Two bugs caused `SC_INITIALIZE_TX`, `SC_BEGIN_EPOCH_TX`, and `SC_END_EPOCH_TX`
log events to sometimes be missing for clients using TickStream catch-up:

1. **`SC_END_EPOCH` events were unreachable via catch-up.** At each epoch
   transition the verifier renames `tick_log_range:<endTick>` and
   `log_ranges:<endTick>` into `backup_end_epoch:*` keys so the new epoch
   can reuse the same tick number. The standard `db_get_logs_by_tick_range`
   only looks at the canonical key, so catch-up returned nothing for the
   end-tick of any past epoch. Live broadcast was fine; only clients that
   reconnected and asked for catch-up across an epoch boundary missed
   these events.

   Fixed by checking the end-epoch backup keys in
   [`performCatchUp`](RESTAPI/QubicSubscriptionManager.cpp) when a tick
   matches the previous epoch's `end_epoch_tick:<epoch>` value, and
   merging those log events into the tick's stream with their original
   slot index (typically `SC_END_EPOCH_TX`).

2. **Race at the start of a new epoch.** A client subscribing right after
   bob restarted for a new epoch could race past `initTick` before the
   indexer had populated `tick_log_range:<initTick>`, missing the
   `SC_INITIALIZE_TX` and `SC_BEGIN_EPOCH_TX` log events. Fixed by waiting
   for `gCurrentIndexingTick` to advance past each tick before reading
   its logs. The wait is a no-op when catch-up is far behind the cursor;
   it only blocks at the leading edge.

**Also fixed**: `db_get_endepoch_log_range_info` now accepts both the
canonical 4096-slot and the legacy 1024-slot LogRangesPerTxInTick layout,
so end-epoch metadata archived before the 4096-tx-per-tick cutover remains
queryable.

**Configurable external service URLs + peer-discovery failover**

All outbound HTTP URLs are now configurable via bob.json keys / docker
env vars. Defaults remain the public `*.qubic.global` / `qubic.li`
endpoints, so existing deployments work unchanged.

New env vars (see [docs/DOCKER_ENV.md](docs/DOCKER_ENV.md) for full reference):

| Env var | Effect |
|---|---|
| `PEER_DISCOVERY_URLS` | Comma-separated list of base URLs that serve `/random-peers`. Bob tries each in order until one returns peers (new failover behavior). |
| `CURRENT_TICK_ENDPOINTS` | Semicolon-separated `url\|path\|shape` triples for the network's current-tick lookup. `shape` is `flat` or `nested`. |
| `STATE_FILES_URLS` | Comma-separated list of **URL templates** (failover order) for per-epoch state snapshot downloads. Each entry may include `{EPOCH}` which is substituted at download time (so mirrors with different layouts work: `https://dl.qubic.global/ep{EPOCH}.zip` vs `https://storage.example.com/{EPOCH}/ep{EPOCH}.zip`). Entries without `{EPOCH}` fall back to `<base>/ep<epoch>.zip` (back-compat). `STATE_FILES_URL` (singular) still accepted. |
| `CHECKIN_URL` | Base URL for the `/checkin` POST. Empty to disable. |

Refactor: all the previously hard-coded `https://api.qubic.global`,
`https://api.qubic.li`, `https://rpc.qubic.org`, `https://dl.qubic.global`
literals in [connection/NodeIntroducer.cpp](connection/NodeIntroducer.cpp)
are now driven by runtime config.

**Peer-discovery failover (new behavior)** — previously bob queried only
`api.qubic.global` for peer discovery and returned an empty list if it
failed. With `PEER_DISCOVERY_URLS` listing multiple base URLs, bob walks
the list in order and uses the first non-empty response — same failover
pattern that the current-tick lookup has used for some time.

**Path-prefix handling fix** — drogon's `HttpClient::newHttpClient`
silently drops the path portion of its base URL, so a configured
endpoint like `https://api.qubic.li/public` would hit `/random-peers`
on the wrong host path. A new `splitOriginAndPath()` helper now extracts
the prefix and prepends it to the request path, so prefix-qualified URLs
work as expected across peer-discovery, current-tick, and check-in calls.

---

## 1.5.2

### Bug Fixes

- **Fixed a three-way deadlock between the tick fetcher, indexer, and log verifier** that could freeze synchronization indefinitely when catching up from far behind.

---

## 1.5.1

> **Required for the epoch 214 cutover (2026-05-20)** — core raises max
> transactions per tick from **1024 → 4096**. Bob must run this version
> (or later) before the epoch boundary.
>
> Also contains a **wire-incompatible change** to the `balance` /
> asset-balance fields. See "Migration" below.

### Epoch-214 cutover: max tx per tick 1024 → 4096

**Canonical layout bumped to 4096**
- `NUMBER_OF_TRANSACTIONS_PER_TICK` is now `4096` in [common/defines.h](common/defines.h).
- `LOG_TX_PER_TICK` auto-scales (4096 + 6 specials).
- Per-tick signature buffers, indexer loops, request bit-flags, and
  on-wire `TickData` size auto-scale.

**Backwards compatibility (read-only)**
- New `LegacyTickData`, `LegacyLogRangesPerTxInTick`, and
  `LegacyFullTickStruct` structs in [common/structs.h](common/structs.h) describe the
  pre-epoch-214 wire/storage layout.
- `db_get_tick_data`, `db_get_vtick_from_kvrocks`,
  `_db_get_log_ranges_by_key`, `db_get_cLogRange_from_kvrocks` all branch
  on the stored blob's byte length and upcast the legacy layout in
  memory. Historical ticks remain queryable via REST/RPC after the
  upgrade.
- `processTickData` accepts both canonical and legacy wire packets,
  verifying each over the byte range matching its original signature.
- All **writes** are in the canonical 4096-slot layout. The legacy
  structs are read-only.

**Behavior intentionally limited**
- `replyTickData` refuses to serve ticks from epochs `< 214`. We only
  hold them upcasted in memory; replying with the canonical layout
  would fail signature verification on the peer side. Pre-cutover
  peers must re-sync legacy ticks from each other or core's archive.

**Constants cleanup**
- Fixed a latent bug: `TickData::contractFees` was declared as
  `contractFees[NUMBER_OF_TRANSACTIONS_PER_TICK]`. It is now correctly
  sized by `MAX_NUMBER_OF_CONTRACTS`. Both used to be 1024 so the wire
  layout happened to match; bumping `NUMBER_OF_TRANSACTIONS_PER_TICK`
  to 4096 without this fix would have broken signature verification.
- `MAX_NUMBER_OF_CONTRACTS` and `NUMBER_OF_TRANSACTIONS_PER_TICK` are
  now defined exactly once (in `defines.h`); the duplicate "placeholder"
  defines in `database/db.h` are removed.
- `contractFees` JSON output loops in `RESTAPI/QubicRpcMapper.cpp` and
  `RESTAPI/bobAPI.cpp` now iterate `MAX_NUMBER_OF_CONTRACTS` instead of
  a literal `1024`.

**Storage impact**
- `tick_data:<tick>` in keydb roughly 4× per tick (mainly the digest
  array). Historical pre-cutover blobs remain at the legacy size; only
  new ticks pay the cost.
- `vtick:<tick>` in kvrocks: nominally 4× but zstd compresses sparse
  digest arrays well; realistic ~2×.
- The bump only raises the ceiling. Actual storage grows with real tx
  throughput.

**Deployment**
- Deploy `1.5.0` **before** the first tick of epoch 214.
- A bob running an older binary across the cutover will signature-fail
  every `TickData` packet for epoch 214+, silently halting sync.

---

### Other 1.5.1 changes

**RPC/REST parity fixes (audit pass)**

Bugs:
- `qubic_getLogs` and `qubic_getTransfers` no longer hardcode `epoch =
  gCurrentProcessingEpoch`. They derive the epoch from `fromTick` (or accept
  an optional `epoch` filter). Historical tick ranges now return their real
  logs instead of empty arrays.
- `qubic_getLogs` accepts both numeric and string `fromTick` / `toTick`.
  Previously a numeric form (`{"fromTick": 123}`) threw an internal error.

Parameter / shape parity:
- `qubic_getAssetTransfers` and `qubic_getAllAssetTransfers` now accept
  either `issuer` or `assetIssuer` (the latter is what the REST endpoints
  use). Old payloads keep working; REST payloads now work unchanged on RPC.
- `qubic_status` accepts an optional `challenge` parameter (string or
  `{"challenge": "..."}` object form). Mirrors the REST `/status?challenge=...`
  feature so callers can verify operator identity.
- `qubic_getTickByNumber` response now includes `votes[]`, `contractFees`,
  `logIdStart`, `logIdEnd` — matching the REST `/tick/{n}` shape. Existing
  fields unchanged; this is additive.
- REST `/findLog` now normalizes topic strings, accepting 0x-prefixed hex,
  60-char uppercase identity, or already-lowercase identity. Previously only
  the third form worked; same input that succeeded on `qubic_findLogIds`
  failed on REST.
- `bobGetBalance` REST keys: fixed typos `"currentBobTick:"` → `"currentBobTick"`
  and `"error:"` → `"error"`. Clients keyed on the typo'd names must update.

**Wire-incompatible**:
- Numeric fields that were previously emitted as JSON strings on the RPC
  surface are now emitted as JSON numbers. Brings RPC into line with REST
  (REST already used numbers via `LogEvent::parseToJson`). Affected fields:
  - `qubic_getBalance`: `balance`, `incomingAmount`, `outgoingAmount`
  - `qubic_getAssetBalance`: `ownershipBalance`, `possessionBalance`
  - `qubic_getLogs` / `qubic_getTransfers` log entries:
    `amount` (QU_TRANSFER, BURNING), `numberOfShares` (ASSET_OWNERSHIP_CHANGE,
    ASSET_POSSESSION_CHANGE)

  Strict-typed clients that decoded these as strings must update.

**Internal — additive on the wire**
- Topic / identity normalization for log-search APIs is now centralized in
  `ApiHelpers::normalizeTopicIdentity`. RPC `qubic_getTransfers`,
  `qubic_findLogIds`, and REST `/findLog` + `/getlogcustom` all accept the
  same input shapes (60-char Qubic identity in either case, 64-char hex,
  0x-prefixed hex). Previously REST `/findLog` rejected 0x-hex and
  `/getlogcustom` accepted only A-Z text.
- `qubic_getLogs` (`logEventToQubicLog`) now delegates body extraction to
  `LogEvent::parseToJson`, so new log types automatically surface on RPC
  without a parallel switch update. Existing fields are unchanged; the
  refactor adds previously-omitted fields for BURNING
  (`contractIndexBurnedFor`) and CONTRACT_* messages (`content`), and
  newly emits bodies for log types that weren't covered before
  (`ASSET_ISSUANCE`, `ORACLE_QUERY_STATUS_CHANGE`, etc.).

**Migration**
1. JSON decoders that read `balance`, `incomingAmount`, `outgoingAmount`,
   `ownershipBalance`, `possessionBalance`, `amount`, or `numberOfShares`
   as strings should be updated to read them as integers.
2. If you parsed REST `/balance/{id}` keys `currentBobTick:` or `error:`,
   drop the trailing colons.

---

## 1.4.3 (unreleased)

**Asset RPC**
- `qubic_getAssetBalance` now accepts an optional `manageSCIndex` (4th positional
  parameter, or named field in an object-form `params`). Required for assets
  managed by a contract other than the issuer — e.g. QDOGE / QX-managed shares
  use `manageSCIndex=1`. Previously the RPC hard-coded `0`, producing
  `ownershipBalance: "-1", possessionBalance: "-1"` for these assets.
- Response now echoes back the `manageSCIndex` that was queried.
- Docs and the RPC playground updated; the REST endpoint
  `/asset/{identity}/{issuer}/{name}/{manageSCIndex}` was already correct.

**Oracle**
- New `PERSIST_ORACLE_TX` env-var / `persist-oracle-tx` config flag for the
  docker image. Enables persisting the raw oracle reply transactions
  (`destinationPublicKey=0`, `inputType ∈ {6,7,10}`) so they can be inspected
  via the standard tx endpoints. Disabled by default.

---

## 1.4.2

**End-of-epoch reliability**
- The end-of-epoch shutdown busy-loop in `bob.cpp` was pegging a CPU and could
  hang indefinitely if a single data thread was stuck in a deep DB call (e.g.
  during heavy kvrocks compaction). It now sleeps 50ms between wake bursts
  and force-exits with `std::_Exit(0)` after a 60-second timeout so the
  supervisor restarts bob for the new epoch instead of leaving the
  REST/WS server alive without sync progress.
- Catch-up on `TickStream` subscriptions no longer silently drops ticks whose
  `tick_data:` row is missing (typical for the empty first tick of an epoch
  or for ticks evicted under `lastNTick` storage). Such ticks are emitted as
  placeholders with `hasNoTickData: true` and `isSkipped: true`.
- `verifyLoggingEvent` broadcasts the end-of-epoch log batch to subscribed
  WebSocket clients before the 30-minute grace period.

**Docker / kvrocks**
- `KVROCKS_TTL` env-var documented and respected by the entrypoint — controls
  how many epochs bob retains. Default 14 days (~2 epochs).
- `docker/kvrocks.conf` compression switched from `snappy` to `zstd`.
  Roughly halves on-disk size for the kind of data bob stores. New SSTs use
  zstd immediately; existing snappy SSTs convert as compactions touch them
  (or run `redis-cli -p 6666 COMPACT` for a one-shot migration).

---

## 1.4.1

**REST**
- New `bobGetEndEpochLog` endpoint to fetch the log range belonging to the
  virtual end-epoch tick. Useful for reconciling dividend distributions and
  end-of-epoch protocol reports.

---

## 1.4.0

> **⚠️ Breaking: transaction status is now tri-state.**
>
> Previously: `executed: true|false`, `status: "success"|"failed"`.
> Now: a third state, `pending`, is emitted when the tx's tick has not yet
> been log-verified. In that case `executed` is JSON `null` and `status` is
> `"pending"`. Strict-typed clients must accept nullable `executed` and the
> new status value.

**Affected surfaces**
- JSON-RPC `qubic_getTransactionReceipt`
- JSON-RPC `qubic_getTickByNumber` (transactions embedded in tick responses
  now also carry `executed` and `status`)
- REST `bobGetTransaction`
- WebSocket `TickStream` deliveries (real-time and catch-up)

**Behavior changes that prompted the new state**
- Transaction-status endpoints now compute execution state directly from
  `TickData` + log ranges + logs, not from the `itx:` index. Consequence:
  receipts are correct regardless of indexer state or spam-filter settings,
  but they need a way to express "we don't know yet for this tick" instead
  of returning a wrong "failed".
- `spam-qu-threshold` default flipped from `100` → `0`. Dust QU transfers
  are indexed like any other tx; receipts reflect their actual execution
  state. Estimated extra kvrocks disk for a 150M-tx-per-epoch workload:
  ~0.5–1 GB.
- Subscription/streaming paths share the same execution rule as the receipt
  endpoint via `ApiHelpers::isTxExecuted`.

**Migration guidance**
1. Treat `status` as `"success" | "failed" | "pending"`.
2. Treat `executed` as nullable (`bool | null`).
3. For receipts, retry with backoff while `status == "pending"`.
4. For `TickStream`, `pending` is terminal for that delivery — the tick will
   re-emit after log verification completes.

**Other changes**
- `/_admin/checkTransactions` audit endpoint unchanged — still probes the
  `itx:` index intentionally.

---

## 1.3.21

- `TickStream` subscription paths now compute `executed` from the already-loaded
  log range / tick logs instead of falling back to `db_get_indexed_tx`. Removes
  the last non-test caller of the indexer's per-tx lookup for streaming.
- Internal refactor of REST API doc comments.
- `SC_NOTIFICATION_TX` constant renamed (underscore fix).
- `bobGetLog` performance improved.
- `bob.json` ships with un-mapped tx logging enabled for easier debugging.

---

## 1.3.20

- New direct-lookup path for single-tx responses (`qubic_getTransactionReceipt`,
  REST `bobGetTransaction`). Returns correct `executed`/`status` regardless of
  whether the `itx:` index has the row — fixes the long-standing
  "low-value tx reported as failed" bug.
- `spam-qu-threshold` default lowered from `100` → `0` in
  `default_config_bob.json`, `docker/bob.json`, and the docs. The threshold
  was originally a RAM-saving measure when indexer data lived in keydb; now
  that it lives in kvrocks, the cost is ~3% extra disk per epoch and worth
  the correctness.
- Large internal cleanup: unit test coverage for `db_*`, asset, log-core,
  and processor modules. Refactor of `common/`, `processors/`, and asset
  handling. No external behavior change beyond the items above.

---

## 1.3.19

- New `WAIT_AT_EPOCH_END` env var (docker) — controls the post-END_EPOCH grace
  period during which bob keeps serving slower peers before exiting.
- RPC tick lookup checks the new `db_is_tick_empty` flag so callers can
  distinguish empty/skipped ticks from unknown ticks.

---

## Earlier (1.3.18 and below)

Earlier 1.3.x releases were largely incremental: configuration knobs,
documentation, bugfixes for tick storage and recovery. See `git log v1.3.0..v1.3.18`.

---

## Versioning conventions

- **Major** (`x.0.0`) — wire-incompatible change to RPC/REST/WS schemas. Clients
  must adapt. Examples: 1.4.0's tri-state status.
- **Minor** (`1.x.0`) — new endpoints/fields, new config knobs, behavior
  expansions that are additive on the wire.
- **Patch** (`1.4.x`) — bugfixes, performance, operational improvements
  (compression, retention defaults, etc.). No client changes required.
