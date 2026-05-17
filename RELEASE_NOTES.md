# Release Notes

Reverse-chronological log of user-visible changes. Entries cover JSON-RPC, REST,
WebSocket subscriptions, docker/config, and indexer behavior. Internal
refactors and test additions are summarized only when they affect runtime
behavior.

For exact commit boundaries, see `git log v<a>..v<b>`.

---

## 1.5.0 (unreleased)

> **⚠️ Wire-incompatible change** to the `balance` / asset-balance fields.
> See "Migration" below.

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
