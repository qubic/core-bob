# bob_probe — Qubic P2P protocol probe

A standalone, single-threaded, heavily-logged tool that speaks the **exact same
wire protocol bob uses** against a Qubic node. Use it to find out *where* bob and
a (new) node software disagree on the wire.

It reuses bob's own `common/structs.h`, `common/defines.h` and
`common/K12AndKeyUtil.h`, so every packet it sends is byte-for-byte identical to
bob's, and every struct size / signature check matches bob exactly — but unlike
bob it runs one request at a time, blocking, and logs **every byte sent and
received**, every decoded header/struct, sizes, timings, and any anomaly.

## Build

```bash
bash tools/build_probe.sh
# or:
g++ -std=c++17 -mavx2 -O2 -I common -I . tools/bob_probe.cpp -o bob_probe -lpthread
```

No redis / spdlog / drogon needed — it only uses bob's header-only code.

## Run

```bash
./bob_probe <ip> <port> [options]

# Full probe against a node:
./bob_probe 1.2.3.4 21841

# Probe a specific (older) tick, verify the computor-list signature, full hexdumps:
./bob_probe 1.2.3.4 21841 --tick 55558000 \
    --arb AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ --hex -1

# Just watch the node's current tick live:
./bob_probe 1.2.3.4 21841 --steps tickinfo --loop-tickinfo
```

### Options

| Option | Meaning |
|--------|---------|
| `--tick <N>` | Tick to request data/votes/txs/logs for (default: node's current tick) |
| `--arb <IDENTITY>` | Arbitrator identity → verify the computor-list signature |
| `--passcode p0-p1-p2-p3` | Passcode for the logging-event requests (the `logs` step) |
| `--steps <list>` | Comma list: `handshake,tickinfo,computors,tickdata,votes,txs,logs` (default: all except handshake; `logs` needs `--passcode`) |
| `--hex <N>` | Hexdump bytes per packet (default 128; `0`=off; `-1`=full) |
| `--timeout <sec>` | Socket receive timeout (default 8) |
| `--max-votes <N>` | Max votes to print (default 8; `-1`=all) |
| `--max-txs <N>` | Max transactions to print (default 16; `-1`=all) |
| `--binary-output` | Print raw packet hexdumps (OFF by default; `--hex` tunes the size) |
| `--loop-tickinfo` | After the run, poll current-tick-info forever |
| `--catchup` | Catch-up mode — walk a range of ticks over one open connection (see below) |
| `--count <N>` | Catch-up: number of ticks to walk (default 100) |
| `--no-color` | Disable ANSI colors (e.g. when piping to a file) |

## What it does (the same sequence bob does)

1. **handshake** — `EXCHANGE_PUBLIC_PEERS` (type 0)
2. **tickinfo** — `REQUEST_CURRENT_TICK_INFO` (27) → `RESPOND_CURRENT_TICK_INFO` (28)
3. **computors** — `REQUEST_COMPUTOR_LIST` (11) → `RESPOND_COMPUTOR_LIST` (2), with optional signature check
4. **tickdata** — `REQUEST_TICK_DATA` (16) → `TickData` (8), with canonical-vs-legacy size detection + signature check
5. **votes** — `REQUEST_QUORUM_TICK` (14) → `TICK_VOTE` (3) × N, each signature-checked
6. **txs** — `REQUEST_TICK_TRANSACTIONS` (29) → `TRANSACTION` (24) × N
7. **logs** (needs `--passcode`) — `REQUEST_ALL_LOG_RANGES` (50) → `LOG_RANGES` (51) for the tick's
   logId range, then `REQUEST_LOG` (44) in chunks of 128 → `RESPOND_LOG` (45), decoding each packed
   26-byte log-event header (epoch, tick, logId, type, body size)

## Logging events (`logs` step, `--passcode`)

The log path is **passcode-gated**: the node whitelists bob's IP and gives it a 4×uint64 passcode
(the same `p0-p1-p2-p3` you put after a `BM:ip:port:` endpoint in bob's config). Pass it with
`--passcode`:

```bash
# Single tick's logs (must be a tick BELOW the node's current verify tick):
./bob_probe 1.2.3.4 21841 --steps logs --tick 55900000 --passcode 12-34-56-78

# Catch-up the log stream over 200 ticks:
./bob_probe 1.2.3.4 21841 --catchup --count 200 --steps logs --passcode 12-34-56-78
```

- Without `--passcode` (or with a wrong one), the node replies `END_RESPONSE` and the probe reports
  *"No logs served … bad/missing passcode"*.
- The node only serves logs for ticks **strictly below** its current verify tick — asking for the
  frontier tick returns nothing. Use a tick a bit behind.
- A successful log response is a single packet with **no terminator** (like tick data), so the probe
  stops on the first `LOG_RANGES`/`RESPOND_LOG`.

## Catch-up mode (`--catchup`)

Simulates bob syncing a range of ticks: it **keeps one connection open** and
walks ticks `[start .. start+count)` sequentially, fetching each tick's data.
It does **not** decode/print per-tick data — only per-tick **timings**, then a
summary of the timings.

```bash
# Walk 500 ticks from a given start, fetching tickdata+votes+txs per tick:
./bob_probe 1.2.3.4 21841 --catchup --tick 56000000 --count 500

# Just tick data, last 1000 ticks (start derived from node's current tick):
./bob_probe 1.2.3.4 21841 --catchup --count 1000 --steps tickdata
```

- `--tick <N>` sets the start tick. If omitted, it starts at `currentTick - count`
  so you catch up the most recent `count` ticks.
- `--steps` selects which per-tick fetches to run, among `tickdata,votes,txs,logs`
  (default: `tickdata,votes,txs`). `logs` is opt-in and needs `--passcode`.
  `tickinfo`/`computors` are not per-tick and are ignored here.
- Each tick prints one compact line, e.g.
  `[ 12/500] tick 56000011  td 72.7ms 136 KB  votes 41ms x676  txs 95ms x312`.
- The run ends with a **timing summary** per fetch type (ticks, empty, total, avg,
  min, max, bytes) plus overall throughput (ticks/s, MB/s, avg per tick).
- It is **sequential** (one tick at a time), so it measures per-tick round-trip
  latency. Real bob pipelines requests (`future-offset`) for higher throughput —
  so treat these numbers as a per-tick latency baseline, not bob's max sync speed.
- Signature verification is skipped in catch-up (it's a network-timing test).
- `empty` in the summary = ticks where the node returned no data for that type
  (normal for ticks with no transactions; meaningful if tick data/votes are missing).

## Reading the output

- `SEND` / `RECV` lines show every packet's `type`, `size`, `payload` size and `dejavu`.
- The probe prints **this build's struct sizes** at startup. If a `RECV` payload
  size doesn't match, you'll get a `WARN`/`ERROR` pinpointing the layout mismatch.
- The most common incompatibility is the **epoch-214 tick layout cutover**
  (`NUMBER_OF_TRANSACTIONS_PER_TICK` 1024→4096): canonical `TickData` is **139376**
  bytes, legacy is **41072**. If the node sends any other size, the probe logs
  *"UNEXPECTED payload size … neither canonical nor legacy"* — which is exactly
  what makes bob log *"processTickData: unexpected payload size"* and drop the tick.
- `END_RESPONSE/NOP (35)` with the matching dejavu means the node finished a
  response. Getting only an END_RESPONSE for tickdata/votes/txs means the node
  has no data for that tick (e.g. you asked for the live frontier tick, or a
  pruned/old one) — try an older tick that the node actually stores.
