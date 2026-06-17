#pragma once

#include <string>
#include <vector>
#include <map>
#include "m256i.h"

// Add tick storage mode enum
enum class TickStorageMode {
    LastNTick,
    Kvrocks,
    Free
};
enum class TxStorageMode {
    LastNTick,
    Kvrocks,
    Free
};

struct AppConfig {
    std::vector<std::string> p2p_nodes;

    std::string log_level;
    std::string keydb_url;
    std::string arbitrator_identity;
    bool run_server = false;
    bool is_testnet = false;
    unsigned request_cycle_ms = 0;
    unsigned request_logging_cycle_ms = 0;
    unsigned future_offset = 10;
    unsigned server_port = 0;
    std::string node_seed;

    // Add new tick storage config with defaults
    TickStorageMode tick_storage_mode = TickStorageMode::LastNTick;
    unsigned last_n_tick_storage = 1000;              // used when mode is LastNTick
    std::string kvrocks_url = "tcp://127.0.0.1:6666"; // used when mode is Kvrocks
    uint64_t indexer_max_activities_per_key = 100000; // indexing 100k activities per key
    unsigned n_tickdata_to_store = 5;

    unsigned max_thread = 0;
    // Spam/Junk detection threshold for QU transfers (amount <= threshold and no input)
    unsigned spam_qu_threshold = 0;
    // How many log IDs to request per RequestLog packet. Defaults to the
    // max-tx-per-tick ceiling so a typical tick's logs fit in one round
    // trip. Lower it (e.g. 256 or 512) on links where 4MB responses cause
    // queueing/stalls; raise it if your BM accepts larger requests.
    // Per-range dedup (verifyLoggingEvent's REFIRE_GUARD_MS) is unaffected.
    unsigned log_event_chunk_size = 4096;
    // Master switch for expensive diagnostic instrumentation (BATCH_AUDIT
    // hashing, per-log source attribution). Default off; turn on while
    // debugging non-deterministic verify failures.
    bool diagnostic_mode = false;
    // transaction storage mode configuration
    TxStorageMode tx_storage_mode = TxStorageMode::LastNTick;
    // For "kvrocks" tx-storage-mode: how long transactions stay in RAM (in ticks)
    unsigned tx_tick_to_live = 10000;

    // time to live (data expiration) for records in kvrocks engine (default 3 weeks - 1209600 seconds) (0 => no expiration)
    long long kvrocks_ttl = 1209600;

    long long wait_at_epoch_end = 1800; // time to wait at epoch end before switching to new epoch- 30mins (1800s) by default
    // RPC/REST API port (default 40420)
    unsigned rpc_port = 40420;
    // Enable admin endpoints (default false for security)
    bool enable_admin_endpoints = false;
    // allow bob to receive log from incoming connections
    bool allow_receive_log_from_incoming_connections = false;

    std::string nodeAlias = "Big fat bob";

    bool allow_check_in_qubic_global = true;

    // When true, persist oracle tx data and log events. Default: true.
    bool persist_oracle_tx = true;

    // External service URLs. Operators can override these (e.g. for a
    // private/sealed network) or extend the failover chain.

    // Peer-discovery endpoints: each is queried with /random-peers until
    // one returns a usable list of peers.
    std::vector<std::string> peer_discovery_urls = {
        "https://api.qubic.global",
        "https://api.qubic.li/public",
    };
    // Current-tick lookups. Each entry is a {base_url, path, shape} triple
    // tried in order. Empty entries are skipped, which lets operators
    // disable a specific failover without removing it from config.
    // Shape values: "flat" → {"tick": N, "epoch": N}
    //               "nested" → {"tickInfo": {"tick": N, "epoch": N}}
    struct TickEndpoint { std::string url; std::string path; std::string shape; };
    std::vector<TickEndpoint> current_tick_endpoints = {
        {"https://api.qubic.global", "/currenttick",       "flat"},
        {"https://api.qubic.li",     "/public/currenttick","flat"},
        {"https://rpc.qubic.org",    "/live/v1/tick-info", "nested"},
    };
    // Where to download per-epoch spectrum/universe state files. Each entry
    // is a URL template that may contain the placeholder `{EPOCH}`, which
    // is substituted with the actual epoch number at download time. This
    // accommodates mirrors that use different layouts, e.g.:
    //   "https://dl.qubic.global/ep{EPOCH}.zip"
    //   "https://storage.qubic.li/{EPOCH}/ep{EPOCH}.zip"
    // For back-compat, an entry without `{EPOCH}` is treated as a base URL
    // and gets "/ep<epoch>.zip" appended (the historical behavior). Bob
    // tries entries in order until one downloads + unzips successfully.
    // Empty list disables the download.
    std::vector<std::string> state_files_urls = {
        "https://dl.qubic.global/ep{EPOCH}.zip",
        "https://storage.qubic.li/network/{EPOCH}/ep{EPOCH}.zip",
    };
    // Where bob reports its status for peer-discovery directories. Empty
    // disables the call (use this together with allow_check_in_qubic_global=false).
    std::string checkin_url = "https://api.qubic.global";
};

// Returns true on success; on failure returns false and fills error with a human-readable message.
bool LoadConfig(const std::string& path, AppConfig& out, std::string& error);