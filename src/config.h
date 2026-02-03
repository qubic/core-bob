#pragma once

#include "core/m256i.h"
#include <map>
#include <string>
#include <vector>

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
    unsigned future_offset = 0;
    unsigned server_port = 0;
    std::string node_seed;

    // Add new tick storage config with defaults
    TickStorageMode tick_storage_mode = TickStorageMode::LastNTick;
    unsigned last_n_tick_storage = 1000;              // used when mode is LastNTick
    std::string kvrocks_url = "tcp://127.0.0.1:6666"; // used when mode is Kvrocks

    unsigned max_thread = 0;
    // Spam/Junk detection threshold for QU transfers (amount <= threshold and no input)
    unsigned spam_qu_threshold = 100;
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
};

// Returns true on success; on failure returns false and fills error with a human-readable message.
bool LoadConfig(const std::string& path, AppConfig& out, std::string& error);