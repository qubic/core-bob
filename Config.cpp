#include "Config.h"
#include "json/reader.h"
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <string>
#include <memory>
#include <thread>
#include <algorithm>
#include <cctype>

namespace {
    // Normalize a single key: lowercase + replace '-' with '_'.
    std::string NormalizeKey(const std::string& key) {
        std::string out;
        out.reserve(key.size());
        for (char c : key) {
            if (c == '-') {
                out.push_back('_');
            } else {
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
        }
        return out;
    }

    // Recursively normalize all object keys in a Json::Value.
    // Arrays are traversed; scalar leaves are left untouched.
    Json::Value NormalizeKeys(const Json::Value& in) {
        if (in.isObject()) {
            Json::Value out(Json::objectValue);
            for (const auto& name : in.getMemberNames()) {
                out[NormalizeKey(name)] = NormalizeKeys(in[name]);
            }
            return out;
        }
        if (in.isArray()) {
            Json::Value out(Json::arrayValue);
            for (const auto& v : in) {
                out.append(NormalizeKeys(v));
            }
            return out;
        }
        return in;
    }
}

bool LoadConfig(const std::string& path, AppConfig& out, std::string& error) {
    std::ifstream ifs(path);
    if (!ifs) {
        error = "cannot open file";
        return false;
    }

    std::stringstream buffer;
    buffer << ifs.rdbuf();
    const std::string json = buffer.str();

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());

    Json::Value rawRoot;
    std::string errs;
    if (!reader->parse(json.data(), json.data() + json.size(), &rawRoot, &errs)) {
        error = "invalid JSON: " + errs;
        return false;
    }

    if (!rawRoot.isObject()) {
        error = "invalid JSON: root must be an object";
        return false;
    }

    // Pre-process: lowercase all keys and convert '-' to '_'.
    // After this point, every lookup must use the normalized form.
    const Json::Value root = NormalizeKeys(rawRoot);

    // merge 'p2p_node' to trusted node
    if (root.isMember("p2p_node")) {
        if (!root["p2p_node"].isArray()) {
            error = "Invalid type: array required for key 'p2p_node'";
            return false;
        }
        for (const auto& v : root["p2p_node"]) {
            if (!v.isString()) {
                error = "Invalid type: elements of 'p2p_node' must be strings";
                return false;
            }
            out.p2p_nodes.emplace_back(v.asString());
        }
    }

    // Optional fields (use defaults from AppConfig if absent)
    if (root.isMember("log_level")) {
        if (!root["log_level"].isString()) {
            error = "Invalid type: string required for key 'log_level'";
            return false;
        }
        out.log_level = root["log_level"].asString();
    }

    if (root.isMember("keydb_url")) {
        if (!root["keydb_url"].isString()) {
            error = "Invalid type: string required for key 'keydb_url'";
            return false;
        }
        out.keydb_url = root["keydb_url"].asString();
    }

    if (root.isMember("kvrocks_url")) {
        if (!root["kvrocks_url"].isString()) {
            error = "Invalid type: string required for key 'kvrocks_url'";
            return false;
        }
        out.kvrocks_url = root["kvrocks_url"].asString();
    } else {
        if (out.kvrocks_url.empty()) {
            out.kvrocks_url = "tcp://127.0.0.1:6666";
        }
    }

    if (root.isMember("indexer_max_activities_per_key")) {
        if (!root["indexer_max_activities_per_key"].isNumeric()) {
            error = "Invalid type: number required for key 'indexer_max_activities_per_key'";
            return false;
        }
        out.indexer_max_activities_per_key = root["indexer_max_activities_per_key"].asUInt64();
    }

    // this config is use in kvrocks mode only, it will determine how many tickData stays on RAM
    // usually use by core BOB for faster distribution
    if (root.isMember("n_tickdata_to_store")) {
        const auto& v = root["n_tickdata_to_store"];
        if (v.isUInt()) {
            out.n_tickdata_to_store = v.asUInt();
        } else if (v.isInt()) {
            int i = v.asInt();
            if (i < 0) {
                error = "Negative integer is invalid for key 'n_tickdata_to_store'";
                return false;
            }
            out.n_tickdata_to_store = static_cast<unsigned>(i);
        } else {
            error = "Invalid type: unsigned integer required for key 'n_tickdata_to_store'";
            return false;
        }
    } else {
        out.n_tickdata_to_store = 5;
    }

    if (root.isMember("arbitrator_identity")) {
        if (!root["arbitrator_identity"].isString()) {
            error = "Invalid type: string required for key 'arbitrator_identity'";
            return false;
        }
        out.arbitrator_identity = root["arbitrator_identity"].asString();
    }
    else
    {
        error = "string required for key 'arbitrator_identity'";
        return false;
    }

    if (root.isMember("run_server")) {
        if (!root["run_server"].isBool()) {
            error = "Invalid type: boolean required for key 'run_server'";
            return false;
        }
        out.run_server = root["run_server"].asBool();
    }

    if (root.isMember("allow_receive_log_from_incoming_connections")) {
        if (!root["allow_receive_log_from_incoming_connections"].isBool()) {
            error = "Invalid type: boolean required for key 'allow_receive_log_from_incoming_connections'";
            return false;
        }
        out.allow_receive_log_from_incoming_connections = root["allow_receive_log_from_incoming_connections"].asBool();
    }

    if (root.isMember("is_testnet")) {
        if (!root["is_testnet"].isBool()) {
            error = "Invalid type: boolean required for key 'is_testnet'";
            return false;
        }
        out.is_testnet = root["is_testnet"].asBool();
    }

    auto validate_uint = [&](const char* key, unsigned& target) -> bool {
        if (!root.isMember(key)) return true;
        const auto& v = root[key];
        if (v.isUInt()) {
            target = v.asUInt();
            return true;
        }
        if (v.isInt()) {
            int i = v.asInt();
            if (i < 0) {
                error = std::string("Negative integer is invalid for key '") + key + "'";
                return false;
            }
            target = static_cast<unsigned>(i);
            return true;
        }
        error = std::string("Invalid type: unsigned integer required for key '") + key + "'";
        return false;
    };

    if (!validate_uint("request_cycle_ms", out.request_cycle_ms)) return false;
    if (!validate_uint("request_logging_cycle_ms", out.request_logging_cycle_ms)) return false;
    if (!validate_uint("future_offset", out.future_offset)) return false;
    if (!validate_uint("server_port", out.server_port)) return false;
    if (!validate_uint("rpc_port", out.rpc_port)) return false;

    // Enable admin endpoints (default false)
    if (root.isMember("enable_admin_endpoints")) {
        if (!root["enable_admin_endpoints"].isBool()) {
            error = "Invalid type: boolean required for key 'enable_admin_endpoints'";
            return false;
        }
        out.enable_admin_endpoints = root["enable_admin_endpoints"].asBool();
    }

    // Maximum threads the system can use (0 means auto/unlimited)
    if (!validate_uint("max_thread", out.max_thread)) return false;
    if (out.max_thread == 0)
    {
        out.max_thread = std::thread::hardware_concurrency();
    }

    // Spam/Junk QU transfer detection threshold (default 0)
    if (!validate_uint("spam_qu_threshold", out.spam_qu_threshold)) return false;

    // Log event chunk size (default = NUMBER_OF_TRANSACTIONS_PER_TICK).
    // 0 is rejected (would cause an infinite loop in the chunk walker).
    if (!validate_uint("log_event_chunk_size", out.log_event_chunk_size)) return false;
    if (out.log_event_chunk_size == 0) out.log_event_chunk_size = 4096;

    if (root.isMember("diagnostic_mode")) {
        if (!root["diagnostic_mode"].isBool()) {
            error = "Invalid type: boolean required for key 'diagnostic_mode'";
            return false;
        }
        out.diagnostic_mode = root["diagnostic_mode"].asBool();
    }

    if (root.isMember("node_seed")) {
        if (!root["node_seed"].isString()) {
            error = "Invalid type: string required for key 'node_seed'";
            return false;
        }
        out.node_seed = root["node_seed"].asString();
    } else {
        out.node_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }

    if (root.isMember("node_alias")) {
        if (!root["node_alias"].isString()) {
            error = "Invalid type: string required for key 'node_alias'";
            return false;
        }
        out.nodeAlias = root["node_alias"].asString();
    }

    // Parse 'tick_storage_mode' and related options
    {
        std::string mode = "lastNTick";
        if (root.isMember("tick_storage_mode")) {
            if (!root["tick_storage_mode"].isString()) {
                error = "Invalid type: string required for key 'tick_storage_mode'";
                return false;
            }
            mode = root["tick_storage_mode"].asString();
        }

        if (mode == "lastNTick") {
            out.tick_storage_mode = TickStorageMode::LastNTick;

            // last_n_tick_storage (default 1000)
            if (root.isMember("last_n_tick_storage")) {
                const auto& v = root["last_n_tick_storage"];
                if (v.isUInt()) {
                    out.last_n_tick_storage = v.asUInt();
                } else if (v.isInt()) {
                    int i = v.asInt();
                    if (i < 0) {
                        error = "Negative integer is invalid for key 'last_n_tick_storage'";
                        return false;
                    }
                    out.last_n_tick_storage = static_cast<unsigned>(i);
                } else {
                    error = "Invalid type: unsigned integer required for key 'last_n_tick_storage'";
                    return false;
                }
            } else {
                // Ensure default if not preset
                if (out.last_n_tick_storage == 0) {
                    out.last_n_tick_storage = 1000;
                }
            }
        } else if (mode == "kvrocks") {
            out.tick_storage_mode = TickStorageMode::Kvrocks;
        } else if (mode == "free") {
            out.tick_storage_mode = TickStorageMode::Free;
            // No related options; implies no garbage cleaner.
        } else {
            error = "Invalid value for 'tick_storage_mode': must be one of 'lastNTick', 'kvrocks', or 'free'";
            return false;
        }
    }

    // Parse 'tx_storage_mode' and related options
    {
        std::string mode = "lastNTick";
        if (root.isMember("tx_storage_mode")) {
            if (!root["tx_storage_mode"].isString()) {
                error = "Invalid type: string required for key 'tx_storage_mode'";
                return false;
            }
            mode = root["tx_storage_mode"].asString();
        }

        if (mode == "lastNTick") {
            out.tx_storage_mode = TxStorageMode::LastNTick;

            // Use the same last_n_tick_storage (default 1000)
            if (root.isMember("last_n_tick_storage")) {
                const auto& v = root["last_n_tick_storage"];
                if (v.isUInt()) {
                    out.last_n_tick_storage = v.asUInt();
                } else if (v.isInt()) {
                    int i = v.asInt();
                    if (i < 0) {
                        error = "Negative integer is invalid for key 'last_n_tick_storage'";
                        return false;
                    }
                    out.last_n_tick_storage = static_cast<unsigned>(i);
                } else {
                    error = "Invalid type: unsigned integer required for key 'last_n_tick_storage'";
                    return false;
                }
            } else {
                if (out.last_n_tick_storage == 0) {
                    out.last_n_tick_storage = 1000;
                }
            }
        } else if (mode == "kvrocks") {
            out.tx_storage_mode = TxStorageMode::Kvrocks;

            // kvrocks_url (default tcp://127.0.0.1:6666) — reuse same URL
            if (root.isMember("kvrocks_url")) {
                if (!root["kvrocks_url"].isString()) {
                    error = "Invalid type: string required for key 'kvrocks_url'";
                    return false;
                }
                out.kvrocks_url = root["kvrocks_url"].asString();
            } else {
                if (out.kvrocks_url.empty()) {
                    out.kvrocks_url = "tcp://127.0.0.1:6666";
                }
            }

            // tx_tick_to_live (unsigned, ticks in RAM)
            if (root.isMember("tx_tick_to_live")) {
                const auto& v = root["tx_tick_to_live"];
                if (v.isUInt()) {
                    out.tx_tick_to_live = v.asUInt();
                } else if (v.isInt()) {
                    int i = v.asInt();
                    if (i < 0) {
                        error = "Negative integer is invalid for key 'tx_tick_to_live'";
                        return false;
                    }
                    out.tx_tick_to_live = static_cast<unsigned>(i);
                } else {
                    error = "Invalid type: unsigned integer required for key 'tx_tick_to_live'";
                    return false;
                }
            }
            else
            {
                out.tx_tick_to_live = 10000;
            }
        } else if (mode == "free") {
            out.tx_storage_mode = TxStorageMode::Free;
            // Do nothing; leave cleanup to keydb.
        } else {
            error = "Invalid value for 'tx_storage_mode': must be one of 'lastNTick', 'kvrocks', or 'free'";
            return false;
        }
    }

    if (root.isMember("kvrocks_ttl")) {
        const auto& v = root["kvrocks_ttl"];
        if (v.isNumeric())
        {
            out.kvrocks_ttl = v.asInt64();
        }
        else
        {
            error = "Invalid type: unsigned integer required for key 'kvrocks_ttl'";
            return false;
        }
    }

    if (root.isMember("wait_at_epoch_end")) {
        const auto& v = root["wait_at_epoch_end"];
        if (v.isNumeric())
        {
            out.wait_at_epoch_end = v.asInt64();
        }
        else
        {
            error = "Invalid type: unsigned integer required for key 'wait_at_epoch_end'";
            return false;
        }
    }

    if (root.isMember("allow_check_in_qubic_global")) {
        if (!root["allow_check_in_qubic_global"].isBool()) {
            error = "Invalid type: boolean required for key 'allow_check_in_qubic_global'";
            return false;
        }
        out.allow_check_in_qubic_global = root["allow_check_in_qubic_global"].asBool();
    }

    // persist_oracle_tx: when true, oracle tx data and log events are persisted (default: true)
    if (root.isMember("persist_oracle_tx")) {
        if (!root["persist_oracle_tx"].isBool()) {
            error = "Invalid type: boolean required for key 'persist_oracle_tx'";
            return false;
        }
        out.persist_oracle_tx = root["persist_oracle_tx"].asBool();
    } else {
        out.persist_oracle_tx = true;
    }

    // External-service URL overrides. All optional; defaults in AppConfig.
    if (root.isMember("peer_discovery_urls")) {
        if (!root["peer_discovery_urls"].isArray()) {
            error = "Invalid type: array required for key 'peer_discovery_urls'";
            return false;
        }
        out.peer_discovery_urls.clear();
        for (const auto& v : root["peer_discovery_urls"]) {
            if (!v.isString()) {
                error = "Invalid type: elements of 'peer_discovery_urls' must be strings";
                return false;
            }
            std::string s = v.asString();
            if (!s.empty()) out.peer_discovery_urls.emplace_back(std::move(s));
        }
    }
    if (root.isMember("current_tick_endpoints")) {
        if (!root["current_tick_endpoints"].isArray()) {
            error = "Invalid type: array required for key 'current_tick_endpoints'";
            return false;
        }
        out.current_tick_endpoints.clear();
        for (const auto& v : root["current_tick_endpoints"]) {
            if (!v.isObject() || !v.isMember("url") || !v["url"].isString()) {
                error = "Each 'current_tick_endpoints' entry must be {url, path, shape}";
                return false;
            }
            AppConfig::TickEndpoint t;
            t.url   = v["url"].asString();
            t.path  = v.isMember("path")  && v["path"].isString()  ? v["path"].asString()  : "/currenttick";
            t.shape = v.isMember("shape") && v["shape"].isString() ? v["shape"].asString() : "flat";
            if (!t.url.empty()) out.current_tick_endpoints.emplace_back(std::move(t));
        }
    }
    if (root.isMember("state_files_urls")) {
        if (!root["state_files_urls"].isArray()) {
            error = "Invalid type: array required for key 'state_files_urls'";
            return false;
        }
        out.state_files_urls.clear();
        for (const auto& v : root["state_files_urls"]) {
            if (!v.isString()) {
                error = "Invalid type: elements of 'state_files_urls' must be strings";
                return false;
            }
            std::string s = v.asString();
            if (!s.empty()) out.state_files_urls.emplace_back(std::move(s));
        }
    } else if (root.isMember("state_files_url")) {
        // Back-compat: accept the single-URL form. Promotes to a 1-element
        // failover list internally.
        if (!root["state_files_url"].isString()) {
            error = "Invalid type: string required for key 'state_files_url'";
            return false;
        }
        out.state_files_urls.clear();
        std::string s = root["state_files_url"].asString();
        if (!s.empty()) out.state_files_urls.emplace_back(std::move(s));
    }
    if (root.isMember("checkin_url")) {
        if (!root["checkin_url"].isString()) {
            error = "Invalid type: string required for key 'checkin_url'";
            return false;
        }
        out.checkin_url = root["checkin_url"].asString();
    }

    if (out.tick_storage_mode == TickStorageMode::LastNTick)
    {
        if (out.tx_storage_mode != TxStorageMode::LastNTick && out.tx_storage_mode != TxStorageMode::Free)
        {
            error = "Conflicted tick and tx storage mode. tick_storage_mode => LastNTick requires tx_storage_mode => LastNTick|Free";
            return false;
        }
    }

    if (out.tick_storage_mode == TickStorageMode::Kvrocks)
    {
        if (out.tx_storage_mode != TxStorageMode::Kvrocks && out.tx_storage_mode != TxStorageMode::Free)
        {
            error = "Conflicted tick and tx storage mode. tick_storage_mode => kvrocks requires tx_storage_mode => kvrocks|Free";
            return false;
        }
    }


    return true;
}
