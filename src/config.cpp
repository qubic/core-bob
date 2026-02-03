#include "config.h"
#include "json/reader.h"
#include <fstream>
#include <json/json.h>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

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

    Json::Value root;
    std::string errs;
    if (!reader->parse(json.data(), json.data() + json.size(), &root, &errs)) {
        error = "invalid JSON: " + errs;
        return false;
    }

    if (!root.isObject()) {
        error = "invalid JSON: root must be an object";
        return false;
    }

    // merge 'p2p-node' to trusted node
    if (root.isMember("p2p-node")) {
        if (!root["p2p-node"].isArray()) {
            error = "Invalid type: array required for key 'p2p-node'";
            return false;
        }
        for (const auto& v : root["p2p-node"]) {
            if (!v.isString()) {
                error = "Invalid type: elements of 'p2p-node' must be strings";
                return false;
            }
            out.p2p_nodes.emplace_back(v.asString());
        }
    }

    // Optional fields (use defaults from AppConfig if absent)
    if (root.isMember("log-level")) {
        if (!root["log-level"].isString()) {
            error = "Invalid type: string required for key 'log-level'";
            return false;
        }
        out.log_level = root["log-level"].asString();
    }

    if (root.isMember("keydb-url")) {
        if (!root["keydb-url"].isString()) {
            error = "Invalid type: string required for key 'keydb-url'";
            return false;
        }
        out.keydb_url = root["keydb-url"].asString();
    }

    if (root.isMember("arbitrator-identity")) {
        if (!root["arbitrator-identity"].isString()) {
            error = "Invalid type: string required for key 'arbitrator-identity'";
            return false;
        }
        out.arbitrator_identity = root["arbitrator-identity"].asString();
    }
    else
    {
        error = "string required for key 'arbitrator-identity'";
        return false;
    }

    if (root.isMember("run-server")) {
        if (!root["run-server"].isBool()) {
            error = "Invalid type: boolean required for key 'run-server'";
            return false;
        }
        out.run_server = root["run-server"].asBool();
    }

    if (root.isMember("allow-receive-log-from-incoming-connections")) {
        if (!root["allow-receive-log-from-incoming-connections"].isBool()) {
            error = "Invalid type: boolean required for key 'allow-receive-log-from-incoming-connections'";
            return false;
        }
        out.allow_receive_log_from_incoming_connections = root["allow-receive-log-from-incoming-connections"].asBool();
    }

    if (root.isMember("is-testnet")) {
        if (!root["is-testnet"].isBool()) {
            error = "Invalid type: boolean required for key 'is-testnet'";
            return false;
        }
        out.is_testnet = root["is-testnet"].asBool();
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

    if (!validate_uint("request-cycle-ms", out.request_cycle_ms)) return false;
    if (!validate_uint("request-logging-cycle-ms", out.request_logging_cycle_ms)) return false;
    if (!validate_uint("future-offset", out.future_offset)) return false;
    if (!validate_uint("server-port", out.server_port)) return false;
    if (!validate_uint("rpc-port", out.rpc_port)) return false;

    // Enable admin endpoints (default false)
    if (root.isMember("enable-admin-endpoints")) {
        if (!root["enable-admin-endpoints"].isBool()) {
            error = "Invalid type: boolean required for key 'enable-admin-endpoints'";
            return false;
        }
        out.enable_admin_endpoints = root["enable-admin-endpoints"].asBool();
    }

    // Maximum threads the system can use (0 means auto/unlimited)
    if (!validate_uint("max-thread", out.max_thread)) return false;
    if (out.max_thread == 0)
    {
        out.max_thread = std::thread::hardware_concurrency();
    }

    // Spam/Junk QU transfer detection threshold (default 0)
    if (!validate_uint("spam-qu-threshold", out.spam_qu_threshold)) return false;

    if (root.isMember("node-seed")) {
        if (!root["node-seed"].isString()) {
            error = "Invalid type: string required for key 'node-seed'";
            return false;
        }
        out.node_seed = root["node-seed"].asString();
    } else {
        out.node_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }

    if (root.isMember("node-alias")) {
        if (!root["node-alias"].isString()) {
            error = "Invalid type: string required for key 'node-alias'";
            return false;
        }
        out.nodeAlias = root["node-alias"].asString();
    }

    // Parse 'tick-storage-mode' and related options
    {
        std::string mode = "lastNTick";
        if (root.isMember("tick-storage-mode")) {
            if (!root["tick-storage-mode"].isString()) {
                error = "Invalid type: string required for key 'tick-storage-mode'";
                return false;
            }
            mode = root["tick-storage-mode"].asString();
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

            // kvrocks-url (default tcp://127.0.0.1:6666)
            if (root.isMember("kvrocks-url")) {
                if (!root["kvrocks-url"].isString()) {
                    error = "Invalid type: string required for key 'kvrocks-url'";
                    return false;
                }
                out.kvrocks_url = root["kvrocks-url"].asString();
            } else {
                if (out.kvrocks_url.empty()) {
                    out.kvrocks_url = "tcp://127.0.0.1:6666";
                }
            }
        } else if (mode == "free") {
            out.tick_storage_mode = TickStorageMode::Free;
            // No related options; implies no garbage cleaner.
        } else {
            error = "Invalid value for 'tick-storage-mode': must be one of 'lastNTick', 'kvrocks', or 'free'";
            return false;
        }
    }

    // Parse 'tx-storage-mode' and related options
    {
        std::string mode = "lastNTick";
        if (root.isMember("tx-storage-mode")) {
            if (!root["tx-storage-mode"].isString()) {
                error = "Invalid type: string required for key 'tx-storage-mode'";
                return false;
            }
            mode = root["tx-storage-mode"].asString();
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

            // kvrocks-url (default tcp://127.0.0.1:6666) — reuse same URL
            if (root.isMember("kvrocks-url")) {
                if (!root["kvrocks-url"].isString()) {
                    error = "Invalid type: string required for key 'kvrocks-url'";
                    return false;
                }
                out.kvrocks_url = root["kvrocks-url"].asString();
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
            error = "Invalid value for 'tx-storage-mode': must be one of 'lastNTick', 'kvrocks', or 'free'";
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

    if (root.isMember("allow-check-in-qubic-global")) {
        if (!root["allow-check-in-qubic-global"].isBool()) {
            error = "Invalid type: boolean required for key 'allow-check-in-qubic-global'";
            return false;
        }
        out.allow_check_in_qubic_global = root["allow-check-in-qubic-global"].asBool();
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
