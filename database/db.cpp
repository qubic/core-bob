#include "db.h"
#include "sw/redis++/redis++.h"
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>
#include <future>
#include "zstd.h" // zstd compression/decompression
#include "Logger.h"
#include "K12AndKeyUtil.h"
#include <cstdlib> // std::exit
#include "shim.h"
// Global Redis client handle
static std::unique_ptr<sw::redis::Redis> g_redis = nullptr;
static std::unique_ptr<sw::redis::Redis> g_kvrocks = nullptr;

void db_connect(const std::string& connectionString) {
    if (g_redis) {
        Logger::get()->info("Database connection already open.\n");
        return;
    }
    try {
        // Ensure a Redis connection pool with 16 connections is used.
        // redis++ supports configuring pool size via URI query parameter `pool_size`.
        std::string uri_with_pool = connectionString;
        if (uri_with_pool.find('?') == std::string::npos) {
            uri_with_pool += "?pool_size=32";
        } else {
            uri_with_pool += "&pool_size=32";
        }

        g_redis = std::make_unique<sw::redis::Redis>(uri_with_pool);
        g_redis->ping();
    } catch (const sw::redis::Error& e) {
        g_redis.reset();
        throw std::runtime_error("Cannot connect to KeyDB: " + std::string(e.what()));
        exit(1);
    }
    Logger::get()->trace("Connected to DB!");
}

void db_close() {
    g_redis.reset();
    Logger::get()->info("Closed keydb DB connections");
}

bool db_insert_tick_vote(const TickVote& vote) {
    if (!g_redis) return false;
    try {
        std::string key = "tick_vote:" + std::to_string(vote.tick) + ":" + std::to_string(vote.computorIndex);
        sw::redis::StringView val(reinterpret_cast<const char *>(&vote), sizeof(vote));
        g_redis->set(key, val, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_tick_data(const TickData& data) {
    if (!g_redis) return false;
    try {
        std::string key = "tick_data:" + std::to_string(data.tick);
        sw::redis::StringView val(reinterpret_cast<const char*>(&data), sizeof(data));
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_transaction(const Transaction* tx) {
    if (!g_redis) return false;
    try {
        size_t tx_size = sizeof(Transaction) + tx->inputSize + SIGNATURE_SIZE;
        char hash[64] = {0};
        getQubicHash(reinterpret_cast<const unsigned char*>(tx), tx_size, hash);
        std::string hash_str(hash);
        // Store by transaction hash only; tick is no longer part of the key.
        std::string key = "transaction:" + hash_str;
        sw::redis::StringView val(reinterpret_cast<const char*>(tx), tx_size);
        g_redis->set(key, val, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_delete_transaction(std::string hash)
{
    if (!g_redis) return false;
    try {
        std::string key = "transaction:" + hash;
        g_redis->unlink(key);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_delete_logs(uint16_t epoch, long long start, long long end)
{
    if (!g_redis) return false;
    try {
        for (long long i = start; i <= end; i++)
        {
            std::string key = "log:" +
                              std::to_string(epoch) + ":" +
                              std::to_string(i);
            g_redis->unlink(key);
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_log(uint16_t epoch, uint32_t tick, uint64_t logId, int logSize, const uint8_t* content) {
    if (!g_redis) return false;
    try {
        std::string key = "log:" +
                          std::to_string(epoch) + ":" +
                          std::to_string(logId);
        // Store the raw log bytes directly as the key value instead of using a hash field.
        sw::redis::StringView val(reinterpret_cast<const char*>(content), static_cast<size_t>(logSize));
        g_redis->set(key, val, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST);
        // Removed: stop tracking per-tick log index (log_index:<epoch>:<tick>)
        // std::string index_key = "log_index:" + std::to_string(epoch) + ":" + std::to_string(tick);
        // g_redis->sadd(index_key, key);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_insert_log_range(uint32_t tick, const LogRangesPerTxInTick& logRange) {
    if (!g_redis) return false;
    try {
        std::string key_struct = "log_ranges:" + std::to_string(tick);
        if (isArrayZero((uint8_t*)&logRange, sizeof(LogRangesPerTxInTick)))
        {
            return false;
        }
        // Compute min/max and store under a per-tick summary key
        long long min_log_id = INTMAX_MAX;
        long long max_log_id = -1;
        for (size_t i = 0; i < LOG_TX_PER_TICK; ++i) {
            if (logRange.fromLogId[i] == -1 || logRange.length[i] == -1) continue;
            min_log_id = std::min(min_log_id, logRange.fromLogId[i]);
            max_log_id = std::max(max_log_id, logRange.fromLogId[i] + logRange.length[i]);
            if (logRange.fromLogId[i] < -1)
            {
//                Logger::get()->error("Log ranges have invalid value: tick {} logRange.fromLogId[i] {}", tick, logRange.fromLogId[i]);
                return false;
            }
            if (logRange.length[i] < -1)
            {
//                Logger::get()->error("Log ranges have invalid value: tick {} logRange.length[i] {}", tick, logRange.length[i]);
                return false;
            }
            //TODO: track END_EPOCH log range
        }

        if (min_log_id == INTMAX_MAX) {
            min_log_id = -1;
            max_log_id = -1;
        }

        // Store the whole struct for the tick
        sw::redis::StringView val(reinterpret_cast<const char*>(&logRange), sizeof(LogRangesPerTxInTick));
        g_redis->set(key_struct, val, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST);

        std::string key_summary = "tick_log_range:" + std::to_string(tick);
        std::unordered_map<std::string, std::string> fields;
        fields["fromLogId"] = std::to_string(min_log_id);
        fields["length"] = (min_log_id == -1) ? std::to_string(-1) : std::to_string(max_log_id - min_log_id);
        g_redis->hmset(key_summary, fields.begin(), fields.end());
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_insert_log_range: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_check_log_range(uint32_t tick)
{
    if (!g_redis) return false;
    try {
        std::string key = "log_ranges:" + std::to_string(tick);
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in check_log_range: {}\n", e.what());
        return false;
    }
    return false;
}

bool db_log_exists(uint16_t epoch, uint64_t logId) {
    if (!g_redis) return false;
    try {
        std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_log_exists: {}\n", e.what());
        return false;
    }
    return false;
}

bool _db_get_log_ranges(uint32_t tick, LogRangesPerTxInTick &logRange) {
    if (!g_redis) return false;
    try {
        // Default to -1s
        memset(&logRange, -1, sizeof(LogRangesPerTxInTick));

        // Fetch the whole struct for the tick
        std::string key = "log_ranges:" + std::to_string(tick);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (sizeof(LogRangesPerTxInTick) - val->size() == 16) // oracle machine logging mismatches
        {
            struct {
                long long fromLogId[1024+5];
                long long length[1024+5];
            } old_struct;
            memcpy(&old_struct, val->data(), val->size());
            memset(&logRange, 0, sizeof(logRange));
            for (int i = 0; i < 1024+5; i++)
            {
                logRange.fromLogId[i] = old_struct.fromLogId[i];
                logRange.length[i] = old_struct.length[i];
            }
            return true;
        }
        if (val->size() != sizeof(LogRangesPerTxInTick)) {
            Logger::get()->warn("LogRange size mismatch for key {}: got {}, expected {}",
                                key.c_str(), val->size(), sizeof(LogRangesPerTxInTick));
            return false;
        }
        memcpy((void*)&logRange, val->data(), sizeof(LogRangesPerTxInTick));
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_try_get_log_ranges: {}\n", e.what());
        return false;
    }
    return false;
}

bool db_delete_log_ranges(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const std::string key = "log_ranges:" + std::to_string(tick);
        g_redis->unlink(key);

        const std::string key_log_range = "tick_log_range:" + std::to_string(tick);
        g_redis->unlink(key_log_range);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_delete_log_ranges: {}\n", e.what());
        return false;
    }
}


bool db_try_get_log_ranges(uint32_t tick, LogRangesPerTxInTick &logRange)
{
    if (_db_get_log_ranges(tick, logRange))
    {
        return true;
    }
    if (db_get_cLogRange_from_kvrocks(tick, logRange))
    {
        return true;
    }
    return false;
}

bool db_try_get_log_range_for_tick(uint32_t tick, long long& fromLogId, long long& length) {
    fromLogId = -1;
    length = -1;

    auto fetchFromDB = [&](sw::redis::Redis* db) -> bool {
        if (!db) return false;
        try {
            const std::string key = "tick_log_range:" + std::to_string(tick);
            std::vector<sw::redis::Optional<std::string>> vals;
            db->hmget(key, {"fromLogId", "length"}, std::back_inserter(vals));
            if (vals.size() == 2 && vals[0] && vals[1]) {
                long long min_id = std::stoll(*vals[0]);
                long long len = std::stoll(*vals[1]);
                if (min_id == -1 || len == -1) {
                    fromLogId = -1;
                    length = -1;
                    return true;
                }
                fromLogId = min_id;
                length = len; // length already stored as (max_log_id - min_log_id)
                return true;
            }
            return false;
        } catch (const sw::redis::Error &e) {
            Logger::get()->error("Redis error in db_try_get_log_range_for_tick: {}\n", e.what());
            return false;
        } catch (const std::logic_error &e) {
            Logger::get()->error("Parsing error in db_try_get_log_range_for_tick: {}\n", e.what());
            return false;
        }
    };

    if (g_redis && fetchFromDB(g_redis.get())) return true;
    if (g_kvrocks && fetchFromDB(g_kvrocks.get())) return true;

    return false;
}


bool
db_get_combined_log_range_for_ticks(uint32_t startTick, uint32_t endTick, long long &fromLogId, long long &length) {
    fromLogId = -1;
    length = -1;
    if (!g_redis || startTick > endTick) return false;

    long long minId = LLONG_MAX;
    long long maxId = -1;

    for (uint32_t tick = startTick; tick <= endTick; tick++) {
        long long tickFromId, tickLength;
        if (!db_try_get_log_range_for_tick(tick, tickFromId, tickLength)) {
            continue;
        }
        if (tickFromId != -1 && tickLength != -1) {
            minId = std::min(minId, tickFromId);
            maxId = std::max(maxId, tickFromId + tickLength);
        }
    }

    if (minId == LLONG_MAX || maxId == -1) {
        fromLogId = -1;
        length = -1;
    } else {
        fromLogId = minId;
        length = maxId - minId;
    }

    return true;
}

bool db_update_latest_tick_and_epoch(uint32_t tick, uint16_t epoch) {
    if (!g_redis) return false;
    try {
        const char* script = R"lua(
local new_tick = tonumber(ARGV[1])
local current_tick = tonumber(redis.call('hget', KEYS[1], 'latest_tick')) or 0
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'latest_tick', new_tick, 'latest_epoch', ARGV[2])
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick), std::to_string(epoch)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_get_latest_tick_and_epoch(uint32_t& tick, uint16_t& epoch)
{
    if (!g_redis) return false;
    try {
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget("db_status", {"latest_tick", "latest_epoch"}, std::back_inserter(vals));

        tick = 0;
        epoch = 0;

        if (vals.size() > 0 && vals[0]) {
            tick = std::stoul(*vals[0]);
        }
        if (vals.size() > 1 && vals[1]) {
            epoch = std::stoi(*vals[1]);
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error& e) {
        Logger::get()->error("Parsing error while getting latest tick/epoch: {}\n", e.what());
        return false;
    }
    return true;
}

/*LOGGING EVENTS*/

bool db_update_latest_event_tick_and_epoch(uint32_t tick, uint16_t epoch) {
    if (!g_redis) return false;
    try {
        g_redis->hset("db_status",
                      std::initializer_list<std::pair<std::string, std::string>>{
                              {"latest_event_tick", std::to_string(tick)},
                              {"latest_event_epoch", std::to_string(epoch)}
                      });
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_get_latest_event_tick_and_epoch(uint32_t& tick, uint16_t& epoch)
{
    if (!g_redis) return false;
    try {
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget("db_status", {"latest_event_tick", "latest_event_epoch"}, std::back_inserter(vals));

        tick = 0;
        epoch = 0;

        if (vals.size() > 0 && vals[0]) {
            tick = std::stoul(*vals[0]);
        }
        if (vals.size() > 1 && vals[1]) {
            epoch = std::stoi(*vals[1]);
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error& e) {
        Logger::get()->error("Parsing error while getting latest event tick/epoch: {}\n", e.what());
        return false;
    }
    return true;
}

bool db_get_end_epoch_log_range(uint16_t epoch, long long &fromLogId, long long &length) {
    fromLogId = -1;
    length = -1;
    if (!g_redis) return false;
    try {
        const std::string key = "end_epoch:tick_log_range:" + std::to_string(epoch);
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget(key, {"fromLogId", "length"}, std::back_inserter(vals));
        if (vals.size() == 2 && vals[0] && vals[1]) {
            fromLogId = std::stoll(*vals[0]);
            length = std::stoll(*vals[1]);
            return true;
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_end_epoch_log_range: {}\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error in db_get_end_epoch_log_range: {}\n", e.what());
    }
    return false;
}

bool db_update_latest_log_id(uint16_t epoch, long long logId) {
    if (!g_redis) return false;
    try {
        const std::string key = "db_status:epoch:" + std::to_string(epoch);
        const char *script = R"lua(
local current_id = tonumber(redis.call('hget', KEYS[1], 'latest_log_id')) or -1
local new_id = tonumber(ARGV[1]) or -1
if new_id > current_id then
    redis.call('hset', KEYS[1], 'latest_log_id', new_id)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {key};
        std::vector<std::string> args = {std::to_string(logId)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return false;
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error in db_update_latest_log_id: {}\n", e.what());
        return false;
    }
    return true;
}

long long db_get_latest_log_id(uint16_t epoch) {
    if (!g_redis) return -1;
    try {
        const std::string key = "db_status:epoch:" + std::to_string(epoch);
        auto result = g_redis->hget(key, "latest_log_id");
        if (result) {
            return std::stoll(*result);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_latest_log_id: {}\n", e.what());
    } catch (const std::exception &e) {
        Logger::get()->error("Exception in db_get_latest_log_id: {}\n", e.what());
    }
    return -1;
}

bool db_update_latest_verified_tick(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const char *script = R"lua(
local current_tick = tonumber(redis.call('hget', KEYS[1], 'latest_verified_tick')) or -1
local new_tick = tonumber(ARGV[1])
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'latest_verified_tick', new_tick)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_update_latest_verified_tick: {}\n", e.what());
        return false;
    }
    return false;
}


long long db_get_latest_verified_tick() {
    if (!g_redis) return -1;
    try {
        auto val = g_redis->hget("db_status", "latest_verified_tick");
        if (val) {
            return std::stoll(*val);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_latest_verified_tick: {}\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error while getting latest verified tick: {}\n", e.what());
    }
    return -1;
}

bool _db_get_log(uint16_t epoch, uint64_t logId, LogEvent &log) {
    if (!g_redis) return false;
    log.clear();
    try {
        std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        // Store raw bytes directly into LogEvent
        log.updateContent(reinterpret_cast<const uint8_t*>(val->data()), static_cast<int>(val->size()));

        // Basic sanity: header must exist and match epoch/logId
        if (!log.hasPackedHeader()) {
            Logger::get()->warn("db_try_get_log: value too small for header at key {}", key);
            return false;
        }
        if (log.getEpoch() != epoch || log.getLogId() != logId) {
            Logger::get()->warn("db_try_get_log: header mismatch for key {}, got epoch {}, logId {}", key, log.getEpoch(), log.getLogId());
            // Not fatal, but indicate bad record
            return false;
        }
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_try_get_log: {}\n", e.what());
        return false;
    }
}

bool db_try_get_log(uint16_t epoch, uint64_t logId, LogEvent &log)
{
    // Try redis first
    if (_db_get_log(epoch, logId, log)) {
        return true;
    }

    // Fall back to kvrocks
    if (!g_kvrocks) return false;
    try {
        const std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);
        auto val = g_kvrocks->get(key);
        if (!val) {
            return false;
        }
        log.updateContent(reinterpret_cast<const uint8_t *>(val->data()), static_cast<int>(val->size()));

        // Basic sanity: header must exist and match epoch/logId
        if (!log.hasPackedHeader()) {
            Logger::get()->warn("db_try_get_log: value too small for header at key {}", key);
            return false;
        }
        if (log.getEpoch() != epoch || log.getLogId() != logId) {
            Logger::get()->warn("db_try_get_log: header mismatch for key {}, got epoch {}, logId {}",
                                key, log.getEpoch(), log.getLogId());
            return false;
        }
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Kvrocks error in db_try_get_log: {}\n", e.what());
        return false;
    }
}

std::vector<LogEvent> db_try_get_logs(uint16_t epoch, long long logIdStart, long long logIdEnd)
{
    std::vector<LogEvent> results;
    for (long long l = logIdStart; l <= logIdEnd; l++)
    {
        LogEvent le;
        if (db_try_get_log(epoch, l, le))
        {
            results.push_back(le);
        }
    }
    return results;
}

std::vector<LogEvent> db_get_logs_by_tick_range(uint16_t epoch, uint32_t start_tick, uint32_t end_tick, bool& success) {
    success = false;
    std::vector<LogEvent> out;
    if (!g_redis) return out;

    try {
        // We rely on the aggregated range for each tick in [start_tick, end_tick].
        // For each tick, read tick_log_range:<tick> which stores (fromLogId, length) in the new compact format,
        // then fetch logs "log:<epoch>:<logId>" for that contiguous id range.
        const std::size_t kChunkSize = 1024;

        for (uint32_t tick = start_tick; tick <= end_tick; ++tick) {
            long long fromLogId = -1;
            long long length = -1;
            if (!db_try_get_log_range_for_tick(tick, fromLogId, length)) {
                // On parsing/redis error: skip this tick.
                return out;
            }
            if (fromLogId == -1 || length == -1 || length == 0) {
                // No logs for this tick; continue.
                continue;
            }

            // Fetch in chunks to avoid oversized commands.
            const uint64_t startId = static_cast<uint64_t>(fromLogId);
            const uint64_t endId = static_cast<uint64_t>(fromLogId + length - 1);
            auto logs = db_try_get_logs(epoch, startId, endId);
            // Convert to LogEvent and filter by header
            int i = 0;
            for (const auto& le: logs) {
                // Basic header validation and range filter
                if (!le.hasPackedHeader())
                {
                    Logger::get()->critical("Log event {} has broken header", startId + i);
                    out.clear();
                    return out;
                }
                if (le.getEpoch() != epoch)
                {
                    Logger::get()->critical("Log event {} has broken epoch {}", startId + i, le.getEpoch());
                    out.clear();
                    return out;
                }

                const auto t = le.getTick();
                if (t < start_tick || t > end_tick)
                {
                    Logger::get()->critical("Log event {} has wrong tick {}", startId + i, le.getTick());
                    out.clear();
                    return out;
                }

                // Optional strict self-check against expected tick
                if (!le.selfCheck(epoch))
                {
                    Logger::get()->critical("Log event {} failed the selfcheck", startId + i);
                    out.clear();
                    return out;
                }
                i++;
                out.emplace_back(std::move(le));
            }
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_logs_by_tick_range: {}\n", e.what());
        out.clear();
        return out;
    } catch (const std::exception& e) {
        Logger::get()->error("Exception in db_get_logs_by_tick_range: {}\n", e.what());
        out.clear();
        return out;
    }
    success = true;
    return out;
}


long long db_get_tick_vote_count(uint32_t tick) {
    if (!g_redis) return -1;
    try {
        // Deterministic bounded check: keys tick_vote:<tick>:0..675
        constexpr int MAX_COMPUTORS = 676;
        constexpr int BATCH_SIZE = 128; // smaller, short-lived operations

        long long count = 0;
        const std::string prefix = "tick_vote:" + std::to_string(tick) + ":";

        std::vector<std::string> keys;
        keys.reserve(BATCH_SIZE);

        for (int start = 0; start < MAX_COMPUTORS; start += BATCH_SIZE) {
            const int end = std::min(MAX_COMPUTORS, start + BATCH_SIZE);

            keys.clear();
            for (int i = start; i < end; ++i) {
                keys.emplace_back(prefix + std::to_string(i));
            }

            std::vector<sw::redis::OptionalString> vals;
            vals.reserve(keys.size());

            // MGET for a short chunk to avoid holding a connection too long.
            g_redis->mget(keys.begin(), keys.end(), std::back_inserter(vals));

            for (const auto &opt : vals) {
                if (opt) {
                    ++count;
                }
            }
        }
        return count;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error: {}\n", e.what());
        return -1;
    }
}


bool db_get_tick_vote(uint32_t tick, uint16_t computorIndex, TickVote& vote) {
    if (!g_redis) return false;
    try {
        // Key is unique; fetch directly.
        const std::string key = "tick_vote:" + std::to_string(tick) + ":" + std::to_string(computorIndex);
        auto val = g_redis->get(key);
        if (val && val->size() == sizeof(TickVote)) {
            memcpy((void*)&vote, val->data(), sizeof(TickVote));
            return true;
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_vote: {}\n", e.what());
    }
    return false;
}

std::vector<TickVote> db_get_tick_votes(uint32_t tick) {
    std::vector<TickVote> votes;
    if (!g_redis) return votes;
    try {
        // Deterministic bounded fetch: keys tick_vote:<tick>:0..675
        constexpr int MAX_COMPUTORS = 676;
        constexpr int BATCH_SIZE = 128; // small chunks to avoid long-lived ops

        votes.reserve(MAX_COMPUTORS);

        const std::string prefix = "tick_vote:" + std::to_string(tick) + ":";

        std::vector<std::string> keys;
        keys.reserve(BATCH_SIZE);

        for (int start = 0; start < MAX_COMPUTORS; start += BATCH_SIZE) {
            const int end = std::min(MAX_COMPUTORS, start + BATCH_SIZE);

            keys.clear();
            for (int i = start; i < end; ++i) {
                keys.emplace_back(prefix + std::to_string(i));
            }

            std::vector<sw::redis::OptionalString> vals;
            vals.reserve(keys.size());

            // MGET for a short chunk
            g_redis->mget(keys.begin(), keys.end(), std::back_inserter(vals));

            for (const auto &opt : vals) {
                if (!opt) continue;
                const auto &s = *opt;
                if (s.size() != sizeof(TickVote)) continue;

                TickVote vote{};
                std::memcpy((void*)&vote, s.data(), sizeof(TickVote));
                votes.push_back(vote);
            }
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_votes: {}\n", e.what());
    }
    return votes;
}

bool db_get_tick_data(uint32_t tick, TickData& data) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (val->size() != sizeof(TickData)) {
            Logger::get()->warn("TickData size mismatch for key {}: got {}, expected {}",
                                key.c_str(), val->size(), sizeof(TickData));
            return false;
        }
        memcpy((void*)&data, val->data(), sizeof(TickData));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_tick_data: {}\n", e.what());
    }
    return false;
}

bool _db_get_transaction(const std::string& tx_hash, std::vector<uint8_t>& tx_data) {
    if (!g_redis) return false;
    try {
        // Tick is no longer used in the key; fetch by hash only.
        const std::string key = "transaction:" + tx_hash;
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        tx_data.assign(val->begin(), val->end());
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_try_get_transaction (by hash, tick ignored): {}\n", e.what());
    }
    return false;
}

bool db_try_get_transaction(const std::string& tx_hash, std::vector<uint8_t>& tx_data) {
    // Try redis first
    if (_db_get_transaction(tx_hash, tx_data)) {
        return true;
    }

    // Fall back to kvrocks
    if (!g_kvrocks) return false;
    try {
        const std::string key = "transaction:" + tx_hash;
        auto val = g_kvrocks->get(key);
        if (!val) {
            return false;
        }
        tx_data.assign(val->begin(), val->end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Kvrocks error in db_try_get_transaction: {}\n", e.what());
    }
    return false;
}


bool db_check_transaction_exist(const std::string& tx_hash) {
    if (!g_redis) return false;
    try {
        const std::string key = "transaction:" + tx_hash;
        return g_redis->exists(key);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_check_transaction_exist: {}\n", e.what());
    }
    return false;
}


bool db_has_tick_data(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        const std::string key2 = "vtick:" + std::to_string(tick);
        return g_redis->exists(key) || g_redis->exists(key2);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_has_tick_data: {}\n", e.what());
        return false;
    }
    return false;
}

std::vector<TickVote> db_get_tick_votes_from_vtick(uint32_t tick) {
    std::vector<TickVote> votes;
    if (!g_redis) return votes;

    try {
        FullTickStruct fts;
        if (!db_get_vtick_from_kvrocks(tick, fts)) {
            return votes;
        }

        for (const auto &vote: fts.tv) {
            votes.push_back(vote);
        }
        return votes;
    } catch (const std::exception &e) {
        Logger::get()->error("Error in db_get_tick_votes_from_vtick: {}\n", e.what());
        votes.clear();
        return votes;
    }
}

std::vector<TickVote> db_try_to_get_votes(uint32_t tick) {
    auto votes = db_get_tick_votes(tick);
    if (votes.empty()) {
        votes = db_get_tick_votes_from_vtick(tick);
    }
    return votes;
}

// Store the whole Computors struct per epoch; key = "computor:<epoch>"
bool db_insert_computors(const Computors& comps) {
    if (!g_redis) return false;
    try {
        sw::redis::StringView val(reinterpret_cast<const char*>(&comps), sizeof(Computors));
        std::string key = "computor:" + std::to_string(comps.epoch);
        g_redis->set(key, val);
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_insert_computors: {}\n", e.what());
        return false;
    }
    return true;
}

// Retrieve the whole Computors struct by epoch; key = "computor:<epoch>"
bool db_get_computors(uint16_t epoch, Computors& comps) {
    if (!g_redis) return false;
    try {
        const std::string key = "computor:" + std::to_string(epoch);
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (val->size() != sizeof(Computors)) {
            Logger::get()->warn("Computors size mismatch for key {}: got {}, expected {}",
                                key.c_str(), val->size(), sizeof(Computors));
            return false;
        }
        std::memcpy((void*)&comps, val->data(), sizeof(Computors));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_computors: {}\n", e.what());
        return false;
    }
    return false;
}

bool db_delete_tick_data(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const std::string key = "tick_data:" + std::to_string(tick);
        g_redis->unlink(key);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_delete_tick_data: {}\n", e.what());
        return false;
    }
}

bool db_delete_tick_vote(uint32_t tick) {
    if (!g_redis) return false;
    try {
        // Delete all tick vote records for computor indices 0-675
        constexpr int MAX_COMPUTORS = 676;
        const std::string prefix = "tick_vote:" + std::to_string(tick) + ":";

        std::vector<std::string> keys;
        keys.reserve(MAX_COMPUTORS);

        // Build deterministic set of keys to delete
        for (int i = 0; i < MAX_COMPUTORS; i++) {
            keys.push_back(prefix + std::to_string(i));
        }

        if (!keys.empty()) {
            g_redis->unlink(keys.begin(), keys.end());
        }
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_delete_tick_vote: {}\n", e.what());
        return false;
    }
}

long long db_get_last_indexed_tick() {
    if (!g_redis) return -1;
    try {
        auto val = g_redis->hget("db_status", "last_indexed_tick");
        if (val) {
            return std::stoll(*val);
        }
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_last_indexed_tick: {}\n", e.what());
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error while getting last_indexed_tick: {}\n", e.what());
    }
    return -1;
}

bool db_update_last_indexed_tick(uint32_t tick) {
    if (!g_redis) return false;
    try {
        const char *script = R"lua(
local current_tick = tonumber(redis.call('hget', KEYS[1], 'last_indexed_tick')) or -1
local new_tick = tonumber(ARGV[1])
if new_tick > current_tick then
    redis.call('hset', KEYS[1], 'last_indexed_tick', new_tick)
    return 1
end
return 0
)lua";
        std::vector<std::string> keys = {"db_status"};
        std::vector<std::string> args = {std::to_string(tick)};
        g_redis->eval<long long>(script, keys.begin(), keys.end(), args.begin(), args.end());
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_update_last_indexed_tick: {}\n", e.what());
        return false;
    }
}

bool db_add_indexer(const std::string &key, uint32_t tickNumber)
{
    if (!g_redis) return false;
    try {
        const std::string member = std::to_string(tickNumber);
        g_redis->zadd(key, member, static_cast<double>(tickNumber), sw::redis::UpdateType::NOT_EXIST);
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_add_indexer: {}\n", e.what());
        return false;
    }
}


bool db_set_indexed_tx(const char *key,
                       int tx_index,
                       long long from_log_id,
                       long long to_log_id,
                       uint64_t timestamp,
                       bool isExecuted) {
    if (!g_redis) return false;
    try {
        indexedTxData data{
            static_cast<int32_t>(tx_index),
            isExecuted,
            static_cast<int64_t>(from_log_id),
            static_cast<int64_t>(to_log_id),
            static_cast<uint64_t>(timestamp)
        };
        sw::redis::StringView val(reinterpret_cast<const char*>(&data), sizeof(data));
        g_redis->set(key, val);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_set_indexed_tx: {}", e.what());
        return false;
    }
}

bool db_get_indexed_tx(const char* tx_hash,
                       int& tx_index,
                       long long& from_log_id,
                       long long& to_log_id,
                       uint64_t& timestamp,
                       bool& executed) {
    if (!g_redis) return false;
    try {
        // Indexed TX stored under "itx:<hash>"
        std::string key = std::string("itx:") + tx_hash;
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        if (val->size() != sizeof(indexedTxData)) {
            Logger::get()->warn("db_get_indexed_tx: size mismatch for key {}. got={}, expected={}",
                                key, val->size(), sizeof(indexedTxData));
            return false;
        }

        indexedTxData data{};
        memcpy(&data, val->data(), sizeof(indexedTxData));

        tx_index     = static_cast<int>(data.tx_index);
        executed     = data.isExecuted;
        from_log_id  = static_cast<long long>(data.from_log_id);
        to_log_id    = static_cast<long long>(data.to_log_id);
        timestamp    = static_cast<uint64_t>(data.timestamp);
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_get_indexed_tx: {}", e.what());
        return false;
    }
}


std::vector<uint32_t> db_search_log(uint32_t scIndex, uint32_t scLogType, uint32_t fromTick, uint32_t toTick,
                                    std::string topic1, std::string topic2, std::string topic3)
{
    std::vector<uint32_t> result;
    if (!g_redis) return result;
    if (topic1.size() != 60) {
        Logger::get()->error("db_search_log: Error topic1 size, expect 60 but get {}", topic1.size());
        return result;
    }
    if (topic2.size() != 60) {
        Logger::get()->error("db_search_log: Error topic2 size, expect 60 but get {}", topic2.size());
        return result;
    }
    if (topic3.size() != 60) {
        Logger::get()->error("db_search_log: Error topic3 size, expect 60 but get {}", topic3.size());
        return result;
    }
    if (std::any_of(topic1.begin(), topic1.end(), ::isupper) ||
        std::any_of(topic2.begin(), topic2.end(), ::isupper) ||
        std::any_of(topic3.begin(), topic3.end(), ::isupper)) {
        Logger::get()->warn("db_search_log: Topics cannot contain uppercase characters");
    }
    try {
        auto toPart = [](const std::string& t) -> std::string {
            return (t == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib") ? std::string("ANY") : t;
        };
        std::string key = "";
        if (topic1 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib" &&
                topic2 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib" &&
                topic3 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib")
        {
            // all topic is empty
            if (scLogType == 0xffffffff)
            {
                // log type is also empty
                key = "indexed:" + std::to_string(scIndex);
            }
            else
            {
                key = "indexed:" + std::to_string(scIndex) + ":" + std::to_string(scLogType) ;
            }
        }
        else
        {
            // have at least 1 non zero topic
            key =   std::string("indexed:") +
                    std::to_string(scIndex) + ":" +
                    std::to_string(scLogType) + ":" +
                    toPart(topic1) + ":" +
                    toPart(topic2) + ":" +
                    toPart(topic3);
        }
        std::vector<std::string> members;
        sw::redis::BoundedInterval<double> range(fromTick, toTick,
                                                 sw::redis::BoundType::CLOSED);

        g_redis->zrangebyscore(key,
                               range,
                               std::back_inserter(members));

        result.reserve(members.size());
        for (const auto& m : members) {
            try {
                result.push_back(static_cast<uint32_t>(std::stoul(m)));
            } catch (const std::exception&) {
                // Skip malformed members
            }
        }
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("Redis error in db_search_log: {}\n", e.what());
        result.clear();
    }

    return result;
}

bool db_update_field(const std::string key, const std::string field, const std::string value) {
    if (!g_redis) return false;
    try {
        g_redis->hset(key, field, value);
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_update_field: {}\n", e.what());
        return false;
    }
}

bool db_copy_transaction_to_kvrocks(const std::string &tx_hash) {
    if (!g_redis || !g_kvrocks) return false;
    try {
        const std::string key = "transaction:" + tx_hash;

        // Read transaction data from KeyDB
        auto val = g_redis->get(key);
        if (!val) {
            return false; // nothing to migrate for this transaction
        }

        // Write to Kvrocks
        sw::redis::StringView view(val->data(), val->size());

        g_kvrocks->set(key, view, std::chrono::seconds(gKvrocksTTL));

        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_migrate_transaction: {}\n", e.what());
        return false;
    }
}

bool db_rename(const std::string &key1, const std::string &key2) {
    if (!g_redis) return false;
    try {
        g_redis->rename(key1, key2);
        return true;
    } catch (const sw::redis::Error &e) {
//        Logger::get()->error("Redis error in db_rename: {} {}=>{}\n", e.what(), key1, key2);
        return false;
    }
}

bool db_insert_u32(const std::string key, uint32_t value) {
    if (!g_redis) return false;
    try {
        g_redis->set(key, std::to_string(value));
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_insert_u32: {}\n", e.what());
        return false;
    }
}



bool db_key_exists(const std::string &key) {
    if (!g_redis) return false;
    try {
        return g_redis->exists(key);
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_key_exists: {}\n", e.what());
        return false;
    }
}

bool db_get_u32(const std::string key, uint32_t &value) {
    if (!g_redis) return false;
    try {
        auto val = g_redis->get(key);
        if (!val) {
            return false;
        }
        value = static_cast<uint32_t>(std::stoul(*val));
        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_u32: {}\n", e.what());
        return false;
    } catch (const std::logic_error &e) {
        Logger::get()->error("Parsing error in db_get_u32: {}\n", e.what());
        return false;
    }
}

bool db_try_get_tick_data(uint32_t tick, TickData& data)
{
    if (db_get_tick_data(tick, data)) {
        return true;
    }
    FullTickStruct full;
    if (db_get_vtick_from_kvrocks(tick, full)) {
        data = full.td;
        return true;
    }
    memset((void*)&data, 0, sizeof(TickData));
    return false;
}

std::vector<TickVote> db_try_get_tick_vote(uint32_t tick)
{
    std::vector<TickVote> result = db_get_tick_votes(tick);
    if (!result.empty()) {
        return result;
    }
    FullTickStruct full;
    if (db_get_vtick_from_kvrocks(tick, full)) {
        for (int i = 0; i < 676; i++) if (full.tv[i].tick == tick) result.push_back(full.tv[i]);
        return result;
    }
    return result;
}

bool db_move_log_to_kvrocks(uint16_t epoch, uint64_t logId) {
    if (!g_redis || !g_kvrocks) return false;

    try {
        const std::string key = "log:" + std::to_string(epoch) + ":" + std::to_string(logId);

        // Check if already in Kvrocks - if so, nothing to do
        if (g_kvrocks->exists(key)) return true;

        if (!g_redis->exists(key)) return false;
        // Read log data from KeyDB
        auto val = g_redis->get(key);
        if (!val) {
            return false; // nothing to migrate for this log
        }

        // Write to Kvrocks
        sw::redis::StringView view(val->data(), val->size());
        g_kvrocks->set(key, view, std::chrono::seconds(gKvrocksTTL));

        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_migrate_log: {}\n", e.what());
        return false;
    }
}

bool db_move_logs_to_kvrocks_by_range(uint16_t epoch, long long fromLogId, long long toLogId) {
    if (!g_redis || !g_kvrocks || fromLogId < 0 || toLogId < fromLogId) return false;

    try {
        bool success = true;
        for (long long logId = fromLogId; logId <= toLogId; logId++) {
            if (!db_move_log_to_kvrocks(epoch, logId)) {
                Logger::get()->warn("Failed to migrate log {}:{}", epoch, logId);
                success = false;
            }
        }
        return success;
    } catch (const std::exception &e) {
        Logger::get()->error("Error in db_migrate_logs_by_range: {}\n", e.what());
        return false;
    }
}

bool db_get_endepoch_log_range_info(const uint16_t epoch, long long &start, long long &length, LogRangesPerTxInTick &lr) {
    if (!g_redis) return false;
    try {
        // Get start and length from end_epoch:tick_log_range:<epoch>
        const std::string key_range = "end_epoch:tick_log_range:" + std::to_string(epoch);
        std::vector<sw::redis::Optional<std::string>> vals;
        g_redis->hmget(key_range, {"fromLogId", "length"}, std::back_inserter(vals));

        if (vals.size() != 2 || !vals[0] || !vals[1]) {
            return false;
        }

        start = std::stoll(*vals[0]);
        length = std::stoll(*vals[1]);

        // Get log ranges from end_epoch:log_ranges:<epoch>
        const std::string key_lr = "end_epoch:log_ranges:" + std::to_string(epoch);
        auto val = g_redis->get(key_lr);
        if (!val || val->size() != sizeof(LogRangesPerTxInTick)) {
            return false;
        }
        memcpy(&lr, val->data(), sizeof(LogRangesPerTxInTick));

        return true;
    } catch (const sw::redis::Error &e) {
        Logger::get()->error("Redis error in db_get_endepoch_log_range_info: {}\n", e.what());
        return false;
    } catch (const std::exception &e) {
        Logger::get()->error("Error in db_get_endepoch_log_range_info: {}\n", e.what());
        return false;
    }
}

// Insert FullTickStruct compressed with zstd under key "vtick:<tick>"
bool db_insert_vtick_to_kvrocks(uint32_t tick, const FullTickStruct& fullTick)
{
    if (!g_kvrocks) return false;
    try {
        const size_t srcSize = sizeof(FullTickStruct);
        const size_t maxCompressed = ZSTD_compressBound(srcSize);

        std::string compressed;
        compressed.resize(maxCompressed);

        size_t const cSize = ZSTD_compress(
                compressed.data(),
                compressed.size(),
                reinterpret_cast<const void*>(&fullTick),
                srcSize,
                ZSTD_defaultCLevel()
        );

        if (ZSTD_isError(cSize)) {
            Logger::get()->error("ZSTD_compress error in db_insert_vtick: {}",
                                 ZSTD_getErrorName(cSize));
            return false;
        }

        // shrink to actual compressed size
        compressed.resize(cSize);

        const std::string key = "vtick:" + std::to_string(tick);
        sw::redis::StringView val(compressed.data(), compressed.size());
        g_kvrocks->set(key, val, std::chrono::seconds(gKvrocksTTL));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("KVROCKS error in db_insert_vtick: {}\n", e.what());
        return false;
    }
}



bool db_get_vtick_from_kvrocks(uint32_t tick, FullTickStruct& outFullTick)
{
    if (!g_kvrocks) return false;
    try {
        const std::string key = "vtick:" + std::to_string(tick);
        auto val = g_kvrocks->get(key);
        if (!val) {
            return false;
        }

        const size_t dstSize = sizeof(FullTickStruct);
        size_t const dSize = ZSTD_decompress(
                reinterpret_cast<void*>(&outFullTick),
                dstSize,
                val->data(),
                val->size()
        );

        if (ZSTD_isError(dSize)) {
            Logger::get()->error("ZSTD_decompress error in db_get_vtick: {}",
                                 ZSTD_getErrorName(dSize));
            return false;
        }

        if (dSize != dstSize) {
            Logger::get()->warn("Decompressed FullTickStruct size mismatch for key {}: got {}, expected {}",
                                key.c_str(), dSize, dstSize);
            return false;
        }
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("KVROCKs error in db_get_vtick: {}\n", e.what());
        return false;
    }
}

bool db_insert_TickLogRange_to_kvrocks(uint32_t tick, long long& logStart, long long& logLen)
{
    if (!g_kvrocks) return false;
    try {
        std::string key_summary = "tick_log_range:" + std::to_string(tick);
        std::unordered_map<std::string, std::string> fields;
        fields["fromLogId"] = std::to_string(logStart);
        fields["length"] = std::to_string(logLen);
        g_kvrocks->hmset(key_summary, fields.begin(), fields.end());
        g_kvrocks->expire(key_summary, std::chrono::seconds(gKvrocksTTL));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("KVROCKS error in db_insert_TickLogRange_to_kvrocks: {}\n", e.what());
        return false;
    }
    return true;
}

// Compress and insert ResponseAllLogIdRangesFromTick under key "cLogRange:<tick>"
bool db_insert_cLogRange_to_kvrocks(uint32_t tick, const LogRangesPerTxInTick& logRange)
{
    if (!g_kvrocks) return false;
    try {
        const size_t srcSize = sizeof(LogRangesPerTxInTick);
        const size_t maxCompressed = ZSTD_compressBound(srcSize);

        std::string compressed;
        compressed.resize(maxCompressed);

        size_t const cSize = ZSTD_compress(
                compressed.data(),
                compressed.size(),
                reinterpret_cast<const void*>(&logRange),
                srcSize,
                ZSTD_defaultCLevel()
        );

        if (ZSTD_isError(cSize)) {
            Logger::get()->error("ZSTD_compress error in db_insert_cLogRange_to_kvrocks: {}",
                                 ZSTD_getErrorName(cSize));
            return false;
        }

        compressed.resize(cSize);

        const std::string key = "cLogRange:" + std::to_string(tick);
        sw::redis::StringView val(compressed.data(), compressed.size());
        g_kvrocks->set(key, val, std::chrono::seconds(gKvrocksTTL));
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("KVROCKS error in db_insert_cLogRange_to_kvrocks: {}\n", e.what());
        return false;
    }
}

// Get and decompress ResponseAllLogIdRangesFromTick stored at "cLogRange:<tick>"
bool db_get_cLogRange_from_kvrocks(uint32_t tick, LogRangesPerTxInTick& outLogRange)
{
    if (!g_kvrocks) return false;
    try {
        const std::string key = "cLogRange:" + std::to_string(tick);
        auto val = g_kvrocks->get(key);
        if (!val) {
            return false;
        }

        const size_t dstSize = sizeof(LogRangesPerTxInTick);
        size_t const dSize = ZSTD_decompress(
                reinterpret_cast<void*>(&outLogRange),
                dstSize,
                val->data(),
                val->size()
        );

        if (ZSTD_isError(dSize)) {
            Logger::get()->error("ZSTD_decompress error in db_get_cLogRange_from_kvrocks: {}",
                                 ZSTD_getErrorName(dSize));
            return false;
        }
        if (dstSize - dSize == 16) // oracle machine logging mismatches
        {
            struct {
                long long fromLogId[1024+5];
                long long length[1024+5];
            } old_struct;
            memcpy(&old_struct, &outLogRange, dSize);
            memset(&outLogRange, 0, sizeof(outLogRange));
            for (int i = 0; i < 1024+5; i++)
            {
                outLogRange.fromLogId[i] = old_struct.fromLogId[i];
                outLogRange.length[i] = old_struct.length[i];
            }
            return true;
        }
        if (dSize != dstSize) {
            Logger::get()->warn("Decompressed ResponseAllLogIdRangesFromTick size mismatch for key {}: got {}, expected {}",
                                key.c_str(), dSize, dstSize);
            return false;
        }
        return true;
    } catch (const sw::redis::Error& e) {
        Logger::get()->error("KVROCKS error in db_get_cLogRange_from_kvrocks: {}\n", e.what());
        return false;
    }
}



void db_kvrocks_connect(const std::string &connectionString) {
    if (g_kvrocks) {
        Logger::get()->info("Kvrocks connection already open.\n");
        return;
    }
    try {
        std::string uri_with_pool = connectionString;
        if (uri_with_pool.find('?') == std::string::npos) {
            uri_with_pool += "?pool_size=32";
        } else {
            uri_with_pool += "&pool_size=32";
        }

        g_kvrocks = std::make_unique<sw::redis::Redis>(uri_with_pool);
        g_kvrocks->ping();
    } catch (const sw::redis::Error &e) {
        g_kvrocks.reset();
        throw std::runtime_error("Cannot connect to Kvrocks: " + std::string(e.what()));
        exit(1);
    }
    Logger::get()->trace("Connected to Kvrocks!");
}

void db_kvrocks_close() {
    g_kvrocks.reset();
    Logger::get()->info("Closed kvrocks DB connections");
}

