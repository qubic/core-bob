#include "LogSubscriptionManager.h"
#include "src/core/structs.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "QubicSubscriptionManager.h"
#include "src/database/db.h"

#include <drogon/drogon.h>
#include <iomanip>
#include <json/json.h>
#include <sstream>

LogSubscriptionManager& LogSubscriptionManager::instance() {
    static LogSubscriptionManager inst;
    return inst;
}

void LogSubscriptionManager::addClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    ClientState state;
    state.conn = conn;
    state.connectedAt = std::chrono::steady_clock::now();
    state.lastTick = 0;
    state.catchUpInProgress = false;

    clients_[conn] = std::move(state);

    Logger::get()->debug("WebSocket client connected. Total clients: {}", clients_.size());
}

void LogSubscriptionManager::removeClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return;

    // Remove from all subscription indexes
    for (const auto& key : it->second.subscriptions) {
        auto subIt = subscriptionIndex_.find(key);
        if (subIt != subscriptionIndex_.end()) {
            subIt->second.erase(conn);
            if (subIt->second.empty()) {
                subscriptionIndex_.erase(subIt);
            }
        }
    }

    clients_.erase(it);

    Logger::get()->debug("WebSocket client disconnected. Total clients: {}", clients_.size());
}

void LogSubscriptionManager::setClientLastTick(const drogon::WebSocketConnectionPtr& conn, uint32_t lastTick) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it != clients_.end()) {
        it->second.lastTick = lastTick;
        it->second.lastLogId = -1;  // Clear log ID when tick is set
    }
}

void LogSubscriptionManager::setClientLastLogId(const drogon::WebSocketConnectionPtr& conn, int64_t lastLogId) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it != clients_.end()) {
        it->second.lastLogId = lastLogId;
    }
}

void LogSubscriptionManager::setClientTransferMinAmount(const drogon::WebSocketConnectionPtr& conn, int64_t minAmount) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it != clients_.end()) {
        it->second.transferMinAmount = minAmount;
    }
}

bool LogSubscriptionManager::subscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return false;

    SubscriptionKey key{scIndex, logType};

    // Add to client's subscription set
    auto [_, inserted] = it->second.subscriptions.insert(key);
    if (!inserted) {
        // Already subscribed
        return true;
    }

    // Add to subscription index
    subscriptionIndex_[key].insert(conn);

    Logger::get()->debug("Client subscribed to scIndex={}, logType={}", scIndex, logType);
    return true;
}

bool LogSubscriptionManager::unsubscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return false;

    SubscriptionKey key{scIndex, logType};

    // Remove from client's subscription set
    if (it->second.subscriptions.erase(key) == 0) {
        // Was not subscribed
        return false;
    }

    // Remove from subscription index
    auto subIt = subscriptionIndex_.find(key);
    if (subIt != subscriptionIndex_.end()) {
        subIt->second.erase(conn);
        if (subIt->second.empty()) {
            subscriptionIndex_.erase(subIt);
        }
    }

    Logger::get()->debug("Client unsubscribed from scIndex={}, logType={}", scIndex, logType);
    return true;
}

void LogSubscriptionManager::unsubscribeAll(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    auto it = clients_.find(conn);
    if (it == clients_.end()) return;

    // Remove from all subscription indexes
    for (const auto& key : it->second.subscriptions) {
        auto subIt = subscriptionIndex_.find(key);
        if (subIt != subscriptionIndex_.end()) {
            subIt->second.erase(conn);
            if (subIt->second.empty()) {
                subscriptionIndex_.erase(subIt);
            }
        }
    }

    it->second.subscriptions.clear();

    Logger::get()->debug("Client unsubscribed from all");
}

bool LogSubscriptionManager::extractSubscriptionKey(const LogEvent& log, SubscriptionKey& key) const {
    uint32_t type = log.getType();

    // Smart contract messages have scIndex and logType embedded in body
    switch (type) {
        case CONTRACT_ERROR_MESSAGE:
        case CONTRACT_WARNING_MESSAGE:
        case CONTRACT_INFORMATION_MESSAGE:
        case CONTRACT_DEBUG_MESSAGE: {
            // Extract scIndex and logType from body
            auto ptr = log.getLogBodyPtr();
            int bodySize = log.getLogSize();
            if (bodySize >= 8) {
                memcpy(&key.scIndex, ptr, 4);
                memcpy(&key.logType, ptr + 4, 4);
                // Only include if logType >= 100000 (indexed custom events)
                if (key.logType >= 100000) {
                    return true;
                }
            }
            return false;
        }

        default:
            // All other event types use scIndex=0 and type as logType
            key.scIndex = 0;
            key.logType = type;
            return true;
    }
}

void LogSubscriptionManager::pushVerifiedLogs(uint32_t tick, uint16_t epoch, const std::vector<LogEvent>& logs) {
    // Prepare messages under lock, then dispatch asynchronously
    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::string>> pendingSends;
    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    if (!db_try_get_tick_data(tick, td))
    {
        Logger::get()->warn("LogSubscriptionManager: Trying to get deleted tick data");
    }
    else
    {
        // Notify Qubic subscription manager of new tick (for newTicks subscriptions)
        QubicSubscriptionManager::instance().onNewTick(tick, td);
    }

    if (!db_try_get_log_ranges(tick, lr))
    {
        Logger::get()->warn("LogSubscriptionManager: Trying to get deleted log range");
    }
    int logTxOrderIndex = 0;
    std::vector<int> logTxOrder;
    // we need to sort the special event, INIT, BEGIN_EPOCH, BEGIN_TICK will be in front, END_TICK, END_EPOCH last
    if (!logs.empty())
    {
        logTxOrder = lr.sort();
        auto log0Id = logs[0].getLogId();
        // scan to find the first cursor
        logTxOrderIndex = lr.scanTxId(logTxOrder, 0, log0Id);
        if (logTxOrderIndex == -1)
        {
            Logger::get()->warn("[4] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
            return;
        }
    }

    {
        std::shared_lock lock(mutex_);

        // Only process for LogSubscriptionManager clients if there are any
        if (!clients_.empty() && !subscriptionIndex_.empty()) {
            for (const auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;
            auto logId = log.getLogId();
            // Find subscribers for this key
            auto subIt = subscriptionIndex_.find(key);
            if (subIt == subscriptionIndex_.end() || subIt->second.empty()) continue;

            int txIndex = logTxOrder[logTxOrderIndex];
            auto s = lr.fromLogId[txIndex];
            auto e = s + lr.length[txIndex] - 1;
            if (logId > e)
            {
                logTxOrderIndex = lr.scanTxId(logTxOrder, logTxOrderIndex + 1, logId);
                if (logTxOrderIndex == -1)
                {
                    Logger::get()->warn("[5] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
                    return;
                }
                txIndex = logTxOrder[logTxOrderIndex];
            }

            // Parse log to JSON using same format as REST API
            std::string parsedJson = const_cast<LogEvent&>(log).parseToJsonWithExtraData(td, txIndex);

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = false;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            std::string jsonStr = writer.write(msg);

            // Get log ID for this event
            logId = static_cast<int64_t>(log.getLogId());

            // Get transfer amount if this is a QU_TRANSFER event
            int64_t transferAmount = 0;
            if (log.getType() == QU_TRANSFER) {
                const QuTransfer* t = const_cast<LogEvent&>(log).getStruct<QuTransfer>();
                if (t) {
                    transferAmount = t->amount;
                }
            }

            // Collect subscribers to send to
            for (const auto& conn : subIt->second) {
                // Skip clients in catch-up to avoid duplicate/out-of-order messages
                auto clientIt = clients_.find(conn);
                if (clientIt != clients_.end()) {
                    // Skip if catch-up is in progress
                    if (clientIt->second.catchUpInProgress) {
                        continue;
                    }
                    // Skip if client's lastTick is >= current tick (client is ahead of system)
                    if (clientIt->second.lastTick >= tick) {
                        continue;
                    }
                    // Skip if client's lastLogId is >= current log ID (client is ahead of system)
                    if (clientIt->second.lastLogId >= 0 && clientIt->second.lastLogId >= logId) {
                        continue;
                    }
                    // Skip QU_TRANSFER events below client's minimum amount threshold
                    if (log.getType() == QU_TRANSFER && clientIt->second.transferMinAmount > 0 &&
                        transferAmount < clientIt->second.transferMinAmount) {
                        continue;
                    }
                }
                pendingSends.emplace_back(conn, jsonStr);
            }
            }
        }  // end if (!clients_.empty() && !subscriptionIndex_.empty())
    }

    // Dispatch sends asynchronously via Drogon's event loop
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([sends = std::move(pendingSends)]() {
                for (const auto& [conn, jsonStr] : sends) {
                    try {
                        if (conn->connected()) {
                            conn->send(jsonStr);
                        }
                    } catch (const std::exception& e) {
                        Logger::get()->warn("Failed to send WebSocket message: {}", e.what());
                    }
                }
            });
        }
    }

    // Notify Qubic subscription manager of new logs (for logs subscriptions)
    if (!logs.empty() && td.tick != 0) {
        QubicSubscriptionManager::instance().onNewLogs(tick, logs, td);
    }

    // Note: tickStream subscriptions are notified from QubicIndexer after indexing
    // completes, so that transaction execution info (executed, logIdFrom) is available
}

void LogSubscriptionManager::performCatchUp(const drogon::WebSocketConnectionPtr& conn, uint32_t toTick) {
    uint32_t fromTick;
    std::unordered_set<SubscriptionKey, SubscriptionKeyHash> subscriptions;

    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it == clients_.end()) return;

        if (it->second.subscriptions.empty()) {
            // No subscriptions, nothing to catch up
            Json::Value msg;
            msg["type"] = "catchUpComplete";
            msg["fromTick"] = 0;
            msg["toTick"] = toTick;
            msg["logsDelivered"] = 0;
            Json::FastWriter writer;
            sendJson(conn, writer.write(msg));
            return;
        }

        fromTick = it->second.lastTick + 1;
        subscriptions = it->second.subscriptions;
        it->second.catchUpInProgress = true;
    }

    // Ensure fromTick is not before the epoch's initial tick
    uint32_t initialTick = gInitialTick.load();
    if (fromTick < initialTick) {
        fromTick = initialTick;
    }

    if (fromTick > toTick) {
        // Already up to date
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastTick = toTick;
        }

        Json::Value msg;
        msg["type"] = "catchUpComplete";
        msg["fromTick"] = fromTick;
        msg["toTick"] = toTick;
        msg["logsDelivered"] = 0;
        Json::FastWriter writer;
        sendJson(conn, writer.write(msg));
        return;
    }

    uint16_t epoch = gCurrentProcessingEpoch.load();
    int logsDelivered = 0;

    // Process in batches to avoid blocking too long
    const uint32_t BATCH_SIZE = 100;

    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    int logTxOrderIndex = 0;
    std::vector<int> logTxOrder;

    for (uint32_t tick = fromTick; tick <= toTick; tick += BATCH_SIZE) {
        uint32_t batchEnd = std::min(tick + BATCH_SIZE - 1, toTick);

        bool success;
        auto logs = db_get_logs_by_tick_range(epoch, tick, batchEnd, success);
        if (logs.empty()) continue;

        if (!success) {
            Logger::get()->warn("Catch-up: failed to fetch logs for ticks {}-{}", tick, batchEnd);
            continue;
        }

        for (auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;
            // Check if client is subscribed to this key
            if (subscriptions.find(key) == subscriptions.end()) continue;
            auto id = log.getLogId();

            if (td.tick != log.getTick())
            {
                if (!db_try_get_tick_data(log.getTick(), td))
                {
                    Logger::get()->warn("LogSubscriptionManager: Trying to get deleted tick data");
                }

                if (!db_try_get_log_ranges(log.getTick(), lr))
                {
                    Logger::get()->warn("LogSubscriptionManager: Trying to get deleted log range");
                }

                {
                    logTxOrder = lr.sort();
                    logTxOrderIndex = lr.scanTxId(logTxOrder, 0, id);// scan to find the first cursor
                    if (logTxOrderIndex == -1)
                    {
                        Logger::get()->warn("[0] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
                        return;
                    }
                }
            }

            int txIndex = logTxOrder[logTxOrderIndex];
            auto s = lr.fromLogId[txIndex];
            auto e = s + lr.length[txIndex] - 1;
            if (id > e) // processed all, move the cursor to next tx
            {
                // rescan to find next cursor
                logTxOrderIndex = lr.scanTxId(logTxOrder, logTxOrderIndex + 1, id);
                if (logTxOrderIndex == -1)
                {
                    Logger::get()->warn("[1] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
                    return;
                }
                txIndex = logTxOrder[logTxOrderIndex];
            }

            // Parse log to JSON using same format as REST API
            std::string parsedJson = log.parseToJsonWithExtraData(td, txIndex);

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = true;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            try {
                conn->send(writer.write(msg));
                logsDelivered++;
            } catch (const std::exception& e) {
                Logger::get()->warn("Catch-up send failed: {}", e.what());
                break;
            }
        }

        // Check if connection is still valid
        if (!conn->connected()) {
            Logger::get()->info("Catch-up aborted: connection closed");
            return;
        }
    }

    // Mark catch-up complete
    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastTick = toTick;
        }
    }

    // Send completion message
    Json::Value msg;
    msg["type"] = "catchUpComplete";
    msg["fromTick"] = fromTick;
    msg["toTick"] = toTick;
    msg["logsDelivered"] = logsDelivered;
    Json::FastWriter writer;
    sendJson(conn, writer.write(msg));

    Logger::get()->info("Catch-up complete: {} logs delivered (ticks {}-{})", logsDelivered, fromTick, toTick);
}

void LogSubscriptionManager::performCatchUpByLogId(const drogon::WebSocketConnectionPtr& conn, int64_t toLogId) {
    int64_t fromLogId;
    std::unordered_set<SubscriptionKey, SubscriptionKeyHash> subscriptions;

    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it == clients_.end()) return;

        if (it->second.subscriptions.empty()) {
            // No subscriptions, nothing to catch up
            Json::Value msg;
            msg["type"] = "catchUpComplete";
            msg["fromLogId"] = Json::Int64(0);
            msg["toLogId"] = Json::Int64(toLogId);
            msg["logsDelivered"] = 0;
            Json::FastWriter writer;
            sendJson(conn, writer.write(msg));
            return;
        }

        // If lastLogId is not set (< 0), skip catch-up entirely
        if (it->second.lastLogId < 0) {
            Json::Value msg;
            msg["type"] = "catchUpComplete";
            msg["fromLogId"] = Json::Int64(0);
            msg["toLogId"] = Json::Int64(toLogId);
            msg["logsDelivered"] = 0;
            Json::FastWriter writer;
            sendJson(conn, writer.write(msg));
            return;
        }

        fromLogId = it->second.lastLogId + 1;
        subscriptions = it->second.subscriptions;
        it->second.catchUpInProgress = true;
    }

    if (fromLogId > toLogId) {
        // Already up to date
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastLogId = toLogId;
        }

        Json::Value msg;
        msg["type"] = "catchUpComplete";
        msg["fromLogId"] = Json::Int64(fromLogId);
        msg["toLogId"] = Json::Int64(toLogId);
        msg["logsDelivered"] = 0;
        Json::FastWriter writer;
        sendJson(conn, writer.write(msg));
        return;
    }

    uint16_t epoch = gCurrentProcessingEpoch.load();
    int logsDelivered = 0;

    // Process in batches to avoid blocking too long
    const int64_t BATCH_SIZE = 1000;

    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    int logTxOrderIndex = 0;
    std::vector<int> logTxOrder;

    for (int64_t id = fromLogId; id <= toLogId; id += BATCH_SIZE) {
        int64_t batchEnd = std::min(id + BATCH_SIZE - 1, toLogId);

        auto logs = db_try_get_logs(epoch, id, batchEnd);

        for (auto& log : logs) {
            SubscriptionKey key;
            if (!extractSubscriptionKey(log, key)) continue;

            // Check if client is subscribed to this key
            if (subscriptions.find(key) == subscriptions.end()) continue;

            if (log.getTick() != td.tick)
            {
                db_try_get_tick_data(log.getTick(), td);
                db_try_get_log_ranges(log.getTick(), lr);
                logTxOrderIndex = 0;
                logTxOrder = lr.sort();
                // scan to find the first cursor
                logTxOrderIndex = lr.scanTxId(logTxOrder, 0, id);
                if (logTxOrderIndex == -1)
                {
                    Logger::get()->warn("[2] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
                    return;
                }
            }
            int txIndex = logTxOrder[logTxOrderIndex];
            auto s = lr.fromLogId[txIndex];
            auto e = s + lr.length[txIndex] - 1;
            if (id > e)
            {
                // rescan to find the next cursor
                logTxOrderIndex = lr.scanTxId(logTxOrder, logTxOrderIndex + 1, id);
                if (logTxOrderIndex == -1)
                {
                    Logger::get()->warn("[3] Unexpected calculation, logTxOrderIndex is -1. Exit function...");
                    return;
                }
                txIndex = logTxOrder[logTxOrderIndex];
            }
            // Parse log to JSON using same format as REST API
            std::string parsedJson = log.parseToJsonWithExtraData(td, txIndex);

            // Parse the JSON string to embed it in our message
            Json::Value parsedLog;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream stream(parsedJson);
            Json::parseFromStream(builder, stream, &parsedLog, &errors);

            // Build WebSocket message with parsed log as "message" field
            Json::Value msg;
            msg["type"] = "log";
            msg["scIndex"] = key.scIndex;
            msg["logType"] = key.logType;
            msg["isCatchUp"] = true;
            msg["message"] = parsedLog;

            Json::FastWriter writer;
            try {
                conn->send(writer.write(msg));
                logsDelivered++;
            } catch (const std::exception& e) {
                Logger::get()->warn("Catch-up send failed: {}", e.what());
                break;
            }
        }

        // Check if connection is still valid
        if (!conn->connected()) {
            Logger::get()->info("Catch-up aborted: connection closed");
            return;
        }
    }

    // Mark catch-up complete
    {
        std::unique_lock lock(mutex_);
        auto it = clients_.find(conn);
        if (it != clients_.end()) {
            it->second.catchUpInProgress = false;
            it->second.lastLogId = toLogId;
        }
    }

    // Send completion message
    Json::Value msg;
    msg["type"] = "catchUpComplete";
    msg["fromLogId"] = Json::Int64(fromLogId);
    msg["toLogId"] = Json::Int64(toLogId);
    msg["logsDelivered"] = logsDelivered;
    Json::FastWriter writer;
    sendJson(conn, writer.write(msg));

    Logger::get()->info("Catch-up by logId complete: {} logs delivered (logIds {}-{})", logsDelivered, fromLogId, toLogId);
}

size_t LogSubscriptionManager::getClientCount() const {
    std::shared_lock lock(mutex_);
    return clients_.size();
}

size_t LogSubscriptionManager::getTotalSubscriptionCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [conn, state] : clients_) {
        count += state.subscriptions.size();
    }
    return count;
}

void LogSubscriptionManager::sendJson(const drogon::WebSocketConnectionPtr& conn, const std::string& json) {
    try {
        conn->send(json);
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send WebSocket JSON: {}", e.what());
    }
}
