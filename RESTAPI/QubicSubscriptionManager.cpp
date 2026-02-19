#include "QubicSubscriptionManager.h"
#include "QubicRpcMapper.h"
#include "Logger.h"
#include "GlobalVar.h"
#include "shim.h"
#include "K12AndKeyUtil.h"
#include "database/db.h"
#include "defines.h"
#include "drogon/drogon.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>

QubicSubscriptionManager& QubicSubscriptionManager::instance() {
    static QubicSubscriptionManager instance;
    return instance;
}

void QubicSubscriptionManager::shutdown() {
    Logger::get()->debug("QubicSubscriptionManager: signaling shutdown");
    stopFlag_.store(true);

    // Wait for all catch-up threads to finish (max 5 seconds)
    int waitCount = 0;
    while (activeCatchUpThreads_.load() > 0 && waitCount < 50) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        waitCount++;
    }

    if (activeCatchUpThreads_.load() > 0) {
        Logger::get()->warn("QubicSubscriptionManager: {} catch-up threads still running after timeout",
                           activeCatchUpThreads_.load());
    } else {
        Logger::get()->debug("QubicSubscriptionManager: all catch-up threads stopped");
    }

    // Clear all subscriptions
    {
        std::unique_lock lock(mutex_);
        subscriptions_.clear();
        clientSubscriptions_.clear();
    }
}

void QubicSubscriptionManager::addClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);
    clientSubscriptions_[conn] = {};
}

void QubicSubscriptionManager::removeClient(const drogon::WebSocketConnectionPtr& conn) {
    std::unique_lock lock(mutex_);

    // Remove all subscriptions for this client
    auto it = clientSubscriptions_.find(conn);
    if (it != clientSubscriptions_.end()) {
        for (const auto& subId : it->second) {
            subscriptions_.erase(subId);
        }
        clientSubscriptions_.erase(it);
    }
}

std::string QubicSubscriptionManager::generateSubscriptionId() {
    uint64_t id = subscriptionCounter_.fetch_add(1);
    std::stringstream ss;
    ss << "qubic_sub_" << std::hex << id;
    return ss.str();
}

std::string QubicSubscriptionManager::subscribe(
    const drogon::WebSocketConnectionPtr& conn,
    QubicSubscriptionType type,
    const LogFilter& filter)
{
    std::unique_lock lock(mutex_);

    // Check if client is registered
    auto clientIt = clientSubscriptions_.find(conn);
    if (clientIt == clientSubscriptions_.end()) {
        return "";
    }

    // Generate subscription ID
    std::string subId = generateSubscriptionId();

    // Create subscription
    QubicSubscription sub;
    sub.id = subId;
    sub.type = type;
    sub.filter = filter;
    sub.conn = conn;

    // If startLogId is specified, mark catch-up in progress
    if (filter.startLogId.has_value()) {
        sub.catchUpInProgress = true;
        sub.catchUpEpoch = filter.startEpoch.value_or(gCurrentProcessingEpoch.load());
        sub.lastLogId = -1;  // Will be set by catch-up thread when queuing starts
    }

    // Store subscription
    subscriptions_[subId] = sub;
    clientIt->second.insert(subId);

    Logger::get()->debug("Qubic subscription created: {} type={} catchUp={}",
                        subId, static_cast<int>(type), sub.catchUpInProgress);

    return subId;
}

bool QubicSubscriptionManager::unsubscribe(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId)
{
    std::unique_lock lock(mutex_);

    // Find subscription
    auto subIt = subscriptions_.find(subscriptionId);
    if (subIt == subscriptions_.end()) {
        return false;
    }

    // Verify ownership
    if (subIt->second.conn != conn) {
        return false;
    }

    // Remove from client's subscription set
    auto clientIt = clientSubscriptions_.find(conn);
    if (clientIt != clientSubscriptions_.end()) {
        clientIt->second.erase(subscriptionId);
    }

    // Remove subscription
    subscriptions_.erase(subIt);

    Logger::get()->debug("Qubic subscription removed: {}", subscriptionId);

    return true;
}

size_t QubicSubscriptionManager::getClientCount() const {
    std::shared_lock lock(mutex_);
    return clientSubscriptions_.size();
}

void QubicSubscriptionManager::onNewTick(uint32_t tick, const TickData& td) {
    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::pair<std::string, Json::Value>>> pendingSends;

    {
        std::shared_lock lock(mutex_);

        if (subscriptions_.empty()) return;

        // Build tick notification in Qubic format
        std::vector<m256i> txDigests;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
            if (td.transactionDigests[i] != m256i::zero()) {
                txDigests.push_back(td.transactionDigests[i]);
            }
        }

        Json::Value tickData = QubicRpc::tickDataToQubicTick(tick, td, txDigests, false);

        // Find all newTicks subscriptions
        for (const auto& [subId, sub] : subscriptions_) {
            if (sub.type == QubicSubscriptionType::NewTicks) {
                pendingSends.emplace_back(sub.conn, std::make_pair(subId, tickData));
            }
        }
    }

    // Send asynchronously
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([this, sends = std::move(pendingSends)]() {
                for (const auto& [conn, subIdAndResult] : sends) {
                    if (conn->connected()) {
                        sendSubscriptionMessage(conn, subIdAndResult.first, subIdAndResult.second);
                    }
                }
            });
        }
    }
}

void QubicSubscriptionManager::onNewLogs(uint32_t tick, const std::vector<LogEvent>& logs,
                                          const TickData& td) {
    if (logs.empty()) return;

    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::pair<std::string, Json::Value>>> pendingSends;
    std::vector<std::tuple<std::string, LogEvent, std::string, std::string>> pendingQueues;

    {
        std::shared_lock lock(mutex_);

        if (subscriptions_.empty()) return;

        // Get log ranges for transaction index lookup
        LogRangesPerTxInTick lr{-1};
        db_try_get_log_ranges(tick, lr);

        for (const auto& log : logs) {
            // Find transaction index
            int txIndex = 0;
            uint64_t logId = log.getLogId();
            for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                    if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                        static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                        txIndex = i;
                        break;
                    }
                }
            }

            // Convert to log format
            Json::Value qubicLog = const_cast<LogEvent&>(log).parseToJsonValueWithExtraData(td, txIndex);

            // Get source/destination identities for filtering (from body.from/to)
            std::string sourceIdentity;
            std::string destIdentity;
            if (qubicLog.isMember("body") && qubicLog["body"].isObject()) {
                const auto& body = qubicLog["body"];
                if (body.isMember("from")) {
                    sourceIdentity = body["from"].asString();
                }
                if (body.isMember("to")) {
                    destIdentity = body["to"].asString();
                }
                // Also check sourcePublicKey/destinationPublicKey for asset transfers
                if (body.isMember("sourcePublicKey")) {
                    sourceIdentity = body["sourcePublicKey"].asString();
                }
                if (body.isMember("destinationPublicKey")) {
                    destIdentity = body["destinationPublicKey"].asString();
                }
            }

            // Check all log and transfer subscriptions
            for (const auto& [subId, sub] : subscriptions_) {
                if (sub.type == QubicSubscriptionType::Logs ||
                    sub.type == QubicSubscriptionType::Transfers) {
                    if (matchesFilter(log, sub.filter, sourceIdentity, destIdentity)) {
                        // Check if catch-up is in progress and we're in queue mode
                        if (sub.catchUpInProgress && sub.lastLogId >= 0) {
                            // Queue for later delivery
                            pendingQueues.emplace_back(subId, log, sourceIdentity, destIdentity);
                        } else if (!sub.catchUpInProgress) {
                            // Send immediately (no catch-up or catch-up complete)
                            pendingSends.emplace_back(sub.conn, std::make_pair(subId, qubicLog));
                        }
                        // If catchUpInProgress but lastLogId < 0, we're not yet in queue mode
                        // (still too far behind), so we skip this log
                    }
                }
            }
        }
    }

    // Queue logs for catch-up subscriptions (needs unique_lock)
    if (!pendingQueues.empty()) {
        std::unique_lock lock(mutex_);
        for (const auto& [subId, log, srcId, dstId] : pendingQueues) {
            auto it = subscriptions_.find(subId);
            if (it != subscriptions_.end() && it->second.catchUpInProgress && it->second.lastLogId >= 0) {
                PendingLogEvent pending;
                pending.log = log;
                pending.sourceIdentity = srcId;
                pending.destIdentity = dstId;
                it->second.pendingLogs.push_back(pending);
            }
        }
    }

    // Send asynchronously
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([this, sends = std::move(pendingSends)]() {
                for (const auto& [conn, subIdAndResult] : sends) {
                    if (conn->connected()) {
                        sendSubscriptionMessage(conn, subIdAndResult.first, subIdAndResult.second);
                    }
                }
            });
        }
    }
}

bool QubicSubscriptionManager::matchesFilter(
    const LogEvent& log,
    const LogFilter& filter,
    const std::string& sourceIdentity,
    const std::string& destIdentity)
{
    // Check log type filter
    if (!filter.logTypes.empty()) {
        bool match = false;
        for (uint32_t lt : filter.logTypes) {
            if (log.getType() == lt) {
                match = true;
                break;
            }
        }
        if (!match) return false;
    }

    // Check identity filter
    if (!filter.identities.empty()) {
        bool match = false;
        for (const auto& id : filter.identities) {
            if (sourceIdentity == id || destIdentity == id) {
                match = true;
                break;
            }
        }
        if (!match) return false;
    }

    return true;
}

void QubicSubscriptionManager::sendSubscriptionMessage(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId,
    const Json::Value& result)
{
    Json::Value msg(Json::objectValue);
    msg["jsonrpc"] = "2.0";
    msg["method"] = "qubic_subscription";
    msg["params"]["subscription"] = subscriptionId;
    msg["params"]["result"] = result;

    Json::FastWriter writer;
    try {
        conn->send(writer.write(msg));
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send Qubic subscription message: {}", e.what());
    }
}

void QubicSubscriptionManager::sendSubscriptionMessageRaw(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId,
    const std::string& resultJson)
{
    // Build JSON-RPC message with pre-formatted result to preserve field order
    std::string msg = "{\"jsonrpc\":\"2.0\",\"method\":\"qubic_subscription\",\"params\":{\"subscription\":\"" +
                      subscriptionId + "\",\"result\":" + resultJson + "}}";
    try {
        conn->send(msg);
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send Qubic subscription message: {}", e.what());
    }
}

std::string QubicSubscriptionManager::subscribeTickStream(
    const drogon::WebSocketConnectionPtr& conn,
    const TickStreamFilter& filter,
    uint32_t startTick)
{
    std::unique_lock lock(mutex_);

    // Check if client is registered
    auto clientIt = clientSubscriptions_.find(conn);
    if (clientIt == clientSubscriptions_.end()) {
        return "";
    }

    // Generate subscription ID
    std::string subId = generateSubscriptionId();

    // Create subscription
    QubicSubscription sub;
    sub.id = subId;
    sub.type = QubicSubscriptionType::TickStream;
    sub.tickStreamFilter = filter;
    sub.conn = conn;
    sub.lastTick = startTick > 0 ? startTick - 1 : 0;
    sub.catchUpInProgress = startTick > 0;

    // Store subscription
    subscriptions_[subId] = sub;
    clientIt->second.insert(subId);

    Logger::get()->info("TickStream subscription created: {} startTick={} lastTick={} catchUpInProgress={} txFilters={} logFilters={}",
                       subId, startTick, sub.lastTick, sub.catchUpInProgress,
                       filter.txFilters.size(), filter.logFilters.size());

    return subId;
}

bool QubicSubscriptionManager::matchesTxFilter(
    const std::string& from,
    const std::string& to,
    int64_t amount,
    uint16_t inputType,
    const TxFilter& filter) const
{
    // Check from identity
    if (!filter.from.empty() && filter.from != from) {
        return false;
    }

    // Check to identity
    if (!filter.to.empty() && filter.to != to) {
        return false;
    }

    // Check minimum amount
    if (filter.minAmount > 0 && amount < filter.minAmount) {
        return false;
    }

    // Check input type (-1 means any)
    if (filter.inputType >= 0 && filter.inputType != static_cast<int16_t>(inputType)) {
        return false;
    }

    return true;
}

bool QubicSubscriptionManager::matchesLogFilter(
    const LogEvent& log,
    const LogStreamFilter& filter) const
{
    uint32_t logType = log.getType();

    // For contract messages, extract scIndex and logType from body
    uint32_t scIndex = 0;
    uint32_t actualLogType = logType;

    if (logType >= CONTRACT_ERROR_MESSAGE && logType <= CONTRACT_DEBUG_MESSAGE) {
        const uint8_t* ptr = log.getLogBodyPtr();
        int bodySize = log.getLogSize();
        if (bodySize >= 8) {
            memcpy(&scIndex, ptr, 4);
            memcpy(&actualLogType, ptr + 4, 4);
        }
    }

    // Check smart contract index
    if (filter.scIndex != scIndex) {
        return false;
    }

    // Check log type
    if (filter.logType != actualLogType) {
        return false;
    }

    // Check transfer minimum amount (for QU_TRANSFER logs, type 0)
    if (filter.transferMinAmount > 0 && actualLogType == QU_TRANSFER && scIndex == 0) {
        const QuTransfer* t = const_cast<LogEvent&>(log).getStruct<QuTransfer>();
        if (t && t->amount < filter.transferMinAmount) {
            return false;
        }
    }

    return true;
}

bool QubicSubscriptionManager::matchesAnyTxFilter(
    const std::string& from,
    const std::string& to,
    int64_t amount,
    uint16_t inputType,
    const TickStreamFilter& sub) const
{
    // Exclude all transactions if requested
    if (sub.excludeTxs) {
        return false;
    }

    // Empty filter list means match all
    if (sub.txFilters.empty()) {
        return true;
    }

    for (const auto& filter : sub.txFilters) {
        if (matchesTxFilter(from, to, amount, inputType, filter)) {
            return true;
        }
    }
    return false;
}

bool QubicSubscriptionManager::matchesAnyLogFilter(
    const LogEvent& log,
    const TickStreamFilter& sub) const
{
    // Exclude all logs if requested
    if (sub.excludeLogs) {
        return false;
    }

    // Empty filter list means match all
    if (sub.logFilters.empty()) {
        return true;
    }

    for (const auto& filter : sub.logFilters) {
        if (matchesLogFilter(log, filter)) {
            return true;
        }
    }
    return false;
}

std::string QubicSubscriptionManager::buildTickStreamJsonString(
    uint32_t tick,
    uint16_t epoch,
    bool isCatchUp,
    const TickData& td,
    const std::vector<StreamTx>& matchedTxs,
    const std::vector<std::pair<LogEvent, int>>& matchedLogs,
    size_t totalTxs,
    size_t totalLogs,
    bool includeInputData) const
{
    // Determine if we have tick data (epoch == 0 means no tick data in database)
    bool hasNoTickData = (td.epoch == 0);
    // A tick is skipped if we have no tick data OR no transactions (226+ computors voted empty)
    bool isSkipped = hasNoTickData || (totalTxs == 0);

    // Apply epoch fallback: if tick data epoch is 0 but tick is in current epoch range, use current epoch
    uint16_t effectiveEpoch = epoch;
    if (effectiveEpoch == 0 && tick >= gInitialTick.load()) {
        effectiveEpoch = gCurrentProcessingEpoch.load();
    }

    // computorIndex can always be calculated from tick number
    uint16_t computorIndex = (td.computorIndex > 0) ? td.computorIndex : (tick % NUMBER_OF_COMPUTORS);

    // Format timestamp from TickData fields
    std::tm timeinfo = {};
    timeinfo.tm_year = static_cast<int>(td.year) + 2000 - 1900;
    timeinfo.tm_mon = td.month - 1;
    timeinfo.tm_mday = td.day;
    timeinfo.tm_hour = td.hour;
    timeinfo.tm_min = td.minute;
    timeinfo.tm_sec = td.second;
    char timeBuf[32];
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);

    // Build transactions array
    Json::Value txArray(Json::arrayValue);
    for (const auto& tx : matchedTxs) {
        Json::Value txJson(Json::objectValue);
        txJson["hash"] = tx.hash;
        txJson["from"] = tx.from;
        txJson["to"] = tx.to;
        txJson["amount"] = static_cast<Json::Int64>(tx.amount);
        txJson["inputType"] = tx.inputType;
        txJson["inputSize"] = tx.inputSize;
        txJson["executed"] = tx.executed;
        txJson["logIdFrom"] = static_cast<Json::Int64>(tx.logIdFrom);
        txJson["logIdLength"] = static_cast<Json::Int64>(tx.logIdLength);

        if (includeInputData && !tx.inputData.empty()) {
            std::stringstream ss;
            ss << "0x";
            for (uint8_t b : tx.inputData) {
                ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
            }
            txJson["inputData"] = ss.str();
        }

        txArray.append(txJson);
    }

    // Build logs array using the same format as qubic_getTransfers
    Json::Value logArray(Json::arrayValue);
    for (const auto& [log, txIndex] : matchedLogs) {
        Json::Value logJson = log.parseToJsonValueWithExtraData(td, txIndex);
        logArray.append(logJson);
    }

    // Build JSON string with controlled order
    Json::FastWriter writer;
    std::string txArrayStr = writer.write(txArray);
    std::string logArrayStr = writer.write(logArray);
    // Remove trailing newlines from FastWriter
    if (!txArrayStr.empty() && txArrayStr.back() == '\n') txArrayStr.pop_back();
    if (!logArrayStr.empty() && logArrayStr.back() == '\n') logArrayStr.pop_back();

    std::stringstream ss;
    ss << "{\"epoch\":" << effectiveEpoch
       << ",\"tick\":" << tick
       << ",\"computorIndex\":" << computorIndex
       << ",\"hasNoTickData\":" << (hasNoTickData ? "true" : "false")
       << ",\"isSkipped\":" << (isSkipped ? "true" : "false")
       << ",\"isCatchUp\":" << (isCatchUp ? "true" : "false")
       << ",\"timestamp\":\"" << timeBuf << "\""
       << ",\"totalLogs\":" << totalLogs
       << ",\"filteredLogs\":" << matchedLogs.size()
       << ",\"totalTxs\":" << totalTxs
       << ",\"filteredTxs\":" << matchedTxs.size()
       << ",\"transactions\":" << txArrayStr
       << ",\"logs\":" << logArrayStr
       << "}";

    return ss.str();
}

void QubicSubscriptionManager::onVerifiedTick(
    uint32_t tick,
    uint16_t epoch,
    const std::vector<LogEvent>& logs,
    const TickData& td)
{
    // Use string pairs for ordered JSON output
    std::vector<std::pair<drogon::WebSocketConnectionPtr, std::pair<std::string, std::string>>> pendingSends;

    {
        std::shared_lock lock(mutex_);

        if (subscriptions_.empty()) {
            return;
        }

        // Count TickStream subscriptions for debugging
        int tickStreamCount = 0;
        for (const auto& [subId, sub] : subscriptions_) {
            if (sub.type == QubicSubscriptionType::TickStream) {
                tickStreamCount++;
            }
        }
        if (tickStreamCount > 0) {
            Logger::get()->debug("onVerifiedTick: tick={} epoch={} logs={} tickStreamSubs={}",
                               tick, epoch, logs.size(), tickStreamCount);
        }

        // Get log ranges for transaction index lookup
        LogRangesPerTxInTick lr{-1};
        db_try_get_log_ranges(tick, lr);

        // Build list of all transactions in this tick
        std::vector<StreamTx> allTxs;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
            if (td.transactionDigests[i] == m256i::zero()) continue;

            std::string txHash = td.transactionDigests[i].toQubicHash();
            std::vector<uint8_t> txData;
            if (!db_try_get_transaction(txHash, txData)) continue;

            Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
            if (!tx) continue;

            StreamTx stx;
            stx.hash = txHash;
            stx.from = getIdentity(tx->sourcePublicKey, false);
            stx.to = getIdentity(tx->destinationPublicKey, false);
            stx.amount = tx->amount;
            stx.inputType = tx->inputType;
            stx.inputSize = tx->inputSize;

            // Copy input data if present
            if (tx->inputSize > 0 && txData.size() >= sizeof(Transaction) + tx->inputSize) {
                const uint8_t* inputPtr = txData.data() + sizeof(Transaction);
                stx.inputData.assign(inputPtr, inputPtr + tx->inputSize);
            }

            // Get execution info from log ranges (more reliable than indexed tx for real-time)
            // The log ranges are set during log verification and contain accurate data
            if (lr.length[i] > 0 && lr.fromLogId[i] >= 0) {
                stx.executed = true;  // Has logs = was executed
                stx.logIdFrom = lr.fromLogId[i];
                stx.logIdLength = lr.length[i];
            } else {
                // No logs for this transaction - check indexed data as fallback
                int txIndex;
                long long fromLogId, toLogId;
                uint64_t txTimestamp;
                bool executed;
                if (db_get_indexed_tx(txHash.c_str(), txIndex, fromLogId, toLogId, txTimestamp, executed)) {
                    stx.executed = executed;
                    stx.logIdFrom = fromLogId;
                    stx.logIdLength = (toLogId >= fromLogId) ? (toLogId - fromLogId + 1) : 0;
                } else {
                    stx.executed = false;
                    stx.logIdFrom = -1;
                    stx.logIdLength = 0;
                }
            }

            allTxs.push_back(std::move(stx));
        }

        size_t totalTxs = allTxs.size();

        // Find all TickStream subscriptions
        for (auto& [subId, sub] : subscriptions_) {
            if (sub.type != QubicSubscriptionType::TickStream) continue;

            // If catch-up is in progress, queue this tick for later delivery
            if (sub.catchUpInProgress) {
                Logger::get()->debug("TickStream {} queuing tick {} during catch-up", subId, tick);
                PendingTickData pending;
                pending.tick = tick;
                pending.epoch = epoch;
                pending.td = td;
                pending.logs = logs;
                sub.pendingTicks.push_back(std::move(pending));
                continue;
            }

            // Skip if we've already sent this tick
            if (tick <= sub.lastTick) {
                Logger::get()->debug("TickStream {} skipped tick {}: already sent (lastTick={})", subId, tick, sub.lastTick);
                continue;
            }

            // Filter transactions for this subscription
            std::vector<StreamTx> matchedTxs;
            for (const auto& stx : allTxs) {
                if (matchesAnyTxFilter(stx.from, stx.to, stx.amount, stx.inputType, sub.tickStreamFilter)) {
                    matchedTxs.push_back(stx);
                }
            }

            // Collect matching logs
            std::vector<std::pair<LogEvent, int>> matchedLogs;
            size_t totalLogs = logs.size();

            for (const auto& log : logs) {
                if (matchesAnyLogFilter(log, sub.tickStreamFilter)) {
                    // Find transaction index for this log
                    int txIndex = 0;
                    uint64_t logId = log.getLogId();
                    for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                        if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                            if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                                static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                                txIndex = i;
                                break;
                            }
                        }
                    }
                    matchedLogs.emplace_back(log, txIndex);
                }
            }

            // Check if we should skip this tick
            bool hasMatches = !matchedTxs.empty() || !matchedLogs.empty();
            bool isHeartbeatTick = (tick % 120 == 0);

            if (sub.tickStreamFilter.skipEmptyTicks && !hasMatches && !isHeartbeatTick) {
                // Update lastTick even when skipping
                sub.lastTick = tick;
                continue;
            }

            // Build JSON string with controlled field order
            std::string tickJsonStr = buildTickStreamJsonString(
                tick, epoch, false, td,
                matchedTxs, matchedLogs,
                totalTxs, totalLogs,
                sub.tickStreamFilter.includeInputData);

            Logger::get()->debug("TickStream sending tick {} to sub {} (txs={}, logs={})",
                               tick, subId, matchedTxs.size(), matchedLogs.size());
            pendingSends.emplace_back(sub.conn, std::make_pair(subId, tickJsonStr));
        }
    }

    // Update lastTick for sent subscriptions (need unique lock)
    if (!pendingSends.empty()) {
        std::unique_lock lock(mutex_);
        for (const auto& [conn, subIdAndResult] : pendingSends) {
            auto it = subscriptions_.find(subIdAndResult.first);
            if (it != subscriptions_.end()) {
                it->second.lastTick = tick;
            }
        }
    }

    // Send asynchronously
    if (!pendingSends.empty()) {
        auto loop = drogon::app().getIOLoop(0);
        if (loop) {
            loop->queueInLoop([this, sends = std::move(pendingSends)]() {
                for (const auto& [conn, subIdAndResult] : sends) {
                    if (conn->connected()) {
                        sendSubscriptionMessageRaw(conn, subIdAndResult.first, subIdAndResult.second);
                    }
                }
            });
        }
    }
}

void QubicSubscriptionManager::performCatchUp(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subId,
    uint32_t fromTick,
    uint32_t toTick)
{
    // Run catch-up in a separate thread to avoid blocking
    activeCatchUpThreads_.fetch_add(1);
    std::thread([this, conn, subId, fromTick, toTick]() {
        // RAII guard to decrement thread count on exit
        struct ThreadGuard {
            std::atomic<int>& counter;
            ~ThreadGuard() { counter.fetch_sub(1); }
        } guard{activeCatchUpThreads_};

        Logger::get()->info("Starting TickStream catch-up {} from {} to {}", subId, fromTick, toTick);

        for (uint32_t tick = fromTick; tick <= toTick; ++tick) {
            // Check if shutdown is requested
            if (stopFlag_.load()) {
                Logger::get()->debug("TickStream catch-up {} aborted: shutdown requested", subId);
                return;
            }

            // Check if connection is still valid
            if (!conn->connected()) {
                Logger::get()->debug("TickStream catch-up {} aborted: connection closed", subId);
                break;
            }

            // Check if subscription still exists
            TickStreamFilter filter;
            {
                std::shared_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it == subscriptions_.end() || it->second.conn != conn) {
                    Logger::get()->debug("TickStream catch-up {} aborted: subscription removed", subId);
                    return;
                }
                filter = it->second.tickStreamFilter;
            }

            // Get tick data from DB
            TickData td;
            if (!db_try_get_tick_data(tick, td)) {
                continue;  // Skip ticks not in DB
            }

            // Get epoch from tick data
            uint16_t epoch = td.epoch;

            // Get logs for this tick
            bool success = false;
            std::vector<LogEvent> logs = db_get_logs_by_tick_range(epoch, tick, tick, success);

            // Get log ranges
            LogRangesPerTxInTick lr{-1};
            db_try_get_log_ranges(tick, lr);

            // Build and filter transactions
            std::vector<StreamTx> matchedTxs;
            size_t totalTxs = 0;
            for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
                if (td.transactionDigests[i] == m256i::zero()) continue;
                totalTxs++;

                std::string txHash = td.transactionDigests[i].toQubicHash();
                std::vector<uint8_t> txData;
                if (!db_try_get_transaction(txHash, txData)) continue;

                Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
                if (!tx) continue;

                StreamTx stx;
                stx.hash = txHash;
                stx.from = getIdentity(tx->sourcePublicKey, false);
                stx.to = getIdentity(tx->destinationPublicKey, false);
                stx.amount = tx->amount;
                stx.inputType = tx->inputType;
                stx.inputSize = tx->inputSize;

                // Copy input data if present
                if (tx->inputSize > 0 && txData.size() >= sizeof(Transaction) + tx->inputSize) {
                    const uint8_t* inputPtr = txData.data() + sizeof(Transaction);
                    stx.inputData.assign(inputPtr, inputPtr + tx->inputSize);
                }

                // Get execution info
                int txIndex;
                long long fromLogId, toLogId;
                uint64_t txTimestamp;
                bool executed;
                if (db_get_indexed_tx(txHash.c_str(), txIndex, fromLogId, toLogId, txTimestamp, executed)) {
                    stx.executed = executed;
                    stx.logIdFrom = fromLogId;
                    stx.logIdLength = (toLogId >= fromLogId) ? (toLogId - fromLogId + 1) : 0;
                } else {
                    stx.executed = false;
                    stx.logIdFrom = -1;
                    stx.logIdLength = 0;
                }

                // Check if matches any filter
                if (matchesAnyTxFilter(stx.from, stx.to, stx.amount, stx.inputType, filter)) {
                    matchedTxs.push_back(std::move(stx));
                }
            }

            // Collect matching logs
            std::vector<std::pair<LogEvent, int>> matchedLogs;
            for (const auto& log : logs) {
                if (matchesAnyLogFilter(log, filter)) {
                    int txIndex = 0;
                    uint64_t logId = log.getLogId();
                    for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                        if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                            if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                                static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                                txIndex = i;
                                break;
                            }
                        }
                    }
                    matchedLogs.emplace_back(log, txIndex);
                }
            }

            // Check if we should skip this tick
            bool hasMatches = !matchedTxs.empty() || !matchedLogs.empty();
            bool isHeartbeatTick = (tick % 120 == 0);

            if (filter.skipEmptyTicks && !hasMatches && !isHeartbeatTick) {
                continue;
            }

            // Build and send JSON message with controlled field order
            std::string tickJsonStr = buildTickStreamJsonString(
                tick, epoch, true, td,
                matchedTxs, matchedLogs,
                totalTxs, logs.size(),
                filter.includeInputData);

            std::string msg = "{\"jsonrpc\":\"2.0\",\"method\":\"qubic_subscription\",\"params\":{\"subscription\":\"" +
                              subId + "\",\"result\":" + tickJsonStr + "}}";

            try {
                conn->send(msg);
            } catch (const std::exception& e) {
                Logger::get()->warn("Failed to send catch-up message: {}", e.what());
                break;
            }

            // Update lastTick
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it != subscriptions_.end()) {
                    it->second.lastTick = tick;
                }
            }

            // Small delay to avoid overwhelming the client
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Drain pending ticks that arrived during catch-up
        while (true) {
            // Check if shutdown is requested
            if (stopFlag_.load()) {
                Logger::get()->debug("TickStream {} pending drain aborted: shutdown requested", subId);
                return;
            }

            // Check if connection is still valid
            if (!conn->connected()) {
                Logger::get()->debug("TickStream {} pending drain aborted: connection closed", subId);
                break;
            }

            // Get next pending tick (if any) and filter config
            std::optional<PendingTickData> pendingTick;
            TickStreamFilter filter;
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it == subscriptions_.end() || it->second.conn != conn) {
                    Logger::get()->debug("TickStream {} pending drain aborted: subscription removed", subId);
                    return;
                }

                if (it->second.pendingTicks.empty()) {
                    // No more pending ticks - mark catch-up as complete
                    it->second.catchUpInProgress = false;
                    Logger::get()->info("TickStream catch-up {} complete (drained {} pending ticks)",
                                       subId, 0);
                    lock.unlock();
                    Json::Value complete(Json::objectValue);
                    complete["catchUpComplete"] = true;
                    sendSubscriptionMessage(conn, subId, complete);
                    break;
                }

                // Take the first pending tick
                pendingTick = std::move(it->second.pendingTicks.front());
                it->second.pendingTicks.erase(it->second.pendingTicks.begin());
                filter = it->second.tickStreamFilter;

                // Skip if we've already sent this tick
                if (pendingTick->tick <= it->second.lastTick) {
                    Logger::get()->debug("TickStream {} skipping pending tick {}: already sent",
                                        subId, pendingTick->tick);
                    continue;
                }
            }

            if (!pendingTick) break;

            // Process the pending tick (similar to real-time processing)
            uint32_t tick = pendingTick->tick;
            uint16_t epoch = pendingTick->epoch;
            const TickData& td = pendingTick->td;
            const std::vector<LogEvent>& logs = pendingTick->logs;

            // Get log ranges
            LogRangesPerTxInTick lr{-1};
            db_try_get_log_ranges(tick, lr);

            // Build and filter transactions
            std::vector<StreamTx> matchedTxs;
            size_t totalTxs = 0;
            for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
                if (td.transactionDigests[i] == m256i::zero()) continue;
                totalTxs++;

                std::string txHash = td.transactionDigests[i].toQubicHash();
                std::vector<uint8_t> txData;
                if (!db_try_get_transaction(txHash, txData)) continue;

                Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
                if (!tx) continue;

                StreamTx stx;
                stx.hash = txHash;
                stx.from = getIdentity(tx->sourcePublicKey, false);
                stx.to = getIdentity(tx->destinationPublicKey, false);
                stx.amount = tx->amount;
                stx.inputType = tx->inputType;
                stx.inputSize = tx->inputSize;

                // Copy input data if present
                if (tx->inputSize > 0 && txData.size() >= sizeof(Transaction) + tx->inputSize) {
                    const uint8_t* inputPtr = txData.data() + sizeof(Transaction);
                    stx.inputData.assign(inputPtr, inputPtr + tx->inputSize);
                }

                // Get execution info from log ranges
                if (lr.length[i] > 0 && lr.fromLogId[i] >= 0) {
                    stx.executed = true;
                    stx.logIdFrom = lr.fromLogId[i];
                    stx.logIdLength = lr.length[i];
                } else {
                    int txIndex;
                    long long fromLogId, toLogId;
                    uint64_t txTimestamp;
                    bool executed;
                    if (db_get_indexed_tx(txHash.c_str(), txIndex, fromLogId, toLogId, txTimestamp, executed)) {
                        stx.executed = executed;
                        stx.logIdFrom = fromLogId;
                        stx.logIdLength = (toLogId >= fromLogId) ? (toLogId - fromLogId + 1) : 0;
                    } else {
                        stx.executed = false;
                        stx.logIdFrom = -1;
                        stx.logIdLength = 0;
                    }
                }

                // Check if matches any filter
                if (matchesAnyTxFilter(stx.from, stx.to, stx.amount, stx.inputType, filter)) {
                    matchedTxs.push_back(std::move(stx));
                }
            }

            // Collect matching logs
            std::vector<std::pair<LogEvent, int>> matchedLogs;
            for (const auto& log : logs) {
                if (matchesAnyLogFilter(log, filter)) {
                    int txIndex = 0;
                    uint64_t logId = log.getLogId();
                    for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                        if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                            if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                                static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                                txIndex = i;
                                break;
                            }
                        }
                    }
                    matchedLogs.emplace_back(log, txIndex);
                }
            }

            // Check if we should skip this tick
            bool hasMatches = !matchedTxs.empty() || !matchedLogs.empty();
            bool isHeartbeatTick = (tick % 120 == 0);

            if (filter.skipEmptyTicks && !hasMatches && !isHeartbeatTick) {
                // Update lastTick even when skipping
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it != subscriptions_.end()) {
                    it->second.lastTick = tick;
                }
                continue;
            }

            // Build and send JSON message (not catch-up since these are live ticks)
            std::string tickJsonStr = buildTickStreamJsonString(
                tick, epoch, false, td,
                matchedTxs, matchedLogs,
                totalTxs, logs.size(),
                filter.includeInputData);

            std::string msg = "{\"jsonrpc\":\"2.0\",\"method\":\"qubic_subscription\",\"params\":{\"subscription\":\"" +
                              subId + "\",\"result\":" + tickJsonStr + "}}";

            try {
                conn->send(msg);
            } catch (const std::exception& e) {
                Logger::get()->warn("Failed to send pending tick message: {}", e.what());
                break;
            }

            // Update lastTick
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it != subscriptions_.end()) {
                    it->second.lastTick = tick;
                }
            }

            // Small delay to avoid overwhelming the client
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Final check to mark complete if we exited early
        {
            bool wasCatchingUp = false;
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it != subscriptions_.end() && it->second.catchUpInProgress) {
                    it->second.catchUpInProgress = false;
                    it->second.pendingTicks.clear();
                    wasCatchingUp = true;
                    Logger::get()->info("TickStream catch-up {} complete", subId);
                }
            }
            if (wasCatchingUp) {
                Json::Value complete(Json::objectValue);
                complete["catchUpComplete"] = true;
                sendSubscriptionMessage(conn, subId, complete);
            }
        }
    }).detach();
}

void QubicSubscriptionManager::performLogsCatchUp(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subId,
    uint16_t epoch, int64_t fromLogId)
{
    // Run catch-up in a separate thread to avoid blocking
    activeCatchUpThreads_.fetch_add(1);
    std::thread([this, conn, subId, epoch, fromLogId]() {
        // RAII guard to decrement thread count on exit
        struct ThreadGuard {
            std::atomic<int>& counter;
            ~ThreadGuard() { counter.fetch_sub(1); }
        } guard{activeCatchUpThreads_};

        Logger::get()->info("Starting Logs catch-up {} from epoch {} logId {}", subId, epoch, fromLogId);

        const int64_t BATCH_SIZE = 1000;  // Fetch 1000 logs at a time
        const int64_t QUEUE_THRESHOLD = 10000;  // Start queuing when within this range

        int64_t currentLogId = fromLogId;
        TickData td{0};
        LogRangesPerTxInTick lr{-1};
        std::vector<int> logTxOrder;

        while (true) {
            // Check if shutdown is requested
            if (stopFlag_.load()) {
                Logger::get()->debug("Logs catch-up {} aborted: shutdown requested", subId);
                return;
            }

            // Check if connection is still valid
            if (!conn->connected()) {
                Logger::get()->debug("Logs catch-up {} aborted: connection closed", subId);
                break;
            }

            // Check if subscription still exists and get filter
            LogFilter filter;
            QubicSubscriptionType subType;
            {
                std::shared_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it == subscriptions_.end()) {
                    Logger::get()->debug("Logs catch-up {} aborted: subscription removed", subId);
                    return;
                }
                filter = it->second.filter;
                subType = it->second.type;
            }

            // Get current latest log ID
            int64_t latestLogId = db_get_latest_log_id(epoch);
            if (latestLogId < 0) {
                // No logs yet, wait and retry
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Check if we're within the queue threshold
            int64_t remaining = latestLogId - currentLogId;
            if (remaining <= QUEUE_THRESHOLD) {
                // Start queuing real-time logs and continue catch-up
                {
                    std::unique_lock lock(mutex_);
                    auto it = subscriptions_.find(subId);
                    if (it != subscriptions_.end()) {
                        it->second.lastLogId = currentLogId;
                        // catchUpInProgress stays true, but now logs will be queued
                    }
                }
                Logger::get()->debug("Logs catch-up {} entering queue mode at logId {} (remaining: {})",
                                    subId, currentLogId, remaining);
            }

            // Determine batch end
            int64_t batchEnd = std::min(currentLogId + BATCH_SIZE - 1, latestLogId);

            // Fetch logs in batch
            for (int64_t logId = currentLogId; logId <= batchEnd; ++logId) {
                // Check for abort conditions periodically
                if (logId % 100 == 0) {
                    if (stopFlag_.load() || !conn->connected()) {
                        break;
                    }
                    std::shared_lock lock(mutex_);
                    if (subscriptions_.find(subId) == subscriptions_.end()) {
                        break;
                    }
                }

                LogEvent log;
                if (!db_try_get_log(epoch, static_cast<uint64_t>(logId), log)) {
                    // Log not found, skip
                    continue;
                }

                // Get tick data if needed
                if (log.getTick() != td.tick || log.getEpoch() != td.epoch) {
                    db_try_get_tick_data(log.getTick(), td);
                    db_try_get_log_ranges(log.getTick(), lr);
                    logTxOrder = lr.sort();
                }

                // Find transaction index for this log
                int txIndex = 0;
                for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                    if (lr.fromLogId[i] >= 0 && lr.length[i] > 0) {
                        if (static_cast<int64_t>(logId) >= lr.fromLogId[i] &&
                            static_cast<int64_t>(logId) < lr.fromLogId[i] + lr.length[i]) {
                            txIndex = i;
                            break;
                        }
                    }
                }

                // Convert to log format
                Json::Value qubicLog = log.parseToJsonValueWithExtraData(td, txIndex);

                // Get source/destination identities for filtering (from body.from/to)
                std::string sourceIdentity;
                std::string destIdentity;
                if (qubicLog.isMember("body") && qubicLog["body"].isObject()) {
                    const auto& body = qubicLog["body"];
                    if (body.isMember("from")) {
                        sourceIdentity = body["from"].asString();
                    }
                    if (body.isMember("to")) {
                        destIdentity = body["to"].asString();
                    }
                    // Also check sourcePublicKey/destinationPublicKey for asset transfers
                    if (body.isMember("sourcePublicKey")) {
                        sourceIdentity = body["sourcePublicKey"].asString();
                    }
                    if (body.isMember("destinationPublicKey")) {
                        destIdentity = body["destinationPublicKey"].asString();
                    }
                }

                // Check if log matches filter
                if (!matchesFilter(log, filter, sourceIdentity, destIdentity)) {
                    continue;
                }

                // Add isCatchUp field
                qubicLog["isCatchUp"] = true;

                // Send the log
                try {
                    sendSubscriptionMessage(conn, subId, qubicLog);
                } catch (const std::exception& e) {
                    Logger::get()->warn("Failed to send catch-up log: {}", e.what());
                    break;
                }

                // Small delay to avoid overwhelming the client
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }

            // Update current position
            currentLogId = batchEnd + 1;

            // Check if we've caught up
            if (currentLogId > latestLogId) {
                break;
            }

            // Small delay between batches
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Drain pending logs that arrived during catch-up
        while (true) {
            if (stopFlag_.load()) {
                Logger::get()->debug("Logs catch-up {} pending drain aborted: shutdown", subId);
                return;
            }

            if (!conn->connected()) {
                Logger::get()->debug("Logs catch-up {} pending drain aborted: connection closed", subId);
                break;
            }

            // Get next pending log (if any) and filter config
            std::optional<PendingLogEvent> pendingLog;
            LogFilter filter;
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it == subscriptions_.end()) {
                    return;
                }
                if (!it->second.pendingLogs.empty()) {
                    pendingLog = it->second.pendingLogs.front();
                    it->second.pendingLogs.erase(it->second.pendingLogs.begin());
                    filter = it->second.filter;
                } else {
                    // No more pending logs, mark catch-up complete
                    it->second.catchUpInProgress = false;
                    it->second.lastLogId = -1;
                    Logger::get()->info("Logs catch-up {} complete", subId);
                    lock.unlock();
                    Json::Value complete(Json::objectValue);
                    complete["catchUpComplete"] = true;
                    sendSubscriptionMessage(conn, subId, complete);
                    return;
                }
            }

            if (!pendingLog) {
                continue;
            }

            // Check if log matches filter
            if (!matchesFilter(pendingLog->log, filter,
                              pendingLog->sourceIdentity, pendingLog->destIdentity)) {
                continue;
            }

            // Get tick data for the log
            TickData pendingTd{0};
            LogRangesPerTxInTick pendingLr{-1};
            db_try_get_tick_data(pendingLog->log.getTick(), pendingTd);
            db_try_get_log_ranges(pendingLog->log.getTick(), pendingLr);

            // Find transaction index
            int txIndex = 0;
            int64_t logId = pendingLog->log.getLogId();
            for (int i = 0; i < LOG_TX_PER_TICK; ++i) {
                if (pendingLr.fromLogId[i] >= 0 && pendingLr.length[i] > 0) {
                    if (logId >= pendingLr.fromLogId[i] &&
                        logId < pendingLr.fromLogId[i] + pendingLr.length[i]) {
                        txIndex = i;
                        break;
                    }
                }
            }

            // Convert to log format
            Json::Value qubicLog = pendingLog->log.parseToJsonValueWithExtraData(pendingTd, txIndex);
            // No isCatchUp field for real-time logs

            try {
                sendSubscriptionMessage(conn, subId, qubicLog);
            } catch (const std::exception& e) {
                Logger::get()->warn("Failed to send pending log: {}", e.what());
                break;
            }

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        // Final cleanup
        {
            bool wasCatchingUp = false;
            {
                std::unique_lock lock(mutex_);
                auto it = subscriptions_.find(subId);
                if (it != subscriptions_.end() && it->second.catchUpInProgress) {
                    it->second.catchUpInProgress = false;
                    it->second.pendingLogs.clear();
                    it->second.lastLogId = -1;
                    wasCatchingUp = true;
                    Logger::get()->info("Logs catch-up {} complete", subId);
                }
            }
            if (wasCatchingUp) {
                Json::Value complete(Json::objectValue);
                complete["catchUpComplete"] = true;
                sendSubscriptionMessage(conn, subId, complete);
            }
        }
    }).detach();
}
