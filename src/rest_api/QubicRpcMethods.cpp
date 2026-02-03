#include "QubicRpcMethods.h"
#include "src/bob.h"
#include "src/core/asset.h"
#include "src/core/entity.h"
#include "src/core/k12_and_key_util.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "src/version.h"
#include "ApiHelpers.h"
#include "src/global_var.h"
#include "QubicRpcMapper.h"
#include "QubicSubscriptionManager.h"
#include "src/database/db.h"
#include <cstring>
#include <sstream>
#include <vector>

// ============================================================================
// Helper Methods
// ============================================================================

bool QubicRpcMethods::isValidIdentityFormat(const std::string& identity) {
    // Qubic identity must be exactly 60 uppercase A-Z characters
    if (identity.size() != 60) {
        return false;
    }
    for (char c : identity) {
        if (c < 'A' || c > 'Z') {
            return false;
        }
    }
    return true;
}

bool QubicRpcMethods::isValidIdentityInput(const std::string& input) {
    // Quick check for empty input
    if (input.empty()) {
        return false;
    }
    // normalizeIdentity returns empty string if invalid
    return !normalizeIdentity(input).empty();
}

std::string QubicRpcMethods::normalizeIdentity(const std::string& input) {
    // If it starts with 0x and is 66 chars, convert from hex
    if (input.size() == 66 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        std::string identity = hexToIdentity(input);
        if (identity.empty() || !isValidIdentityFormat(identity)) {
            return "";
        }
        return identity;
    }
    // If it's 64 hex chars without 0x prefix
    if (input.size() == 64) {
        bool isHex = true;
        for (char c : input) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                isHex = false;
                break;
            }
        }
        if (isHex) {
            std::string identity = hexToIdentity("0x" + input);
            if (identity.empty() || !isValidIdentityFormat(identity)) {
                return "";
            }
            return identity;
        }
    }
    // Validate Qubic identity format (60 uppercase A-Z characters)
    if (!isValidIdentityFormat(input)) {
        return "";
    }
    return input;
}

std::string QubicRpcMethods::hexToIdentity(const std::string& hex) {
    m256i publicKey;
    if (!QubicRpc::hexToPublicKey(hex, publicKey)) {
        return "";
    }
    char identity[64] = {0};
    getIdentityFromPublicKey(publicKey.m256i_u8, identity, false);
    return std::string(identity);
}

std::string QubicRpcMethods::identityToHex(const std::string& identity) {
    if (identity.size() != 60) {
        return "";
    }
    uint8_t publicKey[32];
    getPublicKeyFromIdentity(identity.c_str(), publicKey);
    return QubicRpc::bytesToHex(publicKey, 32);
}

// ============================================================================
// Chain Info Methods
// ============================================================================

Json::Value QubicRpcMethods::chainId() {
    Json::Value result(Json::objectValue);
    result["chainId"] = QubicRpc::uint64ToHex(QubicRpc::CHAIN_ID);
    result["chainIdDecimal"] = Json::UInt64(QubicRpc::CHAIN_ID);
    result["network"] = "qubic-mainnet";
    return result;
}

Json::Value QubicRpcMethods::clientVersion() {
    return std::string("QubicBob/") + BOB_VERSION;
}

Json::Value QubicRpcMethods::syncing() {
    auto status = ApiHelpers::getSyncStatus();

    Json::Value result(Json::objectValue);
    result["epoch"] = status.epoch;
    result["initialTick"] = status.initialTick;

    // Tick status breakdown
    result["currentFetchingTick"] = status.currentFetchingTick;
    result["currentFetchingLogTick"] = status.currentFetchingLogTick;
    result["currentVerifyLoggingTick"] = status.currentVerifyLoggingTick;
    result["currentIndexingTick"] = status.currentIndexingTick;

    // Network tick (0 = unknown/not available)
    if (status.lastSeenNetworkTick > 0) {
        result["lastSeenNetworkTick"] = status.lastSeenNetworkTick;
    }

    if (!status.isSyncing) {
        result["syncing"] = false;
    } else {
        result["syncing"] = true;
        result["progress"] = status.progress;
    }

    return result;
}

Json::Value QubicRpcMethods::status() {
    std::string jsonStr = bobGetStatus();

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse status";
        return error;
    }

    return result;
}

Json::Value QubicRpcMethods::getCurrentEpoch() {
    auto info = ApiHelpers::getCurrentEpochInfo();

    Json::Value result(Json::objectValue);
    result["epoch"] = info.epoch;
    result["currentTick"] = info.currentTick;
    result["initialTick"] = info.initialTick;
    result["endTick"] = info.endTick;
    result["endTickStartLogId"] = Json::Int64(info.endTickStartLogId);
    result["endTickEndLogId"] = Json::Int64(info.endTickEndLogId);

    return result;
}

// ============================================================================
// Tick Methods
// ============================================================================

Json::Value QubicRpcMethods::getTickNumber() {
    return Json::UInt(gCurrentVerifyLoggingTick.load());
}

Json::Value QubicRpcMethods::getTickByNumber(const std::string& tickTag, bool includeTransactions) {
    int64_t tick = QubicRpc::parseTickTag(tickTag);
    if (tick < 0) {
        return Json::Value::null;
    }

    TickData td;
    if (!db_try_get_tick_data(static_cast<uint32_t>(tick), td)) {
        return Json::Value::null;
    }

    // Collect transaction digests
    std::vector<m256i> txDigests;
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
        if (td.transactionDigests[i] != m256i::zero()) {
            txDigests.push_back(td.transactionDigests[i]);
        }
    }

    return QubicRpc::tickDataToQubicTick(static_cast<uint32_t>(tick), td, txDigests, includeTransactions);
}

// todo: remove this or implement it properly
Json::Value QubicRpcMethods::getTickByHash(const std::string& tickHash, bool includeTransactions) {
    m256i targetHash;
    if (!QubicRpc::hexToPublicKey(tickHash, targetHash)) {
        return Json::Value::null;
    }

    // Search recent ticks (last 1000)
    uint32_t currentTick = gCurrentVerifyLoggingTick.load();
    uint32_t startTick = currentTick > 1000 ? currentTick - 1000 : gInitialTick.load();

    for (uint32_t tick = currentTick; tick >= startTick; --tick) {
        TickData td;
        if (db_try_get_tick_data(tick, td)) {
            if (memcmp(td.signature, targetHash.m256i_u8, 32) == 0) {
                std::vector<m256i> txDigests;
                for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
                    if (td.transactionDigests[i] != m256i::zero()) {
                        txDigests.push_back(td.transactionDigests[i]);
                    }
                }
                return QubicRpc::tickDataToQubicTick(tick, td, txDigests, includeTransactions);
            }
        }
        if (tick == startTick) break;
    }

    return Json::Value::null;
}

// ============================================================================
// Transaction Methods
// ============================================================================

Json::Value QubicRpcMethods::getTransactionByHash(const std::string& txHashInput) {
    // Normalize hash - could be hex or Qubic format
    std::string qubicHash;
    if (txHashInput.size() == 66 && txHashInput[0] == '0' && txHashInput[1] == 'x') {
        qubicHash = QubicRpc::hexToQubicIdentity(txHashInput);
    } else {
        qubicHash = txHashInput;
    }

    if (qubicHash.empty()) {
        return Json::Value::null;
    }

    // Fetch transaction data
    std::vector<uint8_t> txData;
    if (!db_try_get_transaction(qubicHash, txData)) {
        return Json::Value::null;
    }

    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());

    // Get tick data for context
    TickData td;
    if (!db_try_get_tick_data(tx->tick, td)) {
        return Json::Value::null;
    }

    // Find transaction index
    int txIndex = -1;
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
        if (td.transactionDigests[i].toQubicHash() == qubicHash) {
            txIndex = i;
            break;
        }
    }

    return QubicRpc::transactionToQubicTx(tx, qubicHash, tx->tick, txIndex, td);
}

Json::Value QubicRpcMethods::getTransactionReceipt(const std::string& txHashInput) {
    // Normalize hash
    std::string qubicHash;
    if (txHashInput.size() == 66 && txHashInput[0] == '0' && txHashInput[1] == 'x') {
        qubicHash = QubicRpc::hexToQubicIdentity(txHashInput);
    } else {
        qubicHash = txHashInput;
    }

    if (qubicHash.empty()) {
        return Json::Value::null;
    }

    // Fetch transaction data
    std::vector<uint8_t> txData;
    if (!db_try_get_transaction(qubicHash, txData)) {
        return Json::Value::null;
    }

    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());

    // Get tick data
    TickData td;
    if (!db_try_get_tick_data(tx->tick, td)) {
        return Json::Value::null;
    }

    // Try to get indexed transaction info (may not be available yet if not indexed)
    int txIndex = -1;
    long long fromLogId = -1, toLogId = -1;
    uint64_t timestamp = 0;
    bool executed = false;
    bool hasIndexedData = db_get_indexed_tx(qubicHash.c_str(), txIndex, fromLogId, toLogId, timestamp, executed);

    // If not indexed, find txIndex by scanning tick data
    if (!hasIndexedData || txIndex < 0) {
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
            if (td.transactionDigests[i].toQubicHash() == qubicHash) {
                txIndex = i;
                break;
            }
        }
    }

    // Get logs for this transaction (if indexed data available)
    std::vector<LogEvent> logs;
    if (hasIndexedData && fromLogId >= 0 && toLogId >= fromLogId) {
        logs = db_try_get_logs(td.epoch, fromLogId, toLogId);
    }

    return QubicRpc::transactionToQubicReceipt(tx, qubicHash, tx->tick, txIndex, td, logs, executed);
}

Json::Value QubicRpcMethods::broadcastTransaction(const std::string& signedTxHex) {
    auto result = ApiHelpers::broadcastTransaction(signedTxHex);

    if (!result.success) {
        Json::Value error(Json::objectValue);
        error["error"] = result.error;
        return error;
    }

    // Return transaction hash on success (similar to eth_sendRawTransaction)
    return result.txHash;
}

// ============================================================================
// Balance & Transfer Methods
// ============================================================================

Json::Value QubicRpcMethods::getBalance(const std::string& identityInput) {
    std::string identity = normalizeIdentity(identityInput);
    if (identity.empty() || identity.size() < 60) {
        Json::Value error(Json::objectValue);
        error["error"] = "Invalid identity format";
        return error;
    }

    auto info = ApiHelpers::getBalanceInfo(identity);

    if (!info.found) {
        Json::Value error(Json::objectValue);
        error["error"] = info.error;
        return error;
    }

    Json::Value result(Json::objectValue);
    result["identity"] = identity;
    result["publicKeyHex"] = identityToHex(identity);
    result["balance"] = std::to_string(info.balance);
    result["incomingAmount"] = std::to_string(info.incomingAmount);
    result["outgoingAmount"] = std::to_string(info.outgoingAmount);
    result["numberOfIncomingTransfers"] = info.numberOfIncomingTransfers;
    result["numberOfOutgoingTransfers"] = info.numberOfOutgoingTransfers;
    result["latestIncomingTransferTick"] = info.latestIncomingTransferTick;
    result["latestOutgoingTransferTick"] = info.latestOutgoingTransferTick;
    result["currentTick"] = info.currentTick;

    if (info.isBeingProcessed) {
        result["warning"] = "Entity is being processed, balance may not be final";
    }

    return result;
}

Json::Value QubicRpcMethods::getTransfers(const Json::Value& filterParams) {
    // Parse filter parameters
    uint32_t fromTick = gCurrentVerifyLoggingTick.load();
    uint32_t toTick = fromTick;

    if (filterParams.isMember("fromTick")) {
        if (filterParams["fromTick"].isNumeric()) {
            fromTick = filterParams["fromTick"].asUInt();
        } else {
            int64_t tick = QubicRpc::parseTickTag(filterParams["fromTick"].asString());
            if (tick >= 0) fromTick = static_cast<uint32_t>(tick);
        }
    }
    if (filterParams.isMember("toTick")) {
        if (filterParams["toTick"].isNumeric()) {
            toTick = filterParams["toTick"].asUInt();
        } else {
            int64_t tick = QubicRpc::parseTickTag(filterParams["toTick"].asString());
            if (tick >= 0) toTick = static_cast<uint32_t>(tick);
        }
    }

    // Limit range to prevent DoS
    const uint32_t MAX_RANGE = 1000;
    if (toTick > fromTick + MAX_RANGE) {
        toTick = fromTick + MAX_RANGE;
    }

    // Parse scIndex (default 0 for protocol logs like QU_TRANSFER)
    uint32_t scIndex = 0;
    if (filterParams.isMember("scIndex") && filterParams["scIndex"].isNumeric()) {
        scIndex = filterParams["scIndex"].asUInt();
    }

    // Parse logType (default 0 = QU_TRANSFER for backwards compatibility)
    uint32_t logType = 0;
    if (filterParams.isMember("logType") && filterParams["logType"].isNumeric()) {
        logType = filterParams["logType"].asUInt();
    }

    // Parse topic filters - use wildcard if not specified
    // Wildcard identity: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB
    const std::string wildcardIdentity = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB";
    std::string topic1 = wildcardIdentity, topic2 = wildcardIdentity, topic3 = wildcardIdentity;

    if (filterParams.isMember("topic1") && filterParams["topic1"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic1"].asString());
        if (!t.empty() && t.size() == 60) topic1 = t;
    }
    if (filterParams.isMember("topic2") && filterParams["topic2"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic2"].asString());
        if (!t.empty() && t.size() == 60) topic2 = t;
    }
    if (filterParams.isMember("topic3") && filterParams["topic3"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic3"].asString());
        if (!t.empty() && t.size() == 60) topic3 = t;
    }

    // Parse optional identity filter (JSON-RPC extension, not in findLog)
    std::string identity;
    bool hasIdentityFilter = false;
    if (filterParams.isMember("identity") && filterParams["identity"].isString()) {
        identity = normalizeIdentity(filterParams["identity"].asString());
        hasIdentityFilter = !identity.empty();
    }

    // Call getCustomLog from bobAPI.cpp - reuse existing implementation
    uint16_t epoch = gCurrentProcessingEpoch.load();
    std::string logsJson = getCustomLog(scIndex, logType, topic1, topic2, topic3, epoch, fromTick, toTick);

    // Parse the JSON array returned by getCustomLog
    Json::Value logsArray;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(logsJson);
    if (!Json::parseFromStream(builder, stream, &logsArray, &errors)) {
        Json::Value errorResult(Json::objectValue);
        errorResult["error"] = "Failed to parse logs";
        return errorResult;
    }

    // Build result
    Json::Value result(Json::objectValue);
    if (hasIdentityFilter) {
        result["identity"] = identity;
    }
    result["fromTick"] = fromTick;
    result["toTick"] = toTick;
    if (scIndex > 0) {
        result["scIndex"] = scIndex;
    }
    result["logType"] = logType;

    Json::Value transfers(Json::arrayValue);

    // Post-process logs to apply identity filter and add direction field
    for (const auto& logEntry : logsArray) {
        // Apply identity filter if specified (JSON-RPC extension)
        if (hasIdentityFilter) {
            bool match = false;
            if (logEntry.isMember("source") && logEntry["source"].asString() == identity) {
                match = true;
            }
            if (logEntry.isMember("destination") && logEntry["destination"].asString() == identity) {
                match = true;
            }
            if (!match) continue;

            // Add direction field for identity-filtered results
            Json::Value enrichedEntry = logEntry;
            if (logEntry.isMember("source") && logEntry["source"].asString() == identity) {
                enrichedEntry["direction"] = "outgoing";
            } else {
                enrichedEntry["direction"] = "incoming";
            }
            transfers.append(enrichedEntry);
        } else {
            transfers.append(logEntry);
        }
    }

    result["transfers"] = transfers;
    result["count"] = static_cast<Json::UInt>(transfers.size());

    return result;
}

Json::Value QubicRpcMethods::findLogIds(const Json::Value& filterParams) {
    // Validate required parameters
    if (!filterParams.isMember("scIndex") || !filterParams["scIndex"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: scIndex";
        return error;
    }
    if (!filterParams.isMember("logType") || !filterParams["logType"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: logType";
        return error;
    }
    if (!filterParams.isMember("fromTick") || !filterParams["fromTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: fromTick";
        return error;
    }
    if (!filterParams.isMember("toTick") || !filterParams["toTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: toTick";
        return error;
    }

    uint32_t scIndex = filterParams["scIndex"].asUInt();
    uint32_t logType = filterParams["logType"].asUInt();
    uint32_t fromTick = filterParams["fromTick"].asUInt();
    uint32_t toTick = filterParams["toTick"].asUInt();

    if (fromTick > toTick) {
        Json::Value error;
        error["error"] = "fromTick must be <= toTick";
        return error;
    }

    // Parse topic filters - use wildcard if not specified
    const std::string wildcardIdentity = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB";
    std::string topic1 = wildcardIdentity, topic2 = wildcardIdentity, topic3 = wildcardIdentity;

    if (filterParams.isMember("topic1") && filterParams["topic1"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic1"].asString());
        if (!t.empty() && t.size() == 60) topic1 = t;
    }
    if (filterParams.isMember("topic2") && filterParams["topic2"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic2"].asString());
        if (!t.empty() && t.size() == 60) topic2 = t;
    }
    if (filterParams.isMember("topic3") && filterParams["topic3"].isString()) {
        std::string t = normalizeIdentity(filterParams["topic3"].asString());
        if (!t.empty() && t.size() == 60) topic3 = t;
    }

    std::string idsJson = bobFindLog(scIndex, logType, topic1, topic2, topic3, fromTick, toTick);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(idsJson);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse log IDs";
        return error;
    }

    return result;
}

Json::Value QubicRpcMethods::getLogsByIdRange(uint16_t epoch, int64_t fromId, int64_t toId) {
    std::string jsonStr = bobGetLog(epoch, fromId, toId);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse logs";
        return error;
    }

    return result;
}

// ============================================================================
// Asset Methods
// ============================================================================

Json::Value QubicRpcMethods::getAssetBalance(const std::string& identityInput,
                                              const std::string& issuerInput,
                                              const std::string& assetName) {
    std::string identity = normalizeIdentity(identityInput);
    std::string issuer = normalizeIdentity(issuerInput);

    if (identity.empty() || issuer.empty()) {
        Json::Value error(Json::objectValue);
        error["error"] = "Invalid identity format";
        return error;
    }

    auto info = ApiHelpers::getAssetBalanceInfo(identity, issuer, assetName, 0);

    if (!info.found && !info.error.empty()) {
        Json::Value error(Json::objectValue);
        error["error"] = info.error;
        return error;
    }

    Json::Value result(Json::objectValue);
    result["identity"] = identity;
    result["issuer"] = issuer;
    result["assetName"] = assetName;
    result["ownershipBalance"] = std::to_string(info.ownershipBalance);
    result["possessionBalance"] = std::to_string(info.possessionBalance);

    return result;
}

Json::Value QubicRpcMethods::getAssets(const std::string& identityInput) {
    // This would require asset indexing to implement efficiently
    Json::Value error(Json::objectValue);
    error["error"] = "Asset listing not yet implemented - use getAssetBalance with known asset";
    return error;
}

// ============================================================================
// Log Methods
// ============================================================================

Json::Value QubicRpcMethods::getLogs(const Json::Value& filterParams) {
    Json::Value result(Json::arrayValue);

    // Parse filter parameters
    uint32_t fromTick = gCurrentVerifyLoggingTick.load();
    uint32_t toTick = fromTick;

    if (filterParams.isMember("fromTick")) {
        int64_t tick = QubicRpc::parseTickTag(filterParams["fromTick"].asString());
        if (tick >= 0) fromTick = static_cast<uint32_t>(tick);
    }
    if (filterParams.isMember("toTick")) {
        int64_t tick = QubicRpc::parseTickTag(filterParams["toTick"].asString());
        if (tick >= 0) toTick = static_cast<uint32_t>(tick);
    }

    // Limit range to prevent DoS
    const uint32_t MAX_RANGE = 1000;
    if (toTick > fromTick + MAX_RANGE) {
        toTick = fromTick + MAX_RANGE;
    }

    // Parse identity filter (maps to address in Eth terms)
    std::vector<std::string> identities;
    if (filterParams.isMember("identity")) {
        if (filterParams["identity"].isArray()) {
            for (const auto& id : filterParams["identity"]) {
                std::string normalized = normalizeIdentity(id.asString());
                if (!normalized.empty()) {
                    identities.push_back(normalized);
                }
            }
        } else if (filterParams["identity"].isString()) {
            std::string normalized = normalizeIdentity(filterParams["identity"].asString());
            if (!normalized.empty()) {
                identities.push_back(normalized);
            }
        }
    }

    // Parse log type filter
    std::vector<uint32_t> logTypes;
    if (filterParams.isMember("logType")) {
        if (filterParams["logType"].isArray()) {
            for (const auto& lt : filterParams["logType"]) {
                logTypes.push_back(lt.asUInt());
            }
        } else if (filterParams["logType"].isNumeric()) {
            logTypes.push_back(filterParams["logType"].asUInt());
        }
    }

    // Fetch logs
    uint16_t epoch = gCurrentProcessingEpoch.load();
    bool success;
    auto logs = db_get_logs_by_tick_range(epoch, fromTick, toTick, success);

    if (!success) {
        return result;
    }

    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    uint64_t logIndexInTick = 0;
    uint32_t currentTick = 0;

    for (auto& log : logs) {
        uint32_t logTick = log.getTick();

        // Load tick data if changed
        if (logTick != currentTick) {
            db_try_get_tick_data(logTick, td);
            db_try_get_log_ranges(logTick, lr);
            currentTick = logTick;
            logIndexInTick = 0;
        }

        // Apply log type filter
        if (!logTypes.empty()) {
            bool match = false;
            for (uint32_t lt : logTypes) {
                if (log.getType() == lt) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;
        }

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

        // Convert to Qubic log format
        Json::Value qubicLog = QubicRpc::logEventToQubicLog(log, td, txIndex, logIndexInTick++);

        // Apply identity filter if specified
        if (!identities.empty()) {
            // Check if any of the identities match source or destination
            bool match = false;
            if (qubicLog.isMember("source")) {
                for (const auto& id : identities) {
                    if (qubicLog["source"].asString() == id) {
                        match = true;
                        break;
                    }
                }
            }
            if (!match && qubicLog.isMember("destination")) {
                for (const auto& id : identities) {
                    if (qubicLog["destination"].asString() == id) {
                        match = true;
                        break;
                    }
                }
            }
            if (!match) continue;
        }

        result.append(qubicLog);
    }

    return result;
}

// ============================================================================
// Subscription Methods
// ============================================================================

std::string QubicRpcMethods::subscribe(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionType,
    const Json::Value& filterParams)
{
    auto& manager = QubicSubscriptionManager::instance();

    if (subscriptionType == "newTicks") {
        return manager.subscribe(conn, QubicSubscriptionType::NewTicks);
    }
    else if (subscriptionType == "logs") {
        LogFilter filter;
        std::optional<int64_t> startLogId;
        std::optional<uint16_t> startEpoch;

        if (filterParams.isObject()) {
            if (filterParams.isMember("identity")) {
                if (filterParams["identity"].isArray()) {
                    for (const auto& id : filterParams["identity"]) {
                        std::string normalized = normalizeIdentity(id.asString());
                        if (!normalized.empty()) {
                            filter.identities.push_back(normalized);
                        }
                    }
                } else if (filterParams["identity"].isString()) {
                    std::string normalized = normalizeIdentity(filterParams["identity"].asString());
                    if (!normalized.empty()) {
                        filter.identities.push_back(normalized);
                    }
                }
            }

            if (filterParams.isMember("logType")) {
                if (filterParams["logType"].isArray()) {
                    for (const auto& lt : filterParams["logType"]) {
                        filter.logTypes.push_back(lt.asUInt());
                    }
                } else if (filterParams["logType"].isNumeric()) {
                    filter.logTypes.push_back(filterParams["logType"].asUInt());
                }
            }

            // Parse catch-up parameters
            if (filterParams.isMember("startLogId") && filterParams["startLogId"].isNumeric()) {
                startLogId = filterParams["startLogId"].asInt64();
                filter.startLogId = startLogId;
            }
            if (filterParams.isMember("startEpoch") && filterParams["startEpoch"].isNumeric()) {
                startEpoch = static_cast<uint16_t>(filterParams["startEpoch"].asUInt());
                filter.startEpoch = startEpoch;
            }
        }

        std::string subId = manager.subscribe(conn, QubicSubscriptionType::Logs, filter);

        // If startLogId specified, trigger catch-up
        if (!subId.empty() && startLogId.has_value()) {
            uint16_t epoch = startEpoch.value_or(gCurrentProcessingEpoch.load());
            manager.performLogsCatchUp(conn, subId, epoch, startLogId.value());
        }

        return subId;
    }
    else if (subscriptionType == "transfers") {
        LogFilter filter;
        filter.logTypes.push_back(QU_TRANSFER);
        std::optional<int64_t> startLogId;
        std::optional<uint16_t> startEpoch;

        if (filterParams.isObject()) {
            if (filterParams.isMember("identity")) {
                if (filterParams["identity"].isArray()) {
                    for (const auto& id : filterParams["identity"]) {
                        std::string normalized = normalizeIdentity(id.asString());
                        if (!normalized.empty()) {
                            filter.identities.push_back(normalized);
                        }
                    }
                } else if (filterParams["identity"].isString()) {
                    std::string normalized = normalizeIdentity(filterParams["identity"].asString());
                    if (!normalized.empty()) {
                        filter.identities.push_back(normalized);
                    }
                }
            }

            // Parse catch-up parameters
            if (filterParams.isMember("startLogId") && filterParams["startLogId"].isNumeric()) {
                startLogId = filterParams["startLogId"].asInt64();
                filter.startLogId = startLogId;
            }
            if (filterParams.isMember("startEpoch") && filterParams["startEpoch"].isNumeric()) {
                startEpoch = static_cast<uint16_t>(filterParams["startEpoch"].asUInt());
                filter.startEpoch = startEpoch;
            }
        }

        std::string subId = manager.subscribe(conn, QubicSubscriptionType::Transfers, filter);

        // If startLogId specified, trigger catch-up
        if (!subId.empty() && startLogId.has_value()) {
            uint16_t epoch = startEpoch.value_or(gCurrentProcessingEpoch.load());
            manager.performLogsCatchUp(conn, subId, epoch, startLogId.value());
        }

        return subId;
    }
    else if (subscriptionType == "tickStream") {
        TickStreamFilter filter;
        uint32_t startTick = 0;

        if (filterParams.isObject()) {
            // Parse txFilters array
            if (filterParams.isMember("txFilters") && filterParams["txFilters"].isArray()) {
                for (const auto& txf : filterParams["txFilters"]) {
                    TxFilter tf;
                    if (txf.isMember("from") && txf["from"].isString()) {
                        tf.from = normalizeIdentity(txf["from"].asString());
                    }
                    if (txf.isMember("to") && txf["to"].isString()) {
                        tf.to = normalizeIdentity(txf["to"].asString());
                    }
                    if (txf.isMember("minAmount") && txf["minAmount"].isNumeric()) {
                        tf.minAmount = txf["minAmount"].asInt64();
                    }
                    if (txf.isMember("inputType") && txf["inputType"].isNumeric()) {
                        tf.inputType = static_cast<int16_t>(txf["inputType"].asInt());
                    }
                    filter.txFilters.push_back(tf);
                }
            }

            // Parse logFilters array
            if (filterParams.isMember("logFilters") && filterParams["logFilters"].isArray()) {
                for (const auto& lf : filterParams["logFilters"]) {
                    LogStreamFilter sf;
                    if (lf.isMember("scIndex") && lf["scIndex"].isNumeric()) {
                        sf.scIndex = lf["scIndex"].asUInt();
                    }
                    if (lf.isMember("logType") && lf["logType"].isNumeric()) {
                        sf.logType = lf["logType"].asUInt();
                    }
                    if (lf.isMember("transferMinAmount") && lf["transferMinAmount"].isNumeric()) {
                        sf.transferMinAmount = lf["transferMinAmount"].asInt64();
                    }
                    filter.logFilters.push_back(sf);
                }
            }

            // Parse startTick
            if (filterParams.isMember("startTick") && filterParams["startTick"].isNumeric()) {
                startTick = filterParams["startTick"].asUInt();
            }

            // Parse skipEmptyTicks (default: false)
            if (filterParams.isMember("skipEmptyTicks") && filterParams["skipEmptyTicks"].isBool()) {
                filter.skipEmptyTicks = filterParams["skipEmptyTicks"].asBool();
            }

            // Parse includeInputData (default: true)
            if (filterParams.isMember("includeInputData") && filterParams["includeInputData"].isBool()) {
                filter.includeInputData = filterParams["includeInputData"].asBool();
            }
        }

        // Create the subscription
        std::string subId = manager.subscribeTickStream(conn, filter, startTick);

        // If startTick specified, trigger catch-up
        if (!subId.empty() && startTick > 0) {
            uint32_t currentTick = gCurrentVerifyLoggingTick.load();
            if (startTick < currentTick) {
                manager.performCatchUp(conn, subId, startTick, currentTick - 1);
            }
        }

        return subId;
    }

    return "";  // Invalid subscription type
}

bool QubicRpcMethods::unsubscribe(
    const drogon::WebSocketConnectionPtr& conn,
    const std::string& subscriptionId)
{
    return QubicSubscriptionManager::instance().unsubscribe(conn, subscriptionId);
}

// ============================================================================
// Epoch Methods
// ============================================================================

Json::Value QubicRpcMethods::getEpochInfo(uint16_t epoch) {
    std::string jsonStr = bobGetEpochInfo(epoch);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse epoch info";
        return error;
    }

    return result;
}

Json::Value QubicRpcMethods::getEndEpochLogs(uint16_t epoch) {
    std::string jsonStr = bobGetEndEpochLog(epoch);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse end epoch logs";
        return error;
    }

    return result;
}

// ============================================================================
// Transfer History Methods
// ============================================================================

Json::Value QubicRpcMethods::getQuTransfers(const Json::Value& filterParams) {
    // Validate required parameters
    if (!filterParams.isMember("identity") || !filterParams["identity"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: identity";
        return error;
    }
    if (!filterParams.isMember("fromTick") || !filterParams["fromTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: fromTick";
        return error;
    }
    if (!filterParams.isMember("toTick") || !filterParams["toTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: toTick";
        return error;
    }

    std::string identity = normalizeIdentity(filterParams["identity"].asString());
    if (identity.empty()) {
        Json::Value error;
        error["error"] = "Invalid identity format";
        return error;
    }

    uint32_t fromTick = filterParams["fromTick"].asUInt();
    uint32_t toTick = filterParams["toTick"].asUInt();

    std::string jsonStr = getQuTransfersForIdentity(fromTick, toTick, identity);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse transfers";
        return error;
    }

    return result;
}

Json::Value QubicRpcMethods::getAssetTransfers(const Json::Value& filterParams) {
    // Validate required parameters
    if (!filterParams.isMember("identity") || !filterParams["identity"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: identity";
        return error;
    }
    if (!filterParams.isMember("issuer") || !filterParams["issuer"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: issuer";
        return error;
    }
    if (!filterParams.isMember("assetName") || !filterParams["assetName"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: assetName";
        return error;
    }
    if (!filterParams.isMember("fromTick") || !filterParams["fromTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: fromTick";
        return error;
    }
    if (!filterParams.isMember("toTick") || !filterParams["toTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: toTick";
        return error;
    }

    std::string identity = normalizeIdentity(filterParams["identity"].asString());
    if (identity.empty()) {
        Json::Value error;
        error["error"] = "Invalid identity format";
        return error;
    }

    std::string issuer = normalizeIdentity(filterParams["issuer"].asString());
    if (issuer.empty()) {
        Json::Value error;
        error["error"] = "Invalid issuer format";
        return error;
    }

    std::string assetName = filterParams["assetName"].asString();
    if (assetName.empty() || assetName.size() > 7) {
        Json::Value error;
        error["error"] = "Invalid assetName (must be 1-7 characters)";
        return error;
    }

    uint32_t fromTick = filterParams["fromTick"].asUInt();
    uint32_t toTick = filterParams["toTick"].asUInt();

    std::string jsonStr = getAssetTransfersForIdentity(fromTick, toTick, identity, issuer, assetName);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse asset transfers";
        return error;
    }

    return result;
}

Json::Value QubicRpcMethods::getAllAssetTransfers(const Json::Value& filterParams) {
    // Validate required parameters
    if (!filterParams.isMember("issuer") || !filterParams["issuer"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: issuer";
        return error;
    }
    if (!filterParams.isMember("assetName") || !filterParams["assetName"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: assetName";
        return error;
    }
    if (!filterParams.isMember("fromTick") || !filterParams["fromTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: fromTick";
        return error;
    }
    if (!filterParams.isMember("toTick") || !filterParams["toTick"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: toTick";
        return error;
    }

    std::string issuer = normalizeIdentity(filterParams["issuer"].asString());
    if (issuer.empty()) {
        Json::Value error;
        error["error"] = "Invalid issuer format";
        return error;
    }

    std::string assetName = filterParams["assetName"].asString();
    if (assetName.empty() || assetName.size() > 7) {
        Json::Value error;
        error["error"] = "Invalid assetName (must be 1-7 characters)";
        return error;
    }

    uint32_t fromTick = filterParams["fromTick"].asUInt();
    uint32_t toTick = filterParams["toTick"].asUInt();

    std::string jsonStr = ::getAllAssetTransfers(fromTick, toTick, issuer, assetName);

    Json::Value result;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(jsonStr);

    if (!Json::parseFromStream(builder, stream, &result, &errors)) {
        Json::Value error;
        error["error"] = "Failed to parse all asset transfers";
        return error;
    }

    return result;
}

// ============================================================================
// Smart Contract Methods
// ============================================================================

Json::Value QubicRpcMethods::querySmartContract(const Json::Value& params) {
    // Validate required parameters
    if (!params.isMember("nonce") || !params["nonce"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: nonce (uint32)";
        return error;
    }
    if (!params.isMember("scIndex") || !params["scIndex"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: scIndex (uint32)";
        return error;
    }
    if (!params.isMember("funcNumber") || !params["funcNumber"].isNumeric()) {
        Json::Value error;
        error["error"] = "Missing required parameter: funcNumber (uint32)";
        return error;
    }
    if (!params.isMember("data") || !params["data"].isString()) {
        Json::Value error;
        error["error"] = "Missing required parameter: data (hex string)";
        return error;
    }

    uint32_t nonce = static_cast<uint32_t>(params["nonce"].asUInt64());
    uint32_t scIndex = params["scIndex"].asUInt();
    uint32_t funcNumber = params["funcNumber"].asUInt();
    std::string data = params["data"].asString();

    // Use the shared helper
    SmartContractQueryResult queryResult = ApiHelpers::querySmartContract(nonce, scIndex, funcNumber, data);

    Json::Value result;
    result["nonce"] = nonce;

    if (!queryResult.error.empty()) {
        result["error"] = queryResult.error;
        return result;
    }

    if (queryResult.success) {
        result["data"] = queryResult.data;
        return result;
    }

    if (queryResult.pending) {
        result["pending"] = true;
        result["message"] = "Query enqueued; poll again with the same nonce to get the result";
        return result;
    }

    result["error"] = "Unknown error";
    return result;
}

// ============================================================================
// Computor Methods
// ============================================================================

Json::Value QubicRpcMethods::getComputors(uint16_t epoch) {
    Json::Value result;

    Computors comps{};

    // For current epoch, use in-memory computorsList if available
    if (epoch == gCurrentProcessingEpoch.load() && computorsList.epoch == epoch) {
        comps = computorsList;
    } else if (!db_get_computors(epoch, comps)) {
        result["error"] = "Computor list not found for epoch " + std::to_string(epoch);
        return result;
    }

    result["epoch"] = comps.epoch;

    Json::Value computorsArray(Json::arrayValue);
    char identity[61];
    for (int i = 0; i < NUMBER_OF_COMPUTORS; i++) {
        getIdentityFromPublicKey(comps.publicKeys[i].m256i_u8, identity, false);
        computorsArray.append(std::string(identity));
    }
    result["computors"] = computorsArray;

    return result;
}
