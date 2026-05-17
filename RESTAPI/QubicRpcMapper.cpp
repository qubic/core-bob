#include "QubicRpcMapper.h"
#include "K12AndKeyUtil.h"
#include "shim.h"
#include "database/db.h"
#include "GlobalVar.h"
#include "defines.h"
#include "ApiHelpers.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>

namespace QubicRpc {

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

std::string bytesToHex(const uint8_t* data, size_t len) {
    static const char* hexdigits = "0123456789abcdef";
    std::string out = "0x";
    out.reserve(2 + len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hexdigits[(data[i] >> 4) & 0xF]);
        out.push_back(hexdigits[data[i] & 0xF]);
    }
    return out;
}

bool hexToBytes(const std::string& hex, uint8_t* out, size_t outLen) {
    std::string h = hex;
    // Strip 0x prefix if present
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
        h = h.substr(2);
    }

    if (h.size() != outLen * 2) {
        return false;
    }

    for (size_t i = 0; i < outLen; ++i) {
        char high = h[i * 2];
        char low = h[i * 2 + 1];

        uint8_t highVal, lowVal;
        if (high >= '0' && high <= '9') highVal = high - '0';
        else if (high >= 'a' && high <= 'f') highVal = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') highVal = high - 'A' + 10;
        else return false;

        if (low >= '0' && low <= '9') lowVal = low - '0';
        else if (low >= 'a' && low <= 'f') lowVal = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') lowVal = low - 'A' + 10;
        else return false;

        out[i] = (highVal << 4) | lowVal;
    }
    return true;
}

// ============================================================================
// Identity/PublicKey Conversions
// ============================================================================

std::string publicKeyToHex(const m256i& publicKey) {
    return bytesToHex(publicKey.m256i_u8, 32);
}

std::string publicKeyToIdentity(const m256i& publicKey) {
    char identity[64] = {0};
    getIdentityFromPublicKey(publicKey.m256i_u8, identity, false);
    return std::string(identity);
}

bool hexToPublicKey(const std::string& hex, m256i& out) {
    return hexToBytes(hex, out.m256i_u8, 32);
}

std::string hexToQubicIdentity(const std::string& hex) {
    m256i publicKey;
    if (!hexToPublicKey(hex, publicKey)) {
        return "";
    }
    char identity[64] = {0};
    getIdentityFromPublicKey(publicKey.m256i_u8, identity, false);
    return std::string(identity);
}

std::string qubicIdentityToHex(const std::string& identity) {
    if (identity.size() != 60) {
        return "";
    }
    uint8_t publicKey[32];
    getPublicKeyFromIdentity(identity.c_str(), publicKey);
    // Check if result is valid (non-zero)
    bool isZero = true;
    for (int i = 0; i < 32; ++i) {
        if (publicKey[i] != 0) {
            isZero = false;
            break;
        }
    }
    if (isZero) {
        return "";
    }
    return bytesToHex(publicKey, 32);
}

// ============================================================================
// Number Formatting
// ============================================================================

std::string uint64ToHex(uint64_t value) {
    if (value == 0) return "0x0";
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

std::string uint32ToHex(uint32_t value) {
    return uint64ToHex(static_cast<uint64_t>(value));
}

std::string int64ToHex(int64_t value) {
    if (value < 0) {
        return uint64ToHex(static_cast<uint64_t>(value));
    }
    return uint64ToHex(static_cast<uint64_t>(value));
}

uint64_t hexToUint64(const std::string& hex) {
    std::string h = hex;
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
        h = h.substr(2);
    }
    return std::stoull(h, nullptr, 16);
}

uint32_t hexToUint32(const std::string& hex) {
    return static_cast<uint32_t>(hexToUint64(hex));
}

// ============================================================================
// Tick Tag Parsing
// ============================================================================

int64_t parseTickTag(const std::string& tag) {
    if (tag == "latest") {
        return static_cast<int64_t>(gCurrentVerifyLoggingTick.load());
    }
    if (tag == "earliest") {
        return static_cast<int64_t>(gInitialTick.load());
    }
    if (tag == "pending") {
        return static_cast<int64_t>(gCurrentFetchingTick.load());
    }

    // Try to parse as decimal number first
    try {
        // Check if it's a hex number
        if (tag.size() >= 2 && tag[0] == '0' && (tag[1] == 'x' || tag[1] == 'X')) {
            return static_cast<int64_t>(hexToUint64(tag));
        }
        // Parse as decimal
        return static_cast<int64_t>(std::stoull(tag));
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// Tick Conversions
// ============================================================================

bool isTickSkipped(const TickData& td, bool hasTxDigests) {
    if (td.epoch == 0 || !hasTxDigests) return true;
    // Tick has digests but quorum may have voted it empty — check if anything was executed
    long long fromLogId = -1, length = -1;
    db_try_get_log_range_for_tick(td.tick, fromLogId, length);
    return (fromLogId == -1 || length <= 0);
}

std::string tickToHash(uint32_t tick, const TickData& td) {
    return bytesToHex(td.signature, 32);
}

Json::Value tickDataToQubicTick(uint32_t tick, const TickData& td,
                                 const std::vector<m256i>& txDigests,
                                 bool includeTransactions) {
    Json::Value result(Json::objectValue);

    result["tickNumber"] = tick;

    bool hasNoTickData = (td.epoch == 0);
    bool ignore;
    bool isSkipped = db_is_tick_empty(tick, ignore);

    result["hasNoTickData"] = hasNoTickData;
    result["isSkipped"] = isSkipped;

    // If tick data epoch is 0 (empty/missing tick data), use current epoch
    // but only if the tick is within the current epoch's range
    uint16_t epoch = td.epoch;
    if (epoch == 0 && tick >= gInitialTick.load()) {
        epoch = gCurrentProcessingEpoch.load();
    }
    result["epoch"] = epoch;
    // computorIndex can always be calculated from tick number
    uint16_t computorIndex = (td.computorIndex > 0) ? td.computorIndex : (tick % NUMBER_OF_COMPUTORS);
    result["computorIndex"] = computorIndex;

    // Signature as hash
    result["signature"] = bytesToHex(td.signature, SIGNATURE_SIZE);
    result["tickHash"] = tickToHash(tick, td);

    // Timestamp from TickData
    std::tm timeinfo = {};
    timeinfo.tm_year = static_cast<int>(td.year) + 2000 - 1900;
    timeinfo.tm_mon = td.month - 1;
    timeinfo.tm_mday = td.day;
    timeinfo.tm_hour = td.hour;
    timeinfo.tm_min = td.minute;
    timeinfo.tm_sec = td.second;
    time_t timestamp = timegm(&timeinfo);

    result["timestamp"] = Json::UInt64(timestamp);

    // Format timestamp as ISO string
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
    result["timestampISO"] = timebuf;

    result["millisecond"] = td.millisecond;

    // Timelock
    result["timelock"] = bytesToHex(td.timelock.m256i_u8, 32);

    // Transaction count and list
    result["transactionCount"] = static_cast<Json::UInt>(txDigests.size());

    // Load the tick's log ranges and logs once so we can annotate each tx
    // with its execution status without doing per-tx DB calls. If either
    // lookup fails the tick hasn't been log-verified yet and we report
    // status as "pending" instead of guessing "failed".
    LogRangesPerTxInTick tickLogRanges{-1};
    std::vector<LogEvent> tickLogs;
    bool logsAvailable = false;
    if (includeTransactions) {
        bool rangesOk = db_try_get_log_ranges(tick, tickLogRanges);
        bool logsOk = false;
        tickLogs = db_get_logs_by_tick_range(epoch, tick, tick, logsOk);
        logsAvailable = rangesOk && logsOk;
    }

    Json::Value transactions(Json::arrayValue);
    for (size_t i = 0; i < txDigests.size(); ++i) {
        if (txDigests[i] != m256i::zero()) {
            if (includeTransactions) {
                // Fetch full transaction data
                std::string qubicHash = txDigests[i].toQubicHash();
                std::vector<uint8_t> txData;
                if (db_try_get_transaction(qubicHash, txData)) {
                    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());

                    Json::Value txJson = transactionToQubicTx(tx, qubicHash,
                                                               tick, static_cast<int>(i), td, false);

                    if (logsAvailable) {
                        int txSlot = -1;
                        for (int s = 0; s < NUMBER_OF_TRANSACTIONS_PER_TICK; ++s) {
                            if (td.transactionDigests[s] == txDigests[i]) {
                                txSlot = s;
                                break;
                            }
                        }
                        bool executed = (txSlot >= 0) &&
                                        ApiHelpers::isTxExecuted(*tx,
                                                                 tickLogRanges.fromLogId[txSlot],
                                                                 tickLogRanges.length[txSlot],
                                                                 tickLogs);
                        txJson["executed"] = executed;
                        txJson["status"] = executed ? "success" : "failed";
                    } else {
                        txJson["executed"] = Json::Value::null;
                        txJson["status"] = "pending";
                    }

                    transactions.append(std::move(txJson));
                }
            } else {
                // Just include the hash
                transactions.append(txDigests[i].toQubicHash());
            }
        }
    }
    result["transactions"] = transactions;

    // Log id range for this tick. Useful when callers want to follow up with
    // a log fetch and don't want a second round-trip just to find the range.
    long long logIdStart = -1, logIdLen = -1;
    if (db_try_get_log_range_for_tick(tick, logIdStart, logIdLen)) {
        result["logIdStart"] = static_cast<Json::Int64>(logIdStart);
        result["logIdEnd"] = static_cast<Json::Int64>(
            (logIdLen > 0) ? (logIdStart + logIdLen - 1) : (logIdStart - 1));
    } else {
        result["logIdStart"] = Json::Value::null;
        result["logIdEnd"] = Json::Value::null;
    }

    // Per-contract fees collected this tick. Emit the full 1024-element array
    // when at least one entry is non-zero; otherwise compress to a scalar 0
    // so the response stays compact for typical empty ticks.
    {
        bool nonZero = false;
        Json::Value fees(Json::arrayValue);
        for (int i = 0; i < 1024; ++i) {
            fees.append(static_cast<Json::Int64>(td.contractFees[i]));
            if (td.contractFees[i]) nonZero = true;
        }
        if (nonZero) {
            result["contractFees"] = fees;
        } else {
            result["contractFees"] = 0;
        }
    }

    // Quorum tick votes — uses the shared serializer in ApiHelpers (same
    // shape as the REST /tick/{n} endpoint).
    {
        auto tick_votes = db_try_get_tick_vote(tick);
        Json::Value votes(Json::arrayValue);
        for (const auto& vote : tick_votes) {
            votes.append(ApiHelpers::tickVoteToJson(vote));
        }
        result["votes"] = votes;
    }

    // Previous tick hash
    if (tick > gInitialTick.load()) {
        TickData prevTd;
        if (db_try_get_tick_data(tick - 1, prevTd)) {
            result["previousTickHash"] = bytesToHex(prevTd.signature, 32);
        } else {
            result["previousTickHash"] = Json::Value::null;
        }
    } else {
        result["previousTickHash"] = Json::Value::null;
    }

    return result;
}

// ============================================================================
// Transaction Conversions
// ============================================================================

Json::Value transactionToQubicTx(const Transaction* tx, const std::string& txHash,
                                  uint32_t tick, int txIndex, const TickData& td,
                                  bool includeTick) {
    Json::Value result(Json::objectValue);

    result["hash"] = txHash;
    if (includeTick) {
        result["tick"] = tick;
    }

    // Source and destination as Qubic identities
    char srcIdentity[64] = {0};
    char dstIdentity[64] = {0};
    getIdentityFromPublicKey(tx->sourcePublicKey, srcIdentity, false);
    getIdentityFromPublicKey(tx->destinationPublicKey, dstIdentity, false);

    result["from"] = std::string(srcIdentity);
    result["to"] = std::string(dstIdentity);

    // Amount as integer (matching existing format)
    result["amount"] = Json::Int64(tx->amount);

    // Input type and size
    result["inputType"] = tx->inputType;
    result["inputSize"] = tx->inputSize;

    // Input data as hex (empty string if no data)
    const uint8_t* inputPtr = reinterpret_cast<const uint8_t*>(tx) + sizeof(Transaction);
    if (tx->inputSize > 0) {
        result["inputData"] = bytesToHex(inputPtr, tx->inputSize);
    } else {
        result["inputData"] = "";
    }

    // Transaction signature (64 bytes after header + input data)
    const uint8_t* sigPtr = reinterpret_cast<const uint8_t*>(tx) + sizeof(Transaction) + tx->inputSize;
    result["signature"] = bytesToHex(sigPtr, SIGNATURE_SIZE);

    return result;
}

Json::Value transactionToQubicReceipt(const Transaction* tx, const std::string& txHash,
                                       uint32_t tick, int txIndex, const TickData& td,
                                       const std::vector<LogEvent>& logs, bool executed,
                                       bool pending) {
    Json::Value result(Json::objectValue);

    result["hash"] = txHash;
    result["tick"] = tick;
    result["tickHash"] = tickToHash(tick, td);
    result["transactionIndex"] = txIndex;
    result["epoch"] = td.epoch;

    // Source and destination
    char srcIdentity[64] = {0};
    char dstIdentity[64] = {0};
    getIdentityFromPublicKey(tx->sourcePublicKey, srcIdentity, false);
    getIdentityFromPublicKey(tx->destinationPublicKey, dstIdentity, false);

    result["from"] = std::string(srcIdentity);
    result["to"] = std::string(dstIdentity);
    result["amount"] = Json::Int64(tx->amount);
    result["inputType"] = tx->inputType;

    // Execution status
    if (pending) {
        result["executed"] = Json::Value::null;
        result["status"] = "pending";
    } else {
        result["executed"] = executed;
        result["status"] = executed ? "success" : "failed";
    }

    // Logs
    Json::Value logsArray(Json::arrayValue);
    uint64_t logIndex = 0;
    for (const auto& log : logs) {
        logsArray.append(logEventToQubicLog(log, td, txIndex, logIndex++));
    }
    result["logs"] = logsArray;
    result["logCount"] = static_cast<Json::UInt>(logs.size());

    return result;
}

// ============================================================================
// Log Conversions
// ============================================================================

std::string logTypeName(uint32_t logType) {
    switch (logType) {
        case QU_TRANSFER: return "QU_TRANSFER";
        case ASSET_ISSUANCE: return "ASSET_ISSUANCE";
        case ASSET_OWNERSHIP_CHANGE: return "ASSET_OWNERSHIP_CHANGE";
        case ASSET_POSSESSION_CHANGE: return "ASSET_POSSESSION_CHANGE";
        case CONTRACT_ERROR_MESSAGE: return "CONTRACT_ERROR";
        case CONTRACT_WARNING_MESSAGE: return "CONTRACT_WARNING";
        case CONTRACT_INFORMATION_MESSAGE: return "CONTRACT_INFO";
        case CONTRACT_DEBUG_MESSAGE: return "CONTRACT_DEBUG";
        case BURNING: return "BURNING";
        case DUST_BURNING: return "DUST_BURNING";
        case SPECTRUM_STATS: return "SPECTRUM_STATS";
        case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE: return "ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE";
        case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE: return "ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE";
        case CONTRACT_RESERVE_DEDUCTION: return "CONTRACT_RESERVE_DEDUCTION";
        case CUSTOM_MESSAGE: return "CUSTOM_MESSAGE";
        default: return "UNKNOWN";
    }
}

Json::Value logEventToQubicLog(const LogEvent& log, const TickData& td,
                                int txIndex, uint64_t logIndexInTick) {
    Json::Value result(Json::objectValue);

    uint32_t logType = log.getType();
    uint32_t tick = log.getTick();

    result["tick"] = tick;
    result["epoch"] = log.getEpoch();
    result["logId"] = Json::UInt64(log.getLogId());
    result["logIndex"] = Json::UInt64(logIndexInTick);
    result["transactionIndex"] = txIndex;

    result["logType"] = logType;
    result["logTypeName"] = logTypeName(logType);

    // Transaction hash
    if (txIndex >= 0 && txIndex < NUMBER_OF_TRANSACTIONS_PER_TICK) {
        result["transactionHash"] = td.transactionDigests[txIndex].toQubicHash();
    } else {
        result["transactionHash"] = Json::Value::null;
    }

    // Delegate body extraction to LogEvent::parseToJson (single source of truth
    // for all log types, including new ones). We then flatten the body fields
    // onto `result` with the eth-style names this RPC has historically used:
    //   from / sourcePublicKey / publicKey  → source
    //   to / destinationPublicKey           → destination
    //   issuerPublicKey                     → issuer
    //   scIndex                             → contractIndex
    //   scLogType                           → contractLogType
    // Other field names pass through unchanged (amount, numberOfShares,
    // assetName, contractIndexBurnedFor, …).
    Json::Value parsed = log.parseToJson();
    if (parsed.isMember("body") && parsed["body"].isObject()) {
        const Json::Value& body = parsed["body"];
        for (auto it = body.begin(); it != body.end(); ++it) {
            const std::string key = it.key().asString();
            const Json::Value& v = *it;
            if (key == "from" || key == "sourcePublicKey" || key == "publicKey") {
                result["source"] = v;
            } else if (key == "to" || key == "destinationPublicKey") {
                result["destination"] = v;
            } else if (key == "issuerPublicKey") {
                result["issuer"] = v;
            } else if (key == "scIndex") {
                result["contractIndex"] = v;
            } else if (key == "scLogType") {
                result["contractLogType"] = v;
            } else {
                result[key] = v;
            }
        }
    }

    // Raw data as hex for all log types
    const uint8_t* bodyPtr = log.getLogBodyPtr();
    uint32_t bodySize = log.getLogSize();
    if (bodyPtr && bodySize > 0) {
        result["rawData"] = bytesToHex(bodyPtr, bodySize);
    } else {
        result["rawData"] = "0x";
    }

    return result;
}

}  // namespace QubicRpc
