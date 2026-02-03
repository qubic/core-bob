#include "QubicRpcMapper.h"
#include "src/global_var.h"
#include "src/core/defines.h"
#include "src/shim.h"
#include "src/core/k12_and_key_util.h"
#include "src/database/db.h"
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

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

std::string tickToHash(uint32_t tick, const TickData& td) {
    return bytesToHex(td.signature, 32);
}

Json::Value tickDataToQubicTick(uint32_t tick, const TickData& td,
                                 const std::vector<m256i>& txDigests,
                                 bool includeTransactions) {
    Json::Value result(Json::objectValue);

    result["tickNumber"] = tick;

    // Determine if we have tick data (epoch == 0 means no tick data in database)
    bool hasNoTickData = (td.epoch == 0);
    // A tick is skipped if we have no tick data OR 226+ computors voted with zero txDigest (empty tick)
    bool isSkipped = hasNoTickData || txDigests.empty();

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

    Json::Value transactions(Json::arrayValue);
    for (size_t i = 0; i < txDigests.size(); ++i) {
        if (txDigests[i] != m256i::zero()) {
            if (includeTransactions) {
                // Fetch full transaction data
                std::string qubicHash = txDigests[i].toQubicHash();
                std::vector<uint8_t> txData;
                if (db_try_get_transaction(qubicHash, txData)) {
                    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
                    transactions.append(transactionToQubicTx(tx, qubicHash,
                                                              tick, static_cast<int>(i), td, false));
                }
            } else {
                // Just include the hash
                transactions.append(txDigests[i].toQubicHash());
            }
        }
    }
    result["transactions"] = transactions;

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

    return result;
}

Json::Value transactionToQubicReceipt(const Transaction* tx, const std::string& txHash,
                                       uint32_t tick, int txIndex, const TickData& td,
                                       const std::vector<LogEvent>& logs, bool executed) {
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
    result["executed"] = executed;
    result["status"] = executed ? "success" : "failed";

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

    // Log-specific data based on type
    switch (logType) {
        case QU_TRANSFER: {
            const QuTransfer* t = const_cast<LogEvent&>(log).getStruct<QuTransfer>();
            if (t) {
                char srcIdentity[64] = {0};
                char dstIdentity[64] = {0};
                getIdentityFromPublicKey(t->sourcePublicKey.m256i_u8, srcIdentity, false);
                getIdentityFromPublicKey(t->destinationPublicKey.m256i_u8, dstIdentity, false);

                result["source"] = std::string(srcIdentity);
                result["destination"] = std::string(dstIdentity);
                result["amount"] = std::to_string(t->amount);
            }
            break;
        }
        case ASSET_OWNERSHIP_CHANGE:
        case ASSET_POSSESSION_CHANGE: {
            const AssetOwnershipChange* a = const_cast<LogEvent&>(log).getStruct<AssetOwnershipChange>();
            if (a) {
                char srcIdentity[64] = {0};
                char dstIdentity[64] = {0};
                getIdentityFromPublicKey(a->sourcePublicKey.m256i_u8, srcIdentity, false);
                getIdentityFromPublicKey(a->destinationPublicKey.m256i_u8, dstIdentity, false);

                result["source"] = std::string(srcIdentity);
                result["destination"] = std::string(dstIdentity);
                result["numberOfShares"] = std::to_string(a->numberOfShares);

                // Asset info
                char issuerIdentity[64] = {0};
                getIdentityFromPublicKey(a->issuerPublicKey.m256i_u8, issuerIdentity, false);
                result["issuer"] = std::string(issuerIdentity);

                char assetName[8] = {0};
                memcpy(assetName, a->name, 7);
                result["assetName"] = std::string(assetName);
            }
            break;
        }
        case BURNING: {
            const Burning* b = const_cast<LogEvent&>(log).getStruct<Burning>();
            if (b) {
                char srcIdentity[64] = {0};
                getIdentityFromPublicKey(b->sourcePublicKey.m256i_u8, srcIdentity, false);
                result["source"] = std::string(srcIdentity);
                result["amount"] = std::to_string(b->amount);
            }
            break;
        }
        case CONTRACT_ERROR_MESSAGE:
        case CONTRACT_WARNING_MESSAGE:
        case CONTRACT_INFORMATION_MESSAGE:
        case CONTRACT_DEBUG_MESSAGE: {
            if (log.getLogSize() >= 8) {
                uint32_t scIndex, scLogType;
                memcpy(&scIndex, log.getLogBodyPtr(), 4);
                memcpy(&scLogType, log.getLogBodyPtr() + 4, 4);
                result["contractIndex"] = scIndex;
                result["contractLogType"] = scLogType;
            }
            break;
        }
        default:
            break;
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
