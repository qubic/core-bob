#include "LogEvent.h"
#include "database/db.h"
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
std::string getOracleQueryStatusString(uint8_t status)
{
    constexpr uint8_t ORACLE_QUERY_STATUS_PENDING = 1;     ///< Query is being processed.
    constexpr uint8_t ORACLE_QUERY_STATUS_COMMITTED = 2;   ///< The quorum has committed to a oracle reply, but it has not been revealed yet.
    constexpr uint8_t ORACLE_QUERY_STATUS_SUCCESS = 3;     ///< The oracle reply has been confirmed and is available.
    constexpr uint8_t ORACLE_QUERY_STATUS_UNRESOLVABLE = 5;///< No valid oracle reply is available, because computors disagreed about the value.
    constexpr uint8_t ORACLE_QUERY_STATUS_TIMEOUT = 4;     ///< No valid oracle reply is available and timeout has hit.

    switch (status)
    {
        case ORACLE_QUERY_STATUS_PENDING:
            return "pending";
        case ORACLE_QUERY_STATUS_COMMITTED:
            return "committed";
        case ORACLE_QUERY_STATUS_SUCCESS:
            return "success";
        case ORACLE_QUERY_STATUS_UNRESOLVABLE:
            return "unresolvable";
        case ORACLE_QUERY_STATUS_TIMEOUT:
            return "timeout";
        default:
            return "unknown";
    }
}

std::string dateAndTimeToString(uint64_t dateAndTime)
{
    uint64_t year = dateAndTime >> 46;
    uint64_t month = (dateAndTime >> 42) & 0b1111;
    uint64_t day = (dateAndTime >> 37) & 0b11111;
    uint64_t hour = (dateAndTime >> 32) & 0b11111;
    uint64_t minute = (dateAndTime >> 26) & 0b111111;
    uint64_t second = (dateAndTime >> 20) & 0b111111;
    uint64_t millisecond = (dateAndTime >> 10) & 0b1111111111;
    uint64_t microsecondDuringMillisecond = dateAndTime & 0b1111111111;
    std::stringstream ss;
    ss << std::setfill('0') << year << "-"
        << std::setw(2) << month << "-"
        << std::setw(2) << day << " "
        << std::setw(2) << hour << ":"
        << std::setw(2) << minute << ":"
        << std::setw(2) << second << "."
        << std::setw(3) << millisecond << "'"
        << std::setw(3) << microsecondDuringMillisecond;
    return ss.str();
}

Json::Value LogEvent::parseToJson() const
{
    auto hex_encode = [](const uint8_t* data, size_t len) -> std::string {
        static const char* hexdigits = "0123456789abcdef";
        std::string out;
        out.resize(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out[2*i]   = hexdigits[(data[i] >> 4) & 0xF];
            out[2*i+1] = hexdigits[data[i] & 0xF];
        }
        return out;
    };
    auto trim_zero_bytes = [](const char* data, size_t len) -> std::string {
        std::string out;
        out.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            if (data[i] != '\0') out.push_back(data[i]);
        }
        return out;
    };

    Json::Value root(Json::objectValue);

    if (!hasPackedHeader()) {
        root["ok"] = false;
        root["error"] = "no_packed_header";
        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        return Json::writeString(wb, root);
    }

    const uint32_t bodySize = getLogSize();
    const uint32_t type = getType();
    const uint16_t epoch = getEpoch();
    const uint32_t tick = getTick();
    const uint64_t logId = getLogId();
    const uint64_t digest = getLogDigest();
    const uint8_t* body_ptr = getLogBodyPtr();

    if (body_ptr == nullptr) {
        root["ok"] = false;
        root["error"] = "null_body_ptr";
        Json::StreamWriterBuilder wb;
        wb["indentation"] = "";
        return Json::writeString(wb, root);
    }

    root["ok"] = true;
    root["epoch"] = epoch;
    root["tick"] = tick;
    root["type"] = type;
    root["logId"] = Json::UInt64(logId);
    root["logDigest"] = hex_encode(reinterpret_cast<const uint8_t *>(&digest), sizeof(digest));
    root["bodySize"] = bodySize;

    Json::Value body(Json::objectValue);
    bool filled = false;

    switch (type) {
        case 0: { // QU_TRANSFER
            const auto needed = static_cast<uint32_t>(sizeof(QuTransfer));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_QuTransfer";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const QuTransfer* t = getStruct<QuTransfer>();
                root["logTypename"] = "QU_TRANSFER";
                body["from"] = t->sourcePublicKey.toQubicHashUpperCase();
                body["to"] = t->destinationPublicKey.toQubicHashUpperCase();
                body["amount"] = Json::Int64(t->amount);
                filled = true;
            }
            break;
        }
        case 1: { // ASSET_ISSUANCE
            const auto needed = static_cast<uint32_t>(sizeof(AssetIssuance));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_AssetIssuance";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const AssetIssuance* a = getStruct<AssetIssuance>();
                root["logTypename"] = "ASSET_ISSUANCE";
                body["issuerPublicKey"] = a->issuerPublicKey.toQubicHashUpperCase();
                body["numberOfShares"] = Json::Int64(a->numberOfShares);
                body["managingContractIndex"] = Json::Int64(a->managingContractIndex);
                body["name"] = trim_zero_bytes(a->name, 7);
                body["numberOfDecimalPlaces"] = static_cast<int>(a->numberOfDecimalPlaces);
                char unitOfMeasurement[7];
                for (int i = 0; i < 7; i++) unitOfMeasurement[i] = 48 +  a->unitOfMeasurement[i];
                body["unitOfMeasurement"] = std::string(unitOfMeasurement, 7);
                filled = true;
            }
            break;
        }
        case 2: { // ASSET_OWNERSHIP_CHANGE
            const auto needed = static_cast<uint32_t>(sizeof(AssetOwnershipChange));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_AssetOwnershipChange";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const AssetOwnershipChange *a = getStruct<AssetOwnershipChange>();
                root["logTypename"] = "ASSET_OWNERSHIP_CHANGE";
                body["sourcePublicKey"] = a->sourcePublicKey.toQubicHashUpperCase();
                body["destinationPublicKey"] = a->destinationPublicKey.toQubicHashUpperCase();
                body["issuerPublicKey"] = a->issuerPublicKey.toQubicHashUpperCase();
                body["assetName"] = trim_zero_bytes(a->name, 7);
                body["numberOfShares"] = Json::Int64(a->numberOfShares);
                filled = true;
            }
            break;
        }
        case 3: { // ASSET_POSSESSION_CHANGE
            const auto needed = static_cast<uint32_t>(sizeof(AssetPossessionChange));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_AssetPossessionChange";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const AssetPossessionChange *a = getStruct<AssetPossessionChange>();
                root["logTypename"] = "ASSET_POSSESSION_CHANGE";
                body["sourcePublicKey"] = a->sourcePublicKey.toQubicHashUpperCase();
                body["destinationPublicKey"] = a->destinationPublicKey.toQubicHashUpperCase();
                body["issuerPublicKey"] = a->issuerPublicKey.toQubicHashUpperCase();
                body["assetName"] = trim_zero_bytes(a->name, 7);
                body["numberOfShares"] = Json::Int64(a->numberOfShares);
                filled = true;
            }
            break;
        }
        case 8: { // BURNING
            const auto needed = static_cast<uint32_t>(sizeof(Burning));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_Burning";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const Burning *b = getStruct<Burning>();
                root["logTypename"] = "BURNING";
                body["publicKey"] = b->sourcePublicKey.toQubicHashUpperCase();
                body["amount"] = Json::Int64(b->amount);
                body["contractIndexBurnedFor"] = Json::Int64(b->contractIndexBurnedFor);
                filled = true;
            }
            break;
        }

        case 11: { // ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE
            const auto needed = static_cast<uint32_t>(sizeof(AssetOwnershipManagingContractChange));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_AssetOwnershipManagingContractChange";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const AssetOwnershipManagingContractChange *a = getStruct<AssetOwnershipManagingContractChange>();
                root["logTypename"] = "ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE";
                body["ownershipPublicKey"] = a->ownershipPublicKey.toQubicHashUpperCase();
                body["issuerPublicKey"] = a->issuerPublicKey.toQubicHashUpperCase();
                body["sourceContractIndex"] = a->sourceContractIndex;
                body["destinationContractIndex"] = a->destinationContractIndex;
                body["numberOfShares"] = Json::Int64(a->numberOfShares);
                body["assetName"] = trim_zero_bytes(a->assetName, 7);
                filled = true;
            }
            break;
        }
        case 12: { // ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE
            const auto needed = static_cast<uint32_t>(sizeof(AssetPossessionManagingContractChange));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_AssetPossessionManagingContractChange";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const AssetPossessionManagingContractChange *a = getStruct<AssetPossessionManagingContractChange>();
                root["logTypename"] = "ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE";
                body["possessionPublicKey"] = a->possessionPublicKey.toQubicHashUpperCase();
                body["ownershipPublicKey"] = a->ownershipPublicKey.toQubicHashUpperCase();
                body["issuerPublicKey"] = a->issuerPublicKey.toQubicHashUpperCase();
                body["sourceContractIndex"] = a->sourceContractIndex;
                body["destinationContractIndex"] = a->destinationContractIndex;
                body["numberOfShares"] = Json::Int64(a->numberOfShares);
                body["assetName"] = trim_zero_bytes(a->assetName, 7);
                filled = true;
            }
            break;
        }

        case 13: { // CONTRACT_RESERVE_DEDUCTION
            const auto needed = static_cast<uint32_t>(sizeof(ContractReserveDeduction));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_ContractReserveDeduction";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const ContractReserveDeduction *c = getStruct<ContractReserveDeduction>();
                root["logTypename"] = "CONTRACT_RESERVE_DEDUCTION";
                body["deductedAmount"] = Json::UInt64(c->deductedAmount);
                body["remainingAmount"] = Json::Int64(c->remainingAmount);
                body["contractIndex"] = c->contractIndex;
                filled = true;
            }
            break;
        }

        case 14: { // ORACLE_QUERY_STATUS_CHANGE
            const auto needed = static_cast<uint32_t>(sizeof(OracleQueryStatusChange));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_OracleQueryStatusChange";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const OracleQueryStatusChange *c = getStruct<OracleQueryStatusChange>();
                root["logTypename"] = "ORACLE_QUERY_STATUS_CHANGE";
                body["queryingEntity"] = c->queryingEntity.toQubicHashUpperCase();
                body["queryId"] = Json::Int64(c->queryId);
                body["interfaceIndex"] = c->interfaceIndex;
                body["type"] = static_cast<unsigned int>(c->type);
                body["typeStr"] = "unknown";
                if (c->type == 0) body["typeStr"] = "ORACLE_QUERY_TYPE_CONTRACT_QUERY";
                if (c->type == 1) body["typeStr"] = "ORACLE_QUERY_TYPE_CONTRACT_SUBSCRIPTION";
                if (c->type == 2) body["typeStr"] = "ORACLE_QUERY_TYPE_USER_QUERY";
                body["status"] = getOracleQueryStatusString(c->status);
                filled = true;
            }
            break;
        }

        case 15: { //ORACLE_SUBSCRIBER_MESSAGE
            const auto needed = static_cast<uint32_t>(sizeof(OracleSubscriberLogMessage));
            if (bodySize < needed) {
                body["error"] = "body_too_small_for_OracleSubscriberLogMessage";
                body["needed"] = needed;
                body["got"] = bodySize;
            } else {
                const OracleSubscriberLogMessage *c = getStruct<OracleSubscriberLogMessage>();
                root["logTypename"] = "ORACLE_SUBSCRIBER_MESSAGE";
                body["subscriptionId"] = c->subscriptionId;
                body["interfaceIndex"] = c->interfaceIndex;
                body["contractIndex"] = c->contractIndex;
                body["periodInMilliseconds"] = c->periodInMilliseconds;
                body["firstQueryDateAndTime"] = dateAndTimeToString(c->firstQueryDateAndTime);
                filled = true;
            }
            break;
        }

        case 255: { // CUSTOM_MESSAGE: 8-byte payload
            if (bodySize == 8) {
                uint64_t v;
                memcpy(&v, body_ptr, sizeof(v));
                body["customMessage"] = std::to_string(v);
                filled = true;
            }
            break;
        }
        case 4: // CONTRACT_ERROR_MESSAGE
        case 5: // CONTRACT_WARNING_MESSAGE
        case 6: // CONTRACT_INFORMATION_MESSAGE
        case 7: // CONTRACT_DEBUG_MESSAGE
        {
            uint32_t scIndex = 0, scLogType = 0;
            if (bodySize >= 4) memcpy(&scIndex, body_ptr, 4);
            if (bodySize >= 8) memcpy(&scLogType, body_ptr + 4, 4);
            body["scIndex"] = scIndex;
            body["scLogType"] = scLogType;
            body["content"] = "";
            if (bodySize > 8) body["content"] = hex_encode(body_ptr+8, bodySize-8);
            filled = true;
            break;
        }
        default:
            // For unknown or struct-based events (no schema here), fall through to hex dump.
            break;
    }

    if (!filled) {
        body["hex"] = hex_encode(body_ptr, bodySize);
    }

    root["body"] = body;
    return root;
}
std::string LogEvent::parseToJsonStr() const
{
    auto root = parseToJson();
    Json::StreamWriterBuilder wb;
    wb["indentation"] = ""; // compact output
    return Json::writeString(wb, root);
}

Json::Value LogEvent::parseToJsonValueWithExtraData(const TickData& td, const int txIndex) const
{
    auto root = parseToJson();
    if (td.tick == getTick())
    {
        std::tm timeinfo = {};
        timeinfo.tm_year = int(td.year) + 2000 - 1900;  // Convert from 2-digit year to years since 1900
        timeinfo.tm_mon = td.month - 1;    // Month (0-11)
        timeinfo.tm_mday = td.day;
        timeinfo.tm_hour = td.hour;
        timeinfo.tm_min = td.minute;
        timeinfo.tm_sec = td.second;
        timeinfo.tm_isdst = -1;
        time_t t = timegm(&timeinfo);
        root["timestamp"] = Json::UInt64(t);
    } else {
        root["timestamp"] = db_get_quorum_unixtime_from_votes(getTick());
    }


    if (txIndex >= 0)
    {
        std::string txHash = "";
        if (txIndex < NUMBER_OF_TRANSACTIONS_PER_TICK)
        {
            txHash = td.transactionDigests[txIndex].toQubicHash();
        }
        else if (txIndex <= LOG_TX_PER_TICK)
        {
            if (txIndex == SC_INITIALIZE_TX) txHash = ("SC_INITIALIZE_TX_" + std::to_string(getTick()));
            if (txIndex == SC_BEGIN_EPOCH_TX) txHash = ("SC_BEGIN_EPOCH_TX_" + std::to_string(getTick()));
            if (txIndex == SC_BEGIN_TICK_TX) txHash = ("SC_BEGIN_TICK_TX_" + std::to_string(getTick()));
            if (txIndex == SC_NOTIFICATION_TX) txHash = ("SC_NOTIFICATION_TX_" + std::to_string(getTick()));
            if (txIndex == SC_END_TICK_TX) txHash = ("SC_END_TICK_TX_" + std::to_string(getTick()));
            if (txIndex == SC_END_EPOCH_TX) txHash = ("SC_END_EPOCH_TX_" + std::to_string(getTick()));
        }
        root["txHash"] = txHash;
        return root;
    }
    root["txHash"] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzunknowntransaction";
    return root;
}

std::string LogEvent::parseToJsonWithExtraData(const TickData& td, const int txIndex) const
{
    auto root = parseToJsonValueWithExtraData(td, txIndex);
    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    return Json::writeString(wb, root);
}

std::string LogEvent::parseToJsonForEndEpoch(uint32_t endEpochTick, const std::string& timestamp) const
{
    auto root = parseToJson();
    root["timestamp"] = timestamp;
    root["txHash"] = "SC_END_EPOCH_TX_" + std::to_string(endEpochTick);
    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    return Json::writeString(wb, root);
}