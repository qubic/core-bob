#include <cstdint>
#include "log_event.h"

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

        case 255: { // CUSTOM_MESSAGE: 8-byte payload
            if (bodySize == 8) {
                uint64_t v;
                memcpy(&v, body_ptr, sizeof(v));
                body["customMessage"] = Json::UInt64(v);
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

    char timestampBuffer[20];
    snprintf(timestampBuffer, sizeof(timestampBuffer), "%02d-%02d-%02d %02d:%02d:%02d",
             td.year, td.month, td.day, td.hour, td.minute, td.second);
    std::string timestamp(timestampBuffer);
    root["timestamp"] = timestamp;

    if (txIndex >= 0)
    {
        std::string txHash = "";
        if (txIndex < NUMBER_OF_TRANSACTIONS_PER_TICK)
        {
            txHash = td.transactionDigests[txIndex].toQubicHash();
        }
        else if (txIndex <= SC_END_EPOCH_TX)
        {
            if (txIndex == SC_INITIALIZE_TX) txHash = ("SC_INITIALIZE_TX_" + std::to_string(td.tick));
            if (txIndex == SC_BEGIN_EPOCH_TX) txHash = ("SC_BEGIN_EPOCH_TX_" + std::to_string(td.tick));
            if (txIndex == SC_BEGIN_TICK_TX) txHash = ("SC_BEGIN_TICK_TX_" + std::to_string(td.tick));
            if (txIndex == SC_END_TICK_TX) txHash = ("SC_END_TICK_TX_" + std::to_string(td.tick));
            if (txIndex == SC_END_EPOCH_TX) txHash = ("SC_END_EPOCH_TX_" + std::to_string(td.tick));
        }
        root["txHash"] = txHash;
        return root;
    }
    root["txHash"] = "null";
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