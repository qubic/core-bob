// interop for other program to interact with BOB
#include "src/bob.h"
#include "src/core/asset.h"
#include "src/core/entity.h"
#include "src/core/k12_and_key_util.h"
#include "src/shim.h"
#include "src/version.h"
#include "ApiHelpers.h"
#include "src/database/db.h"
#include <iomanip>
#include <json/json.h>
#include <sstream>
#include <vector>
// helper: hex-encode
static std::string toHex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string bobGetBalance(const char* identity)
{
    if (!identity) return "{\"error\": \"Wrong identity format\"}";

    auto info = ApiHelpers::getBalanceInfo(identity);

    if (!info.found) {
        return "{\"error\": \"" + info.error + "\"}";
    }

    std::string error = "null";
    if (info.isBeingProcessed) {
        error = "This entity is being processed. currentBobTick is smaller than latestIncomingTransferTick/latestOutgoingTransferTick";
    }

    return std::string("{") +
           "\"incomingAmount\":" + std::to_string(info.incomingAmount) +
           ",\"outgoingAmount\":" + std::to_string(info.outgoingAmount) +
           ",\"balance\":" + std::to_string(info.balance) +
           ",\"numberOfIncomingTransfers\":" + std::to_string(info.numberOfIncomingTransfers) +
           ",\"numberOfOutgoingTransfers\":" + std::to_string(info.numberOfOutgoingTransfers) +
           ",\"latestIncomingTransferTick\":" + std::to_string(info.latestIncomingTransferTick) +
           ",\"latestOutgoingTransferTick\":" + std::to_string(info.latestOutgoingTransferTick) +
           ",\"currentBobTick:\":" + std::to_string(info.currentTick) +
           ",\"error:\":\"" + error + "\""
           "}";
}

std::string bobGetAsset(const std::string identity, const std::string assetName, const std::string assetIssuer, uint32_t manageSCIndex)
{
    auto info = ApiHelpers::getAssetBalanceInfo(identity, assetIssuer, assetName, manageSCIndex);

    Json::Value root;
    root["ownershipBalance"] = Json::Int64(info.ownershipBalance);
    root["possessionBalance"] = Json::Int64(info.possessionBalance);
    Json::FastWriter writer;
    return writer.write(root);
}

std::string bobGetTransaction(const char* txHash)
{
    if (!txHash) return "{\"error\": \"Invalid transaction hash\"}";

    try {
        auto info = ApiHelpers::getTransactionInfo(txHash);

        if (!info.found) {
            return "{\"error\": \"" + info.error + "\"}";
        }

        if (!info.hasIndexedInfo) {
            return std::string("{") +
                   "\"hash\":\"" + info.hash + "\"," +
                   "\"from\":\"" + info.from + "\"," +
                   "\"to\":\"" + info.to + "\"," +
                   "\"amount\":" + std::to_string(info.amount) + "," +
                   "\"tick\":" + std::to_string(info.tick) + "," +
                   "\"inputSize\":" + std::to_string(info.inputSize) + "," +
                   "\"inputType\":" + std::to_string(info.inputType) + "," +
                   "\"inputData\":\"" + info.inputData + "\"" +
                   "}";
        }

        return std::string("{") +
               "\"hash\":\"" + info.hash + "\"," +
               "\"from\":\"" + info.from + "\"," +
               "\"to\":\"" + info.to + "\"," +
               "\"amount\":" + std::to_string(info.amount) + "," +
               "\"tick\":" + std::to_string(info.tick) + "," +
               "\"logIdFrom\":" + std::to_string(info.logIdFrom) + "," +
               "\"logIdTo\":" + std::to_string(info.logIdTo) + "," +
               "\"transactionIndex\":" + std::to_string(info.transactionIndex) + "," +
               "\"executed\":" + (info.executed ? "true" : "false") + "," +
               "\"timestamp\":" + std::to_string(info.timestamp) + "," +
               "\"inputSize\":" + std::to_string(info.inputSize) + "," +
               "\"inputType\":" + std::to_string(info.inputType) + "," +
               "\"inputData\":\"" + info.inputData + "\"" +
               "}";
    } catch (const std::exception &e) {
        return std::string("{\"error\": \"") + e.what() + "\"}";
    }
}

std::string bobGetEndEpochLog(uint16_t epoch)
{
    std::string result;
    result.push_back('[');
    bool first = true;
    LogRangesPerTxInTick lr{-1};
    std::vector<int> logTxOrder;
    long long start, length, end;
    if (!db_get_endepoch_log_range_info(epoch, start, length, lr))
    {
        return "{\"error\": \"bob doesn't have enough info\"}";
    }
    end = start + length - 1;

    // Get end epoch tick and timestamp from the last real tick
    uint32_t endEpochTick = 0;
    db_get_u32("end_epoch_tick:" + std::to_string(epoch), endEpochTick);
    std::string timestamp;
    if (endEpochTick > 0) {
        TickData td{0};
        if (db_try_get_tick_data(endEpochTick - 1, td)) {
            char timestampBuffer[32];
            snprintf(timestampBuffer, sizeof(timestampBuffer), "%02d-%02d-%02d %02d:%02d:%02d",
                     td.year, td.month, td.day, td.hour, td.minute, td.second);
            timestamp = timestampBuffer;
        }
    }

    for (int64_t id = start; id <= end; ++id) {
        LogEvent log;
        if (db_try_get_log(epoch, static_cast<uint64_t>(id), log)) {
            std::string js = log.parseToJsonForEndEpoch(endEpochTick, timestamp);
            if (!first) result.push_back(',');
            result += js;
            first = false;
        } else {
            Json::Value err(Json::objectValue);
            err["ok"] = false;
            err["error"] = "not_found";
            err["epoch"] = epoch;
            err["logId"] = Json::UInt64(static_cast<uint64_t>(id));
            Json::StreamWriterBuilder wb;
            wb["indentation"] = "";
            std::string js = Json::writeString(wb, err);
            if (!first) result.push_back(',');
            result += js;
            first = false;
        }
    }

    result.push_back(']');
    return result;
}

std::string bobGetLog(uint16_t epoch, int64_t start, int64_t end)
{

    if (start < 0 || end < 0 || end < start) {
        return "{\"error\":\"Wrong range\"}";
    }

    std::string result;
    result.push_back('[');
    bool first = true;
    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    int logTxOrderIndex = 0;
    std::vector<int> logTxOrder;

    for (int64_t id = start; id <= end; ++id) {
        LogEvent log;
        if (db_try_get_log(epoch, static_cast<uint64_t>(id), log)) {
            if (log.getTick() != td.tick || log.getEpoch() != td.epoch)
            {
                db_try_get_tick_data(log.getTick(), td);
                if (td.epoch != epoch)
                {
                    Json::Value err(Json::objectValue);
                    err["ok"] = false;
                    err["error"] = "This tick is owned by epoch" + std::to_string(td.epoch)
                            + ", if you want to query log from epoch " + std::to_string(epoch)
                            + " use endpoint /getEndEpochLog instead";
                    err["epoch"] = epoch;
                    err["logId"] = Json::UInt64(static_cast<uint64_t>(id));
                    Json::StreamWriterBuilder wb;
                    wb["indentation"] = "";
                    std::string js = Json::writeString(wb, err);
                    if (!first) result.push_back(',');
                    result += js;
                    result.push_back(']');
                    return result; // solve seamless transition case
                }
                db_try_get_log_ranges(log.getTick(), lr);
                logTxOrderIndex = 0;
                logTxOrder = lr.sort();
                // scan to find the first cursor
                logTxOrderIndex = lr.scanTxId(logTxOrder, 0, log.getLogId());
                if (logTxOrderIndex == -1)
                {
                    result.push_back(']');
                    return result;
                }
            }
            int txIndex = logTxOrder[logTxOrderIndex];
            auto s = lr.fromLogId[txIndex];
            auto e = s + lr.length[txIndex] - 1;
            if (id > e) // processed all, move the cursor to next tx
            {
                logTxOrderIndex++; // continous log, don't need to scan
                txIndex = logTxOrder[logTxOrderIndex];
            }
            std::string js = log.parseToJsonWithExtraData(td, txIndex);
            if (!first) result.push_back(',');
            result += js;
            first = false;
        } else {
            Json::Value err(Json::objectValue);
            err["ok"] = false;
            err["error"] = "not_found";
            err["epoch"] = epoch;
            err["logId"] = Json::UInt64(static_cast<uint64_t>(id));
            Json::StreamWriterBuilder wb;
            wb["indentation"] = "";
            std::string js = Json::writeString(wb, err);
            if (!first) result.push_back(',');
            result += js;
            first = false;
        }
    }

    result.push_back(']');
    return result;

}


std::string bobGetTick(const uint32_t tick) {
    TickData td {};
    db_try_get_tick_data(tick, td);
    long long logid_start, logid_len, logid_end;
    db_try_get_log_range_for_tick(tick, logid_start, logid_len);
    logid_end = logid_start + logid_len - 1;
    Json::Value root;
    root["tick"] = tick;

    // Set TickData -> root["tickdata"]
    Json::Value tdJson;
    tdJson["computorIndex"] = td.computorIndex;
    tdJson["epoch"] = td.epoch;
    tdJson["tick"] = td.tick;

    tdJson["millisecond"] = td.millisecond;
    tdJson["second"] = td.second;
    tdJson["minute"] = td.minute;
    tdJson["hour"] = td.hour;
    tdJson["day"] = td.day;
    tdJson["month"] = td.month;
    tdJson["year"] = td.year;

    tdJson["logIdStart"] = Json::Int64(logid_start);
    tdJson["logIdEnd"] = Json::Int64(logid_end);
    // m256i fields as hex
    tdJson["timelock"] = td.timelock.toQubicHash();

    // transactionDigests[1024] as hex array
    {
        Json::Value digests(Json::arrayValue);
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
            if (td.transactionDigests[i] != m256i::zero())
                digests.append(td.transactionDigests[i].toQubicHash());
        }
        tdJson["transactionDigests"] = digests;
    }

    // contractFees[1024] as numeric array
    {
        bool nonZero = false;
        Json::Value fees(Json::arrayValue);
        for (int i = 0; i < 1024; ++i) {
            fees.append(static_cast<Json::Int64>(td.contractFees[i]));
            if (td.contractFees[i]) nonZero = true;
        }
        if (nonZero) tdJson["contractFees"] = fees;
        else tdJson["contractFees"] = 0;
    }

    // signature as hex
    tdJson["signature"] = byteToHexStr(td.signature, 64);

    root["tickdata"] = tdJson;

    // Add TickVote array (minimal fields, keep signatures as hex)
    auto tick_votes = db_try_get_tick_vote(tick);
    Json::Value votes(Json::arrayValue);
    for (const auto &vote : tick_votes) {
        Json::Value voteObj;
        // Basic info
        voteObj["computorIndex"] = vote.computorIndex;
        voteObj["epoch"] = vote.epoch;
        voteObj["tick"] = vote.tick;

        // Timestamp fields
        voteObj["millisecond"] = vote.millisecond;
        voteObj["second"] = vote.second;
        voteObj["minute"] = vote.minute;
        voteObj["hour"] = vote.hour;
        voteObj["day"] = vote.day;
        voteObj["month"] = vote.month;
        voteObj["year"] = vote.year;

        // Digest integers
        voteObj["prevResourceTestingDigest"] = vote.prevResourceTestingDigest;
        voteObj["saltedResourceTestingDigest"] = vote.saltedResourceTestingDigest;
        voteObj["prevTransactionBodyDigest"] = vote.prevTransactionBodyDigest;
        voteObj["saltedTransactionBodyDigest"] = vote.saltedTransactionBodyDigest;

        // m256i digests (use toQubicHash())
        voteObj["prevSpectrumDigest"] = vote.prevSpectrumDigest.toQubicHash();
        voteObj["prevUniverseDigest"] = vote.prevUniverseDigest.toQubicHash();
        voteObj["prevComputerDigest"] = vote.prevComputerDigest.toQubicHash();
        voteObj["saltedSpectrumDigest"] = vote.saltedSpectrumDigest.toQubicHash();
        voteObj["saltedUniverseDigest"] = vote.saltedUniverseDigest.toQubicHash();
        voteObj["saltedComputerDigest"] = vote.saltedComputerDigest.toQubicHash();

        voteObj["transactionDigest"] = vote.transactionDigest.toQubicHash();
        voteObj["expectedNextTickTransactionDigest"] = vote.expectedNextTickTransactionDigest.toQubicHash();

        // Signature as hex
        voteObj["signature"] = byteToHexStr(vote.signature, SIGNATURE_SIZE);

        votes.append(voteObj);
    }
    root["votes"] = votes;

    // Convert to string
    Json::FastWriter writer;
    return writer.write(root);
}


std::string bobFindLog(uint32_t scIndex, uint32_t logType,
                       const std::string& t1, const std::string& t2, const std::string& t3,
                       uint32_t fromTick, uint32_t toTick)
{
    if (fromTick > toTick) {
        return "{\"error\":\"Wrong range\"}";
    }

    if (!t1.empty() && t1.length() != 60) {
        return "{\"error\":\"Invalid length topic1\"}";
    }
    if (!t2.empty() && t2.length() != 60) {
        return "{\"error\":\"Invalid length topic2\"}";
    }
    if (!t3.empty() && t3.length() != 60) {
        return "{\"error\":\"Invalid length topic3\"}";
    }
    std::string st1 = t1,st2 = t2,st3 = t3;
    std::transform(t1.begin(), t1.end(), st1.begin(), ::tolower);
    std::transform(t2.begin(), t2.end(), st2.begin(), ::tolower);
    std::transform(t3.begin(), t3.end(), st3.begin(), ::tolower);

    std::vector<uint32_t> ids = db_search_log(scIndex, logType, fromTick, toTick, st1, st2, st3);

    // Return as a compact JSON array
    std::string result;
    result.push_back('[');
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) result.push_back(',');
        result += std::to_string(ids[i]);
    }
    result.push_back(']');
    return result;
}

std::string getCustomLog(uint32_t scIndex, uint32_t logType,
                         const std::string& st1, const std::string& st2, const std::string& st3,
                         uint16_t epoch, uint32_t startTick, uint32_t endTick)
{
    m256i topic[3];
    getPublicKeyFromIdentity(st1.data(), topic[0].m256i_u8);
    getPublicKeyFromIdentity(st2.data(), topic[1].m256i_u8);
    getPublicKeyFromIdentity(st3.data(), topic[2].m256i_u8);
    bool success;
    auto logs = db_get_logs_by_tick_range(epoch, startTick, endTick, success);
    std::string result = "[";
    TickData td{0};
    LogRangesPerTxInTick lr{-1};
    int logTxOrderIndex = 0;
    std::vector<int> logTxOrder;
    for (auto& le : logs)
    {
        auto id = le.getLogId();
        if (le.getTick() != td.tick)
        {
            db_try_get_tick_data(le.getTick(), td);
            db_try_get_log_ranges(le.getTick(), lr);
            logTxOrderIndex = 0;
            logTxOrder = lr.sort();
            // scan to find the first cursor
            logTxOrderIndex = lr.scanTxId(logTxOrder, 0, le.getLogId());
            if (logTxOrderIndex == -1)
            {
                result.push_back(']');
                return result;
            }
        }

        int txIndex = logTxOrder[logTxOrderIndex];
        auto s = lr.fromLogId[txIndex];
        auto e = s + lr.length[txIndex] - 1;
        if (id > e) // processed all, move the cursor to next tx
        {
            logTxOrderIndex++; // continous log, don't need to scan
            txIndex = logTxOrder[logTxOrderIndex];
        }

        if (scIndex == 0 && !le.isSCType()) // protocol log
        {
            if (le.getType() == logType)
            {
                result += le.parseToJsonWithExtraData(td, txIndex) + ",";
            }
        }
        else if (le.isSCType()) // smart contract
        {
            auto le_sz = le.getLogSize();
            if (le_sz >= 8)
            {
                auto logBody = le.getLogBodyPtr();
                uint32_t tmp;
                memcpy(&tmp, logBody, 4);
                if (tmp == scIndex)
                {
                    memcpy(&tmp, logBody + 4, 4);
                    bool match_topic = true;
                    if (topic[0] != m256i::zero() && le_sz >= 40) match_topic &= (memcmp(topic[0].m256i_u8, logBody + 8, 32) == 0);
                    if (topic[1] != m256i::zero() && le_sz >= 72) match_topic &= (memcmp(topic[1].m256i_u8, logBody + 40, 32) == 0);
                    if (topic[2] != m256i::zero() && le_sz >= 96) match_topic &= (memcmp(topic[2].m256i_u8, logBody + 72, 32) == 0);
                    if (match_topic)
                    {
                        result += le.parseToJsonWithExtraData(td, txIndex) + ",";
                    }
                }
            }
        }
    }

    if (!result.empty() && result.back() == ',') {
        result.pop_back();
    }
    result += "]";
    return result;
}

/*
 * Logger::get()->info("========================================");
    Logger::get()->info("BOB Version: {}", BOB_VERSION);
    Logger::get()->info("Git Commit:  {}", GIT_COMMIT_HASH);
    Logger::get()->info("Compiler:    {}", COMPILER_NAME);
    Logger::get()->info("========================================");
 * */

std::string bobGetExtraStatus()
{
    Json::Value root;
    root["type"] = "bob";
    root["version"] = BOB_VERSION;
    root["alias"] = gNodeAlias;
    auto current = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    root["uptime"] = current -gStartTimeUnix;
    root["timestamp"] = current;
    root["operator"] = nodeIdentity;
    struct {
        char type[4];
        char version[16];
        char alias[12];
        uint64_t uptime;
        uint64_t timestamp;
        uint8_t op[32];
    } data;
    memset(&data, 0, sizeof(data));
    memcpy(data.type, "bob", 3);
    memcpy(data.version, BOB_VERSION, std::min(int(strlen(BOB_VERSION)),16));
    memcpy(data.alias, gNodeAlias.data(), std::min(int(gNodeAlias.size()),12));
    data.uptime = current -gStartTimeUnix;
    data.timestamp = current;
    memcpy(data.op, nodePublickey.m256i_u8, 32);

    uint8_t hash[32];
    KangarooTwelve((uint8_t *) &data, sizeof(data), hash, 32);
    uint8_t signature[64];
    sign(nodeSubseed.m256i_u8, nodePublickey.m256i_u8, hash, signature);
    root["messageHex"] = byteToHexStr((const uint8_t*)&data, sizeof(data));
    root["signature"] = byteToHexStr(signature, 64);
    Json::FastWriter writer;
    return writer.write(root);
}

std::string bobGetStatus()
{
    auto status = ApiHelpers::getSyncStatus();

    return std::string("{") +
           "\"currentProcessingEpoch\":" + std::to_string(status.epoch) +
           ",\"currentFetchingTick\":" + std::to_string(status.currentFetchingTick) +
           ",\"currentFetchingLogTick\":" + std::to_string(status.currentFetchingLogTick) +
           ",\"currentVerifyLoggingTick\":" + std::to_string(status.currentVerifyLoggingTick) +
           ",\"currentIndexingTick\":" + std::to_string(status.currentIndexingTick) +
           ",\"initialTick\":" + std::to_string(status.initialTick) +
           R"(,"bobVersion": ")" + BOB_VERSION + "\""
           ",\"bobVersionGitHash\": \"" + GIT_COMMIT_HASH + "\""
           ",\"bobCompiler\": \"" + COMPILER_NAME + "\""
            ",\"extraInfo\": " + bobGetExtraStatus() +
           "}";
}

std::string bobGetEpochInfo(uint16_t epoch)
{
    auto info = ApiHelpers::getEpochInfo(epoch);

    Json::Value root;
    root["epoch"] = info.epoch;
    root["initialTick"] = info.initialTick;
    root["endTick"] = info.endTick;
    root["endTickStartLogId"] = Json::Int64(info.endTickStartLogId);
    root["endTickEndLogId"] = Json::Int64(info.endTickEndLogId);
    root["lastIndexedTick"] = Json::Int64(info.lastIndexedTick);
    Json::FastWriter writer;
    return writer.write(root);
}

std::string getQuTransfersForIdentity(uint32_t fromTick, uint32_t toTick, const std::string& identity)
{
    // Validate tick range
    if (toTick < fromTick) {
        return "{\"error\":\"Invalid tick range: toTick must be >= fromTick\"}";
    }
    if (toTick - fromTick >= 1000) {
        return "{\"error\":\"Invalid tick range: toTick - fromTick must be < 1000\"}";
    }
    if (identity.length() != 60) {
        return "{\"error\":\"Invalid identity length\"}";
    }
    m256i requester;
    getPublicKeyFromIdentity(identity.data(), requester.m256i_u8);
    std::string lcIdentity = identity;
    std::transform(lcIdentity.begin(), lcIdentity.end(), lcIdentity.begin(), ::tolower);

    // Get ticks for outgoing transfers (identity is sender - topic1)
    std::vector<uint32_t> outgoingTicks = db_search_log(0, 0, fromTick, toTick, lcIdentity, WILDCARD, WILDCARD);

    // Get ticks for incoming transfers (identity is receiver - topic2)
    std::vector<uint32_t> incomingTicks = db_search_log(0, 0, fromTick, toTick, WILDCARD, lcIdentity, WILDCARD);

    Json::Value result;
    Json::Value inArray(Json::arrayValue);
    Json::Value outArray(Json::arrayValue);

    LogRangesPerTxInTick lr{};
    TickData td{};

    for (auto tick : outgoingTicks)
    {
        db_try_get_log_ranges(tick, lr);
        db_try_get_tick_data(tick, td);
        if (td.epoch == 0) continue;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK + NUMBER_OF_SPECIAL_EVENT_PER_TICK; i++)
        {
            long long s,e,l;
            s = lr.fromLogId[i];
            l = lr.length[i];
            e = s + l - 1;
            auto vle = db_try_get_logs(td.epoch, s, e);
            for (auto& le : vle)
            {
                if (le.getType() == QU_TRANSFER)
                {
                    auto qt = le.getStruct<QuTransfer>();
                    if (qt->sourcePublicKey == requester)
                    {
                        if (i < NUMBER_OF_TRANSACTIONS_PER_TICK)
                        {
                            outArray.append(td.transactionDigests[i].toQubicHash());
                        }
                        else
                        {
                            if (i == SC_INITIALIZE_TX) outArray.append("SC_INITIALIZE_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_EPOCH_TX) outArray.append("SC_BEGIN_EPOCH_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_TICK_TX) outArray.append("SC_BEGIN_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_TICK_TX) outArray.append("SC_END_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_EPOCH_TX) outArray.append("SC_END_EPOCH_TX_" + std::to_string(tick));
                        }
                        break;
                    }
                }
            }
        }
    }

    for (auto tick : incomingTicks)
    {
        db_try_get_log_ranges(tick, lr);
        db_try_get_tick_data(tick, td);
        if (td.epoch == 0) continue;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK + NUMBER_OF_SPECIAL_EVENT_PER_TICK; i++)
        {
            long long s,e,l;
            s = lr.fromLogId[i];
            l = lr.length[i];
            e = s + l - 1;
            auto vle = db_try_get_logs(td.epoch, s, e);
            for (auto& le : vle)
            {
                if (le.getType() == QU_TRANSFER)
                {
                    auto qt = le.getStruct<QuTransfer>();
                    if (qt->destinationPublicKey == requester)
                    {
                        if (i < NUMBER_OF_TRANSACTIONS_PER_TICK)
                        {
                            inArray.append(td.transactionDigests[i].toQubicHash());
                        }
                        else
                        {
                            if (i == SC_INITIALIZE_TX) inArray.append("SC_INITIALIZE_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_EPOCH_TX) inArray.append("SC_BEGIN_EPOCH_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_TICK_TX) inArray.append("SC_BEGIN_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_TICK_TX) inArray.append("SC_END_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_EPOCH_TX) inArray.append("SC_END_EPOCH_TX_" + std::to_string(tick));
                        }
                        break;
                    }
                }
            }
        }
    }

    result["in"] = inArray;
    result["out"] = outArray;

    Json::FastWriter writer;
    return writer.write(result);
}

std::string getAssetTransfersForIdentity(uint32_t fromTick, uint32_t toTick, const std::string& identity,
                                         const std::string& assetIssuer, const std::string& assetName)
{
    // Validate tick range
    if (toTick < fromTick) {
        return "{\"error\":\"Invalid tick range: toTick must be >= fromTick\"}";
    }
    if (toTick - fromTick >= 1000) {
        return "{\"error\":\"Invalid tick range: toTick - fromTick must be < 1000\"}";
    }
    if (identity.length() != 60 || assetIssuer.length() != 60) {
        return "{\"error\":\"Invalid identity length\"}";
    }

    if (assetName.length() > 7) {
        return "{\"error\":\"Invalid assetName length\"}";
    }
    uint8_t assetHash[39] = {0};
    getPublicKeyFromIdentity(assetIssuer.c_str(), assetHash);
    memcpy(assetHash + 32, assetName.data(), assetName.size());
    uint8_t out[32];
    char hash[64] = {0};
    KangarooTwelve(assetHash, 39, out, 32);
    getIdentityFromPublicKey(out, hash, true);
    std::string assetHashStr(hash);

    m256i requester{};
    m256i issuerPubkey{};
    getPublicKeyFromIdentity(identity.data(), requester.m256i_u8);
    getPublicKeyFromIdentity(assetIssuer.c_str(), issuerPubkey.m256i_u8);

    std::string lcIdentity = identity;
    std::transform(lcIdentity.begin(), lcIdentity.end(), lcIdentity.begin(), ::tolower);

    std::vector<uint32_t> outgoingTicks = db_search_log(0, ASSET_OWNERSHIP_CHANGE, fromTick, toTick, lcIdentity, WILDCARD, assetHashStr);
    std::vector<uint32_t> incomingTicks = db_search_log(0, ASSET_OWNERSHIP_CHANGE, fromTick, toTick, WILDCARD, lcIdentity, assetHashStr);

    Json::Value result;
    Json::Value inArray(Json::arrayValue);
    Json::Value outArray(Json::arrayValue);

    LogRangesPerTxInTick lr{};
    TickData td{};

    for (auto tick : outgoingTicks)
    {
        db_try_get_log_ranges(tick, lr);
        db_try_get_tick_data(tick, td);
        if (td.epoch == 0) continue;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK + NUMBER_OF_SPECIAL_EVENT_PER_TICK; i++)
        {
            long long s,e,l;
            s = lr.fromLogId[i];
            l = lr.length[i];
            e = s + l - 1;
            auto vle = db_try_get_logs(td.epoch, s, e);
            for (auto& le : vle)
            {
                if (le.getType() == ASSET_OWNERSHIP_CHANGE || le.getType() == ASSET_POSSESSION_CHANGE)
                {
                    auto aoc = le.getStruct<AssetOwnershipChange>();
                    char name[8] = {0};
                    memcpy(name, aoc->name, 7);
                    if (aoc->sourcePublicKey == requester && aoc->issuerPublicKey == issuerPubkey && std::string(name) == assetName)
                    {
                        if (i < NUMBER_OF_TRANSACTIONS_PER_TICK)
                        {
                            outArray.append(td.transactionDigests[i].toQubicHash());
                        }
                        else
                        {
                            if (i == SC_INITIALIZE_TX) outArray.append("SC_INITIALIZE_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_EPOCH_TX) outArray.append("SC_BEGIN_EPOCH_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_TICK_TX) outArray.append("SC_BEGIN_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_TICK_TX) outArray.append("SC_END_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_EPOCH_TX) outArray.append("SC_END_EPOCH_TX_" + std::to_string(tick));
                        }
                        break;
                    }
                }
            }
        }
    }

    for (auto tick : incomingTicks)
    {
        db_try_get_log_ranges(tick, lr);
        db_try_get_tick_data(tick, td);
        if (td.epoch == 0) continue;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK + NUMBER_OF_SPECIAL_EVENT_PER_TICK; i++)
        {
            long long s,e,l;
            s = lr.fromLogId[i];
            l = lr.length[i];
            e = s + l - 1;
            auto vle = db_try_get_logs(td.epoch, s, e);
            for (auto& le : vle)
            {
                if (le.getType() == ASSET_OWNERSHIP_CHANGE || le.getType() == ASSET_POSSESSION_CHANGE)
                {
                    auto aoc = le.getStruct<AssetOwnershipChange>();
                    char name[8] = {0};
                    memcpy(name, aoc->name, 7);
                    if (aoc->destinationPublicKey == requester  && aoc->issuerPublicKey == issuerPubkey && std::string(name) == assetName)
                    {
                        if (i < NUMBER_OF_TRANSACTIONS_PER_TICK)
                        {
                            inArray.append(td.transactionDigests[i].toQubicHash());
                        }
                        else
                        {
                            if (i == SC_INITIALIZE_TX) inArray.append("SC_INITIALIZE_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_EPOCH_TX) inArray.append("SC_BEGIN_EPOCH_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_TICK_TX) inArray.append("SC_BEGIN_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_TICK_TX) inArray.append("SC_END_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_EPOCH_TX) inArray.append("SC_END_EPOCH_TX_" + std::to_string(tick));
                        }
                        break;
                    }
                }
            }
        }
    }

    result["in"] = inArray;
    result["out"] = outArray;

    Json::FastWriter writer;
    return writer.write(result);
}

std::string getAllAssetTransfers(uint32_t fromTick, uint32_t toTick, const std::string& assetIssuer, const std::string& assetName)
{
    // Validate tick range
    if (toTick < fromTick) {
        return "{\"error\":\"Invalid tick range: toTick must be >= fromTick\"}";
    }
    if (toTick - fromTick >= 1000) {
        return "{\"error\":\"Invalid tick range: toTick - fromTick must be < 1000\"}";
    }
    if (assetIssuer.length() != 60) {
        return "{\"error\":\"Invalid identity length\"}";
    }

    if (assetName.length() > 7) {
        return "{\"error\":\"Invalid assetName length\"}";
    }
    m256i issuerPubkey{};
    getPublicKeyFromIdentity(assetIssuer.c_str(), issuerPubkey.m256i_u8);

    uint8_t assetHash[39] = {0};
    getPublicKeyFromIdentity(assetIssuer.c_str(), assetHash);
    memcpy(assetHash + 32, assetName.data(), assetName.size());
    uint8_t out[32];
    char hash[64] = {0};
    KangarooTwelve(assetHash, 39, out, 32);
    getIdentityFromPublicKey(out, hash, true);
    std::string assetHashStr(hash);

    std::vector<uint32_t> outgoingTicks = db_search_log(0, ASSET_OWNERSHIP_CHANGE, fromTick, toTick, WILDCARD, WILDCARD, assetHashStr);

    Json::Value result;
    Json::Value outArray(Json::arrayValue);
    LogRangesPerTxInTick lr{};
    TickData td{};

    for (auto tick : outgoingTicks)
    {
        db_try_get_log_ranges(tick, lr);
        db_try_get_tick_data(tick, td);
        if (td.epoch == 0) continue;
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK + NUMBER_OF_SPECIAL_EVENT_PER_TICK; i++)
        {
            long long s,e,l;
            s = lr.fromLogId[i];
            l = lr.length[i];
            e = s + l - 1;
            auto vle = db_try_get_logs(td.epoch, s, e);
            for (auto& le : vle)
            {
                if (le.getType() == ASSET_OWNERSHIP_CHANGE || le.getType() == ASSET_POSSESSION_CHANGE)
                {
                    auto aoc = le.getStruct<AssetOwnershipChange>(); // both ownership/possesion using same struct at the moment
                    char name[8] = {0};
                    memcpy(name, aoc->name, 7);
                    if (aoc->issuerPublicKey == issuerPubkey && std::string(name) == assetName)
                    {
                        if (i < NUMBER_OF_TRANSACTIONS_PER_TICK)
                        {
                            outArray.append(td.transactionDigests[i].toQubicHash());
                        }
                        else
                        {
                            if (i == SC_INITIALIZE_TX) outArray.append("SC_INITIALIZE_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_EPOCH_TX) outArray.append("SC_BEGIN_EPOCH_TX_" + std::to_string(tick));
                            if (i == SC_BEGIN_TICK_TX) outArray.append("SC_BEGIN_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_TICK_TX) outArray.append("SC_END_TICK_TX_" + std::to_string(tick));
                            if (i == SC_END_EPOCH_TX) outArray.append("SC_END_EPOCH_TX_" + std::to_string(tick));
                        }
                        break;
                    }
                }
            }
        }
    }

    result = outArray;

    Json::FastWriter writer;
    return writer.write(result);
}
