#include "src/core/structs.h"
#include "src/database/db.h"
#include "src/shim.h"
#include "src/rest_api/QubicSubscriptionManager.h"

#include <atomic>
#include <chrono>
#include <thread>

static bool matchesTransaction(const QuTransfer &transfer, const Transaction &tx) {
    return transfer.sourcePublicKey == tx.sourcePublicKey &&
            transfer.destinationPublicKey == tx.destinationPublicKey &&
           transfer.amount == tx.amount;
}

static std::string getTransactionHash(const unsigned char *digest) {
    char hash[65] = {0};
    getIdentityFromPublicKey(digest, hash, true);
    return std::string(hash);
}

static int getTransactionIndexFromLogId(const LogRangesPerTxInTick &logrange, long long logId) {
    for (int i = 0; i < LOG_TX_PER_TICK; i++) {
        if (logId >= logrange.fromLogId[i] && logId < logrange.fromLogId[i] + logrange.length[i]) {
            return i;
        }
    }
    return -1;
}

// Index a single verified tick. Extend this to build/search indexes as needed.
static uint64_t calculateUnixTimestamp(const TickData &td) {
    std::tm timeinfo = {};
    timeinfo.tm_year = int(td.year) + 2000 - 1900;  // Convert from 2-digit year to years since 1900
    timeinfo.tm_mon = td.month - 1;    // Month (0-11)  
    timeinfo.tm_mday = td.day;
    timeinfo.tm_hour = td.hour;
    timeinfo.tm_min = td.minute;
    timeinfo.tm_sec = td.second;
    timeinfo.tm_isdst = -1;
    time_t t = timegm(&timeinfo);

    uint64_t millis = static_cast<uint64_t>(t) * 1000u + static_cast<uint64_t>(td.millisecond);
    return millis;
}

static void indexTick(uint32_t tick, const TickData &td) {
    LogRangesPerTxInTick logrange{};
    uint64_t timestamp = td.epoch == gCurrentProcessingEpoch ? calculateUnixTimestamp(td) : 0;
    db_try_get_log_ranges(tick, logrange);
    if (td.tick == tick)
    {
        for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
            if (td.transactionDigests[i] == m256i::zero()) continue;
            std::string txHash = getTransactionHash(td.transactionDigests[i].m256i_u8);
            std::string key = "itx:" + txHash;

            LogEvent firstEvent;
            bool isExecuted = false;
            if (logrange.length[i] > 0) {
                if (!db_try_get_log(td.epoch, logrange.fromLogId[i], firstEvent))
                {
                    Logger::get()->critical("Failed to index data for tick {}. Malformed database."
                                            "You need to force bob to reverified and reindex DB with command:"
                                            "hdel db_status latest_verified_tick and hdel db_status last_indexed_tick", tick);
                    exit(1);
                }
                if (firstEvent.getType() == QU_TRANSFER) { // QuTransfer type
                    QuTransfer transfer{};
                    memcpy((void*)&transfer, firstEvent.getLogBodyPtr(), sizeof(QuTransfer));
                    std::vector<uint8_t> tx_data;
                    if (db_try_get_transaction(txHash, tx_data)) {
                        auto tx = (Transaction*)tx_data.data();
                        if (tx->amount < gSpamThreshold && tx->inputSize == 0 && tx->inputType == 0) // spam tx => not index
                        {
                            continue;
                        }
                        isExecuted = matchesTransaction(transfer, *tx);
                    }
                }
            }

            db_set_indexed_tx(key.c_str(), i, logrange.fromLogId[i],
                              logrange.fromLogId[i] + logrange.length[i] - 1, timestamp,
                              isExecuted);
        }
    }

    // handling 5 special events
    for (int i = SC_INITIALIZE_TX; i <= SC_END_EPOCH_TX; i++)
    {
        std::string key = "itx:" + std::to_string(tick) + "_" + std::to_string(i);
        db_set_indexed_tx(key.c_str(), i, logrange.fromLogId[i],
                          logrange.fromLogId[i] + logrange.length[i] - 1, timestamp,
                          true);
    }

    // now handling all log events
    bool success;
    auto vle = db_get_logs_by_tick_range(td.epoch, tick, tick, success);
    uint32_t SC_index = 0;
    uint32_t logType = 0;
    m256i topic1, topic2, topic3;
    for (int i = 0; i < vle.size(); i++)
    {
        auto& le  = vle[i];
        auto type = le.getType();
        SC_index = 0xffffffff;
        switch(type)
        {
            case QU_TRANSFER:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<QuTransfer>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                topic3 = m256i::zero();
                break;
            }
            case ASSET_ISSUANCE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetIssuance>();
                topic1 = e->issuerPublicKey;
                topic2 = m256i::zero();
                memcpy(topic2.m256i_u8, ((uint8_t*)e) + 32, 31);
                topic3 = m256i::zero();
                break;
            }
            case ASSET_OWNERSHIP_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetOwnershipChange>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->name, 7);
                KangarooTwelve(assetHash, 39, topic3.m256i_u8, 32);
                break;
            }
            case ASSET_POSSESSION_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetPossessionChange>();
                topic1 = e->sourcePublicKey;
                topic2 = e->destinationPublicKey;
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->name, 7);
                KangarooTwelve(assetHash, 39, topic3.m256i_u8, 32);
                break;
            }
            case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetOwnershipManagingContractChange>();
                topic1 = e->ownershipPublicKey;
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->assetName, 7);
                KangarooTwelve(assetHash, 39, topic2.m256i_u8, 32);
                break;
            }
            case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<AssetPossessionManagingContractChange>();
                topic1 = e->ownershipPublicKey;
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                uint8_t assetHash[39];
                memcpy(assetHash, e->issuerPublicKey.m256i_u8, 32);
                memcpy(assetHash + 32, e->assetName, 7);
                KangarooTwelve(assetHash, 39, topic2.m256i_u8, 32);
                break;
            }
            case BURNING:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<Burning>();
                topic1 = e->sourcePublicKey;
                topic2 = m256i(0,0,0,e->contractIndexBurnedFor);
                topic3 = m256i::zero();
                break;
            }

            case CONTRACT_RESERVE_DEDUCTION:
            {
                SC_index = 0; logType = type;
                auto e = le.getStruct<ContractReserveDeduction>();
                topic1 = m256i(0,0,0,e->contractIndex);
                topic2 = m256i::zero();
                topic3 = m256i::zero();
                break;
            }

            case CONTRACT_ERROR_MESSAGE:
            case CONTRACT_WARNING_MESSAGE:
            case CONTRACT_INFORMATION_MESSAGE:
            case CONTRACT_DEBUG_MESSAGE:
            {
                auto ptr = le.getLogBodyPtr();
                int le_sz = le.getLogSize();
                if (le_sz >= 8)
                {
                    memcpy(&SC_index, ptr, 4);
                    memcpy(&logType, ptr +4, 4);
                    if (logType >= 100000)
                    {
                        topic1 = m256i::zero();
                        topic2 = m256i::zero();
                        topic3 = m256i::zero();
                        if (le_sz - 8 > 0) memcpy(topic1.m256i_u8, ptr + 8, std::min(32, le_sz-8));
                        if (le_sz - 40 > 0) memcpy(topic2.m256i_u8, ptr + 40, std::min(32, le_sz-40));
                        if (le_sz - 72 > 0) memcpy(topic3.m256i_u8, ptr + 72, std::min(32, le_sz-72));
                    }
                    else
                    {
                        SC_index = 0xffffffff;
                    }
                }
                break;
            }
            case SPECTRUM_STATS:
                // nothing to do
                break;
            case DUST_BURNING:
                // TODO: simulate and implement this
                break;
            case CUSTOM_MESSAGE:
            {
                // no indexing
                break;
            }
            default:
                break;
        }
        if (SC_index != 0xffffffff)
        {
            std::string key;
            if (!(SC_index == 0 && logType == 0))
            {
                //bool db_add_indexer(const std::string &key, uint32_t tickNumber)
                if (SC_index != 0)
                {
                    key = "indexed:" + std::to_string(SC_index);
                    db_add_indexer(key, tick);
                }
                key = "indexed:" + std::to_string(SC_index) + ":" + std::to_string(logType);
                db_add_indexer(key, tick);
            }
            // populate all scenarios with topic1,2,3
            // 3 bits => 0=>7
            for (int bit = 1; bit < 8; bit++) // case 0,0,0 is already handled above
            {
                key = "indexed:" + std::to_string(SC_index) + ":" + std::to_string(logType) + ":";
                int isSet = 0;
                for (int j = 0; j < 3; j++)
                {
                    const m256i &topic = (j == 0) ? topic1 : ((j == 1) ? topic2 : topic3);
                    if (topic == m256i::zero()) {
                        key += std::string("ANY") + ((j == 2) ? "" : ":");
                    } else if ((bit >> j) & 1) {
                        char qhash[64] = {0};
                        getIdentityFromPublicKey(topic.m256i_u8, qhash, true);
                        std::string str_hash(qhash);
                        key += str_hash + ((j == 2) ? "" : ":");
                        isSet++;
                    } else {
                        key += std::string("ANY") + ((j == 2) ? "" : ":");
                    }
                }
                if (isSet) db_add_indexer(key, tick);
            }
        }
    }

    Logger::get()->trace("Indexed verified tick {}", tick);
    db_insert_u32("lastIndexedTick:"+std::to_string(gCurrentProcessingEpoch), tick);
}

void indexVerifiedTicks()
{
    using namespace std::chrono_literals;

    // Recover the last indexed tick; start from -1 if none is stored yet.
    long long lastIndexed = -1;
    lastIndexed = db_get_last_indexed_tick();
    if (lastIndexed == -1) lastIndexed = gInitialTick.load() - 1;
    // users opt to skip the last part of previous epoch
    if (lastIndexed < gInitialTick.load() - 1) lastIndexed = gInitialTick.load() - 1;
    gCurrentIndexingTick = lastIndexed;
    Logger::get()->info("QubicIndexer: starting at last_indexed_tick={}", lastIndexed);

    while (!gStopFlag.load(std::memory_order_relaxed))
    {
        // Check for reindex signal from admin API
        long long reindexTick = gReindexFromTick.exchange(-1, std::memory_order_acq_rel);
        if (reindexTick >= 0)
        {
            Logger::get()->info("QubicIndexer: reindex signal received, resetting to tick {}", reindexTick);
            lastIndexed = reindexTick - 1;
            gCurrentIndexingTick = lastIndexed;
            // Persist the new starting point
            db_update_last_indexed_tick(static_cast<uint32_t>(lastIndexed));
        }

        uint32_t nextTick = static_cast<uint32_t>(lastIndexed + 1);
        if (nextTick == gCurrentVerifyLoggingTick && gIsEndEpoch)
        {
            // the final thread in bob 4-processors model
            Logger::get()->info("Finish indexing last tick. Exiting...");
            break;
        }
        if (nextTick >= gCurrentVerifyLoggingTick && !gStopFlag.load(std::memory_order_relaxed))
        {
            SLEEP(10);
            continue;
        }
        if (gStopFlag.load(std::memory_order_relaxed)) break;

        // Only proceed when the verified-compressed record exists.
        TickData td;
        db_try_get_tick_data(nextTick, td);
        indexTick(nextTick, td);

        // Persist progress.
        if (!db_update_last_indexed_tick(nextTick)) {
            Logger::get()->warn("QubicIndexer: failed to update last_indexed_tick to {}", nextTick);
            // Best-effort sleep to avoid hammering DB if there's a transient error.
            SLEEP(1000);
            continue;
        }

        lastIndexed = nextTick;
        gCurrentIndexingTick = lastIndexed;

        // Notify tickStream subscribers after indexing is complete
        // (all transaction execution info is now available)
        // This is wrapped in try-catch to ensure indexer continues even if notification fails
        if (QubicSubscriptionManager::instance().getClientCount() > 0) {
            try {
                // Get logs for this tick
                bool success = false;
                std::vector<LogEvent> logs = db_get_logs_by_tick_range(td.epoch, nextTick, nextTick, success);
                QubicSubscriptionManager::instance().onVerifiedTick(nextTick, td.epoch, logs, td);
            } catch (const std::exception& e) {
                Logger::get()->warn("QubicIndexer: tickStream notification failed for tick {}: {}", nextTick, e.what());
            } catch (...) {
                Logger::get()->warn("QubicIndexer: tickStream notification failed for tick {}: unknown error", nextTick);
            }
        }
    }

    Logger::get()->info("QubicIndexer: stopping gracefully at last_indexed_tick={}", lastIndexed);
}
