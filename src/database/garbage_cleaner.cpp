#include "db.h"
#include "src/core/structs.h"
#include "src/shim.h"

#include <string>

static const std::string KEY_LAST_CLEAN_TICK_DATA = "garbage_cleaner:last_clean_tick_data";
static const std::string KEY_LAST_CLEAN_TX_TICK = "garbage_cleaner:last_clean_tx_tick";

bool cleanTransactionAndLogsAndSaveToDisk(TickData& td, LogRangesPerTxInTick& lr)
{
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (td.transactionDigests[i] != m256i::zero())
        {
            if (gTxStorageMode == TxStorageMode::Kvrocks) db_copy_transaction_to_kvrocks(td.transactionDigests[i].toQubicHash());

            if (lr.fromLogId[i] > 0 && lr.length[i] > 0)
            {
                long long start = lr.fromLogId[i];
                long long end = start + lr.length[i] - 1; // inclusive
                if (gTxStorageMode == TxStorageMode::Kvrocks) db_move_logs_to_kvrocks_by_range(td.epoch, start, end);
                db_delete_logs(td.epoch, start, end);
            }
            db_delete_transaction(td.transactionDigests[i].toQubicHash());
        }
    }
    return true;
}
void compressTickAndMoveToKVRocks(uint32_t tick)
{
    // Load TickData
    // Prepare the aggregated struct
    FullTickStruct full{};
    std::memset((void*)&full, 0, sizeof(full));
    int count = 0;
    int emptyCount = 0;
    auto votes = db_get_tick_votes(tick);
    for (const auto& v : votes)
    {
        if (v.computorIndex < 676 && v.epoch != 0)
        {
            std::memcpy((void*)&full.tv[v.computorIndex], &v, sizeof(TickVote));
            count++;
            if (v.transactionDigest == m256i::zero()) emptyCount++;
        }
    }
    if (count <= 225)
    {
        Logger::get()->warn("Tick {} Votes ({}) are deleted before being saved to disk, please check your KeyDB and bob config, make sure data is not evicted too early.", tick, count);
    }
    if (!db_get_tick_data(tick, full.td))
    {
        // failed to get tick data, find out if it's really empty tick
        if (emptyCount <= 225)
        {
            Logger::get()->warn("Tick Data are deleted before being saved to disk, please check your KeyDB and bob config, make sure data is not evicted too early.");
            Logger::get()->warn("Failed to save tick {}", tick);
            return;
        }
    }
    // Insert the compressed record
    if (!db_insert_vtick_to_kvrocks(tick, full))
    {
        Logger::get()->error("compressTick: Failed to insert vtick for tick {}", tick);
        return;
    }
    LogRangesPerTxInTick lr{};
    if (db_try_get_log_ranges(tick, lr))
    {
        db_insert_cLogRange_to_kvrocks(tick, lr);
    }
    long long log_start, log_len;
    if (db_try_get_log_range_for_tick(tick, log_start, log_len))
    {
        db_insert_TickLogRange_to_kvrocks(tick, log_start, log_len);
    }
    Logger::get()->trace("compressTick: Compressed tick {}", tick);
}

bool cleanTransactionLogs(uint32_t tick)
{
    TickData td{};
    LogRangesPerTxInTick lr{};
    if (!db_try_get_tick_data(tick, td))
    {
        return false;
    }
    if (!db_try_get_log_ranges(tick, lr))
    {
        Logger::get()->error("Failed to get log range for this tick {} - epoch {}", td.tick, td.epoch);
        return false;
    }
    // Save log ranges to kvrocks before deleting from Redis
    // This ensures log ranges remain available for transaction execution lookups
    db_insert_cLogRange_to_kvrocks(tick, lr);
    long long log_start, log_len;
    if (db_try_get_log_range_for_tick(tick, log_start, log_len))
    {
        db_insert_TickLogRange_to_kvrocks(tick, log_start, log_len);
    }
    db_delete_log_ranges(tick);
    return cleanTransactionAndLogsAndSaveToDisk(td, lr);
}

bool cleanRawTick(uint32_t fromTick, uint32_t toTick, bool withTransactions)
{
    Logger::get()->trace("Start cleaning raw tick data from {} to {}", fromTick, toTick);
    for (uint32_t tick = fromTick; tick <= toTick; tick++)
    {
        if (withTransactions)
        {
            cleanTransactionLogs(tick);
        }
        // Delete raw TickData
        if (!db_delete_tick_data(tick))
        {
            Logger::get()->warn("cleanRawTick: Failed to delete TickData for tick {}", tick);
        }

        // Delete all TickVotes for this tick (attempt all indices; API treats missing as success)
        db_delete_tick_vote(tick);
    }
    Logger::get()->trace("Cleaned raw tick data from {} to {}", fromTick, toTick);
    return true;
}

void garbageCleaner()
{
    Logger::get()->info("Start garbage cleaner");
    uint32_t loadedCleanTickData = 0;
    uint32_t loadedCleanTxTick = 0;

    long long lastCleanTickData;
    long long lastCleanTransactionTick;

    if (db_get_u32(KEY_LAST_CLEAN_TICK_DATA, loadedCleanTickData) && loadedCleanTickData > 0)
    {
        lastCleanTickData = loadedCleanTickData;
        Logger::get()->info("Loaded lastCleanTickData from DB: {}", lastCleanTickData);
    }
    else
    {
        lastCleanTickData = gInitialTick;
        Logger::get()->info("No persisted lastCleanTickData found, using default: {}", lastCleanTickData);
    }

    if (db_get_u32(KEY_LAST_CLEAN_TX_TICK, loadedCleanTxTick) && loadedCleanTxTick > 0)
    {
        lastCleanTransactionTick = loadedCleanTxTick;
        Logger::get()->info("Loaded lastCleanTransactionTick from DB: {}", lastCleanTransactionTick);
    }
    else
    {
        lastCleanTransactionTick = gInitialTick;
        Logger::get()->info("No persisted lastCleanTransactionTick found, using default: {}", lastCleanTransactionTick);
    }

    if (lastCleanTickData < gInitialTick) lastCleanTickData = gInitialTick;
    if (lastCleanTransactionTick < gInitialTick) lastCleanTransactionTick = gInitialTick;
    uint32_t lastReportedTick = 0;
    while (!gStopFlag.load())
    {
        SLEEP(100);
        if (gStopFlag.load()) break;
        if (gTickStorageMode == TickStorageMode::LastNTick)
        {
            long long cleanToTick = (long long)(gCurrentIndexingTick.load()) - 5;
            cleanToTick = std::min(cleanToTick, (long long)(gCurrentIndexingTick) - 1 - gLastNTickStorage);
            if (lastCleanTickData < cleanToTick)
            {
                if (cleanRawTick(lastCleanTickData + 1, cleanToTick, gTxStorageMode == TxStorageMode::LastNTick /*also clean txs*/))
                {
                    lastCleanTickData = cleanToTick;
                    db_insert_u32(KEY_LAST_CLEAN_TICK_DATA, static_cast<uint32_t>(lastCleanTickData));
                }

                if (cleanToTick - lastReportedTick > 1000)
                {
                    Logger::get()->trace("Cleaned up to tick {}", cleanToTick);
                    lastReportedTick = cleanToTick;
                }
            }
        }
        else if (gTickStorageMode == TickStorageMode::Kvrocks)
        {
            long long cleanToTick = (long long)(gCurrentIndexingTick.load()) - 5;
            if (lastCleanTickData < cleanToTick)
            {
                for (long long t = lastCleanTickData + 1; t <= cleanToTick; t++)
                {
                    compressTickAndMoveToKVRocks(t);
                }
                Logger::get()->trace("Compressed tick {}->{} to kvrocks", lastCleanTickData + 1, cleanToTick);
                if (cleanRawTick(lastCleanTickData + 1, cleanToTick, false /*do not clean txs instantly*/))
                {
                    lastCleanTickData = cleanToTick;
                    db_insert_u32(KEY_LAST_CLEAN_TICK_DATA, static_cast<uint32_t>(lastCleanTickData));
                }
                Logger::get()->trace("Cleaned tick {}->{} in keydb", lastCleanTickData + 1, cleanToTick);
                if (cleanToTick - lastReportedTick > 1000)
                {
                    Logger::get()->trace("Compressed and cleaned up to tick {}", cleanToTick);
                    lastReportedTick = cleanToTick;
                }
            }
        }

        if (gTxStorageMode == TxStorageMode::Kvrocks)
        {
            long long cleanToTick = (long long)(gCurrentIndexingTick.load()) - 5;
            cleanToTick = std::min(cleanToTick, (long long)(gCurrentIndexingTick) - 1 - gTxTickToLive);
            if (lastCleanTransactionTick < cleanToTick)
            {
                for (long long t = lastCleanTransactionTick + 1; t <= cleanToTick; t++)
                {
                    cleanTransactionLogs(t);
                }
                lastCleanTransactionTick = cleanToTick;
                db_insert_u32(KEY_LAST_CLEAN_TX_TICK, static_cast<uint32_t>(lastCleanTransactionTick));
            }
        }
    }
    if (gIsEndEpoch)
    {
        Logger::get()->info("Garbage cleaner detected END EPOCH signal. Cleaning all data left on RAM");
        if (gTickStorageMode == TickStorageMode::LastNTick)
        {
            long long cleanToTick = (long long)(gCurrentIndexingTick.load()) - 1;
            if (lastCleanTickData < cleanToTick)
            {
                if (cleanRawTick(lastCleanTickData + 1, cleanToTick, true))
                {
                    Logger::get()->info("Cleaned all raw tick data");
                    db_insert_u32(KEY_LAST_CLEAN_TICK_DATA, static_cast<uint32_t>(cleanToTick));
                }
            }
        }
        else if (gTickStorageMode == TickStorageMode::Kvrocks)
        {
            long long cleanToTick = (long long)(gCurrentIndexingTick.load()) - 1;
            if (lastCleanTickData < cleanToTick)
            {
                for (long long t = lastCleanTickData + 1; t <= cleanToTick; t++)
                {
                    compressTickAndMoveToKVRocks(t);
                }
                Logger::get()->trace("Compressed tick {}->{} to kvrocks", lastCleanTickData + 1, cleanToTick);
                if (cleanRawTick(lastCleanTickData + 1, cleanToTick, true))
                {
                    Logger::get()->info("Cleaned all raw tick data");
                    db_insert_u32(KEY_LAST_CLEAN_TICK_DATA, static_cast<uint32_t>(cleanToTick));
                }
            }
        }
    }
    Logger::get()->info("Exited garbage cleaner");
}