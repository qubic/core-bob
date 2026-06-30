#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <set>
#include <array>
#include <cstring>
#include "m256i.h"
#include "connection/connection.h"
#include "structs.h"
#include "GlobalVar.h"
#include "spdlogDriver/Logger.h"
#include "database/db.h"
#include "K12AndKeyUtil.h"
#include "commonFunctions.h"
#include "Entity.h"
#include "Asset.h"
#include <string>
#include <filesystem>
#include "Profiler.h"
#include "shim.h"
#include <future>
#include "LoggingEventProcessorCore.h"
#include "RESTAPI/QubicSubscriptionManager.h"

using namespace std::chrono_literals;

static void KangarooTwelve64To32(void* input, void* output)
{
    KangarooTwelve((uint8_t*)input, 64, (uint8_t*)output, 32);
}

void computeSpectrumDigest(const uint32_t tickStart, const uint32_t tickEnd)
{
    unsigned int digestIndex;
    if (tickStart != UINT32_MAX)
    {
        for (digestIndex = 0; digestIndex < SPECTRUM_CAPACITY; digestIndex++)
        {
            if ( ((spectrum[digestIndex].latestIncomingTransferTick >= tickStart) && (spectrum[digestIndex].latestIncomingTransferTick <= tickEnd))
            || ((spectrum[digestIndex].latestOutgoingTransferTick >= tickStart) && (spectrum[digestIndex].latestOutgoingTransferTick <= tickEnd)))
            {
                KangarooTwelve64To32(&spectrum[digestIndex], &spectrumDigests[digestIndex]);
                spectrumChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
            }
        }
    }
    else
    {
        for (digestIndex = 0; digestIndex < SPECTRUM_CAPACITY; digestIndex++)
        {
            KangarooTwelve64To32(&spectrum[digestIndex], &spectrumDigests[digestIndex]);
            spectrumChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
        }
    }

    unsigned int previousLevelBeginning = 0;
    unsigned int numberOfLeafs = SPECTRUM_CAPACITY;
    while (numberOfLeafs > 1)
    {
        for (unsigned int i = 0; i < numberOfLeafs; i += 2)
        {
            if (spectrumChangeFlags[i >> 6] & (3ULL << (i & 63)))
            {
                KangarooTwelve64To32(&spectrumDigests[previousLevelBeginning + i], &spectrumDigests[digestIndex]);
                spectrumChangeFlags[i >> 6] &= ~(3ULL << (i & 63));
                spectrumChangeFlags[i >> 7] |= (1ULL << ((i >> 1) & 63));
            }
            digestIndex++;
        }
        previousLevelBeginning += numberOfLeafs;
        numberOfLeafs >>= 1;
    }
    spectrumChangeFlags[0] = 0;
}

m256i getUniverseDigest(const uint32_t tickStart, const uint32_t tickEnd)
{
    unsigned int digestIndex;
    if (tickStart != UINT32_MAX) {
        for (digestIndex = 0; digestIndex < ASSETS_CAPACITY; digestIndex++)
        {
            if (assetChangeFlags[digestIndex >> 6] & (1ULL << (digestIndex & 63)))
            {
                KangarooTwelve((uint8_t*)&assets[digestIndex], sizeof(AssetRecord), (uint8_t*)&assetDigests[digestIndex], 32);
            }
        }
    }
    else
    {
        for (digestIndex = 0; digestIndex < ASSETS_CAPACITY; digestIndex++)
        {
            KangarooTwelve((uint8_t*)&assets[digestIndex], sizeof(AssetRecord), (uint8_t*)&assetDigests[digestIndex], 32);
            assetChangeFlags[digestIndex >> 6] |= (1ULL << (digestIndex & 63));
        }
    }

    unsigned int previousLevelBeginning = 0;
    unsigned int numberOfLeafs = ASSETS_CAPACITY;
    while (numberOfLeafs > 1)
    {
        for (unsigned int i = 0; i < numberOfLeafs; i += 2)
        {
            if (assetChangeFlags[i >> 6] & (3ULL << (i & 63)))
            {
                KangarooTwelve64To32(&assetDigests[previousLevelBeginning + i], &assetDigests[digestIndex]);
                assetChangeFlags[i >> 6] &= ~(3ULL << (i & 63));
                assetChangeFlags[i >> 7] |= (1ULL << ((i >> 1) & 63));
            }
            digestIndex++;
        }
        previousLevelBeginning += numberOfLeafs;
        numberOfLeafs >>= 1;
    }
    assetChangeFlags[0] = 0;

    return assetDigests[(ASSETS_CAPACITY * 2 - 1) - 1];
}

// Small helper to load a fixed-size array from a binary file with uniform logging.
static bool loadFile(const std::string& path,
                     void* outBuffer,
                     size_t elementSize,
                     size_t elementCount,
                     const char* label)
{
    Logger::get()->info("Loading file {}", path);
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        Logger::get()->error("Failed to open {} file: {}", label, path);
        return false;
    }
    size_t readCount = fread(outBuffer, elementSize, elementCount, f);
    fclose(f);
    if (readCount != elementCount) {
        Logger::get()->error("Failed to read {} file. Expected {} records, got {}",
                             label, elementCount, readCount);
        return false;
    }
    return true;
}

#define SAVE_PERIOD 1000

void saveFiles(const std::string tickSpectrum, const std::string tickUniverse)
{
    FILE *f = fopen(tickSpectrum.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open spectrum file for writing: {}", tickSpectrum);
    } else {
        if (fwrite(spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, f) != SPECTRUM_CAPACITY) {
            Logger::get()->critical("Failed to write spectrum file: {}", tickSpectrum);
            exit(3);
        }
        fclose(f);
    }

    f = fopen(tickUniverse.c_str(), "wb");
    if (!f) {
        Logger::get()->error("Failed to open universe file for writing: {}", tickUniverse);
    } else {
        if (fwrite(assets, sizeof(AssetRecord), ASSETS_CAPACITY, f) != ASSETS_CAPACITY) {
            Logger::get()->critical("Failed to write universe file: {}", tickUniverse);
            exit(3);
        }
        fclose(f);
    }
}

void saveState(uint32_t& tracker, uint32_t lastVerified)
{
    Logger::get()->info("Saving verified universe/spectrum {} - Do not shutdown", lastVerified);
    std::string tickSpectrum = "spectrum." + std::to_string(lastVerified);
    std::string tickUniverse = "universe." + std::to_string(lastVerified);
    saveFiles(tickSpectrum, tickUniverse);
    db_update_latest_verified_tick(lastVerified);
    tickSpectrum = "spectrum." + std::to_string(tracker);
    tickUniverse = "universe." + std::to_string(tracker);
    if (std::filesystem::exists(tickSpectrum) && std::filesystem::exists(tickUniverse)) {
        std::filesystem::remove(tickSpectrum);
        std::filesystem::remove(tickUniverse);
    }
    Logger::get()->info("Saved checkpoints. Deleted old verified universe/spectrum {}. ", lastVerified);
    tracker = lastVerified;
    db_insert_u32("verified_history:" + std::to_string(gCurrentProcessingEpoch), lastVerified);
}

// Helper to convert byte array to hex string
static std::string bytes_to_hex_string(const unsigned char* bytes, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

static bool checkLogExistAndVerify(uint16_t epoch, long long logId)
{
    LogEvent le{};
    if (!db_try_get_log(epoch, logId, le))
    {
        return false;
    }
    if (!le.selfCheck(epoch))
    {
        return false;
    }
    return true;
}

void verifyLoggingEvent()
{
    gIsEndEpoch = false;
    bool saveLastTick = false;
    bool needBootstrapFiles = false;
    uint32_t lastQuorumTick = 0;
    uint32_t lastVerifiedTick = db_get_latest_verified_tick();
    std::string spectrumFilePath;
    std::string assetFilePath;
    // Choose default files based on lastVerifiedTick; fallback to epoch files if any is missing.
    if (lastVerifiedTick != -1 && lastVerifiedTick >= gInitialTick) {
        std::string tickSpectrum = "spectrum." + std::to_string(lastVerifiedTick);
        std::string tickUniverse = "universe." + std::to_string(lastVerifiedTick);
        if (std::filesystem::exists(tickSpectrum) && std::filesystem::exists(tickUniverse)) {
            spectrumFilePath = std::move(tickSpectrum);
            assetFilePath    = std::move(tickUniverse);
        } else {
            Logger::get()->error("Cannot find snapshot files: {} and {}", tickSpectrum, tickUniverse);
            Logger::get()->error("Reason: Bob wasn't exited gracefully last time or your snapshot files are corrupted. You need to cleanup your DB");
            exit(1);
        }
    } else {
        spectrumFilePath = "spectrum." + std::to_string(gCurrentProcessingEpoch);
        assetFilePath    = "universe." + std::to_string(gCurrentProcessingEpoch);
        needBootstrapFiles = true;
        lastVerifiedTick =  gInitialTick - 1;
    }

    if (!loadFile(spectrumFilePath, spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, "spectrum")) {
        if (needBootstrapFiles)
        {
            Logger::get()->info("Cannot find bootstrap files, trying to download from qubic.global");
            DownloadStateFiles(gCurrentProcessingEpoch);
            if (!loadFile(spectrumFilePath, spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, "spectrum"))
            {
                return;
            }
        } else {
            return;
        }
    }

    if (!loadFile(assetFilePath, assets, sizeof(AssetRecord), ASSETS_CAPACITY, "universe")) {
        return;
    }
    gCurrentVerifyLoggingTick = lastVerifiedTick+1;

    auto futSpectrum = std::async(std::launch::async, []() {
        computeSpectrumDigest(UINT32_MAX, UINT32_MAX);
    });
    auto futUniverse = std::async(std::launch::async, []() {
        return getUniverseDigest(UINT32_MAX, UINT32_MAX);
    });

    // Synchronize both
    futSpectrum.get();
    futUniverse.get();

    while (gCurrentFetchingLogTick == gInitialTick) {
        if (gStopFlag.load()) return;
        SLEEP(100);
    }
    while (!gStopFlag.load())
    {
        while (gCurrentVerifyLoggingTick > (gCurrentFetchingLogTick - 1) && !gStopFlag.load()) SLEEP(100);
        if (gStopFlag.load()) return;
        uint32_t processFromTick = gCurrentVerifyLoggingTick;
        // NOTE: need to this to allow bob to verify the last virtual tick END_EPOCH
        // but this will create warnings while syncing.
        // TODO: fix warning or find another way to detect END_EPOCH
        uint32_t maxVerifiableTick = gCurrentFetchingLogTick - 1;//std::min(gCurrentFetchingLogTick - 1, gCurrentFetchingTick - 1);
        uint32_t processToTick = std::min(gCurrentVerifyLoggingTick + BATCH_VERIFICATION, maxVerifiableTick);
        // detect END_EPOCH
        for (uint32_t tick = processFromTick; tick <= processToTick; tick++)
        {
            LogRangesPerTxInTick lr{};
            if (db_try_get_log_ranges(tick, lr))
            {
                if (lr.fromLogId[SC_END_EPOCH_TX] != -1 && lr.length[SC_END_EPOCH_TX] != -1)
                {
                    if (!saveLastTick)
                    {
                        saveLastTick = true;
                        Logger::get()->info("Saving verified universe/spectrum 1 tick before new epoch");
                        saveState(lastVerifiedTick, gCurrentVerifyLoggingTick - 1);
                        saveFiles("spectrum."+std::to_string(tick-1), "universe."+std::to_string(tick-1));
                    }
                    if (processFromTick < tick) processToTick = tick - 1;
                    Logger::get()->info("Detect end epoch at tick {} ({} => {}). Setting last batch to {}->{}",
                                        tick, lr.fromLogId[SC_END_EPOCH_TX], lr.length[SC_END_EPOCH_TX], processFromTick, processToTick);
                }
            }
        }
        std::vector<LogEvent> vle;
        {
            PROFILE_SCOPE("db_get_logs_by_tick_range");
gatherAllLoggingEvents:
            bool success = false;
            vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, processFromTick, processToTick, success);
            // verify if we have enough logging
            long long fromId, length;
            db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);
            if (vle.size() > length)
            {
                Logger::get()->critical("Bob has more log than needed for tick {}->{} "
                                        "unexpected behavior {} but get {}", processFromTick, processToTick, vle.size(), length);
            }
            if (fromId != -1 && length != -1 && vle.size() != length)
            {
                Logger::get()->info("Entering rescue mode to refetch malformed data");
                Logger::get()->info("tick {}->{} unexpected behavior expected {} but get {}", processFromTick, processToTick, length, vle.size());
                Logger::get()->info("Trying to refetch log ranges");
                for (uint32_t t = processFromTick; t <= processToTick; t++) db_delete_log_ranges(t);
                refetchLogFromTick = processFromTick;
                refetchLogToTick = processToTick;
                bool received_full = false;
                const auto outerWaitStart = std::chrono::steady_clock::now();
                constexpr auto OUTER_WAIT_BUDGET = std::chrono::seconds(30);
                bool outerWaitTimedOut = false;
                while (!received_full)
                {
                    received_full = true;
                    for (uint32_t t = processFromTick; t <= processToTick; t++)
                    {
                        if (!db_check_log_range(t))
                        {
                            received_full = false;
                            break;
                        }
                    }
                    if (received_full) break;
                    if (std::chrono::steady_clock::now() - outerWaitStart > OUTER_WAIT_BUDGET) {
                        Logger::get()->warn("rescue: not all log_ranges for batch {}->{} arrived within {}s; proceeding with what we have",
                                            processFromTick, processToTick,
                                            std::chrono::duration_cast<std::chrono::seconds>(OUTER_WAIT_BUDGET).count());
                        outerWaitTimedOut = true;
                        break;
                    }
                    SLEEP(100);
                    if (gStopFlag.load(std::memory_order_relaxed)) return;
                }
                refetchLogFromTick = -1;
                refetchLogToTick = -1;
                (void)outerWaitTimedOut; // downstream loop handles missing ranges via per-tick guards
                Logger::get()->info("Successfully refetched all log ranges");
                db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);
                Logger::get()->info("New log range for tick {}->{} : logID {}->{}", processFromTick, processToTick, fromId, fromId+length-1);

                auto endId = fromId + length - 1;
                int dataRefetchAttempts = 0;
                int metadataWipeRounds = 0;
                const auto rescueStart = std::chrono::steady_clock::now();
                constexpr auto MAX_RESCUE_BUDGET = std::chrono::seconds(120);
                while (!gStopFlag.load())
                {
                    db_delete_logs_from_redis(gCurrentProcessingEpoch, fromId, endId);
                    refetchFromId = fromId;
                    refetchToId = endId;
                    Logger::get()->info("Deleted malformed log, waiting for new data");
                    // Bound the wait. 10s per attempt × 3 attempts = 30s
                    // before the first metadata wipe; with up to 3 wipe
                    // rounds the total ceiling before bob self-restarts is
                    // ~90s — well below any reasonable "is bob alive" timeout.
                    bool received_full = false;
                    const auto waitStart = std::chrono::steady_clock::now();
                    constexpr auto WAIT_BUDGET = std::chrono::seconds(10);
                    while (!received_full)
                    {
                        if (gStopFlag.load(std::memory_order_relaxed)) return;
                        received_full = true;
                        long long missing = 0;
                        for (auto lid = fromId; lid <= endId; lid++)
                        {
                            if (!checkLogExistAndVerify(gCurrentProcessingEpoch, lid))
                            {
                                received_full = false;
                                missing++;
                            }
                        }
                        if (received_full) break;
                        if (std::chrono::steady_clock::now() - waitStart > WAIT_BUDGET) {
                            Logger::get()->warn("rescue: log range {}=>{} for batch {}->{} still has {} missing ids after {}s; falling through to retry/escalation",
                                                fromId, endId, processFromTick, processToTick, missing,
                                                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - waitStart).count());
                            break;
                        }
                        SLEEP(100);
                    }
                    vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, processFromTick, processToTick, success);
                    if (vle.size() == length)
                    {
                        Logger::get()->info("Successfully refetch data log {} => {}", refetchFromId, refetchToId);
                        break;
                    }
                    Logger::get()->info("Failed to get data log for tick {}->{}: {} => {}", processFromTick, processToTick, refetchFromId, refetchToId);
                    Logger::get()->info("Expected {} but get {}", length, vle.size());
                    dataRefetchAttempts++;
                    // After a few rounds of refetching logs against the same
                    // metadata, the bad data is almost certainly the metadata
                    // itself (BM's tick_log_range maps an id to a tick that
                    // disagrees with the log content's packed-header tick).
                    // The atomic SETNX in db_insert_log_range makes that
                    // metadata permanent unless we wipe it explicitly. Wipe
                    // log_ranges + tick_log_range for the batch's ticks and
                    // re-run the outer refetch so a fresh BM response can
                    // produce a consistent mapping.
                    // Hard ceiling: if rescue churns for >120s without producing
                    // a clean batch, the data really isn't recoverable here.
                    // Bail to misalignment recovery (exit(1) → container
                    // restart), same as the digest-mismatch path. On reboot
                    // refetchFromId/refetchToId reset to -1, the main fetch
                    // resumes, and bob will reach this batch fresh.
                    if (std::chrono::steady_clock::now() - rescueStart > MAX_RESCUE_BUDGET) {
                        Logger::get()->critical("rescue: batch {}->{} has been stuck for >{}s and {} wipe rounds; triggering self-restart",
                                                processFromTick, processToTick,
                                                std::chrono::duration_cast<std::chrono::seconds>(MAX_RESCUE_BUDGET).count(),
                                                metadataWipeRounds);
                        Logger::get()->info("Forcing bob to exit (rescue ceiling)");
                        // Rewind one tick so the restarted bob doesn't get
                        // stuck on the same stale spectrum→bad-batch pairing.
                        if (processFromTick > 0) {
                            db_update_latest_event_tick_and_epoch(processFromTick - 1, gCurrentProcessingEpoch);
                        }
                        refetchFromId = -1;
                        refetchToId = -1;
                        exit(1);
                    }
                    if (dataRefetchAttempts >= 3)
                    {
                        metadataWipeRounds++;
                        Logger::get()->warn("rescue: log refetch keeps failing for batch {}->{} (wipe round {}); wiping per-tick log_ranges metadata and re-requesting from peers",
                                            processFromTick, processToTick, metadataWipeRounds);
                        for (uint32_t t = processFromTick; t <= processToTick; t++) {
                            db_delete_log_ranges(t);
                        }
                        // Re-prime the fetcher to re-request log_ranges, then
                        // wait until every tick has its range back (bounded).
                        refetchLogFromTick = processFromTick;
                        refetchLogToTick = processToTick;
                        const auto rangeWaitStart = std::chrono::steady_clock::now();
                        constexpr auto RANGE_WAIT_BUDGET = std::chrono::seconds(20);
                        bool received_full_ranges = false;
                        while (!received_full_ranges) {
                            received_full_ranges = true;
                            for (uint32_t t = processFromTick; t <= processToTick; t++) {
                                if (!db_check_log_range(t)) { received_full_ranges = false; break; }
                            }
                            if (received_full_ranges) break;
                            if (std::chrono::steady_clock::now() - rangeWaitStart > RANGE_WAIT_BUDGET) {
                                Logger::get()->warn("rescue: not all log_ranges for batch {}->{} returned within {}s of wipe round {}; proceeding anyway",
                                                    processFromTick, processToTick,
                                                    std::chrono::duration_cast<std::chrono::seconds>(RANGE_WAIT_BUDGET).count(),
                                                    metadataWipeRounds);
                                break;
                            }
                            SLEEP(100);
                            if (gStopFlag.load(std::memory_order_relaxed)) return;
                        }
                        refetchLogFromTick = -1;
                        refetchLogToTick = -1;
                        // Recompute fromId / length / endId from the fresh
                        // per-tick metadata; the new span may differ.
                        db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);
                        endId = (fromId >= 0 && length > 0) ? fromId + length - 1 : -1;
                        if (fromId < 0 || length <= 0) {
                            Logger::get()->warn("rescue: no usable log range for batch {}->{} after metadata refetch; will retry",
                                                processFromTick, processToTick);
                            SLEEP(1000);
                        }
                        dataRefetchAttempts = 0;
                    }
                }
                if (gStopFlag.load()) return;
                refetchFromId = -1;
                refetchToId = -1;
            }
        }

        // Per-tick audit: emit one BATCH_AUDIT line PER TICK in the batch, not
        // one for the whole batch. Batch boundaries vary between runs (verify
        // runs as soon as the fetcher has data), so a batch-level fingerprint
        // can't be compared across restarts when the splits don't align. A
        // per-tick fingerprint is always alignable on `tick=N`: grep for it
        // across two runs and any divergence proves the per-tick log content
        // differs between fetches.
        //
        // K12-hashing every log byte is the heavy diagnostic; gated behind
        // gDiagnosticMode so it's a single branch when off.
        if (gDiagnosticMode.load(std::memory_order_relaxed))
        {
            uint32_t curTick = 0;
            uint8_t acc[32] = {0};
            int countInTick = 0;
            auto emit = [&]() {
                if (countInTick == 0) return;
                char hex[17] = {0};
                for (int b = 0; b < 8; ++b) std::snprintf(hex + b*2, 3, "%02x", acc[b]);
                Logger::get()->trace("BATCH_AUDIT input: tick={} count={} hash={}",
                                    curTick, countInTick, hex);
                memset(acc, 0, 32);
                countInTick = 0;
            };
            for (auto& le : vle) {
                uint32_t t = le.getTick();
                if (t != curTick && countInTick > 0) emit();
                curTick = t;
                LogEvent& mut = const_cast<LogEvent&>(le);
                const uint8_t* p = mut.getRawPtr();
                size_t sz = LogEvent::PackedHeaderSize + le.getLogSize();
                if (!p || sz == 0) continue;
                // Fold this log into this tick's accumulator: acc = K12(acc || log_bytes)
                std::vector<uint8_t> buf;
                buf.reserve(32 + sz);
                buf.insert(buf.end(), acc, acc + 32);
                buf.insert(buf.end(), p, p + sz);
                KangarooTwelve(buf.data(), buf.size(), acc, 32);
                countInTick++;
            }
            emit();
            // Also include ticks in the batch that have NO logs at all (the
            // simulator processes nothing for them, but they still count as
            // verified). Each gets a sentinel audit line so comparison knows
            // they were considered.
            {
                std::set<uint32_t> seen;
                for (auto& le : vle) seen.insert(le.getTick());
                for (uint32_t t = processFromTick; t <= processToTick; t++) {
                    if (seen.find(t) == seen.end()) {
                        Logger::get()->trace("BATCH_AUDIT input: tick={} count=0 hash=0000000000000000", t);
                    }
                }
            }
        }

        LogEvent* ple = nullptr; // to solve the case of transferring ownership & possession, they go with pair
        LogEvent* ple1 = nullptr; // to solve the case of transferring management rights, they go with pair
        {
            PROFILE_SCOPE("simulating");
            for (int i = 0; i < vle.size(); i++)
            {
                auto& le  = vle[i];
                // If self-check fails, skip this entry and reset any pairing state to avoid
                // dereferencing invalid bodies or headers.
                if (!le.selfCheck(gCurrentProcessingEpoch))
                {
                    Logger::get()->critical("Failed selfCheck in logging event");
                    ple = nullptr;
                    ple1 = nullptr;
                    exit(2);
                }

                auto type = le.getType();
                switch(type)
                {
                    case QU_TRANSFER:
                        processQuTransfer(le);
                        break;
                    case ASSET_ISSUANCE:
                        processIssueAsset(le);
                        break;
                    case ASSET_OWNERSHIP_CHANGE:
                    case ASSET_POSSESSION_CHANGE:
                        if (ple)
                        {
                            processChangeOwnershipAndPossession(*ple, le);
                            ple = nullptr;
                        }
                        else
                        {
                            ple = &le;
                        }
                        break;
                    case ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE:
                    case ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE:
                        if (ple1)
                        {
                            processChangeManagingContract(*ple1, le);
                            ple1 = nullptr;
                        }
                        else
                        {
                            ple1 = &le;
                        }
                        break;
                    case BURNING:
                    {
                        processQuBurn(le);
                        break;
                    }
                    case CONTRACT_ERROR_MESSAGE:
                    case CONTRACT_WARNING_MESSAGE:
                    case CONTRACT_INFORMATION_MESSAGE:
                    case CONTRACT_DEBUG_MESSAGE:
                    {
                        auto data = le.getLogBodyPtr();
                        if (le.getLogSize() >= 8)
                        {
                            uint32_t scIndex, logType;
                            memcpy(&scIndex, data, 4);
                            memcpy(&logType, data + 4, 4);
                            if (scIndex == 4 && logType == QUTIL_STMB_LOG_TYPE)
                            {
                                // send to many benchmark, need to simulate
                                processSendToManyBenchmark(le);
                            }
                        }
                        break;
                    }
                    case SPECTRUM_STATS:
                    {
                        // nothing to do
                        break;
                    }
                    case DUST_BURNING:
                    {
                        // TODO: simulate and implement this
                        break;
                    }
                    case CUSTOM_MESSAGE:
                    {
                        uint64_t msg = le.getCustomMessage();
                        if (msg == CUSTOM_MESSAGE_OP_START_DISTRIBUTE_DIVIDENDS)
                        {
                            i += 1;
                            std::vector<LogEvent> dd;
                            while (msg != CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS && i < vle.size())
                            {
                                // Skip any malformed entries inside the dividend window as well.
                                if (!vle[i].selfCheck(gCurrentProcessingEpoch))
                                {
                                    Logger::get()->critical("Failed logEvent selfCheck in dividend window");
                                    i += 1;
                                    exit(2);
                                }

                                if (vle[i].getType() != 255)
                                {
                                    dd.push_back(vle[i]);
                                    i += 1;
                                }
                                else
                                {
                                    msg = vle[i].getCustomMessage();
                                    if (msg == CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS)
                                    {
                                        break;
                                    }
                                    else
                                    {
                                        Logger::get()->error("Expecting OP_END_DISTRIBUTE_DIVIDENDS, but received {}", msg);
                                        break;
                                    }
                                }
                            }
                            if (msg != CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS)
                            {
                                Logger::get()->critical("Missing OP END Distribute dividends");
                                exit(-1);
                            }
                            processDistributeDividends(dd);
                        }
                        if (msg == CUSTOM_MESSAGE_OP_END_EPOCH)
                        {
                            gIsEndEpoch = true;
                            lastQuorumTick = le.getTick() - 1;
                            Logger::get()->info("Detect END_EPOCH message at tick {}", le.getTick());
                            break;
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }

verifyNodeStateDigest:
            // Helper lambda to push verified logs to WebSocket subscribers.
            // Used for both regular verified batches and the final end-epoch batch.
            auto broadcastVerifiedLogs = [&]() {
                if (QubicSubscriptionManager::instance().getClientCount() == 0) return;
                try {
                    if (!vle.empty()) {
                        // Group logs by tick for proper ordering
                        uint32_t currentTick = 0;
                        std::vector<LogEvent> tickLogs;
                        for (const auto& log : vle) {
                            uint32_t logTick = log.getTick();
                            if (logTick != currentTick && !tickLogs.empty()) {
                                TickData td{0};
                                if (db_try_get_tick_data(currentTick, td)) {
                                    QubicSubscriptionManager::instance().onNewTick(currentTick, td);
                                    QubicSubscriptionManager::instance().onNewLogs(currentTick, tickLogs, td);
                                }
                                tickLogs.clear();
                            }
                            currentTick = logTick;
                            tickLogs.push_back(log);
                        }
                        if (!tickLogs.empty()) {
                            TickData td{0};
                            if (db_try_get_tick_data(currentTick, td)) {
                                QubicSubscriptionManager::instance().onNewTick(currentTick, td);
                                QubicSubscriptionManager::instance().onNewLogs(currentTick, tickLogs, td);
                            }
                        }
                    } else {
                        // No logs but we still need to notify newTicks subscribers
                        TickData td{0};
                        if (db_try_get_tick_data(processToTick, td)) {
                            QubicSubscriptionManager::instance().onNewTick(processToTick, td);
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::get()->warn("LoggingEventProcessor: WebSocket notification failed: {}", e.what());
                } catch (...) {
                    Logger::get()->warn("LoggingEventProcessor: WebSocket notification failed: unknown error");
                }
            };

            if (gIsEndEpoch) {
                // Broadcast the final batch (which contains the END_EPOCH log events)
                // to WebSocket subscribers before exiting the verification loop.
                broadcastVerifiedLogs();
                break;
            }
            while (processToTick >= gCurrentFetchingTick)
            {
            SLEEP(100); // need to wait until tick data and votes arrive
            if (gStopFlag.load(std::memory_order_relaxed)) return;
        }
        if (gStopFlag.load()) break;
        m256i spectrumDigest, universeDigest;
        std::vector<TickVote> votes;
        int voteCount = 0;
        bool hasTickData = false;
        bool matchedQuorum = false;
        int nonEmptyTick = 0;
        int emptyTick = 0;
        {
            PROFILE_SCOPE("computeDigests");
            computeSpectrumDigest(processFromTick, processToTick);
            spectrumDigest = spectrumDigests[(SPECTRUM_CAPACITY * 2 - 1) - 1];
            universeDigest = getUniverseDigest(processFromTick, processToTick);

            votes = db_try_to_get_votes(processToTick);
            //verifying spectrum and universe state
            voteCount = 0;
            m256i saltedDataSpectrum[2];
            m256i saltedDataUniverse[2];
            saltedDataSpectrum[1] = spectrumDigest;
            saltedDataUniverse[1] = universeDigest;

            for (auto& vote: votes)
            {
                if (vote.transactionDigest == m256i::zero()) emptyTick++;
                else nonEmptyTick++;
                if (vote.computorIndex >= NUMBER_OF_COMPUTORS) continue;
                saltedDataSpectrum[0] = computorsList.publicKeys[vote.computorIndex];
                saltedDataUniverse[0] = computorsList.publicKeys[vote.computorIndex];
                m256i salted;
                KangarooTwelve64To32(saltedDataSpectrum->m256i_u8, salted.m256i_u8);
                if (salted != vote.saltedSpectrumDigest) continue;
                KangarooTwelve64To32(saltedDataUniverse->m256i_u8, salted.m256i_u8);
                if (salted != vote.saltedUniverseDigest) continue;
                voteCount++;
            }
            if (emptyTick >= 226)
            {
                hasTickData = false;
            } else if (nonEmptyTick >= 451)
            {
                hasTickData = true;
            } else {
                Logger::get()->warn("Missing votes for tick {}. EmptyCount {} | NonEmptyCount {} | Total {}"
                                    " Trying to refetch it.", processToTick, emptyTick, nonEmptyTick, votes.size());
                refetchTickVotes = processToTick;
                SLEEP(1000);
                goto verifyNodeStateDigest;
            }
            if (hasTickData)
            {
                if (voteCount >= 451) matchedQuorum = true;
            }
            else
            {
                if (voteCount >= 226) matchedQuorum = true;
            }
        }

        // Output audit: emit bob's resulting digest pair regardless of match
        // outcome. Compare across crashes: same input_hash + same output
        // digests but different verify outcome = something downstream
        // (quorum vote arrival, vote validation) is racey. Same input_hash
        // + different output digests = simulation is non-deterministic.
        if (gDiagnosticMode.load(std::memory_order_relaxed))
        {
            char sdHex[17] = {0}, udHex[17] = {0};
            for (int b = 0; b < 8; ++b) {
                std::snprintf(sdHex + b*2, 3, "%02x", spectrumDigest.m256i_u8[b]);
                std::snprintf(udHex + b*2, 3, "%02x", universeDigest.m256i_u8[b]);
            }
            Logger::get()->trace("BATCH_AUDIT output: from={} to={} spectrum={} universe={} voteCount={} hasTickData={} matched={}",
                                processFromTick, processToTick,
                                sdHex, udHex, voteCount, hasTickData ? "yes" : "no",
                                matchedQuorum ? "yes" : "no");
        }

        if (!matchedQuorum)
        {
            Logger::get()->warn("Failed to verify digests at tick {} -> {}, please check!", processFromTick, processToTick);
            if (
                    (nonEmptyTick >= 451 )
                    || (emptyTick >= 226)
               )
            {
                // quorum already reach but not matched
                Logger::get()->critical("Misalignment states!!! Cleaning all potential malformed data and restarting bob");
                gStopFlag.store(true);
                SLEEP(1000);
                processToTick = gCurrentFetchingLogTick - 1;
                long long fromId, length;
                db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);
                auto endId = fromId + length - 1;
                for (uint32_t t = processFromTick; t <= processToTick; t++) db_delete_log_ranges(t);
                db_delete_logs_from_redis(gCurrentProcessingEpoch, fromId, endId);
                Logger::get()->info("Deleted all potential malformed data. Setting last fetched logging to {}", processFromTick-1);
                db_update_latest_event_tick_and_epoch(processFromTick-1, gCurrentProcessingEpoch);
                Logger::get()->warn("Forcing bob to exit");
                exit(1); // force exit because this is critical situation
            }
            else
            {
                Logger::get()->warn("Entering rescue mode to refetch votes for tick {}", processToTick);
                refetchTickVotes = processToTick;
                SLEEP(1000);
                goto verifyNodeStateDigest;
            }
        }
        else
        {
            Logger::get()->trace("Verified logging event tick {}->{}", processFromTick, processToTick);
            if (processToTick - lastVerifiedTick >= SAVE_PERIOD)
            {
                saveState(lastVerifiedTick, processToTick);
            }

            // Push verified logs to WebSocket subscribers (for logs/transfers subscriptions)
            // Note: tickStream subscriptions are notified from QubicIndexer after indexing
            // Wrapped in try-catch to ensure log verification continues even if notification fails
            broadcastVerifiedLogs();

            gCurrentVerifyLoggingTick = processToTick + 1;
        }
    }
    if (gIsEndEpoch)
    {
        Logger::get()->info("Reorg spectrum and universe...");
        reorganizeSpectrum();
        assetsEndEpoch();
        gCurrentVerifyLoggingTick = lastQuorumTick + 1;
        // begin epoch transition procedure
        uint16_t nextEpoch = gCurrentProcessingEpoch + 1;
        Logger::get()->info("Saving universe/spectrum for new epoch", nextEpoch);
        std::string tickSpectrum = "spectrum." + std::to_string(nextEpoch);
        std::string tickUniverse = "universe." + std::to_string(nextEpoch);

        FILE *f = fopen(tickSpectrum.c_str(), "wb");
        if (!f) {
            Logger::get()->error("Failed to open spectrum file for writing: {}", tickSpectrum);
        } else {
            if (fwrite(spectrum, sizeof(EntityRecord), SPECTRUM_CAPACITY, f) != SPECTRUM_CAPACITY) {
                Logger::get()->error("Failed to write spectrum file: {}", tickSpectrum);
            }
            fclose(f);
        }

        f = fopen(tickUniverse.c_str(), "wb");
        if (!f) {
            Logger::get()->error("Failed to open universe file for writing: {}", tickUniverse);
        } else {
            if (fwrite(assets, sizeof(AssetRecord), ASSETS_CAPACITY, f) != ASSETS_CAPACITY) {
                Logger::get()->error("Failed to write universe file: {}", tickUniverse);
            }
            fclose(f);
        }

        // exit all requesters
        // serve slower nodes 30 more minutes before officially switching epoch
        Logger::get()->info("Received END_EPOCH message. Serving 30 minutes and then closing BOB");

        std::string key = "end_epoch_tick:" + std::to_string(gCurrentProcessingEpoch);
        uint32_t endTick = lastQuorumTick + 1; // the system just "borrow" this tick index
        db_insert_u32(key, endTick);
        // copy log range struct
        db_copy("log_ranges:" + std::to_string(endTick), "end_epoch:log_ranges:"+std::to_string(gCurrentProcessingEpoch));
        // copy log range meta data per tick
        db_hcopy("tick_log_range:" + std::to_string(endTick), "end_epoch:tick_log_range:"+std::to_string(gCurrentProcessingEpoch));
        // end epoch tick is a virtual tick for logging, we set it back to lastQuorumTick
        db_update_field("db_status", "latest_event_tick", std::to_string(lastQuorumTick));
        db_insert_u32("verified_history:" + std::to_string(gCurrentProcessingEpoch), lastQuorumTick); // update historical tracker
        SLEEP(1000ULL * gTimeToWaitEpochEnd); // default: 30 minutes
        gStopFlag.store(true);
        // the endTick tick is a virtual tick, we need to migrate its data to new keys:
        // these operation are needed when it does seamless transition because in new epoch
        // the init tick will be the same as this end epoch tick
        db_rename("tick_log_range:" + std::to_string(endTick),
                  "backup_end_epoch:tick_log_range:"+std::to_string(gCurrentProcessingEpoch));
        db_rename("log_ranges:" + std::to_string(endTick),
                  "backup_end_epoch:log_ranges:"+std::to_string(gCurrentProcessingEpoch));
    }
    Logger::get()->info("verifyLoggingEvent stopping gracefully.");
}

// The logging fetcher thread from trusted nodes only (no signature require)
void EventRequestFromTrustedNode(ConnectionPool& connPoolWithPwd,
                                 uint64_t request_logging_cycle_ms,
                                 uint32_t future_offset)
{
    // 10ms is plenty for our 100ms+ request cycle and stops the loop from
    // burning CPU + flooding the log when nothing is happening.
    auto idleBackoff = 10;
    uint64_t lastRequestMs = 0;
    int64_t lastRequestLogid = -1;
    uint32_t stallTick = 0;
    uint64_t stallStartMs = 0;
    uint64_t lastStallLogMs = 0;

    // Per-range in-flight tracking. With gLogEventChunkSize pegged
    // to NUMBER_OF_TRANSACTIONS_PER_TICK (4096) each response is ~4 MB
    // and takes longer than `request_logging_cycle_ms` to arrive. A
    // naive "fire every cycle" loop would re-issue the same range many
    // times before the first response lands, wasting BM bandwidth.
    //
    // The ring tracks recently-fired (fromId, toId) pairs with their
    // fire-time. Before each smartLogRequest we check the ring: if the
    // exact range was fired within REFIRE_GUARD_MS we skip; otherwise
    // we fire and record. Different ranges fire independently, so
    // prefetch for tick N+1, N+2, … can run in parallel with tick N's
    // response still arriving.
    //
    // Broken-connection recovery: the chunk loop's existing
    // db_log_exists shrinking trims received ids out of the next
    // request, and after REFIRE_GUARD_MS the original (s, e) becomes
    // re-eligible — smartLogRequest's random BM pick will then route
    // to a different connection most of the time.
    // Sizing: with a 128-id chunk, a single tick fans out into 32 chunks,
    // and bob also fires for `future_offset` prefetch ticks per cycle. To
    // dedup *all* in-flight ranges (not just the most recent 16), the ring
    // has to hold the full burst — otherwise rotated-out slots cause
    // duplicate fires that flood the BM.
    struct InflightSlot { uint64_t fromId; uint64_t toId; uint64_t firedAtMs; };
    constexpr size_t INFLIGHT_SLOTS = 1024;
    constexpr uint64_t REFIRE_GUARD_MS = 400;
    std::array<InflightSlot, INFLIGHT_SLOTS> inflight{};

    auto tryFireLogRequest = [&](uint64_t s, uint64_t e, uint64_t nowMs) -> bool {
        // GC expired entries
        for (auto& sl : inflight) {
            if (sl.firedAtMs && nowMs - sl.firedAtMs >= REFIRE_GUARD_MS) sl.firedAtMs = 0;
        }
        // Dedup: skip if the same (s,e) is still within its guard window
        for (const auto& sl : inflight) {
            if (sl.firedAtMs && sl.fromId == s && sl.toId == e) return false;
        }
        // Insert into first empty slot, otherwise overwrite oldest
        size_t victim = 0; uint64_t oldest = UINT64_MAX;
        for (size_t i = 0; i < inflight.size(); ++i) {
            if (!inflight[i].firedAtMs) { victim = i; break; }
            if (inflight[i].firedAtMs < oldest) { oldest = inflight[i].firedAtMs; victim = i; }
        }
        inflight[victim] = { s, e, nowMs };
        RequestLog rl{{0,0,0,0}, s, e};
        std::string dest;
        connPoolWithPwd.smartLogRequest((uint8_t*)&rl, 0, sizeof(RequestLog),
                                        RequestLog::type(), true, &dest);
        gReqLog.fetch_add(1, std::memory_order_relaxed);
        Logger::get()->debug("Requested log {}=>{} to {}", s, e, dest.empty() ? "-" : dest);
        return true;
    };

    while (!gStopFlag.load(std::memory_order_relaxed)) {
        try {
            bool shouldRequestLogRange = false;
            bool shouldRequestLogEvent = false;
            uint64_t currentMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (currentMs - lastRequestMs > request_logging_cycle_ms)
            {
//                Logger::get()->debug("current {} last {} - cycle {}", currentMs, lastRequestMs, request_logging_cycle_ms);
                lastRequestMs = currentMs;
                shouldRequestLogRange = true;
                shouldRequestLogEvent = true;
            }
            while (refetchLogFromTick != -1 && refetchLogToTick != -1 && !gStopFlag.load(std::memory_order_relaxed))
            {
                for (uint32_t t = refetchLogFromTick; t <= refetchLogToTick; t++)
                {
                    if (!db_check_log_range(t))
                    {
                        RequestAllLogIdRangesFromTick ralr{{0,0,0,0},t};
                        connPoolWithPwd.smartLogRequest((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
                        gReqLogRanges.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                SLEEP(1000);
            }
            while (refetchFromId != -1 && refetchToId != -1 && !gStopFlag.load(std::memory_order_relaxed))
            {
                const uint64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                for (long long s = refetchFromId; s <= refetchToId; s += gLogEventChunkSize) {
                    long long e = std::min(refetchToId, s + gLogEventChunkSize - 1);
                    tryFireLogRequest((uint64_t)s, (uint64_t)e, nowMs);
                }
                SLEEP(1000);
            }
            // note: need this to allow bob to get the last virtual tick of END_EPOCH
            if (gCurrentFetchingLogTick >= (gCurrentFetchingTick+1))
            {
                SLEEP(100);
                continue;
            }
            if (gStopFlag.load(std::memory_order_relaxed)) break;

            if (!db_check_log_range(gCurrentFetchingLogTick))
            {
                if (shouldRequestLogRange)
                {
                    RequestAllLogIdRangesFromTick ralr{{0,0,0,0},gCurrentFetchingLogTick};
                    connPoolWithPwd.smartLogRequest((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
                        gReqLogRanges.fetch_add(1, std::memory_order_relaxed);
                    Logger::get()->debug("logFetch[{}]: requesting logRange (no summary yet)", gCurrentFetchingLogTick.load());
                }
                // else: cycle hasn't elapsed yet, nothing to do — silent, no log
            } else {
                long long fromId, length;
                if (!db_try_get_log_range_for_tick(gCurrentFetchingLogTick, fromId, length))
                {
                    // Two cases land here: (1) the per-tick summary hash was
                    // never written but the log_ranges blob exists, or (2)
                    // the summary was rejected as corrupt by the validator
                    // in db_try_get_log_range_for_tick. Try to regenerate
                    // from the source blob — but if the blob ALSO produces
                    // an out-of-range pair, both keys are bad: wipe them and
                    // let the next cycle re-request from peers.
                    Logger::get()->debug("logFetch[{}]: branch=missing-summary, regenerating tick_log_range", gCurrentFetchingLogTick.load());
                    LogRangesPerTxInTick logRange{};
                    db_try_get_log_ranges(gCurrentFetchingLogTick, logRange);
                    long long checkMin, checkMax;
                    logRange.getMinMax(checkMin, checkMax);
                    constexpr long long MAX_PLAUSIBLE_LEN = NUMBER_OF_TRANSACTIONS_PER_TICK * 1024LL;
                    bool blobIsBad = (checkMin < -1 || checkMax < -1)
                                   || (checkMin >= 0 && (checkMax < checkMin || (checkMax - checkMin) > MAX_PLAUSIBLE_LEN));
                    if (blobIsBad) {
                        Logger::get()->warn("logFetch[{}]: source log_ranges blob is also corrupt (min={} max={}); deleting and re-requesting from peers",
                                            gCurrentFetchingLogTick.load(), checkMin, checkMax);
                        db_delete_log_ranges(gCurrentFetchingLogTick);
                    } else {
                        db_insert_log_range(gCurrentFetchingLogTick, logRange);
                    }
                    continue;
                }
                if (fromId == -1 || length == -1)
                {
                    Logger::get()->debug("logFetch[{}]: branch=no-logs-this-tick, advancing", gCurrentFetchingLogTick.load());
                    gCurrentFetchingLogTick++;
                    continue;
                }
                long long origFromId = fromId;
                long long endId = fromId + length - 1; // inclusive
                while (db_log_exists(gCurrentProcessingEpoch, fromId) && fromId <= endId) fromId++;
                if (lastRequestLogid < fromId)
                {
                    shouldRequestLogEvent = true;
                    lastRequestLogid = fromId;
                }
                if (shouldRequestLogEvent)
                {
                    long long received = fromId - origFromId;
                    if (received < length) {
                        // Only log when there's actually something missing —
                        // i.e. when this cycle's request will fire chunks.
                        Logger::get()->debug("logFetch[{}]: have-range fromId={} len={} received={}/{} still missing={}",
                                             gCurrentFetchingLogTick.load(), origFromId, length, received, length, length - received);
                    }
                    for (long long s = fromId; s <= endId; s += gLogEventChunkSize) {
                        long long e = std::min(endId, s + gLogEventChunkSize - 1);
                        while (db_log_exists(gCurrentProcessingEpoch, e) && e >= fromId) e--;
                        if (e < s) continue; // e826c58 fix: skip fully-fetched chunk (was e < fromId)
                        tryFireLogRequest((uint64_t)s, (uint64_t)e, currentMs);
                    }
                }
                if (fromId > endId)
                {
                    Logger::get()->debug("logFetch[{}]: advancing (all {} ids received)", gCurrentFetchingLogTick.load(), length);
                    gCurrentFetchingLogTick++;
                    db_update_latest_event_tick_and_epoch(gCurrentFetchingLogTick, gCurrentProcessingEpoch);
                }
            }
            if (shouldRequestLogRange)
            {
                for (int i = 1; i < future_offset; i++)
                {
                    if (!db_check_log_range(gCurrentFetchingLogTick + i))
                    {
                        RequestAllLogIdRangesFromTick ralr{{0,0,0,0},gCurrentFetchingLogTick + i};
                        connPoolWithPwd.smartLogRequest((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
                        gReqLogRanges.fetch_add(1, std::memory_order_relaxed);
                        Logger::get()->debug("Requested logRange {}", gCurrentFetchingLogTick + i);
                    } else {
                        long long fromId, length;
                        if (!db_try_get_log_range_for_tick(gCurrentFetchingLogTick+ i, fromId, length)) continue;
                        if (fromId == -1 || length == -1) continue;
                        long long endId = fromId + length - 1; // inclusive
                        while (db_log_exists(gCurrentProcessingEpoch, fromId) && fromId <= endId) fromId++;
                        for (long long s = fromId; s <= endId; s += gLogEventChunkSize) {
                            long long e = std::min(endId, s + gLogEventChunkSize - 1);
                            while (db_log_exists(gCurrentProcessingEpoch, e) && e >= fromId) e--;
                            if (e < s) continue;
                            tryFireLogRequest((uint64_t)s, (uint64_t)e, currentMs);
                        }
                    }
                }
            }
            // Stall detection: log warning if stuck on the same tick for 30s
            uint32_t currentLogTick = gCurrentFetchingLogTick.load();
            if (currentLogTick != stallTick) {
                stallTick = currentLogTick;
                stallStartMs = currentMs;
                lastStallLogMs = 0;
            } else if (currentMs - stallStartMs >= 30000 && currentMs - lastStallLogMs >= 30000) {
                lastStallLogMs = currentMs;
                bool hasLogRange = db_check_log_range(currentLogTick);
                if (hasLogRange) {
                    long long fromId, length;
                    db_try_get_log_range_for_tick(currentLogTick, fromId, length);
                    long long endId = (fromId >= 0 && length > 0) ? fromId + length - 1 : -1;
                    long long missing = 0;
                    for (long long id = fromId; id <= endId; id++) {
                        if (!db_log_exists(gCurrentProcessingEpoch, id)) missing++;
                    }
                    Logger::get()->warn("FetchingLog stalled on tick {} for {}s: hasLogRange=true fromId={} endId={} missing={}/{}",
                                       currentLogTick, (currentMs - stallStartMs) / 1000, fromId, endId, missing, length);
                } else {
                    Logger::get()->warn("FetchingLog stalled on tick {} for {}s: hasLogRange=false (no peer responded with log range)",
                                       currentLogTick, (currentMs - stallStartMs) / 1000);
                }
            }

            SLEEP(idleBackoff);
        } catch (std::logic_error &ex) {

        }
    }

    Logger::get()->info("EventRequestFromTrustedNode stopping gracefully.");
}