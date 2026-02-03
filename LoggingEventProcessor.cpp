#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <cstring>
#include "m256i.h"
#include "connection/connection.h"
#include "structs.h"
#include "GlobalVar.h"
#include "Logger.h"
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
#include "RESTAPI/LogSubscriptionManager.h"
#include "RESTAPI/QubicSubscriptionManager.h"

using namespace std::chrono_literals;
extern "C" {
    // declare for xkcp
int KT128(const unsigned char *input, size_t inputByteLen,
          unsigned char *output, size_t outputByteLen,
          const unsigned char *customization, size_t customByteLen);
}

static void KangarooTwelve64To32(void* input, void* output)
{
//    KT128((uint8_t*)input, 64, (uint8_t*)output, 32, nullptr, 0);
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

void processQuTransfer(LogEvent& le)
{
    QuTransfer qt;
    memcpy((void*)&qt, le.getLogBodyPtr(), sizeof(QuTransfer));
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx != -1)
    {
        if (!decreaseEnergy(src_idx, qt.amount, le.getTick()))
        {
            Logger::get()->critical("QUs transfer: Failed to decrease energy");
        }
    }
    else
    {
        if (qt.sourcePublicKey != m256i::zero()){
            Logger::get()->critical("QUs transfer has invalid source index");
        }
    }
    increaseEnergy(qt.destinationPublicKey, qt.amount, le.getTick());
}

bool processDistributeDividends(std::vector<LogEvent>& vle)
{
    if (vle.size() == 0) return true;
    // sanity check
    for (auto& le : vle)
    {
        if (le.getType() != QU_TRANSFER) return false;
    }
    QuTransfer qt;
    memcpy((void*)&qt, vle[0].getLogBodyPtr(), sizeof(QuTransfer));
    auto src_id = qt.sourcePublicKey;
    long long total = 0;
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        if (qt1.sourcePublicKey != qt.sourcePublicKey) return false;
        total += qt1.amount;
    }
    auto src_idx = spectrumIndex(qt.sourcePublicKey);
    if (src_idx == -1) return false;
    decreaseEnergy(src_idx, total, vle[0].getTick());
    for (auto& le : vle)
    {
        QuTransfer qt1;
        memcpy((void*)&qt1, le.getLogBodyPtr(), sizeof(QuTransfer));
        increaseEnergy(qt1.destinationPublicKey, qt1.amount, vle[0].getTick());
    }
    return true;
}

void processQuBurn(LogEvent& le)
{
    Burning b;
    memcpy((void*)&b, le.getLogBodyPtr(), sizeof(Burning));
    auto src_idx = spectrumIndex(b.sourcePublicKey);
    if (src_idx != -1) decreaseEnergy(src_idx, b.amount, le.getTick());
}

void processIssueAsset(LogEvent& le)
{
    AssetIssuance ai;
    memcpy((void*)&ai, le.getLogBodyPtr(), sizeof(AssetIssuance));
    int issuanceIndex, ownershipIndex, possessionIndex;
    issueAsset(ai.issuerPublicKey, ai.name, ai.numberOfDecimalPlaces, ai.unitOfMeasurement, ai.numberOfShares, ai.managingContractIndex,
               &issuanceIndex, &ownershipIndex, &possessionIndex);
}

// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeOwnershipAndPossession(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_CHANGE) && (le1.getType() == ASSET_POSSESSION_CHANGE)) || ((le1.getType() == ASSET_OWNERSHIP_CHANGE) && (le0.getType() == ASSET_POSSESSION_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipChange aoc{};
    AssetPossessionChange apc{};
    memcpy((void*)&aoc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipChange));
    memcpy((void*)&apc, possession.getLogBodyPtr(), sizeof(AssetPossessionChange));
    if (memcmp(&aoc, &apc, sizeof(AssetOwnershipChange)) != 0)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, aoc.name, 7);
    transferShareOwnershipAndPossession(assetName, aoc.issuerPublicKey, aoc.sourcePublicKey, aoc.sourcePublicKey, aoc.numberOfShares, aoc.managingContractIndex, aoc.destinationPublicKey);
}

// this is currently go with a pair Possession & Ownership
// need to update when the core changes ie: only transfer either Possession or Ownership
void processChangeManagingContract(LogEvent& le0, LogEvent& le1)
{
    // sanity check
    bool valid = true;
    valid &= ((le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le1.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE))
            || ((le1.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE) && (le0.getType() == ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE));
    if (!valid)
    {
        Logger::get()->error("Invalid pair Possession or Ownership");
        exit(1);
    }
    LogEvent ownership, possession;
    if (le0.getType() == ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE)
    {
        ownership = le0;
        possession = le1;
    }
    else
    {
        ownership = le1;
        possession = le0;
    }
    AssetOwnershipManagingContractChange omcc{};
    AssetPossessionManagingContractChange pmcc{};
    memcpy((void*)&omcc, ownership.getLogBodyPtr(), sizeof(AssetOwnershipManagingContractChange));
    memcpy((void*)&pmcc, possession.getLogBodyPtr(), sizeof(AssetPossessionManagingContractChange));
    if (omcc.ownershipPublicKey != pmcc.ownershipPublicKey ||
            (memcmp(omcc.assetName, pmcc.assetName, 7) != 0) ||
            (omcc.numberOfShares != pmcc.numberOfShares) ||
            (omcc.sourceContractIndex != pmcc.sourceContractIndex) ||
            (omcc.destinationContractIndex != pmcc.destinationContractIndex)
        )
    {
        Logger::get()->error("Invalid pair Possession or Ownership in transfering management rights");
        exit(1);
    }
    uint64_t assetName = 0;
    memcpy((void*)&assetName, omcc.assetName, 7);
    long long nshare = omcc.numberOfShares;
    auto issuer = omcc.issuerPublicKey;
    auto owner = omcc.ownershipPublicKey;
    auto poss = pmcc.possessionPublicKey;
    auto src_id = omcc.sourceContractIndex;
    auto dst_id = omcc.destinationContractIndex;
    int issuanceIndex, ownershipIndex, possessionIndex;
    findIssuerIndex(issuer, assetName, &issuanceIndex);
    findOwnershipIndex(issuanceIndex, owner, src_id, &ownershipIndex);
    findPossessionIndex(ownershipIndex, poss, src_id, &possessionIndex);
    int destinationOwnershipIndexPtr, destinationPossessionIndexPtr;
    if (!transferShareManagementRights(ownershipIndex, possessionIndex, dst_id, dst_id, nshare,
                                  &destinationOwnershipIndexPtr, &destinationPossessionIndexPtr, false))
    {
        Logger::get()->error("Failed to transfer management rights");
        exit(1);
    }
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
        uint32_t processToTick = std::min(gCurrentVerifyLoggingTick + BATCH_VERIFICATION, gCurrentFetchingLogTick - 1);
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
                    Logger::get()->info("Detect end epoch at tick {}. Setting last batch to {}->{}", tick, processFromTick, processToTick);
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
                    if (!received_full) SLEEP(100);
                    if (gStopFlag.load(std::memory_order_relaxed)) return;
                }
                refetchLogFromTick = -1;
                refetchLogToTick = -1;
                Logger::get()->info("Successfully refetched all log ranges");
                db_get_combined_log_range_for_ticks(processFromTick, processToTick, fromId, length);
                Logger::get()->info("New log range for tick {}->{} : logID {}->{}", processFromTick, processToTick, fromId, fromId+length-1);

                auto endId = fromId + length - 1;
                while (!gStopFlag.load())
                {
                    db_delete_logs(gCurrentProcessingEpoch, fromId, endId);
                    refetchFromId = fromId;
                    refetchToId = endId;
                    Logger::get()->info("Deleted malformed log, waiting for new data");
                    bool received_full = false;
                    while (!received_full)
                    {
                        received_full = true;
                        for (auto lid = fromId; lid <= endId; lid++)
                        {
                            if (!checkLogExistAndVerify(gCurrentProcessingEpoch, lid))
                            {
                                received_full = false;
                                break;
                            }
                        }
                        if (!received_full) SLEEP(100);
                    }
                    vle = db_get_logs_by_tick_range(gCurrentProcessingEpoch, processFromTick, processToTick, success);
                    if (vle.size() == length)
                    {
                        Logger::get()->info("Successfully refetch data log {} => {}", refetchFromId, refetchToId);
                        break;
                    }
                    else
                    {
                        Logger::get()->info("Failed to get data log for tick {}->{}: {} => {}", processFromTick, processToTick, refetchFromId, refetchToId);
                        Logger::get()->info("Expected {} but get {}", length, vle.size());
                    }
                }
                if (gStopFlag.load()) return;
                refetchFromId = -1;
                refetchToId = -1;
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
                    case SPECTRUM_STATS:
                        // nothing to do
                        break;
                    case DUST_BURNING:
                        // TODO: simulate and implement this
                        break;
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
                            Logger::get()->info("Detect END_EPOCH message at tick {}", lastQuorumTick);
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
        if (gIsEndEpoch) break;
        while (gCurrentVerifyLoggingTick == gCurrentFetchingTick)
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
                db_delete_logs(gCurrentProcessingEpoch, fromId, endId);
                Logger::get()->info("Deleted all potential malformed data. Setting last fetched logging to {}", processFromTick-1);
                db_update_latest_event_tick_and_epoch(processFromTick-1, gCurrentProcessingEpoch);
                break;
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
            bool hasLogSubClients = LogSubscriptionManager::instance().getClientCount() > 0;
            bool hasQubicSubClients = QubicSubscriptionManager::instance().getClientCount() > 0;

            if (hasLogSubClients || hasQubicSubClients) {
                try {
                    if (!vle.empty()) {
                        // Group logs by tick for proper ordering
                        uint32_t currentTick = 0;
                        std::vector<LogEvent> tickLogs;
                        for (const auto& log : vle) {
                            uint32_t logTick = log.getTick();
                            if (logTick != currentTick && !tickLogs.empty()) {
                                LogSubscriptionManager::instance().pushVerifiedLogs(currentTick, gCurrentProcessingEpoch, tickLogs);
                                tickLogs.clear();
                            }
                            currentTick = logTick;
                            tickLogs.push_back(log);
                        }
                        if (!tickLogs.empty()) {
                            LogSubscriptionManager::instance().pushVerifiedLogs(currentTick, gCurrentProcessingEpoch, tickLogs);
                        }
                    } else if (hasQubicSubClients) {
                        // No logs but we still need to notify newTicks subscribers
                        // Call with empty logs for processToTick
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
            }

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
        SLEEP(1000ULL * gTimeToWaitEpochEnd); // 30 minutes
        gStopFlag.store(true);
        // the endTick tick is a virtual tick, we need to migrate its data to new keys:
        uint32_t endTick = lastQuorumTick + 1; // the system just "borrow" this tick index

        db_rename("tick_log_range:" + std::to_string(endTick),
                      "end_epoch:tick_log_range:"+std::to_string(gCurrentProcessingEpoch));
        db_rename("log_ranges:" + std::to_string(endTick),
                      "end_epoch:log_ranges:"+std::to_string(gCurrentProcessingEpoch));
        std::string key = "end_epoch_tick:" + std::to_string(gCurrentProcessingEpoch);
        db_insert_u32(key, endTick);
        // end epoch tick is a virtual tick for logging, we set it back to lastQuorumTick
        db_update_field("db_status", "latest_event_tick", std::to_string(lastQuorumTick));
        db_insert_u32("verified_history:" + std::to_string(gCurrentProcessingEpoch), lastQuorumTick); // update historical tracker
    }
    Logger::get()->info("verifyLoggingEvent stopping gracefully.");
}

// The logging fetcher thread from trusted nodes only (no signature require)
void EventRequestFromTrustedNode(ConnectionPool& connPoolWithPwd,
                                 std::chrono::milliseconds request_logging_cycle_ms)
{
    auto idleBackoff = request_logging_cycle_ms;

    while (!gStopFlag.load(std::memory_order_relaxed)) {
        try {
            while (refetchLogFromTick != -1 && refetchLogToTick != -1 && !gStopFlag.load(std::memory_order_relaxed))
            {
                for (uint32_t t = refetchLogFromTick; t <= refetchLogToTick; t++)
                {
                    if (!db_check_log_range(t))
                    {
                        RequestAllLogIdRangesFromTick ralr{{0,0,0,0},t};
                        connPoolWithPwd.sendWithPasscodeToRandom((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
                    }
                }
                SLEEP(1000);
            }
            while (refetchFromId != -1 && refetchToId != -1 && !gStopFlag.load(std::memory_order_relaxed))
            {
                for (long long s = refetchFromId; s <= refetchToId; s += BOB_LOG_EVENT_CHUNK_SIZE) {
                    long long e = std::min(refetchToId, s + BOB_LOG_EVENT_CHUNK_SIZE - 1);
                    RequestLog rl{{0,0,0,0},(unsigned long long)(s),(unsigned long long)(e)};
                    connPoolWithPwd.sendWithPasscodeToRandom((uint8_t *) &rl, 0, sizeof(RequestLog), RequestLog::type(), true);
                }
                SLEEP(1000);
            }
            if (gCurrentFetchingLogTick >= (gCurrentFetchingTick+1))
            {
                SLEEP(100);
                continue;
            }
            if (gStopFlag.load(std::memory_order_relaxed)) break;
            if (!db_check_log_range(gCurrentFetchingLogTick))
            {
                RequestAllLogIdRangesFromTick ralr{{0,0,0,0},gCurrentFetchingLogTick};
                connPoolWithPwd.sendWithPasscodeToRandom((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
            } else {
                long long fromId, length;
                if (!db_try_get_log_range_for_tick(gCurrentFetchingLogTick, fromId, length)) continue;
                if (fromId == -1 || length == -1)
                {
                    Logger::get()->trace("Tick {} doesn't generate any log. Advancing logEvent tick", gCurrentFetchingLogTick);
                    gCurrentFetchingLogTick++;
                    continue;
                }
                long long endId = fromId + length - 1; // inclusive
                while (db_log_exists(gCurrentProcessingEpoch, fromId) && fromId <= endId)
                {
                    fromId++;
                }
                for (long long s = fromId; s <= endId; s += BOB_LOG_EVENT_CHUNK_SIZE) {
                    long long e = std::min(endId, s + BOB_LOG_EVENT_CHUNK_SIZE - 1);
                    RequestLog rl{{0,0,0,0},(unsigned long long)(s),(unsigned long long)(e)};
                    connPoolWithPwd.sendWithPasscodeToRandom((uint8_t *) &rl, 0, sizeof(RequestLog), RequestLog::type(), true);
                }
                if (fromId > endId)
                {
                    Logger::get()->trace("Advancing logEvent tick {}", gCurrentFetchingLogTick);
                    gCurrentFetchingLogTick++;
                    db_update_latest_event_tick_and_epoch(gCurrentFetchingLogTick, gCurrentProcessingEpoch);
                }
            }
            for (int i = 1; i < 5; i++)
            {
                if (!db_check_log_range(gCurrentFetchingLogTick + i))
                {
                    RequestAllLogIdRangesFromTick ralr{{0,0,0,0},gCurrentFetchingLogTick + i};
                    connPoolWithPwd.sendWithPasscodeToRandom((uint8_t*)&ralr, 0, sizeof(RequestAllLogIdRangesFromTick), RequestAllLogIdRangesFromTick::type(), true);
                }
            }
            SLEEP(idleBackoff);
        } catch (std::logic_error &ex) {

        }
    }

    Logger::get()->info("EventRequestFromTrustedNode stopping gracefully.");
}