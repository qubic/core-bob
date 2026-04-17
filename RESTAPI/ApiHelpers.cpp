#include "ApiHelpers.h"
#include "K12AndKeyUtil.h"
#include "Entity.h"
#include "Asset.h"
#include "GlobalVar.h"
#include "shim.h"
#include "database/db.h"
#include "structs.h"
#include "bob.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace ApiHelpers {

// ============================================================================
// Utility Functions
// ============================================================================

std::string bytesToHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string getIdentityStr(const uint8_t* publicKey, bool lowercase) {
    return getIdentity(publicKey, lowercase);
}

// ============================================================================
// Balance Functions
// ============================================================================

BalanceInfo getBalanceInfo(const std::string& identity) {
    BalanceInfo info;

    if (identity.size() < 60) {
        info.error = "Wrong identity format";
        return info;
    }

    m256i pk{};
    getPublicKeyFromIdentity(identity.data(), pk.m256i_u8);
    int index = spectrumIndex(pk);

    if (index < 0) {
        info.error = "Identity not found in spectrum";
        return info;
    }

    const auto& e = spectrum[index];
    info.found = true;
    info.incomingAmount = e.incomingAmount;
    info.outgoingAmount = e.outgoingAmount;
    info.balance = e.incomingAmount - e.outgoingAmount;
    info.numberOfIncomingTransfers = e.numberOfIncomingTransfers;
    info.numberOfOutgoingTransfers = e.numberOfOutgoingTransfers;
    info.latestIncomingTransferTick = e.latestIncomingTransferTick;
    info.latestOutgoingTransferTick = e.latestOutgoingTransferTick;
    info.currentTick = gCurrentVerifyLoggingTick.load() - 1;

    // Check if entity is being processed
    if (e.numberOfIncomingTransfers > info.currentTick ||
        e.numberOfOutgoingTransfers > info.currentTick) {
        info.isBeingProcessed = true;
    }

    return info;
}

// ============================================================================
// Asset Functions
// ============================================================================

AssetBalanceInfo getAssetBalanceInfo(const std::string& identity,
                                      const std::string& assetIssuer,
                                      const std::string& assetName,
                                      uint32_t manageSCIndex) {
    AssetBalanceInfo info;

    if (identity.size() < 60 || assetIssuer.size() < 60) {
        info.error = "Invalid identity format";
        return info;
    }

    m256i pk, issuer;
    uint64_t asset_name = 0;

    getPublicKeyFromIdentity(identity.c_str(), pk.m256i_u8);
    getPublicKeyFromIdentity(assetIssuer.c_str(), issuer.m256i_u8);
    memcpy(&asset_name, assetName.data(), std::min(size_t(7), assetName.size()));

    long long ownershipBalance, possessionBalance;
    getAssetBalances(pk, issuer, asset_name, manageSCIndex, ownershipBalance, possessionBalance);

    info.found = true;
    info.ownershipBalance = ownershipBalance;
    info.possessionBalance = possessionBalance;

    return info;
}

// ============================================================================
// Transaction Functions
// ============================================================================

namespace {

uint64_t tickDataToUnixMillis(const TickData& td) {
    std::tm timeinfo = {};
    timeinfo.tm_year = int(td.year) + 2000 - 1900;
    timeinfo.tm_mon  = td.month - 1;
    timeinfo.tm_mday = td.day;
    timeinfo.tm_hour = td.hour;
    timeinfo.tm_min  = td.minute;
    timeinfo.tm_sec  = td.second;
    timeinfo.tm_isdst = -1;
    time_t t = timegm(&timeinfo);
    return static_cast<uint64_t>(t) * 1000u + static_cast<uint64_t>(td.millisecond);
}

bool firstLogMatchesQuTransfer(const LogEvent& firstEvent, const Transaction& tx) {
    if (firstEvent.getType() != QU_TRANSFER) return true;
    // Protocol-report transactions (zero destination + protocol inputType) still
    // execute when any log is emitted — don't require the transfer to match.
    if (tx.destinationPublicKey == m256i::zero() &&
        (tx.inputType == 1 || tx.inputType == 2 || tx.inputType == 3 ||
         tx.inputType == 4 || tx.inputType == 5 || tx.inputType == 6 ||
         tx.inputType == 7 || tx.inputType == 8 || tx.inputType == 9 ||
         tx.inputType == 10)) {
        return true;
    }
    QuTransfer transfer{};
    memcpy(&transfer, firstEvent.getLogBodyPtr(), sizeof(QuTransfer));
    return transfer.sourcePublicKey == tx.sourcePublicKey &&
           transfer.destinationPublicKey == tx.destinationPublicKey &&
           transfer.amount == tx.amount;
}

} // namespace

TxExecutionDetails computeTxExecutionDetails(const std::string& txHash,
                                             const Transaction& tx,
                                             const TickData& td) {
    TxExecutionDetails out;

    if (td.tick != tx.tick) {
        return out;
    }

    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; ++i) {
        if (td.transactionDigests[i] == m256i::zero()) continue;
        if (td.transactionDigests[i].toQubicHash() == txHash) {
            out.transactionIndex = i;
            break;
        }
    }
    if (out.transactionIndex < 0) {
        return out;
    }

    out.resolved = true;
    out.timestamp = tickDataToUnixMillis(td) / 1000; // seconds, to match db_get_indexed_tx

    LogRangesPerTxInTick logrange{};
    if (!db_try_get_log_ranges(tx.tick, logrange)) {
        return out;
    }

    const long long from = logrange.fromLogId[out.transactionIndex];
    const long long length = logrange.length[out.transactionIndex];
    if (from < 0 || length <= 0) {
        return out;
    }
    out.fromLogId = from;
    out.toLogId   = from + length - 1;

    out.logs = db_try_get_logs(td.epoch, out.fromLogId, out.toLogId);
    if (out.logs.empty()) {
        return out;
    }

    out.executed = firstLogMatchesQuTransfer(out.logs.front(), tx);
    return out;
}

bool isTxExecuted(const Transaction& tx,
                  long long fromLogId,
                  long long length,
                  const std::vector<LogEvent>& tickLogs) {
    if (length <= 0 || fromLogId < 0) return false;

    // tickLogs is sorted by logId — find the first log for this tx.
    for (const auto& log : tickLogs) {
        if (static_cast<long long>(log.getLogId()) == fromLogId) {
            return firstLogMatchesQuTransfer(log, tx);
        }
    }
    return false;
}

TransactionInfo getTransactionInfo(const std::string& txHash) {
    TransactionInfo info;

    if (txHash.empty()) {
        info.error = "Invalid transaction hash";
        return info;
    }

    std::vector<uint8_t> txData;
    if (!db_try_get_transaction(txHash.c_str(), txData)) {
        info.error = "Transaction not found";
        return info;
    }

    Transaction* tx = reinterpret_cast<Transaction*>(txData.data());
    if (!tx) {
        info.error = "Invalid transaction data";
        return info;
    }

    info.found = true;
    info.hash = txHash;
    info.from = getIdentity(tx->sourcePublicKey, false);
    info.to = getIdentity(tx->destinationPublicKey, false);
    info.amount = tx->amount;
    info.tick = tx->tick;
    info.inputSize = tx->inputSize;
    info.inputType = tx->inputType;

    // Encode input data as hex
    if (tx->inputSize > 0) {
        const uint8_t* input = txData.data() + sizeof(Transaction);
        info.inputData = bytesToHex(input, tx->inputSize);
    }

    // Authoritative lookup: compute execution state directly from primary
    // data so the response is correct even when the itx: index was skipped
    // (e.g. dust txs filtered by spam-qu-threshold) or has not been written
    // for this tick yet.
    TickData td;
    if (db_try_get_tick_data(tx->tick, td)) {
        auto details = computeTxExecutionDetails(txHash, *tx, td);
        if (details.resolved) {
            info.hasIndexedInfo = true;
            info.transactionIndex = details.transactionIndex;
            info.logIdFrom = details.fromLogId;
            info.logIdTo = details.toLogId;
            info.timestamp = details.timestamp;
            info.executed = details.executed;
        }
    }

    return info;
}

// ============================================================================
// Epoch Functions
// ============================================================================

EpochInfo getEpochInfo(uint16_t epoch) {
    EpochInfo info;
    info.epoch = epoch;

    std::string es = std::to_string(epoch);

    uint32_t initTick = 0;
    db_get_u32("init_tick:" + es, initTick);
    info.initialTick = initTick;

    uint32_t endTick = 0;
    db_get_u32("end_epoch_tick:" + es, endTick);
    info.endTick = endTick;

    long long start = -1, length = -1;
    db_get_end_epoch_log_range(epoch, start, length);
    info.endTickStartLogId = start;
    info.endTickEndLogId = start + length - 1;

    uint32_t lastIndexedTick = 0;
    db_get_u32("lastIndexedTick:"+std::to_string(epoch), lastIndexedTick);
    info.lastIndexedTick = lastIndexedTick;

    if (epoch == gCurrentProcessingEpoch.load()) {
        info.latestLogId = db_get_latest_log_id(epoch);
    } else if (info.endTickEndLogId >= 0) {
        info.latestLogId = info.endTickEndLogId;
    }

    info.found = true;
    return info;
}

EpochInfo getCurrentEpochInfo() {
    uint16_t epoch = gCurrentProcessingEpoch.load();
    EpochInfo info = getEpochInfo(epoch);
    info.currentTick = gCurrentVerifyLoggingTick.load();
    return info;
}

// ============================================================================
// Sync Status Functions
// ============================================================================

SyncStatus getSyncStatus() {
    SyncStatus status;

    status.epoch = gCurrentProcessingEpoch.load();
    status.initialTick = gInitialTick.load();
    status.currentFetchingTick = gCurrentFetchingTick.load();
    status.currentFetchingLogTick = gCurrentFetchingLogTick.load();
    status.currentVerifyLoggingTick = gCurrentVerifyLoggingTick.load();
    status.currentIndexingTick = gCurrentIndexingTick.load();
    status.lastSeenNetworkTick = gLastSeenNetworkTick.load();

    // Determine sync status
    uint32_t verifyLoggingTick = status.currentVerifyLoggingTick;
    uint32_t fetchingTick = status.currentFetchingTick;
    uint32_t networkTick = status.lastSeenNetworkTick;

    bool isSynced;
    if (networkTick > 0) {
        // If we know the network tick, use it for sync determination
        isSynced = (networkTick <= verifyLoggingTick + 10);
    } else {
        // Fallback: compare internal pipeline stages
        isSynced = (fetchingTick <= verifyLoggingTick + 10);
    }

    status.isSyncing = !isSynced;

    if (status.isSyncing) {
        uint32_t targetTick = (networkTick > 0) ? networkTick : fetchingTick;
        uint32_t initialTick = status.initialTick;
        if (verifyLoggingTick > initialTick && targetTick > initialTick) {
            status.progress = static_cast<double>(verifyLoggingTick - initialTick) /
                              static_cast<double>(targetTick - initialTick);
        }
    }

    return status;
}

// ============================================================================
// Broadcast Transaction Functions
// ============================================================================

BroadcastResult broadcastTransaction(const std::string& signedTxHex) {
    BroadcastResult result;

    // Check if Bob has any connections to broadcast through
    if (gNumBMConnection == 0) {
        result.error = "Bob has no connection to any BM";
        return result;
    }

    // Strip 0x prefix if present
    std::string hex = signedTxHex;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex = hex.substr(2);
    }

    // Validate hex length is even
    if (hex.size() % 2 != 0) {
        result.error = "Hex data length must be even";
        return result;
    }

    // Validate all characters are hex
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            result.error = "Data must be a valid hex string";
            return result;
        }
    }

    // Convert hex to bytes with RequestResponseHeader prepended
    std::vector<uint8_t> txData;
    txData.resize(sizeof(RequestResponseHeader) + hex.length() / 2);

    auto hdr = reinterpret_cast<RequestResponseHeader*>(txData.data());
    hdr->setType(BROADCAST_TRANSACTION);
    hdr->zeroDejavu();
    hdr->setSize(txData.size());

    // Decode hex into transaction data (after header)
    for (size_t i = 0, count = 0; i < hex.length(); i += 2, count++) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        txData[sizeof(RequestResponseHeader) + count] = byte;
    }

    // Validate transaction structure
    auto tx = reinterpret_cast<Transaction*>(txData.data() + sizeof(RequestResponseHeader));
    size_t expectedSize = sizeof(RequestResponseHeader) + sizeof(Transaction) + tx->inputSize + SIGNATURE_SIZE;

    if (txData.size() != expectedSize) {
        result.error = "Invalid transaction size";
        return result;
    }

    // Verify signature
    m256i digest{};
    const uint8_t* signature = txData.data() + sizeof(RequestResponseHeader) + sizeof(Transaction) + tx->inputSize;
    size_t messageSize = txData.size() - sizeof(RequestResponseHeader) - SIGNATURE_SIZE;

    KangarooTwelve(reinterpret_cast<const uint8_t*>(tx), messageSize, digest.m256i_u8, 32);

    if (!verify(tx->sourcePublicKey, digest.m256i_u8, signature)) {
        result.error = "Invalid signature";
        return result;
    }

    // Enqueue for broadcast
    MRB_SC.EnqueuePacket(txData.data());

    // Calculate transaction hash (K12 of entire tx including signature)
    KangarooTwelve(reinterpret_cast<const uint8_t*>(tx), txData.size() - sizeof(RequestResponseHeader), digest.m256i_u8, 32);

    // Convert to Qubic identity format (60-char hash)
    char hash[64] = {0};
    getIdentityFromPublicKey(digest.m256i_u8, hash, true);

    result.success = true;
    result.txHash = std::string(hash);
    return result;
}

// ============================================================================
// Smart Contract Query Functions
// ============================================================================

// Helper to validate and parse hex input
static bool parseHexInput(const std::string& inputDataHex, std::vector<uint8_t>& dataBytes, std::string& error) {
    std::string hex = inputDataHex;

    // Strip 0x prefix if present
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex = hex.substr(2);
    }

    // Validate hex length is even
    if (hex.size() % 2 != 0) {
        error = "Data hex length must be even";
        return false;
    }

    // Validate all characters are hex
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            error = "Data must be a valid hex string";
            return false;
        }
    }

    // Convert hex to bytes
    dataBytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        dataBytes.push_back(byte);
    }

    return true;
}

m256i makeHashQuerySC(uint32_t scIndex, uint32_t funcNumber, const std::string& inputDataHex)
{
    m256i digest{};
    std::vector<uint8_t> nonceData;
    nonceData.reserve(sizeof(uint32_t) * 2 + inputDataHex.size());

    // Append scIndex and funcNumber
    nonceData.insert(nonceData.end(),
                     reinterpret_cast<uint8_t *>(&scIndex),
                     reinterpret_cast<uint8_t *>(&scIndex) + sizeof(uint32_t));
    nonceData.insert(nonceData.end(),
                     reinterpret_cast<uint8_t *>(&funcNumber),
                     reinterpret_cast<uint8_t *>(&funcNumber) + sizeof(uint32_t));

    // Append input hex data
    nonceData.insert(nonceData.end(), inputDataHex.begin(), inputDataHex.end());

    // Calculate K12 hash
    KangarooTwelve(nonceData.data(), nonceData.size(), digest.m256i_u8, 32);
    return digest;
}

SmartContractQueryResult checkSmartContractResult(uint32_t nonce, uint32_t scIndex,
                                                  uint32_t funcNumber, const std::string& inputDataHex)
{
    SmartContractQueryResult result;
    result.nonce = nonce;

    std::vector<uint8_t> out;
    if (responseSCData.get(nonce, out)) {
        result.success = true;
        result.data = bytesToHex(out.data(), out.size());

        m256i hash = ApiHelpers::makeHashQuerySC(scIndex, funcNumber, inputDataHex);
        gTCM->add(hash, out);
        return result;
    }

    {
        m256i digest{};
        digest = makeHashQuerySC(scIndex, funcNumber, inputDataHex);
        if (gTCM->tryGet(digest, out))
        {
            result.success = true;
            result.data = bytesToHex(out.data(), out.size());
            return result;
        }
    }
    result.success = false;
    result.data = "";
    result.pending = true;
    return result;
}

// Non-blocking enqueue: send a SC query and return immediately
bool enqueueSmartContractRequest(uint32_t nonce, uint32_t scIndex, uint32_t funcNumber, const uint8_t* data, uint32_t dataSize)
{
    std::vector<uint8_t> vdata(dataSize + sizeof(RequestContractFunction) + sizeof(RequestResponseHeader));
    RequestContractFunction rcf{};
    rcf.contractIndex = scIndex;
    rcf.inputSize = dataSize;
    rcf.inputType = funcNumber;

    auto header = (RequestResponseHeader*)vdata.data();
    header->setType(RequestContractFunction::type);
    header->setSize(dataSize + sizeof(RequestResponseHeader) + sizeof(RequestContractFunction));
    header->setDejavu(nonce);

    memcpy(vdata.data() + sizeof(RequestResponseHeader), &rcf, sizeof(RequestResponseHeader));
    if (dataSize)
        memcpy(vdata.data() + sizeof(RequestResponseHeader) + sizeof(RequestContractFunction), data, dataSize);

    // fire-and-forget to SC thread
    return MRB_SC.EnqueuePacket(vdata.data());
}

SmartContractQueryResult querySmartContract(uint32_t nonce, uint32_t scIndex,
                                             uint32_t funcNumber, const std::string& inputDataHex) {
    SmartContractQueryResult result;
    result.nonce = nonce;

    // Check if Bob has any connections
    if (gNumBMConnection == 0) {
        result.error = "Bob has no connection to any BM";
        return result;
    }

    result = checkSmartContractResult(nonce, scIndex, funcNumber, inputDataHex);
    if (result.success)
    {
        return result;
    }

    // Parse input data
    std::vector<uint8_t> dataBytes;
    if (!parseHexInput(inputDataHex, dataBytes, result.error)) {
        return result;
    }

    // Enqueue the request
    enqueueSmartContractRequest(nonce, scIndex, funcNumber, dataBytes.data(),
                                 static_cast<uint32_t>(dataBytes.size()));

    // Return pending status
    result.pending = true;
    return result;
}

} // namespace ApiHelpers
