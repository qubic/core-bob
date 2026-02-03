#include "ApiHelpers.h"
#include "src/bob.h"
#include "src/core/asset.h"
#include "src/core/entity.h"
#include "src/core/k12_and_key_util.h"
#include "src/core/structs.h"
#include "src/database/db.h"
#include "src/shim.h"

#include <cstring>
#include <iomanip>
#include <sstream>

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

    // Try to get indexed information
    int tx_index;
    long long from_log_id, to_log_id;
    uint64_t timestamp;
    bool executed;

    if (db_get_indexed_tx(txHash.c_str(), tx_index, from_log_id, to_log_id, timestamp, executed)) {
        info.hasIndexedInfo = true;
        info.transactionIndex = tx_index;
        info.logIdFrom = from_log_id;
        info.logIdTo = to_log_id;
        info.timestamp = timestamp;
        info.executed = executed;
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
    } else {
        result.pending = true;
    }

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

    // Check cache first
    std::vector<uint8_t> out;
    if (responseSCData.get(nonce, out)) {
        result.success = true;
        result.data = bytesToHex(out.data(), out.size());
        return result;
    }

    // cache level 2
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
