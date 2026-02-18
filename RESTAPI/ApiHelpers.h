#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <vector>
#include "Entity.h"

// ============================================================================
// Shared Data Structures for API responses
// ============================================================================

struct BalanceInfo {
    int64_t incomingAmount = 0;
    int64_t outgoingAmount = 0;
    int64_t balance = 0;
    uint32_t numberOfIncomingTransfers = 0;
    uint32_t numberOfOutgoingTransfers = 0;
    uint32_t latestIncomingTransferTick = 0;
    uint32_t latestOutgoingTransferTick = 0;
    uint32_t currentTick = 0;
    bool isBeingProcessed = false;
    bool found = false;
    std::string error;
};

struct AssetBalanceInfo {
    int64_t ownershipBalance = 0;
    int64_t possessionBalance = 0;
    bool found = false;
    std::string error;
};

struct TransactionInfo {
    std::string hash;
    std::string from;
    std::string to;
    int64_t amount = 0;
    uint32_t tick = 0;
    uint16_t inputSize = 0;
    uint16_t inputType = 0;
    std::string inputData;  // hex encoded

    // Indexed info (may not be available)
    bool hasIndexedInfo = false;
    int transactionIndex = -1;
    int64_t logIdFrom = -1;
    int64_t logIdTo = -1;
    uint64_t timestamp = 0;
    bool executed = false;

    bool found = false;
    std::string error;
};

struct EpochInfo {
    uint16_t epoch = 0;
    uint32_t initialTick = 0;
    uint32_t endTick = 0;
    int64_t endTickStartLogId = -1;
    int64_t endTickEndLogId = -1;
    int64_t latestLogId = -1;
    uint32_t currentTick = 0;
    uint32_t lastIndexedTick = 0;
    bool found = false;
    std::string error;
};

struct SyncStatus {
    uint16_t epoch = 0;
    uint32_t initialTick = 0;
    uint32_t currentFetchingTick = 0;
    uint32_t currentFetchingLogTick = 0;
    uint32_t currentVerifyLoggingTick = 0;
    uint32_t currentIndexingTick = 0;
    uint32_t lastSeenNetworkTick = 0;  // 0 = unknown
    bool isSyncing = false;
    double progress = 0.0;
};

struct BroadcastResult {
    bool success = false;
    std::string txHash;      // Transaction hash (60-char Qubic format) on success
    std::string error;       // Error message on failure
};

struct SmartContractQueryResult {
    bool success = false;
    bool pending = false;    // True if query was enqueued but result not yet available
    uint32_t nonce = 0;
    std::string data;        // hex-encoded response data
    std::string error;
};

// ============================================================================
// Shared Helper Functions (Core Logic)
// ============================================================================

namespace ApiHelpers {

// Get balance information for an identity (60-char Qubic format)
BalanceInfo getBalanceInfo(const std::string& identity);

// Get asset balance for an identity
AssetBalanceInfo getAssetBalanceInfo(const std::string& identity,
                                      const std::string& assetIssuer,
                                      const std::string& assetName,
                                      uint32_t manageSCIndex = 0);

// Get transaction by hash (60-char Qubic format)
TransactionInfo getTransactionInfo(const std::string& txHash);

// Get epoch information
EpochInfo getEpochInfo(uint16_t epoch);

// Get current epoch info
EpochInfo getCurrentEpochInfo();

// Get sync status
SyncStatus getSyncStatus();

// Broadcast a signed transaction
// @param signedTxHex: hex-encoded signed transaction (with or without 0x prefix)
// @return BroadcastResult with txHash on success, error message on failure
BroadcastResult broadcastTransaction(const std::string& signedTxHex);

// Query a smart contract (synchronous - checks cache only)
// @param nonce: unique identifier for this query (used for caching)
// @param scIndex: smart contract index
// @param funcNumber: function number to call
// @param inputDataHex: hex-encoded input data (with or without 0x prefix)
// @return SmartContractQueryResult with response data or pending status
SmartContractQueryResult querySmartContract(uint32_t nonce, uint32_t scIndex,
                                             uint32_t funcNumber, const std::string& inputDataHex);

// Check if a smart contract query result is available (by nonce)
// @param nonce: unique identifier for the query
// @return SmartContractQueryResult with response data if available
SmartContractQueryResult checkSmartContractResult(uint32_t nonce, uint32_t scIndex,
                                                  uint32_t funcNumber, const std::string& inputDataHex);

// @return K12 of scIndex funcNumber and inputDataHex
m256i makeHashQuerySC(uint32_t scIndex, uint32_t funcNumber, const std::string& inputDataHex);
// ============================================================================
// Utility Functions
// ============================================================================

// Convert bytes to hex string
std::string bytesToHex(const uint8_t* data, size_t length);

// Get identity string from public key bytes
std::string getIdentityStr(const uint8_t* publicKey, bool lowercase = false);

} // namespace ApiHelpers
