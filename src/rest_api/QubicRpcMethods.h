#pragma once

#include <json/json.h>
#include <string>
#include "drogon/WebSocketConnection.h"

class QubicRpcMethods {
public:
    // ========================================================================
    // Chain Info Methods
    // ========================================================================

    // qubic_chainId - Returns chain identifier
    static Json::Value chainId();

    // qubic_clientVersion - Returns client version string
    static Json::Value clientVersion();

    // qubic_syncing - Returns sync status
    static Json::Value syncing();

    // qubic_status - Returns full node status (same as /status REST endpoint)
    static Json::Value status();

    // qubic_getCurrentEpoch - Returns current epoch number
    static Json::Value getCurrentEpoch();

    // ========================================================================
    // Tick Methods (replaces Block methods)
    // ========================================================================

    // qubic_getTickNumber - Returns latest verified tick number
    static Json::Value getTickNumber();

    // qubic_getTickByNumber - Returns tick data by tick number or tag
    // @param tickTag: "latest", "earliest", "pending", or numeric tick
    // @param includeTransactions: if true, include full transaction objects
    static Json::Value getTickByNumber(const std::string& tickTag, bool includeTransactions);

    // qubic_getTickByHash - Returns tick data by signature hash
    static Json::Value getTickByHash(const std::string& tickHash, bool includeTransactions);

    // ========================================================================
    // Transaction Methods
    // ========================================================================

    // qubic_getTransactionByHash - Returns transaction by hash (60-char Qubic hash or 0x hex)
    static Json::Value getTransactionByHash(const std::string& txHash);

    // qubic_getTransactionReceipt - Returns transaction receipt with logs
    static Json::Value getTransactionReceipt(const std::string& txHash);

    // qubic_broadcastTransaction - Broadcasts a signed transaction
    static Json::Value broadcastTransaction(const std::string& signedTxHex);

    // ========================================================================
    // Balance & Transfer Methods
    // ========================================================================

    // qubic_getBalance - Returns full balance info for an identity
    // @param identity: 60-char Qubic identity or 0x + 64 hex public key
    static Json::Value getBalance(const std::string& identity);

    // qubic_getTransfers - Returns transfers/logs matching filter criteria
    // Supports same filtering as findLog endpoint:
    // @param filterParams: JSON object with optional fields:
    //   - identity: identity to filter by (source/destination)
    //   - fromTick: starting tick number or tag
    //   - toTick: ending tick number or tag
    //   - scIndex: smart contract index (0 for protocol logs like QU_TRANSFER)
    //   - logType: log type filter (0=QU_TRANSFER, 1=ASSET_ISSUANCE, etc.)
    //   - topic1, topic2, topic3: identity filters for SC log data
    static Json::Value getTransfers(const Json::Value& filterParams);

    // ========================================================================
    // Asset Methods (Qubic-specific)
    // ========================================================================

    // qubic_getAssetBalance - Returns asset balance for an identity
    // @param identity: owner identity
    // @param issuer: asset issuer identity
    // @param assetName: asset name (up to 7 chars)
    static Json::Value getAssetBalance(const std::string& identity,
                                        const std::string& issuer,
                                        const std::string& assetName);

    // qubic_getAssets - Returns list of assets owned by identity
    // Note: This is a placeholder - requires asset indexing
    static Json::Value getAssets(const std::string& identity);

    // ========================================================================
    // Log/Event Methods
    // ========================================================================

    // qubic_getLogs - Returns logs matching filter
    static Json::Value getLogs(const Json::Value& filterParams);

    // qubic_findLogIds - Returns only log IDs matching filter (same as /findLog REST endpoint)
    // @param filterParams: JSON object with fields:
    //   - scIndex: smart contract index (required)
    //   - logType: log type (required)
    //   - topic1, topic2, topic3: identity filters
    //   - fromTick, toTick: tick range (required)
    // Returns: array of log IDs
    static Json::Value findLogIds(const Json::Value& filterParams);

    // qubic_getLogsByIdRange - Returns logs by ID range (same as /log REST endpoint)
    // @param epoch: epoch number
    // @param fromId: starting log ID (inclusive)
    // @param toId: ending log ID (inclusive)
    static Json::Value getLogsByIdRange(uint16_t epoch, int64_t fromId, int64_t toId);

    // ========================================================================
    // Epoch Methods
    // ========================================================================

    // qubic_getEpochInfo - Returns epoch info (tick range, log boundaries)
    // @param epoch: epoch number
    static Json::Value getEpochInfo(uint16_t epoch);

    // qubic_getEndEpochLogs - Returns end-of-epoch logs
    // @param epoch: epoch number
    static Json::Value getEndEpochLogs(uint16_t epoch);

    // qubic_getComputors - Returns computor list for an epoch
    // @param epoch: epoch number (optional, defaults to current epoch)
    // Returns: { "epoch": ..., "computors": [...identities] }
    static Json::Value getComputors(uint16_t epoch);

    // ========================================================================
    // Transfer History Methods
    // ========================================================================

    // qubic_getQuTransfers - Returns QU transfer history for an identity
    // @param filterParams: JSON object with fields:
    //   - identity: 60-char Qubic identity (required)
    //   - fromTick: starting tick number (required)
    //   - toTick: ending tick number (required, max range 1000)
    // Returns: { "in": [...txHashes], "out": [...txHashes] }
    static Json::Value getQuTransfers(const Json::Value& filterParams);

    // qubic_getAssetTransfers - Returns asset transfer history for an identity
    // @param filterParams: JSON object with fields:
    //   - identity: 60-char Qubic identity (required)
    //   - issuer: asset issuer identity (required)
    //   - assetName: asset name up to 7 chars (required)
    //   - fromTick: starting tick number (required)
    //   - toTick: ending tick number (required, max range 1000)
    // Returns: { "in": [...txHashes], "out": [...txHashes] }
    static Json::Value getAssetTransfers(const Json::Value& filterParams);

    // qubic_getAllAssetTransfers - Returns all transfers for a specific asset
    // @param filterParams: JSON object with fields:
    //   - issuer: asset issuer identity (required)
    //   - assetName: asset name up to 7 chars (required)
    //   - fromTick: starting tick number (required)
    //   - toTick: ending tick number (required, max range 1000)
    // Returns: array of transaction hashes
    static Json::Value getAllAssetTransfers(const Json::Value& filterParams);

    // ========================================================================
    // Smart Contract Methods
    // ========================================================================

    // qubic_querySmartContract - Query a smart contract function
    // @param params: JSON object with fields:
    //   - nonce: unique identifier for the query (required, uint32)
    //   - scIndex: smart contract index (required, uint32)
    //   - funcNumber: function number to call (required, uint32)
    //   - data: hex-encoded input data (required, with or without 0x prefix)
    // Returns: { "nonce": ..., "data": "..." } or { "pending": true, "nonce": ..., "message": "..." }
    static Json::Value querySmartContract(const Json::Value& params);

    // ========================================================================
    // Subscription Methods (WebSocket only)
    // ========================================================================

    // qubic_subscribe - Subscribe to events
    // @param subscriptionType: "newTicks", "logs", "transfers"
    static std::string subscribe(const drogon::WebSocketConnectionPtr& conn,
                                  const std::string& subscriptionType,
                                  const Json::Value& filterParams);

    // qubic_unsubscribe - Unsubscribe from events
    static bool unsubscribe(const drogon::WebSocketConnectionPtr& conn,
                             const std::string& subscriptionId);

    // Validates that identity is exactly 60 uppercase A-Z characters
    // Returns true if valid Qubic identity format (60 uppercase A-Z)
    static bool isValidIdentityFormat(const std::string& identity);

    // Validates identity input (accepts both Qubic identity and hex format)
    // Returns true if valid and can be normalized
    static bool isValidIdentityInput(const std::string& input);

private:

    // Helper to normalize identity input (accepts both Qubic identity and hex)
    // Returns empty string if validation fails
    static std::string normalizeIdentity(const std::string& input);

    // Helper to convert hex to Qubic identity
    static std::string hexToIdentity(const std::string& hex);

    // Helper to convert Qubic identity to hex
    static std::string identityToHex(const std::string& identity);
};
