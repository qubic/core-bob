#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <atomic>
#include <optional>
#include "drogon/WebSocketConnection.h"
#include "LogEvent.h"
#include "structs.h"

// Subscription types for Qubic API
enum class QubicSubscriptionType {
    NewTicks,    // New tick notifications
    Logs,        // Log events matching filter
    Transfers,   // QU transfer events (specialized log filter)
    TickStream   // Full tick stream with transactions and logs
};

// Log filter for subscriptions (used by Logs/Transfers subscriptions)
struct LogFilter {
    std::optional<uint32_t> fromTick;
    std::optional<uint32_t> toTick;
    std::vector<std::string> identities;  // Filter by source or destination identity
    std::vector<uint32_t> logTypes;       // Filter by log type
    // Catch-up parameters
    std::optional<int64_t> startLogId;    // Start from this log ID for catch-up
    std::optional<uint16_t> startEpoch;   // Epoch for startLogId (default: current)
};

// Pending log for catch-up queue
struct PendingLogEvent {
    LogEvent log;
    std::string sourceIdentity;
    std::string destIdentity;
};

// Transaction filter for TickStream subscriptions
struct TxFilter {
    std::string from;           // Source identity (empty = any)
    std::string to;             // Destination identity (empty = any)
    int64_t minAmount{0};       // Minimum amount filter
    int16_t inputType{-1};      // Input type filter (-1 = any)
};

// Log filter for TickStream subscriptions
struct LogStreamFilter {
    uint32_t scIndex{0};        // Smart contract index
    uint32_t logType{0};        // Log type
    int64_t transferMinAmount{0}; // Min amount for QU_TRANSFER events
};

// TickStream subscription filter
struct TickStreamFilter {
    std::vector<TxFilter> txFilters;
    std::vector<LogStreamFilter> logFilters;
    bool skipEmptyTicks{false};   // If true, skip ticks with no matches (except every 120 ticks)
    bool includeInputData{true};  // Include full inputData in transactions
    bool excludeTxs{false};       // If true, exclude all transactions from output
    bool excludeLogs{false};      // If true, exclude all logs from output
};

// Transaction data for streaming
struct StreamTx {
    std::string hash;
    std::string from;
    std::string to;
    int64_t amount;
    uint16_t inputType;
    uint16_t inputSize;
    std::vector<uint8_t> inputData;
    bool executed;
    int64_t logIdFrom;
    int64_t logIdLength;
};

// Pending tick data for catch-up queue
struct PendingTickData {
    uint32_t tick;
    uint16_t epoch;
    TickData td;
    std::vector<LogEvent> logs;
};

// Subscription entry
struct QubicSubscription {
    std::string id;
    QubicSubscriptionType type;
    LogFilter filter;                      // Used for Logs/Transfers
    TickStreamFilter tickStreamFilter;     // Used for TickStream
    drogon::WebSocketConnectionPtr conn;
    uint32_t lastTick{0};                  // Last tick sent (for TickStream)
    bool catchUpInProgress{false};         // True while catch-up is running
    std::vector<PendingTickData> pendingTicks;  // Ticks queued during catch-up (TickStream)
    // Logs/Transfers catch-up state
    int64_t lastLogId{-1};                 // Last log ID sent during catch-up
    uint16_t catchUpEpoch{0};              // Epoch for catch-up
    std::vector<PendingLogEvent> pendingLogs;  // Logs queued during catch-up
};

class QubicSubscriptionManager {
public:
    static QubicSubscriptionManager& instance();

    // Shutdown - signal all catch-up threads to stop and wait for them
    void shutdown();

    // Client lifecycle
    void addClient(const drogon::WebSocketConnectionPtr& conn);
    void removeClient(const drogon::WebSocketConnectionPtr& conn);

    // Subscription management
    std::string subscribe(const drogon::WebSocketConnectionPtr& conn,
                          QubicSubscriptionType type,
                          const LogFilter& filter = {});
    std::string subscribeTickStream(const drogon::WebSocketConnectionPtr& conn,
                                     const TickStreamFilter& filter,
                                     uint32_t startTick = 0);
    bool unsubscribe(const drogon::WebSocketConnectionPtr& conn,
                     const std::string& subscriptionId);

    // Event distribution (called from LoggingEventProcessor)
    void onNewTick(uint32_t tick, const TickData& td);
    void onNewLogs(uint32_t tick, const std::vector<LogEvent>& logs, const TickData& td);
    void onVerifiedTick(uint32_t tick, uint16_t epoch,
                        const std::vector<LogEvent>& logs, const TickData& td);

    // Catch-up for TickStream subscriptions
    void performCatchUp(const drogon::WebSocketConnectionPtr& conn,
                        const std::string& subId,
                        uint32_t fromTick, uint32_t toTick);

    // Catch-up for Logs/Transfers subscriptions (logId-based)
    void performLogsCatchUp(const drogon::WebSocketConnectionPtr& conn,
                            const std::string& subId,
                            uint16_t epoch, int64_t fromLogId);

    // Get client count for monitoring
    size_t getClientCount() const;

private:
    QubicSubscriptionManager() = default;

    std::string generateSubscriptionId();
    bool matchesFilter(const LogEvent& log, const LogFilter& filter,
                       const std::string& sourceIdentity,
                       const std::string& destIdentity);
    void sendSubscriptionMessage(const drogon::WebSocketConnectionPtr& conn,
                                 const std::string& subscriptionId,
                                 const Json::Value& result);
    void sendSubscriptionMessageRaw(const drogon::WebSocketConnectionPtr& conn,
                                    const std::string& subscriptionId,
                                    const std::string& resultJson);

    // TickStream filter matching helpers
    bool matchesTxFilter(const std::string& from, const std::string& to,
                         int64_t amount, uint16_t inputType,
                         const TxFilter& filter) const;
    bool matchesLogFilter(const LogEvent& log, const LogStreamFilter& filter) const;
    bool matchesAnyTxFilter(const std::string& from, const std::string& to,
                            int64_t amount, uint16_t inputType,
                            const TickStreamFilter& sub) const;
    bool matchesAnyLogFilter(const LogEvent& log, const TickStreamFilter& sub) const;

    // Build tick stream JSON string with controlled field order
    std::string buildTickStreamJsonString(uint32_t tick, uint16_t epoch, bool isCatchUp,
                                          const TickData& td,
                                          const std::vector<StreamTx>& matchedTxs,
                                          const std::vector<std::pair<LogEvent, int>>& matchedLogs,
                                          size_t totalTxs, size_t totalLogs,
                                          bool includeInputData) const;

    mutable std::shared_mutex mutex_;

    // Client -> subscriptions mapping
    std::unordered_map<drogon::WebSocketConnectionPtr,
                       std::unordered_set<std::string>> clientSubscriptions_;

    // Subscription ID -> subscription data
    std::unordered_map<std::string, QubicSubscription> subscriptions_;

    // Counter for generating subscription IDs
    std::atomic<uint64_t> subscriptionCounter_{0};

    // Shutdown flag for catch-up threads
    std::atomic<bool> stopFlag_{false};

    // Count of active catch-up threads
    std::atomic<int> activeCatchUpThreads_{0};
};
