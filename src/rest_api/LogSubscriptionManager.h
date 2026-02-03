#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <chrono>
#include <functional>

#include "src/core/log_event/log_event.h"
#include "drogon/WebSocketConnection.h"

// Subscription key: (scIndex, logType) pair
struct SubscriptionKey {
    uint32_t scIndex;
    uint32_t logType;

    bool operator==(const SubscriptionKey& other) const {
        return scIndex == other.scIndex && logType == other.logType;
    }
};

// Hash function for SubscriptionKey
struct SubscriptionKeyHash {
    std::size_t operator()(const SubscriptionKey& k) const {
        return std::hash<uint64_t>()((static_cast<uint64_t>(k.scIndex) << 32) | k.logType);
    }
};

// Per-client subscription state
struct ClientState {
    drogon::WebSocketConnectionPtr conn;
    std::unordered_set<SubscriptionKey, SubscriptionKeyHash> subscriptions;
    uint32_t lastTick{0};           // For catch-up tracking by tick
    int64_t lastLogId{-1};          // For catch-up tracking by log ID (-1 = not set)
    bool catchUpInProgress{false};  // True while catch-up is running
    std::chrono::steady_clock::time_point connectedAt;
    int64_t transferMinAmount{0};   // Minimum amount for QU_TRANSFER events (0 = no filter)
};

// Singleton manager for WebSocket log subscriptions
class LogSubscriptionManager {
public:
    static LogSubscriptionManager& instance();

    // Client management
    void addClient(const drogon::WebSocketConnectionPtr& conn);
    void removeClient(const drogon::WebSocketConnectionPtr& conn);

    // Set lastTick for catch-up (called during init message)
    void setClientLastTick(const drogon::WebSocketConnectionPtr& conn, uint32_t lastTick);

    // Set lastLogId for catch-up by log ID
    void setClientLastLogId(const drogon::WebSocketConnectionPtr& conn, int64_t lastLogId);

    // Set minimum transfer amount filter for QU_TRANSFER events
    void setClientTransferMinAmount(const drogon::WebSocketConnectionPtr& conn, int64_t minAmount);

    // Subscription management
    bool subscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType);
    bool unsubscribe(const drogon::WebSocketConnectionPtr& conn, uint32_t scIndex, uint32_t logType);
    void unsubscribeAll(const drogon::WebSocketConnectionPtr& conn);

    // Push verified logs to matching subscribers (called from indexer thread)
    void pushVerifiedLogs(uint32_t tick, uint16_t epoch, const std::vector<LogEvent>& logs);

    // Perform catch-up: send historical logs from lastTick+1 to currentTick
    // This is async and should be called after subscriptions are set
    void performCatchUp(const drogon::WebSocketConnectionPtr& conn, uint32_t toTick);

    // Perform catch-up by log ID: send historical logs from lastLogId+1 to toLogId
    void performCatchUpByLogId(const drogon::WebSocketConnectionPtr& conn, int64_t toLogId);

    // Stats
    size_t getClientCount() const;
    size_t getTotalSubscriptionCount() const;

private:
    LogSubscriptionManager() = default;
    ~LogSubscriptionManager() = default;
    LogSubscriptionManager(const LogSubscriptionManager&) = delete;
    LogSubscriptionManager& operator=(const LogSubscriptionManager&) = delete;

    // Extract (scIndex, logType) from a LogEvent
    bool extractSubscriptionKey(const LogEvent& log, SubscriptionKey& key) const;

    // Send a JSON message to a connection
    void sendJson(const drogon::WebSocketConnectionPtr& conn, const std::string& json);

    mutable std::shared_mutex mutex_;

    // Connection pointer -> ClientState
    std::unordered_map<drogon::WebSocketConnectionPtr, ClientState> clients_;

    // SubscriptionKey -> Set of connections subscribed to this key
    std::unordered_map<SubscriptionKey, std::unordered_set<drogon::WebSocketConnectionPtr>, SubscriptionKeyHash> subscriptionIndex_;
};
