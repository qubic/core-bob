#include "LogWebSocket.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "LogSubscriptionManager.h"
#include "src/database/db.h"

#include <json/json.h>

void LogWebSocket::handleNewConnection(const drogon::HttpRequestPtr& req,
                                       const drogon::WebSocketConnectionPtr& wsConnPtr) {
    // Reject connections until bootstrap is complete
    if (gCurrentVerifyLoggingTick.load() <= gInitialTick.load()) {
        Logger::get()->debug("Log WebSocket connection rejected (bootstrap in progress) from {}",
                            req->getPeerAddr().toIpPort());
        Json::Value error;
        error["type"] = "error";
        error["message"] = "Server is starting up, please try again later";
        Json::FastWriter writer;
        wsConnPtr->send(writer.write(error));
        wsConnPtr->shutdown();
        return;
    }

    Logger::get()->debug("WebSocket connection established from {}", req->getPeerAddr().toIpPort());

    // Add client to subscription manager
    LogSubscriptionManager::instance().addClient(wsConnPtr);

    // Send welcome message with current state
    Json::Value welcome;
    welcome["type"] = "welcome";
    welcome["currentVerifiedTick"] = gCurrentVerifyLoggingTick.load();
    welcome["currentEpoch"] = gCurrentProcessingEpoch.load();

    Json::FastWriter writer;
    wsConnPtr->send(writer.write(welcome));
}

void LogWebSocket::handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) {
    Logger::get()->debug("WebSocket connection closed");

    // Remove client from subscription manager
    LogSubscriptionManager::instance().removeClient(wsConnPtr);
}

void LogWebSocket::handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr,
                                    std::string&& message,
                                    const drogon::WebSocketMessageType& type) {
    // Silently ignore ping/pong and other control frames
    if (type == drogon::WebSocketMessageType::Ping ||
        type == drogon::WebSocketMessageType::Pong ||
        type == drogon::WebSocketMessageType::Close) {
        return;
    }

    if (type != drogon::WebSocketMessageType::Text) {
        sendError(wsConnPtr, "Only text messages are supported", "INVALID_TYPE");
        return;
    }

    // Parse JSON
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(message);

    if (!Json::parseFromStream(builder, stream, &root, &errors)) {
        sendError(wsConnPtr, "Invalid JSON: " + errors, "PARSE_ERROR");
        return;
    }

    // Get action
    if (!root.isMember("action") || !root["action"].isString()) {
        sendError(wsConnPtr, "Missing or invalid 'action' field", "MISSING_ACTION");
        return;
    }

    std::string action = root["action"].asString();

    if (action == "subscribe") {
        handleSubscribe(wsConnPtr, root);
    } else if (action == "unsubscribe") {
        handleUnsubscribe(wsConnPtr, root);
    } else if (action == "unsubscribeAll") {
        handleUnsubscribeAll(wsConnPtr);
    } else if (action == "ping") {
        handlePing(wsConnPtr);
    } else {
        sendError(wsConnPtr, "Unknown action: " + action, "UNKNOWN_ACTION");
    }
}

void LogWebSocket::handleSubscribe(const drogon::WebSocketConnectionPtr& conn, const Json::Value& msg) {
    auto& manager = LogSubscriptionManager::instance();

    // Determine catch-up mode: lastLogId takes priority over lastTick
    bool useLogIdCatchUp = false;
    int64_t lastLogId = -1;

    if (msg.isMember("lastLogId") && !msg["lastLogId"].isNull()) {
        if (msg["lastLogId"].isInt64() || msg["lastLogId"].isUInt64() || msg["lastLogId"].isInt() || msg["lastLogId"].isUInt()) {
            lastLogId = msg["lastLogId"].asInt64();
            manager.setClientLastLogId(conn, lastLogId);
            useLogIdCatchUp = true;
        }else{
            manager.setClientLastLogId(conn, -1);
            useLogIdCatchUp = false;  
        }
    } else if (msg.isMember("lastTick") && !msg["lastTick"].isNull()) {
        if (msg["lastTick"].isUInt() || msg["lastTick"].isUInt64()) {
            manager.setClientLastTick(conn, msg["lastTick"].asUInt());
        }
    } else {
        // Default to current tick - client will only receive new events
        manager.setClientLastTick(conn, gCurrentVerifyLoggingTick.load());
    }

    // Set transfer minimum amount filter (default 0 = no filter)
    if (msg.isMember("transferMinAmount") && !msg["transferMinAmount"].isNull()) {
        if (msg["transferMinAmount"].isInt64() || msg["transferMinAmount"].isUInt64() ||
            msg["transferMinAmount"].isInt() || msg["transferMinAmount"].isUInt()) {
            manager.setClientTransferMinAmount(conn, msg["transferMinAmount"].asInt64());
        }
    }

    // Handle batch subscriptions
    if (msg.isMember("subscriptions") && msg["subscriptions"].isArray()) {
        const auto& subs = msg["subscriptions"];
        int successCount = 0;

        for (const auto& sub : subs) {
            if (!sub.isMember("scIndex") || !sub.isMember("logType")) continue;
            if (!(sub["scIndex"].isUInt() || sub["scIndex"].isUInt64())) continue;
            if (!(sub["logType"].isUInt() || sub["logType"].isUInt64())) continue;

            uint32_t scIndex = sub["scIndex"].asUInt();
            uint32_t logType = sub["logType"].asUInt();

            if (manager.subscribe(conn, scIndex, logType)) {
                successCount++;
            }
        }

        // Send batch acknowledgment
        Json::Value ack;
        ack["type"] = "ack";
        ack["action"] = "subscribe";
        ack["success"] = true;
        ack["subscriptionsAdded"] = successCount;

        Json::FastWriter writer;
        conn->send(writer.write(ack));

        // Trigger catch-up after batch subscription
        if (useLogIdCatchUp) {
            int64_t currentLogId = db_get_latest_log_id(gCurrentProcessingEpoch.load());
            if (currentLogId > 0) {
                manager.performCatchUpByLogId(conn, currentLogId);
            }
        } else {
            uint32_t currentTick = gCurrentVerifyLoggingTick.load();
            if (currentTick > 0) {
                manager.performCatchUp(conn, currentTick - 1);
            }
        }

        return;
    }

    // Handle single subscription
    if (!msg.isMember("scIndex") || !msg.isMember("logType")) {
        sendError(conn, "scIndex and logType are required", "MISSING_PARAMS");
        return;
    }

    if (!(msg["scIndex"].isUInt() || msg["scIndex"].isUInt64()) ||
        !(msg["logType"].isUInt() || msg["logType"].isUInt64())) {
        sendError(conn, "scIndex and logType must be positive integers", "INVALID_PARAMS");
        return;
    }

    uint32_t scIndex = msg["scIndex"].asUInt();
    uint32_t logType = msg["logType"].asUInt();

    bool success = manager.subscribe(conn, scIndex, logType);
    sendAck(conn, "subscribe", success, scIndex, logType);

    // Trigger catch-up after subscription
    if (success) {
        if (useLogIdCatchUp) {
            int64_t currentLogId = db_get_latest_log_id(gCurrentProcessingEpoch.load());
            if (currentLogId > 0) {
                manager.performCatchUpByLogId(conn, currentLogId);
            }
        } else {
            uint32_t currentTick = gCurrentVerifyLoggingTick.load();
            if (currentTick > 0) {
                manager.performCatchUp(conn, currentTick - 1);
            }
        }
    }
}

void LogWebSocket::handleUnsubscribe(const drogon::WebSocketConnectionPtr& conn, const Json::Value& msg) {
    if (!msg.isMember("scIndex") || !msg.isMember("logType")) {
        sendError(conn, "scIndex and logType are required", "MISSING_PARAMS");
        return;
    }

    if (!(msg["scIndex"].isUInt() || msg["scIndex"].isUInt64()) ||
        !(msg["logType"].isUInt() || msg["logType"].isUInt64())) {
        sendError(conn, "scIndex and logType must be positive integers", "INVALID_PARAMS");
        return;
    }

    uint32_t scIndex = msg["scIndex"].asUInt();
    uint32_t logType = msg["logType"].asUInt();

    bool success = LogSubscriptionManager::instance().unsubscribe(conn, scIndex, logType);
    sendAck(conn, "unsubscribe", success, scIndex, logType);
}

void LogWebSocket::handleUnsubscribeAll(const drogon::WebSocketConnectionPtr& conn) {
    LogSubscriptionManager::instance().unsubscribeAll(conn);

    Json::Value ack;
    ack["type"] = "ack";
    ack["action"] = "unsubscribeAll";
    ack["success"] = true;

    Json::FastWriter writer;
    conn->send(writer.write(ack));
}

void LogWebSocket::handlePing(const drogon::WebSocketConnectionPtr& conn) {
    Json::Value pong;
    pong["type"] = "pong";
    pong["serverTick"] = gCurrentVerifyLoggingTick.load();
    pong["serverEpoch"] = gCurrentProcessingEpoch.load();

    Json::FastWriter writer;
    conn->send(writer.write(pong));
}

void LogWebSocket::sendError(const drogon::WebSocketConnectionPtr& conn,
                             const std::string& message,
                             const std::string& code) {
    Json::Value err;
    err["type"] = "error";
    err["message"] = message;
    err["code"] = code;

    Json::FastWriter writer;
    conn->send(writer.write(err));
}

void LogWebSocket::sendAck(const drogon::WebSocketConnectionPtr& conn,
                           const std::string& action,
                           bool success,
                           uint32_t scIndex,
                           uint32_t logType) {
    Json::Value ack;
    ack["type"] = "ack";
    ack["action"] = action;
    ack["success"] = success;

    if (scIndex > 0 || logType > 0) {
        ack["scIndex"] = scIndex;
        ack["logType"] = logType;
    }

    Json::FastWriter writer;
    conn->send(writer.write(ack));
}
