#pragma once

#include "drogon/WebSocketController.h"
#include <json/json.h>

class LogWebSocket : public drogon::WebSocketController<LogWebSocket> {
public:
    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr,
                          std::string&& message,
                          const drogon::WebSocketMessageType& type) override;

    void handleNewConnection(const drogon::HttpRequestPtr& req,
                             const drogon::WebSocketConnectionPtr& wsConnPtr) override;

    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override;

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/logs");
    WS_PATH_LIST_END

private:
    void handleSubscribe(const drogon::WebSocketConnectionPtr& conn, const Json::Value& msg);
    void handleUnsubscribe(const drogon::WebSocketConnectionPtr& conn, const Json::Value& msg);
    void handleUnsubscribeAll(const drogon::WebSocketConnectionPtr& conn);
    void handlePing(const drogon::WebSocketConnectionPtr& conn);

    void sendError(const drogon::WebSocketConnectionPtr& conn, const std::string& message, const std::string& code = "ERROR");
    void sendAck(const drogon::WebSocketConnectionPtr& conn, const std::string& action, bool success,
                 uint32_t scIndex = 0, uint32_t logType = 0);
};
