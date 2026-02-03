#pragma once

#include "drogon/WebSocketController.h"
#include <json/json.h>
#include <string>

// JSON-RPC 2.0 error codes - shared with QubicRpcHandler.h
#ifndef QUBIC_RPC_ERROR_CODES_DEFINED
#define QUBIC_RPC_ERROR_CODES_DEFINED
namespace QubicRpcError {
    constexpr int PARSE_ERROR = -32700;
    constexpr int INVALID_REQUEST = -32600;
    constexpr int METHOD_NOT_FOUND = -32601;
    constexpr int INVALID_PARAMS = -32602;
    constexpr int INTERNAL_ERROR = -32603;
    constexpr int RESOURCE_NOT_FOUND = -32001;
    constexpr int RESOURCE_UNAVAILABLE = -32002;
    constexpr int LIMIT_EXCEEDED = -32005;
}
#endif

class QubicRpcWebSocket : public drogon::WebSocketController<QubicRpcWebSocket> {
public:
    void handleNewMessage(const drogon::WebSocketConnectionPtr& wsConnPtr,
                          std::string&& message,
                          const drogon::WebSocketMessageType& type) override;

    void handleNewConnection(const drogon::HttpRequestPtr& req,
                             const drogon::WebSocketConnectionPtr& wsConnPtr) override;

    void handleConnectionClosed(const drogon::WebSocketConnectionPtr& wsConnPtr) override;

    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/qubic");
    WS_PATH_LIST_END

private:
    // Process a single JSON-RPC request
    Json::Value processRequest(const drogon::WebSocketConnectionPtr& conn,
                               const Json::Value& request);

    // Dispatch to method handler
    Json::Value dispatchMethod(const drogon::WebSocketConnectionPtr& conn,
                               const Json::Value& id,
                               const std::string& method,
                               const Json::Value& params);

    // Send response to client
    void sendResponse(const drogon::WebSocketConnectionPtr& conn, const Json::Value& response);
};
