#include "QubicRpcWebSocket.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "QubicRpcHandler.h"
#include "QubicRpcMapper.h"
#include "QubicRpcMethods.h"
#include "QubicSubscriptionManager.h"
#include <sstream>

void QubicRpcWebSocket::handleNewConnection(
    const drogon::HttpRequestPtr& req,
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    // Reject connections until bootstrap is complete
    if (gCurrentVerifyLoggingTick.load() <= gInitialTick.load()) {
        Logger::get()->debug("Qubic JSON-RPC WebSocket connection rejected (bootstrap in progress) from {}",
                            req->getPeerAddr().toIpPort());
        Json::Value error;
        error["jsonrpc"] = "2.0";
        error["error"]["code"] = -32000;
        error["error"]["message"] = "Server is starting up, please try again later";
        error["id"] = Json::Value::null;
        Json::FastWriter writer;
        wsConnPtr->send(writer.write(error));
        wsConnPtr->shutdown();
        return;
    }

    Logger::get()->debug("Qubic JSON-RPC WebSocket connection from {}",
                        req->getPeerAddr().toIpPort());

    // Register with subscription manager
    QubicSubscriptionManager::instance().addClient(wsConnPtr);
}

void QubicRpcWebSocket::handleConnectionClosed(
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    Logger::get()->debug("Qubic JSON-RPC WebSocket connection closed");

    // Cleanup subscriptions
    QubicSubscriptionManager::instance().removeClient(wsConnPtr);
}

void QubicRpcWebSocket::handleNewMessage(
    const drogon::WebSocketConnectionPtr& wsConnPtr,
    std::string&& message,
    const drogon::WebSocketMessageType& type)
{
    // Ignore non-text messages
    if (type == drogon::WebSocketMessageType::Ping ||
        type == drogon::WebSocketMessageType::Pong ||
        type == drogon::WebSocketMessageType::Close) {
        return;
    }

    if (type != drogon::WebSocketMessageType::Text) {
        sendResponse(wsConnPtr, QubicRpcHandler::makeError(Json::Value::null,
                     QubicRpcError::INVALID_REQUEST, "Only text messages are supported"));
        return;
    }

    // Parse JSON
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(message);

    if (!Json::parseFromStream(builder, stream, &root, &errors)) {
        sendResponse(wsConnPtr, QubicRpcHandler::makeError(Json::Value::null,
                     QubicRpcError::PARSE_ERROR, "Parse error: " + errors));
        return;
    }

    // Handle batch requests (array of requests)
    if (root.isArray()) {
        if (root.empty()) {
            sendResponse(wsConnPtr, QubicRpcHandler::makeError(Json::Value::null,
                         QubicRpcError::INVALID_REQUEST, "Empty batch"));
            return;
        }

        Json::Value responses(Json::arrayValue);
        for (const auto& req : root) {
            Json::Value response = processRequest(wsConnPtr, req);
            if (!response.isNull()) {
                responses.append(response);
            }
        }

        if (!responses.empty()) {
            sendResponse(wsConnPtr, responses);
        }
        return;
    }

    // Single request
    Json::Value response = processRequest(wsConnPtr, root);
    if (!response.isNull()) {
        sendResponse(wsConnPtr, response);
    }
}

Json::Value QubicRpcWebSocket::processRequest(
    const drogon::WebSocketConnectionPtr& conn,
    const Json::Value& request)
{
    // Validate JSON-RPC 2.0 structure
    if (!request.isObject()) {
        return QubicRpcHandler::makeError(Json::Value::null, QubicRpcError::INVALID_REQUEST,
                        "Request must be an object");
    }

    // Check jsonrpc version
    if (!request.isMember("jsonrpc") || request["jsonrpc"].asString() != "2.0") {
        return QubicRpcHandler::makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Invalid JSON-RPC version");
    }

    // Check method
    if (!request.isMember("method") || !request["method"].isString()) {
        return QubicRpcHandler::makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Missing or invalid method");
    }

    std::string method = request["method"].asString();
    if (method.empty()) {
        return QubicRpcHandler::makeError(request.get("id", Json::Value::null),
                        QubicRpcError::INVALID_REQUEST, "Method cannot be empty");
    }
    Json::Value params = request.get("params", Json::Value(Json::arrayValue));
    Json::Value id = request.get("id", Json::Value::null);

    // If no id, this is a notification - no response required
    if (id.isNull() && !request.isMember("id")) {
        dispatchMethod(conn, id, method, params);
        return Json::Value::null;
    }

    return dispatchMethod(conn, id, method, params);
}

Json::Value QubicRpcWebSocket::dispatchMethod(
    const drogon::WebSocketConnectionPtr& conn,
    const Json::Value& id,
    const std::string& method,
    const Json::Value& params)
{
    // Try common methods first (shared with HTTP handler)
    Json::Value result = QubicRpcHandler::dispatchCommonMethod(id, method, params);
    if (!result.isNull()) {
        return result;
    }

    // Handle subscription methods (WebSocket only)
    try {
        if (method == "qubic_subscribe") {
            if (!params.isArray() || params.size() < 1) {
                return QubicRpcHandler::makeError(id, QubicRpcError::INVALID_PARAMS, "Missing subscription type");
            }
            std::string subType = params[0].asString();
            Json::Value filterParams = params.size() > 1 ? params[1] : Json::Value();
            std::string subId = QubicRpcMethods::subscribe(conn, subType, filterParams);
            if (subId.empty()) {
                return QubicRpcHandler::makeError(id, QubicRpcError::INVALID_PARAMS,
                               "Invalid subscription type: " + subType +
                               ". Valid types: newTicks, logs, transfers, tickStream");
            }
            return QubicRpcHandler::makeResult(id, subId);
        }
        if (method == "qubic_unsubscribe") {
            if (!params.isArray() || params.size() < 1) {
                return QubicRpcHandler::makeError(id, QubicRpcError::INVALID_PARAMS, "Missing subscription ID");
            }
            bool success = QubicRpcMethods::unsubscribe(conn, params[0].asString());
            return QubicRpcHandler::makeResult(id, success);
        }

        // Method not found
        return QubicRpcHandler::makeError(id, QubicRpcError::METHOD_NOT_FOUND, "Method not found: " + method);

    } catch (const std::exception& e) {
        Logger::get()->error("Error in qubic_rpc method {}: {}", method, e.what());
        return QubicRpcHandler::makeError(id, QubicRpcError::INTERNAL_ERROR, e.what());
    }
}

void QubicRpcWebSocket::sendResponse(const drogon::WebSocketConnectionPtr& conn,
                                      const Json::Value& response) {
    Json::FastWriter writer;
    try {
        conn->send(writer.write(response));
    } catch (const std::exception& e) {
        Logger::get()->warn("Failed to send Qubic RPC response: {}", e.what());
    }
}
