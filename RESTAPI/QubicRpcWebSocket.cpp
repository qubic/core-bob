#include "QubicRpcWebSocket.h"
#include "QubicRpcHandler.h"
#include "QubicRpcMethods.h"
#include "QubicSubscriptionManager.h"
#include "QubicRpcMapper.h"
#include "spdlogDriver/Logger.h"
#include "shim.h"
#include <sstream>

static constexpr int MAX_MESSAGES_PER_SECOND = 20;
static constexpr int MAX_RATE_LIMIT_STRIKES = 3;

// Resolve the real client IP from proxy headers, falling back to peer address
static std::string resolveClientIp(const drogon::HttpRequestPtr& req) {
    // X-Forwarded-For: client, proxy1, proxy2 - take the leftmost
    auto xff = req->getHeader("X-Forwarded-For");
    if (!xff.empty()) {
        auto comma = xff.find(',');
        std::string ip = (comma != std::string::npos) ? xff.substr(0, comma) : xff;
        while (!ip.empty() && ip.front() == ' ') ip.erase(ip.begin());
        while (!ip.empty() && ip.back() == ' ') ip.pop_back();
        if (!ip.empty()) return ip;
    }
    // X-Real-IP: single IP set by nginx/proxy
    auto xri = req->getHeader("X-Real-IP");
    if (!xri.empty()) return xri;
    // Direct connection
    return req->getPeerAddr().toIp();
}

static WsConnectionContext* getWsContext(const drogon::WebSocketConnectionPtr& conn) {
    auto ctx = conn->getContext<WsConnectionContext>();
    return ctx.get();
}

void QubicRpcWebSocket::handleNewConnection(
    const drogon::HttpRequestPtr& req,
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    std::string peerIp = req->getPeerAddr().toIpPort();
    std::string clientIp = resolveClientIp(req);

    // Attach context to connection
    auto ctx = std::make_shared<WsConnectionContext>();
    ctx->peerIp = peerIp;
    ctx->clientIp = clientIp;
    wsConnPtr->setContext(ctx);

    // Reject connections until bootstrap is complete
    if (gCurrentVerifyLoggingTick.load() <= gInitialTick.load()) {
        Logger::get()->info("WS connection rejected (bootstrap in progress) client={} peer={}",
                            clientIp, peerIp);
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

    Logger::get()->info("WS connection opened client={} peer={}", clientIp, peerIp);

    // Register with subscription manager
    QubicSubscriptionManager::instance().addClient(wsConnPtr);
}

void QubicRpcWebSocket::handleConnectionClosed(
    const drogon::WebSocketConnectionPtr& wsConnPtr)
{
    auto* ctx = getWsContext(wsConnPtr);
    if (ctx) {
        Logger::get()->info("WS connection closed client={} peer={}", ctx->clientIp, ctx->peerIp);
    } else {
        Logger::get()->info("WS connection closed");
    }

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

    // Rate limiting
    auto* ctx = getWsContext(wsConnPtr);
    if (ctx) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ctx->windowStart);
        if (elapsed.count() >= 1) {
            // Reset window
            ctx->windowStart = now;
            ctx->messageCount = 1;
            ctx->rateLimitStrikes = 0;
        } else {
            ctx->messageCount++;
            if (ctx->messageCount > MAX_MESSAGES_PER_SECOND) {
                ctx->rateLimitStrikes++;
                if (ctx->rateLimitStrikes >= MAX_RATE_LIMIT_STRIKES) {
                    Logger::get()->warn("WS rate limit exceeded, disconnecting client={} peer={}",
                                       ctx->clientIp, ctx->peerIp);
                    sendResponse(wsConnPtr, QubicRpcHandler::makeError(Json::Value::null,
                                 QubicRpcError::LIMIT_EXCEEDED, "Rate limit exceeded, disconnecting"));
                    wsConnPtr->shutdown();
                    return;
                }
                sendResponse(wsConnPtr, QubicRpcHandler::makeError(Json::Value::null,
                             QubicRpcError::LIMIT_EXCEEDED, "Rate limit exceeded: max " +
                             std::to_string(MAX_MESSAGES_PER_SECOND) + " messages/second"));
                return;
            }
        }
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
                // Check if it was a valid type but limit exceeded
                if (subType == "newTicks" || subType == "logs" || subType == "transfers" || subType == "tickStream") {
                    auto* ctx = getWsContext(conn);
                    Logger::get()->warn("WS subscription limit reached type={} client={} peer={}",
                                       subType,
                                       ctx ? ctx->clientIp : "unknown",
                                       ctx ? ctx->peerIp : "unknown");
                    return QubicRpcHandler::makeError(id, QubicRpcError::LIMIT_EXCEEDED,
                                   "Maximum subscriptions per connection reached");
                }
                return QubicRpcHandler::makeError(id, QubicRpcError::INVALID_PARAMS,
                               "Invalid subscription type: " + subType +
                               ". Valid types: newTicks, logs, transfers, tickStream");
            }
            // Log successful subscription with IP info
            auto* ctx = getWsContext(conn);
            Logger::get()->info("WS subscribe type={} id={} client={} peer={}",
                               subType, subId,
                               ctx ? ctx->clientIp : "unknown",
                               ctx ? ctx->peerIp : "unknown");
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
