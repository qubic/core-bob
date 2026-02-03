#pragma once

#include <json/json.h>
#include <string>

// JSON-RPC 2.0 error codes
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

namespace QubicRpcHandler {

// Process a single JSON-RPC request (for HTTP - no subscription support)
Json::Value processRequest(const Json::Value& request);

// Process a batch of requests
Json::Value processBatch(const Json::Value& requests);

// Dispatch to method handler (HTTP version - subscription methods return error)
Json::Value dispatchMethod(const Json::Value& id,
                           const std::string& method,
                           const Json::Value& params);

// Dispatch common methods (shared between HTTP and WebSocket)
// Returns Json::Value::null if method is not found (caller should handle subscription methods)
// Returns valid response for all other cases (success or error)
Json::Value dispatchCommonMethod(const Json::Value& id,
                                  const std::string& method,
                                  const Json::Value& params);

// JSON-RPC 2.0 message builders
Json::Value makeResult(const Json::Value& id, const Json::Value& result);
Json::Value makeError(const Json::Value& id, int code, const std::string& message);

}  // namespace QubicRpcHandler
