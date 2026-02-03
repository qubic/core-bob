#include "drogon/drogon.h"
#include "drogon/HttpAppFramework.h"
#include "drogon/HttpResponse.h"
#include "drogon/utils/Utilities.h"

// Include WebSocket controllers to trigger auto-registration
#include "LogWebSocket.h"
#include "QubicRpcWebSocket.h"
#include "QubicRpcHandler.h"
#include "QubicSubscriptionManager.h"

#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <sstream>

#include "src/bob.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "ApiHelpers.h"
#include "src/database/db.h"

// OpenAPI spec - embedded at compile time or loaded from file
static std::string g_openApiSpec;
static std::once_flag g_openApiLoadOnce;

namespace {
    std::once_flag g_startOnce;
    std::atomic<bool> g_started{false};

    drogon::HttpResponsePtr makeJsonResponse(const std::string& jsonStr, drogon::HttpStatusCode code = drogon::k200OK) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(code);
        resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
        resp->setBody(jsonStr);
        return resp;
    }

    drogon::HttpResponsePtr makeError(const std::string& msg, drogon::HttpStatusCode code = drogon::k400BadRequest) {
        Json::Value err;
        err["ok"] = false;
        err["error"] = msg;
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(code);
        return resp;
    }

    void registerRoutes() {
        using namespace drogon;

        // Load OpenAPI spec once
        std::call_once(g_openApiLoadOnce, []() {
            // Try to load from file first (for development)
            std::ifstream file("RESTAPI/openapi.json");
            if (!file.is_open()) {
                file.open("openapi.json");
            }
            if (file.is_open()) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                g_openApiSpec = buffer.str();
                file.close();  // Explicitly close the file
            } else {
                // Minimal fallback spec
                g_openApiSpec = R"({"openapi":"3.0.3","info":{"title":"QubicBob API","version":"1.0.0"},"paths":{}})";
            }
        });

        // GET /swagger - Swagger UI
        app().registerHandler(
            "/swagger",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                const std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QubicBob API - Swagger UI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/openapi.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
                deepLinking: true,
                showExtensions: true,
                showCommonExtensions: true
            });
        };
    </script>
</body>
</html>)";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_TEXT_HTML);
                resp->setBody(html);
                callback(resp);
            },
            {Get}
        );

        // GET /openapi.json - OpenAPI specification
        app().registerHandler(
            "/openapi.json",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(g_openApiSpec);
                resp->addHeader("Access-Control-Allow-Origin", "*");
                callback(resp);
            },
            {Get}
        );

        // GET /balance/{identity}
        app().registerHandler(
            "/balance/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& identity) {
                try {
                    std::string result = bobGetBalance(identity.c_str());
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("balance error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );

        // GET /asset/{identity}/{issuer}/{asset_name}/{manageSCIndex}
        app().registerHandler(
                "/asset/{1}/{2}/{3}/{4}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &identity, const std::string &issuer, const std::string &assetName,
                   const std::string &manageSCIndexStr) {
                    try {
                        unsigned long long v = std::stoull(manageSCIndexStr);
                        if (v > std::numeric_limits<uint32_t>::max()) {
                            callback(makeError("manageSCIndex out of uint32 range"));
                            return;
                        }
                        uint32_t manageSCIndex = static_cast<uint32_t>(v);
                        std::string result = bobGetAsset(identity, assetName, issuer, manageSCIndex);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("manageSCIndex must be an integer"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("manageSCIndex out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("asset error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /epochinfo/{epoch}
        app().registerHandler(
                "/epochinfo/{1}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &epochStr) {
                    try {
                        uint16_t epoch = std::stoi(epochStr);
                        std::string result = bobGetEpochInfo(epoch);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("epoch must be an integer"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("epoch out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("epochinfo error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /tx/{tx_hash}
        app().registerHandler(
            "/tx/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& txHash) {
                try {
                    std::string result = bobGetTransaction(txHash.c_str());
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("tx error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );

        // GET /log/{epoch}/{from_id}/{to_id}
        app().registerHandler(
                "/log/{1}/{2}/{3}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &epochStr, const std::string &fromStr, const std::string &toStr) {
                    try {
                        // Parse as 64-bit integers
                        uint16_t epoch = std::stoll(epochStr);
                        int64_t fromId = std::stoll(fromStr);
                        int64_t toId = std::stoll(toStr);
                        if (toId < fromId) {
                            callback(makeError("to_id must be >= from_id"));
                            return;
                        }
                        std::string result = bobGetLog(epoch, fromId, toId);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("from_id/to_id must be integers"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("from_id/to_id out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("log error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /getEndEpochLog/{epoch}
        app().registerHandler(
                "/getEndEpochLog/{1}",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback,
                   const std::string &epochStr) {
                    try {
                        uint16_t epoch = std::stoi(epochStr);
                        std::string result = bobGetEndEpochLog(epoch);
                        callback(makeJsonResponse(result));
                    } catch (const std::invalid_argument &) {
                        callback(makeError("epoch must be an integer"));
                    } catch (const std::out_of_range &) {
                        callback(makeError("epoch out of range"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("getEndEpochLog error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );



        // GET /tick/{tick_number}
        app().registerHandler(
            "/tick/{1}",
            [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback, const std::string& tickStr) {
                try {
                    unsigned long long v = std::stoull(tickStr);
                    if (v > std::numeric_limits<uint32_t>::max()) {
                        callback(makeError("tick number out of uint32 range"));
                        return;
                    }
                    uint32_t tickNum = static_cast<uint32_t>(v);
                    std::string result = bobGetTick(tickNum);
                    callback(makeJsonResponse(result));
                } catch (const std::invalid_argument&) {
                    callback(makeError("tick_number must be an integer"));
                } catch (const std::out_of_range&) {
                    callback(makeError("tick_number out of range"));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("tick error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Get}
        );
        app().registerHandler(
                "/findLog",
                [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto& j = *jsonPtr;

                        auto getU32 = [&](const char* key, uint32_t& out) -> bool {
                            if (!j.isMember(key) || !(j[key].isUInt() || j[key].isUInt64())) return false;
                            unsigned long long v = j[key].asUInt64();
                            if (v > std::numeric_limits<uint32_t>::max()) return false;
                            out = static_cast<uint32_t>(v);
                            return true;
                        };

                        uint32_t fromTick, toTick, scIndex, logType;
                        if (!getU32("fromTick", fromTick) ||
                            !getU32("toTick", toTick) ||
                            !getU32("scIndex", scIndex) ||
                            !getU32("logType", logType)) {
                            callback(makeError("All numeric fields must be uint32: fromTick, toTick, scIndex, logType"));
                            return;
                        }

                        if (!j.isMember("topic1") || !j["topic1"].isString() ||
                            !j.isMember("topic2") || !j["topic2"].isString() ||
                            !j.isMember("topic3") || !j["topic3"].isString()) {
                            callback(makeError("topic1, topic2, topic3 (strings) are required"));
                            return;
                        }

                        if (fromTick > toTick) {
                            callback(makeError("fromTick must be <= toTick"));
                            return;
                        }

                        const std::string topic1 = j["topic1"].asString();
                        const std::string topic2 = j["topic2"].asString();
                        const std::string topic3 = j["topic3"].asString();

                        std::string result = bobFindLog(scIndex, logType, topic1, topic2, topic3, fromTick, toTick);
                        callback(makeJsonResponse(result));
                    } catch (const std::exception& ex) {
                        callback(makeError(std::string("findLog error: ") + ex.what(), drogon::k500InternalServerError));
                    }
                },
                {Post}
        );
        app().registerHandler(
                "/getlogcustom",
                [](const HttpRequestPtr& req, std::function<void (const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto& j = *jsonPtr;

                        auto getU32 = [&](const char* key, uint32_t& out) -> bool {
                            if (!j.isMember(key) || !(j[key].isUInt() || j[key].isUInt64())) return false;
                            unsigned long long v = j[key].asUInt64();
                            if (v > std::numeric_limits<uint32_t>::max()) return false;
                            out = static_cast<uint32_t>(v);
                            return true;
                        };


                        uint32_t tick, startTick, endTick, scIndex, logType;
                        uint32_t epoch;
                        if (
                            !getU32("scIndex", scIndex) ||
                            !getU32("logType", logType) ||
                            !getU32("epoch", epoch)) {
                            callback(makeError("All numeric fields must be uint32: epoch, scIndex, logType"));
                            return;
                        }
                        if (getU32("tick", tick)) {
                            startTick = tick;
                            endTick = tick;
                        } else {
                            if (!getU32("startTick", startTick) ||
                                !getU32("endTick", endTick)) {
                                callback(makeError("Either tick (uint32) or both startTick and endTick (uint32) are required"));
                                return;
                            }
                        }

                        std::string topics[3] = {"", "", ""};
                        for (int i = 1; i <= 3; ++i) {
                            std::string key = "topic" + std::to_string(i);
                            if (!j.isMember(key) || !j[key].isString()) {
                                topics[i-1] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB";
                            } else {
                                topics[i-1] = j[key].asString();
                                // To uppercase
                                std::transform(topics[i-1].begin(), topics[i-1].end(), topics[i-1].begin(), ::toupper);
                            }
                        }

                        // Reuse the existing find API with a single-tick window
                        std::string result = getCustomLog(scIndex, logType, topics[0], topics[1], topics[2], epoch, startTick, endTick);
                        callback(makeJsonResponse(result));
                    } catch (const std::exception& ex) {
                        callback(makeError(std::string("getlogcustom error: ") + ex.what(), drogon::k500InternalServerError));
                    }
                },
                {Post}
        );

        // POST /getQuTransferForIdentity
        app().registerHandler(
            "/getQuTransfersForIdentity",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || !json.isMember("identity")) {
                        callback(makeError("Missing required fields: fromTick, toTick, identity"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string identity = json["identity"].asString();
                    std::string result = getQuTransfersForIdentity(fromTick, toTick, identity);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getQuTransfersForIdentity error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // POST /getAssetTransferForIdentity
        app().registerHandler(
            "/getAssetTransfersForIdentity",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || !json.isMember("identity") ||
                        !json.isMember("assetIssuer") || !json.isMember("assetName")) {
                        callback(makeError("Missing required fields: fromTick, toTick, identity, assetIssuer, assetName"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string identity = json["identity"].asString();
                    std::string assetIssuer = json["assetIssuer"].asString();
                    std::string assetName = json["assetName"].asString();
                    std::string result = getAssetTransfersForIdentity(fromTick, toTick, identity, assetIssuer,
                                                                      assetName);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getAssetTransfersForIdentity error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // POST /getAllAssetTransfer
        app().registerHandler(
            "/getAllAssetTransfers",
            [](const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
                try {
                    auto jsonPtr = req->getJsonObject();
                    if (!jsonPtr) {
                        callback(makeError("Invalid JSON body"));
                        return;
                    }
                    const auto& json = *jsonPtr;
                    
                    if (!json.isMember("fromTick") || !json.isMember("toTick") || 
                        !json.isMember("assetIssuer") || !json.isMember("assetName")) {
                        callback(makeError("Missing required fields: fromTick, toTick, assetIssuer, assetName"));
                        return;
                    }
                    
                    uint32_t fromTick = json["fromTick"].asUInt();
                    uint32_t toTick = json["toTick"].asUInt();
                    std::string assetIssuer = json["assetIssuer"].asString();
                    std::string assetName = json["assetName"].asString();
                    
                    std::string result = getAllAssetTransfers(fromTick, toTick, assetIssuer, assetName);
                    callback(makeJsonResponse(result));
                } catch (const std::exception& ex) {
                    callback(makeError(std::string("getAllAssetTransfers error: ") + ex.what(), k500InternalServerError));
                }
            },
            {Post}
        );

        // GET /status - Returns node status information
        app().registerHandler(
                "/status",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        std::string result = bobGetStatus();
                        callback(makeJsonResponse(result));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("status error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // POST /querySmartContract
        app().registerHandler(
                "/querySmartContract",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
    try {
        auto jsonPtr = req->getJsonObject();
        if (!jsonPtr) {
            callback(makeError("Invalid or missing JSON body"));
            return;
        }
        const auto &j = *jsonPtr;

        // Validate required parameters
        if (!j.isMember("nonce") || !j["nonce"].isUInt64()) {
            callback(makeError("nonce (uint32) is required"));
            return;
        }
        if (!j.isMember("scIndex") || !j["scIndex"].isUInt()) {
            callback(makeError("scIndex (uint32) is required"));
            return;
        }
        if (!j.isMember("funcNumber") || !j["funcNumber"].isUInt()) {
            callback(makeError("funcNumber (uint32) is required"));
            return;
        }
        if (!j.isMember("data") || !j["data"].isString()) {
            callback(makeError("data (hex string) is required"));
            return;
        }

        const uint32_t nonce = static_cast<uint32_t>(j["nonce"].asUInt64());
        const uint32_t scIndex = static_cast<uint32_t>(j["scIndex"].asUInt());
        const uint32_t funcNumber = static_cast<uint32_t>(j["funcNumber"].asUInt());
        const std::string data = j["data"].asString();

        // Use shared helper for initial query
        SmartContractQueryResult queryResult = ApiHelpers::querySmartContract(nonce, scIndex, funcNumber, data);

        // Handle errors
        if (!queryResult.error.empty()) {
            callback(makeError(queryResult.error));
            return;
        }

        // If result is immediately available, return it
        if (queryResult.success) {
            Json::Value root;
            root["nonce"] = nonce;
            root["data"] = queryResult.data;
            Json::FastWriter writer;
            callback(makeJsonResponse(writer.write(root)));
            return;
        }

        // Result is pending - poll with timeout using event loop
        auto sharedCallback = std::make_shared<std::function<void(const HttpResponsePtr&)>>(std::move(callback));
        auto attemptCount = std::make_shared<int>(0);
        auto startTime = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());

        auto loop = drogon::app().getIOLoop(0);

        auto pollResultPtr = std::make_shared<std::function<void()>>();
        std::weak_ptr<std::function<void()>> pollResultWeak = pollResultPtr;

        *pollResultPtr = [nonce, sharedCallback, attemptCount, startTime, loop, pollResultWeak, scIndex, funcNumber, data]() {
            // Check for result using shared helper
            SmartContractQueryResult result = ApiHelpers::checkSmartContractResult(nonce, scIndex, funcNumber, data);

            if (result.success) {
                Json::Value root;
                root["nonce"] = nonce;
                root["data"] = result.data;
                Json::FastWriter writer;
                (*sharedCallback)(makeJsonResponse(writer.write(root)));
                return;
            }

            // Check timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - *startTime
            ).count();

            (*attemptCount)++;
            if (*attemptCount >= 20 || elapsed >= 3) {  // Max ~2 seconds or 20 attempts
                Json::Value root;
                root["error"] = "pending";
                root["message"] = "Query enqueued; try again with the same nonce";
                root["nonce"] = nonce;
                Json::FastWriter writer;
                auto resp = makeJsonResponse(writer.write(root), drogon::k202Accepted);
                resp->setCloseConnection(true);
                (*sharedCallback)(resp);
                return;
            }

            // Continue polling
            if (auto pollFunc = pollResultWeak.lock()) {
                loop->runAfter(0.1, *pollFunc);
            }
        };

        // Start polling after 100ms
        loop->runAfter(0.1, *pollResultPtr);

    } catch (const std::exception &ex) {
        callback(makeError(std::string("querySmartContract error: ") + ex.what(), k500InternalServerError));
    }
});

        // POST /broadcastTransaction
        app().registerHandler(
                "/broadcastTransaction",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid or missing JSON body"));
                            return;
                        }
                        const auto &j = *jsonPtr;

                        if (!j.isMember("data") || !j["data"].isString()) {
                            callback(makeError("data (hex string) is required"));
                            return;
                        }

                        auto result = ApiHelpers::broadcastTransaction(j["data"].asString());
                        if (!result.success) {
                            callback(makeError(result.error));
                            return;
                        }

                        callback(makeJsonResponse("{\"txHash\": \"" + result.txHash + "\"}"));
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("broadcast error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Post}
        );

        // POST /qubic - Qubic JSON-RPC endpoint (HTTP)
        app().registerHandler(
                "/qubic",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    // Set CORS headers for browser compatibility
                    auto setCorsHeaders = [](const HttpResponsePtr& resp) {
                        resp->addHeader("Access-Control-Allow-Origin", "*");
                        resp->addHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
                        resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
                    };

                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            // Try parsing raw body
                            std::string body(req->getBody());
                            if (body.empty()) {
                                auto resp = makeError("Invalid or missing JSON body");
                                setCorsHeaders(resp);
                                callback(resp);
                                return;
                            }

                            Json::Value root;
                            Json::CharReaderBuilder builder;
                            std::string errors;
                            std::istringstream stream(body);
                            if (!Json::parseFromStream(builder, stream, &root, &errors)) {
                                Json::Value errResp = QubicRpcHandler::makeError(
                                    Json::Value::null, QubicRpcError::PARSE_ERROR, "Parse error: " + errors);
                                auto resp = HttpResponse::newHttpJsonResponse(errResp);
                                resp->setStatusCode(k200OK);
                                setCorsHeaders(resp);
                                callback(resp);
                                return;
                            }

                            // Process the request
                            Json::Value response;
                            if (root.isArray()) {
                                response = QubicRpcHandler::processBatch(root);
                            } else {
                                response = QubicRpcHandler::processRequest(root);
                            }

                            if (response.isNull()) {
                                // Notification - no response
                                auto resp = HttpResponse::newHttpResponse();
                                resp->setStatusCode(k204NoContent);
                                setCorsHeaders(resp);
                                callback(resp);
                            } else {
                                auto resp = HttpResponse::newHttpJsonResponse(response);
                                resp->setStatusCode(k200OK);
                                setCorsHeaders(resp);
                                callback(resp);
                            }
                            return;
                        }

                        const auto& json = *jsonPtr;

                        // Process the request
                        Json::Value response;
                        if (json.isArray()) {
                            response = QubicRpcHandler::processBatch(json);
                        } else {
                            response = QubicRpcHandler::processRequest(json);
                        }

                        if (response.isNull()) {
                            // Notification - no response
                            auto resp = HttpResponse::newHttpResponse();
                            resp->setStatusCode(k204NoContent);
                            setCorsHeaders(resp);
                            callback(resp);
                        } else {
                            auto resp = HttpResponse::newHttpJsonResponse(response);
                            resp->setStatusCode(k200OK);
                            setCorsHeaders(resp);
                            callback(resp);
                        }
                    } catch (const std::exception &ex) {
                        Json::Value errResp = QubicRpcHandler::makeError(
                            Json::Value::null, QubicRpcError::INTERNAL_ERROR, ex.what());
                        auto resp = HttpResponse::newHttpJsonResponse(errResp);
                        resp->setStatusCode(k200OK);
                        setCorsHeaders(resp);
                        callback(resp);
                    }
                },
                {Post, Options}
        );

        // OPTIONS /qubic - CORS preflight
        app().registerHandler(
                "/qubic",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k204NoContent);
                    resp->addHeader("Access-Control-Allow-Origin", "*");
                    resp->addHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
                    resp->addHeader("Access-Control-Allow-Headers", "Content-Type");
                    resp->addHeader("Access-Control-Max-Age", "86400");
                    callback(resp);
                },
                {Options}
        );

        // Admin endpoints - only registered if enabled via config
        if (gEnableAdminEndpoints) {
            Logger::get()->info("Admin endpoints enabled");

            // POST /_admin/reindex - Force re-indexing from a specific tick
            app().registerHandler(
                "/_admin/reindex",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        auto jsonPtr = req->getJsonObject();
                        if (!jsonPtr) {
                            callback(makeError("Invalid JSON body"));
                            return;
                        }
                        const auto& json = *jsonPtr;

                        if (!json.isMember("fromTick") || !json["fromTick"].isUInt()) {
                            callback(makeError("fromTick (uint32) is required"));
                            return;
                        }

                        uint32_t fromTick = json["fromTick"].asUInt();

                        // Signal the indexer to restart from the specified tick
                        // The indexer checks gReindexFromTick on each iteration and will reset
                        gReindexFromTick.store(static_cast<long long>(fromTick), std::memory_order_release);

                        Json::Value result;
                        result["ok"] = true;
                        result["message"] = "Reindex signal sent to indexer";
                        result["fromTick"] = fromTick;
                        result["currentIndexingTick"] = gCurrentIndexingTick.load();
                        auto resp = HttpResponse::newHttpJsonResponse(result);
                        callback(resp);
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("reindex error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Post}
        );

        // GET /_admin/checkIndexing - Check indexing status for a tick range or epoch
        app().registerHandler(
                "/_admin/checkIndexing",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        uint32_t fromTick = 0;
                        uint32_t toTick = 0;
                        uint16_t epoch = 0;

                        // Check query parameters
                        auto epochStr = req->getParameter("epoch");
                        auto fromTickStr = req->getParameter("fromTick");
                        auto toTickStr = req->getParameter("toTick");

                        if (!epochStr.empty()) {
                            epoch = static_cast<uint16_t>(std::stoul(epochStr));
                            // Get epoch boundaries from EpochInfo
                            auto epochInfo = ApiHelpers::getEpochInfo(epoch);
                            if (epochInfo.initialTick == 0) {
                                callback(makeError("Epoch " + std::to_string(epoch) + " not found"));
                                return;
                            }
                            fromTick = epochInfo.initialTick;
                            // Try to get end tick from next epoch or use current tick
                            auto nextEpochInfo = ApiHelpers::getEpochInfo(epoch + 1);
                            if (nextEpochInfo.initialTick > 0) {
                                toTick = nextEpochInfo.initialTick - 1;
                            } else {
                                // Current epoch - use latest verified tick
                                toTick = gCurrentVerifyLoggingTick.load();
                            }
                        } else if (!fromTickStr.empty()) {
                            fromTick = std::stoul(fromTickStr);
                            if (!toTickStr.empty()) {
                                toTick = std::stoul(toTickStr);
                            } else {
                                toTick = fromTick + 100; // Default range of 100 ticks
                            }
                        } else {
                            callback(makeError("Either 'epoch' or 'fromTick' parameter is required"));
                            return;
                        }

                        // Limit range to prevent excessive queries
                        const uint32_t MAX_RANGE = 10000;
                        if (toTick - fromTick > MAX_RANGE) {
                            toTick = fromTick + MAX_RANGE;
                        }

                        Json::Value result;
                        result["fromTick"] = fromTick;
                        result["toTick"] = toTick;
                        result["totalTicks"] = toTick - fromTick + 1;

                        uint32_t ticksWithData = 0;
                        uint32_t ticksWithLogRange = 0;
                        uint32_t ticksWithTransactions = 0;
                        uint32_t ticksMissing = 0;
                        Json::Value missingTicks(Json::arrayValue);
                        Json::Value tickDetails(Json::arrayValue);

                        // Check each tick
                        for (uint32_t tick = fromTick; tick <= toTick; tick++) {
                            TickData td;
                            bool hasTickData = db_try_get_tick_data(tick, td);
                            bool hasLogRange = db_check_log_range(tick);

                            // Count transactions from TickData (non-zero digests)
                            long long txCount = 0;
                            if (hasTickData) {
                                for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
                                    if (td.transactionDigests[i] != m256i::zero()) {
                                        txCount++;
                                    }
                                }
                            }

                            if (!hasTickData) {
                                ticksMissing++;
                                if (missingTicks.size() < 100) { // Limit missing ticks list
                                    missingTicks.append(tick);
                                }
                            } else {
                                ticksWithData++;
                            }

                            if (hasLogRange) {
                                ticksWithLogRange++;
                            }

                            if (txCount > 0) {
                                ticksWithTransactions++;
                            }

                            // For detailed mode, include per-tick info (limit to first 100 for performance)
                            auto detailedStr = req->getParameter("detailed");
                            if (!detailedStr.empty() && detailedStr == "true" && tickDetails.size() < 100) {
                                Json::Value tickInfo;
                                tickInfo["tick"] = tick;
                                tickInfo["hasTickData"] = hasTickData;
                                tickInfo["hasLogRange"] = hasLogRange;
                                tickInfo["txCount"] = static_cast<Json::Int64>(txCount);

                                if (hasTickData) {
                                    tickInfo["epoch"] = td.epoch;
                                    tickInfo["computorIndex"] = td.computorIndex;
                                }

                                if (hasLogRange) {
                                    long long logFrom, logLen;
                                    if (db_try_get_log_range_for_tick(tick, logFrom, logLen)) {
                                        tickInfo["logRangeFrom"] = static_cast<Json::Int64>(logFrom);
                                        tickInfo["logRangeLength"] = static_cast<Json::Int64>(logLen);
                                    }
                                }

                                tickDetails.append(tickInfo);
                            }
                        }

                        result["ticksWithData"] = ticksWithData;
                        result["ticksWithLogRange"] = ticksWithLogRange;
                        result["ticksWithTransactions"] = ticksWithTransactions;
                        result["ticksMissing"] = ticksMissing;

                        if (!missingTicks.empty()) {
                            result["missingTicks"] = missingTicks;
                            if (ticksMissing > 100) {
                                result["missingTicksTruncated"] = true;
                            }
                        }

                        if (!tickDetails.empty()) {
                            result["details"] = tickDetails;
                            if (toTick - fromTick + 1 > 100) {
                                result["detailsTruncated"] = true;
                            }
                        }

                        // Summary status
                        double completeness = static_cast<double>(ticksWithData) / static_cast<double>(toTick - fromTick + 1) * 100.0;
                        result["completeness"] = completeness;
                        result["status"] = (ticksMissing == 0) ? "complete" : (completeness > 95.0 ? "mostly_complete" : "incomplete");

                        // Add current indexing state
                        result["currentState"]["lastIndexedTick"] = static_cast<Json::Int64>(db_get_last_indexed_tick());
                        result["currentState"]["currentIndexingTick"] = gCurrentIndexingTick.load();
                        result["currentState"]["currentVerifyLoggingTick"] = gCurrentVerifyLoggingTick.load();

                        auto resp = HttpResponse::newHttpJsonResponse(result);
                        callback(resp);
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("checkIndexing error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
        );

        // GET /_admin/checkTransactions - Check transaction indexing consistency for a tick range
        // Finds transactions with logs that aren't marked as executed, or vice versa
        app().registerHandler(
                "/_admin/checkTransactions",
                [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
                    try {
                        uint32_t fromTick = 0;
                        uint32_t toTick = 0;

                        auto fromTickStr = req->getParameter("fromTick");
                        auto toTickStr = req->getParameter("toTick");

                        if (fromTickStr.empty()) {
                            callback(makeError("fromTick parameter is required"));
                            return;
                        }

                        fromTick = std::stoul(fromTickStr);
                        if (!toTickStr.empty()) {
                            toTick = std::stoul(toTickStr);
                        } else {
                            toTick = fromTick + 100;
                        }

                        // Limit range
                        const uint32_t MAX_RANGE = 1000;
                        if (toTick - fromTick > MAX_RANGE) {
                            toTick = fromTick + MAX_RANGE;
                        }

                        Json::Value result;
                        result["fromTick"] = fromTick;
                        result["toTick"] = toTick;

                        uint32_t totalTxChecked = 0;
                        uint32_t txWithLogsNotExecuted = 0;
                        uint32_t txExecutedNoLogs = 0;
                        uint32_t txConsistent = 0;
                        uint32_t txNotIndexed = 0;

                        Json::Value inconsistentTxs(Json::arrayValue);

                        // Check each tick
                        for (uint32_t tick = fromTick; tick <= toTick; tick++) {
                            TickData td;
                            if (!db_try_get_tick_data(tick, td)) {
                                continue;
                            }

                            // Check log ranges for this tick to get transaction hashes
                            LogRangesPerTxInTick logRange;
                            if (!db_try_get_log_ranges(tick, logRange)) {
                                continue;
                            }

                            // Iterate through transaction digests in tick data
                            for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
                                // Check if this transaction slot has a digest (not all zeros)
                                bool hasDigest = false;
                                for (int j = 0; j < 32; j++) {
                                    if (td.transactionDigests[i].m256i_u8[j] != 0) {
                                        hasDigest = true;
                                        break;
                                    }
                                }

                                if (!hasDigest) {
                                    continue;
                                }

                                // Convert digest to hash string
                                char hashStr[64] = {0};
                                getIdentityFromPublicKey(td.transactionDigests[i].m256i_u8, hashStr, true);
                                std::string txHash(hashStr);

                                totalTxChecked++;

                                // Get indexed transaction data
                                int txIndex = -1;
                                long long fromLogId = -1, toLogId = -1;
                                uint64_t timestamp = 0;
                                bool executed = false;

                                bool hasIndexedData = db_get_indexed_tx(txHash.c_str(), txIndex, fromLogId, toLogId, timestamp, executed);

                                if (!hasIndexedData) {
                                    txNotIndexed++;
                                    continue;
                                }

                                bool hasLogs = (fromLogId >= 0 && toLogId >= fromLogId);

                                // Check consistency
                                if (hasLogs && !executed) {
                                    // Has logs but not marked as executed - this is the bug case
                                    txWithLogsNotExecuted++;
                                    if (inconsistentTxs.size() < 100) {
                                        Json::Value txInfo;
                                        txInfo["txHash"] = txHash;
                                        txInfo["tick"] = tick;
                                        txInfo["txIndex"] = txIndex;
                                        txInfo["fromLogId"] = static_cast<Json::Int64>(fromLogId);
                                        txInfo["toLogId"] = static_cast<Json::Int64>(toLogId);
                                        txInfo["executed"] = executed;
                                        txInfo["issue"] = "has_logs_not_executed";
                                        inconsistentTxs.append(txInfo);
                                    }
                                } else if (!hasLogs && executed) {
                                    // Marked as executed but no logs - might be valid for some tx types
                                    // but worth flagging for review
                                    txExecutedNoLogs++;
                                    if (inconsistentTxs.size() < 100) {
                                        Json::Value txInfo;
                                        txInfo["txHash"] = txHash;
                                        txInfo["tick"] = tick;
                                        txInfo["txIndex"] = txIndex;
                                        txInfo["fromLogId"] = static_cast<Json::Int64>(fromLogId);
                                        txInfo["toLogId"] = static_cast<Json::Int64>(toLogId);
                                        txInfo["executed"] = executed;
                                        txInfo["issue"] = "executed_no_logs";
                                        inconsistentTxs.append(txInfo);
                                    }
                                } else {
                                    txConsistent++;
                                }
                            }
                        }

                        result["totalTxChecked"] = totalTxChecked;
                        result["txConsistent"] = txConsistent;
                        result["txNotIndexed"] = txNotIndexed;
                        result["txWithLogsNotExecuted"] = txWithLogsNotExecuted;
                        result["txExecutedNoLogs"] = txExecutedNoLogs;

                        if (!inconsistentTxs.empty()) {
                            result["inconsistentTransactions"] = inconsistentTxs;
                            if (txWithLogsNotExecuted + txExecutedNoLogs > 100) {
                                result["inconsistentTruncated"] = true;
                            }
                        }

                        result["status"] = (txWithLogsNotExecuted == 0 && txExecutedNoLogs == 0) ? "consistent" : "inconsistent";

                        auto resp = HttpResponse::newHttpJsonResponse(result);
                        callback(resp);
                    } catch (const std::exception &ex) {
                        callback(makeError(std::string("checkTransactions error: ") + ex.what(), k500InternalServerError));
                    }
                },
                {Get}
            );
        } // end if (gEnableAdminEndpoints)

    }

    void startServerIfNeeded() {
        std::call_once(g_startOnce, []() {
            if (g_started.exchange(true)) return;

            registerRoutes();

            // Configure and start Drogon
            drogon::app()
                .setLogLevel(trantor::Logger::kInfo)
                .addListener("0.0.0.0", gRpcPort)  // listen at rpc_port (default 40420)
                .setThreadNum(std::max(2, gMaxThreads))
                .setIdleConnectionTimeout(120)      // Increased for WebSocket connections
                .setKeepaliveRequestsNumber(200)
                .setMaxConnectionNum(128)          // Limit max concurrent connections
                .setMaxConnectionNumPerIP(25)      // Limit per-IP connections (prevents single client abuse)
                .disableSigtermHandling()
                .reusePort()                        // Enable SO_REUSEADDR to avoid "Address already in use" errors
                ;

            // Run Drogon in a background thread so it doesn't block the main program
            std::thread([]() {
                drogon::app().run();
            }).detach();
        });
    }
} // namespace

// Optional explicit control APIs (in case another part of the program wants to manage lifecycle)
void startRESTServer() {
    Logger::get()->info("Start REST API server");
    startServerIfNeeded();
}

void stopRESTServer() {
    // First, shutdown subscription manager to stop catch-up threads
    QubicSubscriptionManager::instance().shutdown();

    // This will trigger a graceful shutdown; if the app isn't running, it's a no-op.
    drogon::app().quit();
    Logger::get()->info("Stop REST API server");
}