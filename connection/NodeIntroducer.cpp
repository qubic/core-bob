#include <drogon/HttpClient.h>
#include <vector>
#include <string>
#include <json/json.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdint>
#include "spdlogDriver/Logger.h"
#include "shim.h"

// Default http timeout for external API calls (in seconds)
static constexpr double HTTP_TIMEOUT_SEC = 10.0;

// Split a URL into origin ("scheme://host[:port]") and path-prefix ("/...").
// drogon's HttpClient::newHttpClient expects origin-only; any path component
// must go into req->setPath. Without splitting, configured prefixes like
// "https://api.qubic.li/public" silently drop the "/public" part and hit
// the wrong endpoint.
static std::pair<std::string, std::string> splitOriginAndPath(const std::string& url)
{
    const std::string schemeSep = "://";
    size_t schemeEnd = url.find(schemeSep);
    if (schemeEnd == std::string::npos) {
        return {url, ""};
    }
    size_t pathStart = url.find('/', schemeEnd + schemeSep.size());
    if (pathStart == std::string::npos) {
        return {url, ""};
    }
    std::string origin = url.substr(0, pathStart);
    std::string prefix = url.substr(pathStart);
    // Trim trailing slash on prefix so we don't end up with "/public//random-peers".
    while (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
    return {origin, prefix};
}

// Try a single peer-discovery base URL. Returns an empty vector on any
// failure so the caller can move on to the next entry in the failover list.
static std::vector<std::string> tryPeerDiscovery(const std::string& baseUrl,
                                                 const int nLite, const int nBob,
                                                 const std::string& mode)
{
    std::vector<std::string> results;
    if (baseUrl.empty()) return results;
    try {
        auto [origin, prefix] = splitOriginAndPath(baseUrl);
        auto client = drogon::HttpClient::newHttpClient(origin);
        auto req = drogon::HttpRequest::newHttpRequest();
        req->setMethod(drogon::Get);
        std::string path = prefix + "/random-peers?service=bobNode&litePeers="
                         + std::to_string(nLite) + "&bobPeers=" + std::to_string(nBob);
        if (mode == "closest") path += "&mode=closest";
        req->setPath(path.c_str());
        Logger::get()->debug("peer-discovery: GET {}{}", origin, path);

        auto [result, response] = client->sendRequest(req, HTTP_TIMEOUT_SEC);
        if (result != drogon::ReqResult::Ok || !response) return results;

        auto jsonPtr = response->getJsonObject();
        if (!jsonPtr) return results;

        if (jsonPtr->isMember("bobPeers") && (*jsonPtr)["bobPeers"].isArray()) {
            for (const auto& peer : (*jsonPtr)["bobPeers"]) {
                if (peer.isString()) {
                    results.push_back("bob:" + peer.asString() + ":21842:0-0-0-0");
                }
            }
        }
        if (jsonPtr->isMember("litePeers") && (*jsonPtr)["litePeers"].isArray()) {
            for (const auto& peer : (*jsonPtr)["litePeers"]) {
                if (peer.isString()) {
                    results.push_back("BM:" + peer.asString() + ":21841:0-0-0-0");
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::get()->warn("peer-discovery {} failed: {}", baseUrl, e.what());
    }
    return results;
}

std::vector<std::string> GetPeerFromDNS(const int nLite, const int nBob, const std::string mode)
{
    // Walk the configured peer-discovery URLs in order and return the first
    // non-empty response. This is intentional failover, not aggregation —
    // we don't want to mix peer sets from multiple authorities.
    for (const auto& baseUrl : gPeerDiscoveryUrls) {
        auto peers = tryPeerDiscovery(baseUrl, nLite, nBob, mode);
        if (!peers.empty()) {
            Logger::get()->debug("peer-discovery: got {} peers from {}", peers.size(), baseUrl);
            return peers;
        }
        Logger::get()->info("peer-discovery: {} returned no peers, trying next", baseUrl);
    }
    Logger::get()->warn("peer-discovery: all {} configured endpoints failed", gPeerDiscoveryUrls.size());
    return {};
}

// Render a state-files URL template by substituting `{EPOCH}` with the
// actual epoch number. For back-compat with the old "base URL only" style,
// templates that don't contain `{EPOCH}` are treated as a base URL with
// "/ep<epoch>.zip" implicitly appended.
static std::string renderStateFilesUrl(const std::string& tmpl, uint16_t epoch)
{
    const std::string placeholder = "{EPOCH}";
    const std::string epochStr = std::to_string(epoch);
    if (tmpl.find(placeholder) == std::string::npos) {
        // No placeholder → legacy "base URL" form; append historical layout.
        return tmpl + "/ep" + epochStr + ".zip";
    }
    std::string out;
    out.reserve(tmpl.size() + 16);
    size_t pos = 0;
    for (;;) {
        size_t next = tmpl.find(placeholder, pos);
        if (next == std::string::npos) { out.append(tmpl, pos, std::string::npos); break; }
        out.append(tmpl, pos, next - pos);
        out.append(epochStr);
        pos = next + placeholder.size();
    }
    return out;
}

bool DownloadStateFiles(uint16_t epoch)
{
    if (gStateFilesUrls.empty()) {
        Logger::get()->info("state-files-urls is empty; skipping spectrum/universe download for epoch {}", epoch);
        return false;
    }
    const std::string zipFile  = "ep" + std::to_string(epoch) + ".zip";
    const std::string fileNames = "spectrum." + std::to_string(epoch)
                                + " universe." + std::to_string(epoch);

    // Walk the configured state-file URLs in order; first download that
    // both fetches and unzips successfully wins.
    for (const auto& tmpl : gStateFilesUrls) {
        if (tmpl.empty()) continue;
        const std::string url = renderStateFilesUrl(tmpl, epoch);
        const std::string wgetCmd = "wget -q --no-check-certificate -O " + zipFile + " \"" + url + "\"";
        int wgetResult = std::system(wgetCmd.c_str());
        if (wgetResult != 0) {
            Logger::get()->warn("state-files: download from {} failed (wget exit {})", url, wgetResult);
            continue;
        }
        const std::string unzipCmd = "unzip -o -q " + zipFile + " " + fileNames;
        int unzipResult = std::system(unzipCmd.c_str());
        if (unzipResult != 0) {
            Logger::get()->warn("state-files: unzip of {} failed (exit {}); trying next mirror", zipFile, unzipResult);
            continue;
        }
        Logger::get()->info("state-files: downloaded ep{}.zip from {}", epoch, url);
        return true;
    }
    Logger::get()->warn("state-files: all {} configured mirrors failed for epoch {}",
                        gStateFilesUrls.size(), epoch);
    return false;
}

void GetLatestTickFromExternalSources(uint32_t& tick, uint16_t& epoch)
{
    if (gIsTestnet) return;
    tick = 0;
    epoch = 0;

    // Walk the configured current-tick endpoints in order until one returns
    // a usable response. Two response shapes are supported:
    //   "flat"   → {"tick": N, "epoch": N}
    //   "nested" → {"tickInfo": {"tick": N, "epoch": N}}
    for (const auto& ep : gCurrentTickEndpoints) {
        if (ep.url.empty()) continue;
        try {
            // Tolerate operators who put a path prefix into the URL field
            // (e.g. "https://api.qubic.li/public") — extract any prefix and
            // prepend it to the configured path.
            auto [origin, prefix] = splitOriginAndPath(ep.url);
            auto client = drogon::HttpClient::newHttpClient(origin);
            auto req = drogon::HttpRequest::newHttpRequest();
            req->setMethod(drogon::Get);
            req->setPath((prefix + ep.path).c_str());
            auto [result, response] = client->sendRequest(req, HTTP_TIMEOUT_SEC);
            if (result != drogon::ReqResult::Ok || !response) continue;
            auto jsonPtr = response->getJsonObject();
            if (!jsonPtr) continue;

            const Json::Value* src = jsonPtr.get();
            if (ep.shape == "nested") {
                if (!jsonPtr->isMember("tickInfo") || !(*jsonPtr)["tickInfo"].isObject()) continue;
                src = &(*jsonPtr)["tickInfo"];
            }
            if (!src->isMember("tick") || !src->isMember("epoch")) continue;

            tick  = (*src)["tick"].asUInt();
            epoch = static_cast<uint16_t>((*src)["epoch"].asUInt());
            return;
        } catch (const std::exception& e) {
            Logger::get()->warn("current-tick {} failed: {}", ep.url, e.what());
        }
    }
}

void CheckInQubicGlobal()
{
    if (gIsTestnet) return;
    // Declare the external function
    extern std::string bobGetExtraStatus(const std::string& challenge = "");

    // Get the JSON string data
    std::string jsonData = bobGetExtraStatus("");

    // Create HTTP client and request — use the configured check-in URL.
    if (gCheckinUrl.empty()) return;
    try {
        auto [origin, prefix] = splitOriginAndPath(gCheckinUrl);
        auto client = drogon::HttpClient::newHttpClient(origin);
        auto req = drogon::HttpRequest::newHttpRequest();
        req->setMethod(drogon::Post);
        req->setPath((prefix + "/checkin").c_str());
        req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
        req->setBody(jsonData);

        auto [result, response] = client->sendRequest(req, HTTP_TIMEOUT_SEC);
        if (result == drogon::ReqResult::Ok && response) {
            Logger::get()->info("Successfully checked in at {}", gCheckinUrl);
        }
    } catch (const std::exception& e) {
        Logger::get()->warn("check-in {} failed: {}", gCheckinUrl, e.what());
    }
}
