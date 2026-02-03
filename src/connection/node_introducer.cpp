#include <drogon/HttpClient.h>
#include <vector>
#include <string>
#include <json/json.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdint>
#include "src/logger/logger.h"

std::vector<std::string> GetPeerFromDNS()
{
    std::vector<std::string> results;
    auto client = drogon::HttpClient::newHttpClient("https://api.qubic.global");
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/random-peers?service=bobNode&litePeers=2&bobPeers=4");

    auto [result, response] = client->sendRequest(req);

    if (result == drogon::ReqResult::Ok && response)
    {
        auto jsonPtr = response->getJsonObject();
        if (jsonPtr && jsonPtr->isMember("bobPeers"))
        {
            const auto& peers = (*jsonPtr)["bobPeers"];
            if (peers.isArray())
            {
                for (const auto& peer : peers)
                {
                    if (peer.isString())
                    {
                        std::string ip = peer.asString();
                        std::string peerString = "bob:" + ip + ":21842:0-0-0-0";
                        results.push_back(peerString);
                    }
                }
            }
        }
        if (jsonPtr && jsonPtr->isMember("litePeers"))
        {
            const auto& peers = (*jsonPtr)["litePeers"];
            if (peers.isArray())
            {
                for (const auto& peer : peers)
                {
                    if (peer.isString())
                    {
                        std::string ip = peer.asString();
                        std::string peerString = "BM:" + ip + ":21841:0-0-0-0";
                        results.push_back(peerString);
                    }
                }
            }
        }
    }

    return results;
}

bool DownloadStateFiles(uint16_t epoch)
{
    std::string url = "https://dl.qubic.global/ep" + std::to_string(epoch) + ".zip";
    std::string zipFile = "ep" + std::to_string(epoch) + ".zip";

    std::string wgetCmd = "wget -q --no-check-certificate -O " + zipFile + " \"" + url + "\"";
    int wgetResult = std::system(wgetCmd.c_str());

    if (wgetResult != 0)
    {
        return false;
    }

    std::string unzipCmd = "unzip -o -q " + zipFile;
    int unzipResult = std::system(unzipCmd.c_str());

    if (unzipResult != 0)
    {
        return false;
    }

    return true;
}

void GetLatestTickFromExternalSources(uint32_t& tick, uint16_t& epoch)
{
    // Try primary API
    auto client1 = drogon::HttpClient::newHttpClient("https://api.qubic.global");
    auto req1 = drogon::HttpRequest::newHttpRequest();
    req1->setMethod(drogon::Get);
    req1->setPath("/currenttick");

    auto [result1, response1] = client1->sendRequest(req1);

    if (result1 == drogon::ReqResult::Ok && response1)
    {
        auto jsonPtr = response1->getJsonObject();
        if (jsonPtr && jsonPtr->isMember("tick") && jsonPtr->isMember("epoch"))
        {
            tick = (*jsonPtr)["tick"].asUInt();
            epoch = static_cast<uint16_t>((*jsonPtr)["epoch"].asUInt());
            return;
        }
    }

    // Try first failover API
    auto client2 = drogon::HttpClient::newHttpClient("https://api.qubic.li");
    auto req2 = drogon::HttpRequest::newHttpRequest();
    req2->setMethod(drogon::Get);
    req2->setPath("/public/currenttick");

    auto [result2, response2] = client2->sendRequest(req2);

    if (result2 == drogon::ReqResult::Ok && response2)
    {
        auto jsonPtr = response2->getJsonObject();
        if (jsonPtr && jsonPtr->isMember("tick") && jsonPtr->isMember("epoch"))
        {
            tick = (*jsonPtr)["tick"].asUInt();
            epoch = static_cast<uint16_t>((*jsonPtr)["epoch"].asUInt());
            return;
        }
    }

    // Try final failover API with different response structure
    auto client3 = drogon::HttpClient::newHttpClient("https://rpc.qubic.org");
    auto req3 = drogon::HttpRequest::newHttpRequest();
    req3->setMethod(drogon::Get);
    req3->setPath("/live/v1/tick-info");

    auto [result3, response3] = client3->sendRequest(req3);

    if (result3 == drogon::ReqResult::Ok && response3)
    {
        auto jsonPtr = response3->getJsonObject();
        if (jsonPtr && jsonPtr->isMember("tickInfo"))
        {
            const auto& tickInfo = (*jsonPtr)["tickInfo"];
            if (tickInfo.isMember("tick") && tickInfo.isMember("epoch"))
            {
                tick = tickInfo["tick"].asUInt();
                epoch = static_cast<uint16_t>(tickInfo["epoch"].asUInt());
                return;
            }
        }
    }

    // If all APIs fail, set to 0
    tick = 0;
    epoch = 0;
}

void CheckInQubicGlobal()
{
    // Declare the external function
    extern std::string bobGetExtraStatus();

    // Get the JSON string data
    std::string jsonData = bobGetExtraStatus();

    // Create HTTP client and request
    auto client = drogon::HttpClient::newHttpClient("https://api.qubic.global");
    auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setPath("/checkin");
    req->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    req->setBody(jsonData);

    // Send the request
    auto [result, response] = client->sendRequest(req);

    if (result == drogon::ReqResult::Ok && response)
    {
        Logger::get()->info("Successfully checked in qubic.global");
    }
}
