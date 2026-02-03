#pragma once
#include <cstdint>
#include <string>
//#ifdef __cplusplus
//extern "C" {
//#endif
int runBob(int argc, char *argv[]);
void requestToExitBob();

// other APIs:
// - human readable
// - easy for SC dev
void startRESTServer();
void stopRESTServer();
std::string bobGetBalance(const char* identity);
std::string bobGetAsset(const std::string identity, const std::string assetName, const std::string issuer, uint32_t manageSCIndex);
std::string bobGetTransaction(const char* txHash);
std::string bobGetLog(uint16_t epoch, int64_t start, int64_t end); // inclusive
std::string bobGetEndEpochLog(uint16_t epoch);
std::string bobGetTick(const uint32_t tick); // return Data And Votes and LogRanges
std::string bobFindLog(uint32_t scIndex, uint32_t logType,
                       const std::string& st1, const std::string& st2, const std::string& st3,
                       uint32_t fromTick, uint32_t toTick);
std::string getCustomLog(uint32_t scIndex, uint32_t logType,
                       const std::string& st1, const std::string& st2, const std::string& st3,
                         uint16_t epoch, uint32_t startTick, uint32_t endTick);
std::string bobGetStatus();
std::string querySmartContract(uint32_t nonce, uint32_t scIndex, uint32_t funcNumber, uint8_t* data, uint32_t dataSize);
bool enqueueSmartContractRequest(uint32_t nonce, uint32_t scIndex, uint32_t funcNumber, const uint8_t* data, uint32_t dataSize);
std::string broadcastTransaction(uint8_t* txDataWithHeader, int size);
std::string bobGetEpochInfo(uint16_t epoch);

//extra APIs:
std::string getQuTransfersForIdentity(uint32_t fromTick, uint32_t toTick, const std::string& identity);
std::string getAssetTransfersForIdentity(uint32_t fromTick, uint32_t toTick, const std::string& identity,
                                         const std::string& assetIssuer, const std::string& assetName);
std::string getAllAssetTransfers(uint32_t fromTick, uint32_t toTick, const std::string& assetIssuer, const std::string& assetName);


// no one request for C ABI atm, add later if needed
//#ifdef __cplusplus
//}
//#endif