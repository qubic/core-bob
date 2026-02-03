#pragma once
#include "config.h"
#include "connection/request_map.h"
#include "core/common_def.h"
#include "core/structs.h"
#include "special_buffer_structs.h"
#include <atomic>
#include <chrono>
#include <map>
#include <thread>

struct GlobalState {
    MutexRoundBuffer MRB_Data{128 * 1024u * 1024u};
    MutexRoundBuffer MRB_Request{64u * 1024u * 1024u};
    MutexRoundBuffer MRB_SC{64u * 1024u * 1024u}; // smart contract reader
    RequestMap requestMapperFrom;
    RequestMap requestMapperTo;
    RequestMap responseSCData;

    std::atomic<uint32_t> gCurrentProcessingTick{0};
    std::atomic<uint16_t> gCurrentProcessingEpoch{0};
    std::atomic<uint32_t> gInitialTick{0};
    std::atomic<uint32_t> gCurrentLoggingEventTick{0};
    std::atomic<uint32_t> gCurrentVerifyLoggingTick{0};
    std::atomic<uint32_t> gCurrentIndexingTick{0};
    std::atomic<uint32_t> gLastSeenNetworkTick{0};  // Network's current tick (0 = unknown)
    std::atomic<long long> gReindexFromTick{-1};   // Signal to indexer to restart from this tick (-1 = no reindex)
    Computors computorsList{0};
    // Fixed-size global state buffers (no heap allocations)
    uint8_t spectrum[SPECTRUM_CAPACITY * 64]; // 64 is sizeof entity
    uint8_t assets[ASSETS_CAPACITY * 48];  // 48 is sizeof asset

    // Change flags bitsets
    unsigned long long assetChangeFlags[ASSETS_CAPACITY / (sizeof(unsigned long long) * 8)];
    unsigned long long spectrumChangeFlags[SPECTRUM_CAPACITY / (sizeof(unsigned long long) * 8)];

    // Pre-sized digest trees: full binary tree storage (2*N - 1) nodes
    m256i spectrumDigests[(SPECTRUM_CAPACITY * 2 - 1)];
    m256i assetDigests[(ASSETS_CAPACITY * 2 - 1)];

    // Rescue mode range
    long long refetchFromId{-1};
    long long refetchToId{-1};
    long long refetchLogFromTick{-1};
    long long refetchLogToTick{-1};
    bool refetchLogFlag;

    // Rescue mode votes
    long long refetchTickVotes{-1};

    // trusted node info
    bool gIsTrustedNode;
    m256i nodeSubseed;
    m256i nodePublickey;
    m256i nodePrivatekey;
    std::string nodeIdentity;

    bool gIsEndEpoch = false;
    bool gAllowReceiveLogFromIncomingConnection = false;

    std::map<m256i, bool> gTrustedEntities;

    TickStorageMode gTickStorageMode = TickStorageMode::LastNTick;
    unsigned gLastNTickStorage = 1000;              // used when mode is LastNTick

    int gMaxThreads = std::thread::hardware_concurrency();

    long long gSpamThreshold;

    TxStorageMode gTxStorageMode = TxStorageMode::LastNTick;
    uint32_t gTxTickToLive = 10000;

    int gNumBMConnection = 0;

    long long gKvrocksTTL = 1209600;
    long long gTimeToWaitEpochEnd = 1800;

    unsigned gRpcPort = 40420;
    bool gEnableAdminEndpoints = false;  // Admin endpoints disabled by default
    std::atomic_int gExitDataThreadCounter;

    std::string nodeAlias = "Big fat bob";

    uint64_t startTimeUnix = 0;

    bool allowCheckInQubicGlobal = true;

    std::atomic_bool gStopFlag;

    TimedCacheMap<>* TCM;
};

// Safe, lazy singleton accessor avoids static init order issues.
GlobalState& GS();

#define SLEEP(x) std::this_thread::sleep_for(std::chrono::milliseconds(x))
#define BATCH_VERIFICATION 64
#define QU_TRANSFER 0
#define ASSET_ISSUANCE 1
#define ASSET_OWNERSHIP_CHANGE 2
#define ASSET_POSSESSION_CHANGE 3
#define CONTRACT_ERROR_MESSAGE 4
#define CONTRACT_WARNING_MESSAGE 5
#define CONTRACT_INFORMATION_MESSAGE 6
#define CONTRACT_DEBUG_MESSAGE 7
#define BURNING 8
#define DUST_BURNING 9
#define SPECTRUM_STATS 10
#define ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE 11
#define ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE 12
#define CONTRACT_RESERVE_DEDUCTION 13
#define CUSTOM_MESSAGE 255
#define CUSTOM_MESSAGE_OP_START_DISTRIBUTE_DIVIDENDS 6217575821008262227ULL // STA_DDIV
#define CUSTOM_MESSAGE_OP_END_DISTRIBUTE_DIVIDENDS 6217575821008457285ULL //END_DDIV
#define CUSTOM_MESSAGE_OP_START_EPOCH 4850183582582395987ULL // STA_EPOC
#define CUSTOM_MESSAGE_OP_END_EPOCH 4850183582582591045ULL //END_EPOC

// the chunk size that has signature from trusted entity in bob
static constexpr long long BOB_LOG_EVENT_CHUNK_SIZE = 128; // do not edit

