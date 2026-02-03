#include "bob.h"
#include "src/core/k12_and_key_util.h"
#include "src/profiler/profiler.h"
#include "config.h"
#include "connection/connection.h"
#include "core/structs.h"
#include "database/db.h"
#include "global_var.h"
#include "logger/logger.h"
#include "shim.h"
#include "version.h"
#include <algorithm> // std::max
#include <chrono>
#include <cstdlib>   // strtoull
#include <cstring>   // memcpy
#include <limits>    // std::numeric_limits
#include <pthread.h> // thread naming on POSIX
#include <random>    // std::random_device, std::mt19937

void tickingVerifyThread();
void tickingDataRequestThread(ConnectionPool& conn_pool, std::chrono::milliseconds requestCycle, uint32_t futureOffset);
void eventRequestFromTrustedNode(ConnectionPool& connPoolWithPwd, std::chrono::milliseconds request_logging_cycle_ms);
void connReceiver(QCPtr conn, const bool isTrustedNode);
void dataProcessorThread();
void requestProcessorThread();
void verifyLoggingEvent();
void indexVerifiedTicks();
void querySmartContractThread(ConnectionPool& connPoolAll);
// Public helpers from QubicServer.cpp
bool startQubicServer(ConnectionPool* cp, uint16_t port = 21842);
void stopQubicServer();
void garbageCleaner();

static inline void set_this_thread_name(const char* name_in) {
    // Linux allows up to 16 bytes including null terminator
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%s", name_in ? name_in : "");
    pthread_setname_np(pthread_self(), buf);
}

void requestToExitBob()
{
    gExitDataThreadCounter = 0;
    gStopFlag = true;
}

void printVersionInfo() {
    Logger::get()->info("========================================");
    Logger::get()->info("BOB Version: {}", BOB_VERSION);
    Logger::get()->info("Git Commit:  {}", GIT_COMMIT_HASH);
    Logger::get()->info("Compiler:    {}", COMPILER_NAME);
    Logger::get()->info("========================================");
}


int runBob(int argc, char *argv[])
{
    // Ignore SIGPIPE so write/send on a closed socket doesn't terminate the process.
    gStopFlag.store(false);
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr);
    // Load configuration from JSON
    const std::string config_path = (argc > 1) ? std::string(argv[1]) : std::string("bob.json");
    AppConfig cfg;
    std::string cfg_error;
    if (!LoadConfig(config_path, cfg, cfg_error)) {
        printf("Failed to load config '%s': %s\n", config_path.c_str(), cfg_error.c_str());
        return -1;
    }
    // trace - debug - info - warn - error - fatal
    std::string log_level = cfg.log_level;
    Logger::init(log_level);
    printVersionInfo();
    {
        getSubseedFromSeed((uint8_t *) cfg.node_seed.c_str(), nodeSubseed.m256i_u8);
        getPrivateKeyFromSubSeed(nodeSubseed.m256i_u8, nodePrivatekey.m256i_u8);
        getPublicKeyFromPrivateKey(nodePrivatekey.m256i_u8, nodePublickey.m256i_u8);
        char identity[64] = {0};
        getIdentityFromPublicKey(nodePublickey.m256i_u8, identity, false);
        nodeIdentity = identity;
        if (cfg.node_seed == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            Logger::get()->warn("Using default bob seed: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    gTickStorageMode = cfg.tick_storage_mode;
    gLastNTickStorage = cfg.last_n_tick_storage;
    gTxStorageMode = cfg.tx_storage_mode;
    gTxTickToLive = cfg.tx_tick_to_live;
    gSpamThreshold = cfg.spam_qu_threshold;
    gMaxThreads = cfg.max_thread;
    gKvrocksTTL = cfg.kvrocks_ttl;
    gTimeToWaitEpochEnd = cfg.wait_at_epoch_end;
    gRpcPort = cfg.rpc_port;
    gEnableAdminEndpoints = cfg.enable_admin_endpoints;
    gNodeAlias = cfg.nodeAlias;
    gStartTimeUnix = std::chrono::duration_cast<std::chrono::seconds>
            (std::chrono::system_clock::now().time_since_epoch()).count();
    gAllowCheckInQubicGlobal = cfg.allow_check_in_qubic_global;
    gAllowReceiveLogFromIncomingConnection = cfg.allow_receive_log_from_incoming_connections;

    // Defaults for new knobs are already in AppConfig
    unsigned int request_cycle_ms = cfg.request_cycle_ms;
    unsigned int request_logging_cycle_ms = cfg.request_logging_cycle_ms;
    unsigned int future_offset = cfg.future_offset;
    // Put redis_url in REDIS_CONNECTION_STRING
    std::string KEYDB_CONNECTION_STRING = cfg.keydb_url;

    // Read server flags
    const bool run_server = cfg.run_server;
    unsigned int server_port_u = cfg.server_port;

    {
        db_connect(KEYDB_CONNECTION_STRING);
        uint32_t tick;
        uint16_t epoch;
        db_get_latest_tick_and_epoch(tick, epoch);
        gCurrentFetchingTick = tick;
        gCurrentProcessingEpoch = epoch;
        uint16_t event_epoch;
        db_get_latest_event_tick_and_epoch(tick, event_epoch);
        gCurrentFetchingLogTick = tick;
        Logger::get()->info("Loaded DB. DATA: Tick: {} | epoch: {}", gCurrentFetchingTick.load(), gCurrentProcessingEpoch.load());
        Logger::get()->info("Loaded DB. EVENT: Tick: {} | epoch: {}", gCurrentFetchingLogTick.load(), event_epoch);
    }
    startRESTServer();

    if (gTickStorageMode == TickStorageMode::Kvrocks)
    {
        db_kvrocks_connect(cfg.kvrocks_url);
        Logger::get()->info("Connected to kvrocks");
    }
    // Collect endpoints from config
    ConnectionPool connPool; // conn pool with passcode
    if (cfg.p2p_nodes.empty())
    {
        Logger::get()->info("Getting peers info from qubic.global");
        cfg.p2p_nodes = GetPeerFromDNS();
    }
    parseConnection(connPool, cfg.p2p_nodes);

    while (connPool.size() > 6) connPool.randomlyRemove();

    if (run_server) {
        if (server_port_u == 0 || server_port_u > 65535) {
            Logger::get()->critical("Invalid server_port {}. Must be in 1..65535", server_port_u);
            return -1;
        }
        const uint16_t server_port = static_cast<uint16_t>(server_port_u);
        if (!startQubicServer(&connPool, server_port)) {
            Logger::get()->critical("Failed to start embedded server on port {}", server_port);
            return -1;
        }
        Logger::get()->info("Embedded server enabled on port {}", server_port);
    }

    uint32_t initTick = 0;
    uint16_t initEpoch = 0;
    uint32_t endEpochTick = 0;
    std::string key = "end_epoch_tick:" + std::to_string(gCurrentProcessingEpoch);
    bool isThisEpochAlreadyEnd = db_get_u32(key, endEpochTick);
    int retryCount = 0;
    while ((initTick == 0 ||
            ( (initEpoch < gCurrentProcessingEpoch && !isThisEpochAlreadyEnd) ||
              (initEpoch <= gCurrentProcessingEpoch && isThisEpochAlreadyEnd)
            ))
            && (!gStopFlag.load())
    )
    {
        doHandshakeAndGetBootstrapInfo(connPool, true, initTick, initEpoch);
        if (isThisEpochAlreadyEnd) Logger::get()->info("Waiting for new epoch info from peers | PeerInitTick: {} PeerInitEpoch {}...", initTick, initEpoch);
        else Logger::get()->info("Doing handshakes and ask for bootstrap info | PeerInitTick: {} PeerInitEpoch {}...", initTick, initEpoch);
        if (initTick == 0 || initEpoch <= gCurrentProcessingEpoch) SLEEP(1000);
        if (retryCount++ > 300)
        {
            Logger::get()->info("No meaningful response after 5 minutes. Exiting bob to get new peers");
            gStopFlag.store(true);
        }
    }
    db_insert_u32("init_tick:"+std::to_string(initEpoch), initTick);
    gInitialTick = initTick;
    if (initTick > gCurrentFetchingTick.load())
    {
        gCurrentFetchingTick = initTick;
    }
    if (initTick > gCurrentFetchingLogTick.load())
    {
        gCurrentFetchingLogTick = initTick;
    }

    if (initEpoch > gCurrentProcessingEpoch.load())
    {
        gCurrentProcessingEpoch = initEpoch;
    }

    if (computorsList.epoch != gCurrentProcessingEpoch.load())
    {
        while (computorsList.epoch != gCurrentProcessingEpoch.load())
        {
            getComputorList(connPool, cfg.arbitrator_identity);
            SLEEP(1000);
        }
    }

    auto request_thread = std::thread(
            [&](){
                set_this_thread_name("io-req");
                tickingDataRequestThread(
                        std::ref(connPool),
                        std::chrono::milliseconds(request_cycle_ms),
                        static_cast<uint32_t>(future_offset)
                );
            }
    );
    auto verify_thread = std::thread([&](){
        set_this_thread_name("verify");
        tickingVerifyThread();
    });
    auto log_request_trusted_nodes_thread = std::thread([&](){
        set_this_thread_name("trusted-log-req");
        eventRequestFromTrustedNode(std::ref(connPool),
                                    std::chrono::milliseconds(request_logging_cycle_ms));
    });
    auto indexer_thread = std::thread([&](){
        set_this_thread_name("indexer");
        indexVerifiedTicks();
    });
    gTCM = new TimedCacheMap<>();
    auto sc_thread = std::thread([&](){
        set_this_thread_name("sc");
        querySmartContractThread(connPool);
    });
    int pool_size = connPool.size();
    std::vector<std::thread> v_recv_thread;
    std::vector<std::thread> v_data_thread;
    Logger::get()->info("Starting {} data processor threads", pool_size);
    const bool isTrustedNode = true;
    gNumBMConnection = 0;
    for (int i = 0; i < pool_size; i++)
    {
        QCPtr qc = nullptr;
        v_recv_thread.emplace_back([&, i](){
            char nm[16];
            std::snprintf(nm, sizeof(nm), "recv-%d", i);
            set_this_thread_name(nm);
            if (connPool.get(i, qc))
            {
                connReceiver(qc, isTrustedNode);
            }
            else
            {
                Logger::get()->warn("Invalid connection index ", i);
            }
        });
        if (qc && qc->isBM()) gNumBMConnection++;
    }
    for (int i = 0; i < std::max(gMaxThreads, pool_size); i++)
    {
        v_data_thread.emplace_back([&](){
            set_this_thread_name("data");
            dataProcessorThread();
        });
        v_data_thread.emplace_back([&, i](){
            char nm[16];
            std::snprintf(nm, sizeof(nm), "reqp-%d", i);
            set_this_thread_name(nm);
            requestProcessorThread();
        });
    }
    std::thread log_event_verifier_thread;
    log_event_verifier_thread = std::thread([&](){
        set_this_thread_name("log-ver");
        verifyLoggingEvent();
    });
    std::thread garbage_thread;
    if (cfg.tick_storage_mode != TickStorageMode::Free || cfg.tx_storage_mode != TxStorageMode::Free)
    {
        garbage_thread = std::thread(garbageCleaner);
    }


    uint32_t prevFetchingTickData = 0;
    uint32_t prevLoggingEventTick = 0;
    uint32_t prevVerifyEventTick = 0;
    uint32_t prevIndexingTick = 0;
    const long long sleep_time = 5;
    int compareLocalTickWithNetworkCount = 0;
    int checkInQubicGlobalCount = 0;
    CheckInQubicGlobal();
    auto start_time = std::chrono::high_resolution_clock::now();
    while (!gStopFlag.load())
    {
        auto current_time = std::chrono::high_resolution_clock::now();
        float duration_ms = float(std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count());
        start_time = std::chrono::high_resolution_clock::now();

        float fetching_td_speed = (prevFetchingTickData == 0) ? 0: float(gCurrentFetchingTick.load() - prevFetchingTickData) / duration_ms * 1000.0f;
        float fetching_le_speed = (prevLoggingEventTick == 0) ? 0: float(gCurrentFetchingLogTick.load() - prevLoggingEventTick) / duration_ms * 1000.0f;
        float verify_le_speed = (prevVerifyEventTick == 0) ? 0: float(gCurrentVerifyLoggingTick.load() - prevVerifyEventTick) / duration_ms * 1000.0f;
        float indexing_speed = (prevIndexingTick == 0) ? 0: float(gCurrentIndexingTick.load() - prevIndexingTick) / duration_ms * 1000.0f;
        prevFetchingTickData = gCurrentFetchingTick.load();
        prevLoggingEventTick = gCurrentFetchingLogTick.load();
        prevVerifyEventTick = gCurrentVerifyLoggingTick.load();
        prevIndexingTick = gCurrentIndexingTick.load();
        Logger::get()->info(
                "Current state: FetchingTick: {} ({:.1f}) | FetchingLog: {} ({:.1f}) | Indexing: {} ({:.1f}) | Verifying: {} ({:.1f})",
                gCurrentFetchingTick.load(), fetching_td_speed,
                gCurrentFetchingLogTick.load(), fetching_le_speed,
                gCurrentIndexingTick.load(), indexing_speed,
                gCurrentVerifyLoggingTick.load(), verify_le_speed);
        requestMapperFrom.clean();
        requestMapperTo.clean();
        responseSCData.clean(10);

        int count = 0;
        while (count++ < sleep_time*10 && !gStopFlag.load()) SLEEP(100);
        if (compareLocalTickWithNetworkCount++ >= 24)
        {
            compareLocalTickWithNetworkCount = 0;
            // looks around and compare network tick once in a while
            uint32_t network_latest_tick;
            uint16_t network_epoch;
            GetLatestTickFromExternalSources(network_latest_tick, network_epoch);
            if (network_latest_tick > 0) {
                gLastSeenNetworkTick.store(network_latest_tick);
            }
            Logger::get()->info("Local Tick: {} | Network tick: {} | Network epoch: {}",
                                gCurrentVerifyLoggingTick.load() -1,
                                network_latest_tick,
                                network_epoch);
        }
        if (checkInQubicGlobalCount++ >= 361 && gAllowCheckInQubicGlobal)
        {
            checkInQubicGlobalCount = 0;
            CheckInQubicGlobal();
        }
    }
    // Signal stop, disconnect sockets first to break any blocking I/O.
    Logger::get()->info("Disconnecting all connections");
    for (int i = 0; i < connPool.size(); i++)
    {
        QCPtr qc;
        if (connPool.get(i, qc))
        {
            qc->disconnect();
        }
    }
    Logger::get()->info("Disconnected all connections");
    // Stop and join producer/request threads first so they cannot enqueue more work.
    verify_thread.join();
    Logger::get()->info("Exited Verifying thread");
    request_thread.join();
    Logger::get()->info("Exited TickDataRequest thread");
    log_request_trusted_nodes_thread.join();
    Logger::get()->info("Exited LogEventRequestTrustedNodes thread");
    indexer_thread.join();
    Logger::get()->info("Exited indexer thread");

    sc_thread.join();
    delete gTCM;
    Logger::get()->info("Exited SC thread");

    if (log_event_verifier_thread.joinable())
    {
        log_event_verifier_thread.join();
        Logger::get()->info("Exited verifyLoggingEvent thread");
    }

    // Now the receivers can drain and exit.
    for (auto& thr : v_recv_thread) thr.join();
    Logger::get()->info("Exited recv threads");

    // Wake all data threads so none remain blocked on MRB.
    int N_data_thread = v_data_thread.size();
    Logger::get()->info("Exiting {} data thread", N_data_thread);
    while (N_data_thread > gExitDataThreadCounter.load())
    {
        const size_t wake_count = v_data_thread.size() * 8; // ensure enough tokens
        std::vector<RequestResponseHeader> tokens(wake_count);
        for (auto& t : tokens) {
            t.randomizeDejavu();
            t.setType(35); // NOP
            t.setSize(8);
        }
        for (size_t i = 0; i < wake_count; ++i) {
            MRB_Data.EnqueuePacket(reinterpret_cast<uint8_t*>(&tokens[i]));
            MRB_Request.EnqueuePacket(reinterpret_cast<uint8_t*>(&tokens[i]));
        }
    }

    for (auto& thr : v_data_thread) thr.join();
    Logger::get()->info("Exited data threads");
    if (cfg.tick_storage_mode != TickStorageMode::Free)
    {
        Logger::get()->info("Exiting garbage cleaner");
        garbage_thread.join();
    }

    if (run_server)
    {
        stopQubicServer();
        Logger::get()->info("Closed Qubic server at port 21842");
    }

    stopRESTServer();
    Logger::get()->info("Closed REST server at port {}", gRpcPort);

    db_close();
    Logger::get()->info("Closed KEYDB connection");
    if (gTickStorageMode == TickStorageMode::Kvrocks)
    {
        db_kvrocks_close();
        Logger::get()->info("Closed KVROCKS connection");
    }
    ProfilerRegistry::instance().printSummary();
    Logger::get()->info("Shutting down logger");
    spdlog::shutdown();
    return 0;
}