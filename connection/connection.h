#pragma once
#include <cstdint>
#include <utility>
#include <vector>
#include <memory>
#include <random>
#include <algorithm>
#include <atomic>
#include <mutex>
#include "structs.h"
#include "SpecialBufferStructs.h"
#define NODE_TYPE_ANY 0
#define NODE_TYPE_BOB 1
#define NODE_TYPE_BM 2
struct ParsedEndpoint
{
    std::string endpoint;
    std::string nodeType;
    std::string ip;
    int port = 0;
    bool has_passcode = false;
    uint64_t passcode_arr[4] = {0, 0, 0, 0};
};
// Not thread safe
class QubicConnection
{
public:
    QubicConnection(const char* nodeIp, int nodePort);
    ~QubicConnection();
    int receiveData(uint8_t* buffer, int sz, int fd);
    int enqueueSend(uint8_t* buffer, int sz);
    int enqueueWithHeader(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);
    void receiveAFullPacket(RequestResponseHeader& header, std::vector<uint8_t>& buffer);
    bool reconnect();
    void disconnect();
    bool isSocketValid()
    {
        return mSocket.load(std::memory_order_relaxed) >= 0;
    }
    char* getNodeIp() { return mNodeIp;}
    uint16_t getNodePort() { return mNodePort;}
    void updatePasscode(const uint64_t passcode[4]){ memcpy(mPasscode, passcode, 8*4); }
    void getPasscode(uint64_t* passcode){ memcpy(passcode, mPasscode, 8*4); }
    // Construct from an already-open socket; this connection is NON-reconnectable.
    QubicConnection(int existingSocket);
    // Expose whether this connection is allowed to reconnect.
    bool isReconnectable()
    {
        return mReconnectable;
    }

    bool isBM()
    {
        return nodeType == "BM";
    }
    bool isBob(){ return nodeType == "bob";}
    void trackLastActivity();
    uint64_t getLastActivityTimestamp();
    void replacePeer(const std::string& ip, const uint16_t port) {
        // Serialize against reconnect()'s do_connect(mNodeIp,...) read.
        std::lock_guard<std::mutex> lk(mSocketMutex);
        memset(mNodeIp, 0, 32);
        size_t n = ip.size();
        if (n > sizeof(mNodeIp) - 1) n = sizeof(mNodeIp) - 1;
        memcpy(mNodeIp, ip.c_str(), n);
        mNodePort = port;
    }
    void askForLatestTick();
    void updateLatestTick(uint32_t tick);
    uint32_t getLatestTick(){return mLatestTick;}
    // non-thread safe operation, only use these functions for bootstrap
    void getBootstrapTickInfo(uint32_t& tick, uint16_t& epoch);
    void getBootstrapInfo(uint32_t& tick, uint16_t& epoch);
    void doHandshake();
    void getComputorList(const uint16_t epoch, Computors& compList);
    void sendEndPacket(uint32_t dejavu = 0xffffffff);
    void setNodeType(std::string _nodeType) { nodeType = std::move(_nodeType); }

    // Diagnostic: count of RespondLog packets this peer has delivered since
    // process start. Read by the periodic state line so traffic distribution
    // across BMs is visible at a glance — useful for spotting a peer that
    // delivers a lot of "wrong tick" logs.
    void incLogsDelivered() { mLogsDelivered.fetch_add(1, std::memory_order_relaxed); }
    uint64_t getLogsDelivered() const { return mLogsDelivered.load(std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> mLogsDelivered{0};
    std::atomic<uint64_t> lastActivityTimestamp;
    char mNodeIp[32];
    int mNodePort;
    std::atomic<int> mSocket;
    // Serializes fd open/close across receiver, sendThread and watchdog
    // threads so a concurrent disconnect()/reconnect() can never double-close
    // an fd (fd-reuse would otherwise close an unrelated live socket).
    std::mutex mSocketMutex;
    uint32_t mLatestTick;
    std::unique_ptr<MutexRoundBuffer> mBuffer;
    uint64_t mPasscode[4]; // for loggingEvent
    bool mReconnectable;   // whether reconnect() is allowed
    std::string nodeType;

    void initSendThread();
    void sendThread();
    std::thread sendThreadHDL;
    bool shouldStop;
};
typedef std::shared_ptr<QubicConnection> QCPtr;
static QCPtr make_qc(const char* nodeIp, int nodePort)
{
    return std::make_shared<QubicConnection>(nodeIp, nodePort);
}
// Factory to build a NON-reconnectable connection from an existing socket.
static QCPtr make_qc_by_socket(int existingSocket)
{
    return std::make_shared<QubicConnection>(existingSocket);
}

class ConnectionPool {
public:
    ConnectionPool();

    void add(const QCPtr& c);
    void add(const std::vector<QCPtr>& cs);

    std::size_t size() const;
    bool get(int i, QCPtr& qc);

    void randomlyRemove();
    void randomlyRemoveBob();
    void removeDisconnectedClient();

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandomBM(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandomBM(uint8_t* buffer, int sz);
    // Sends to the best BM connection. Returns bytes sent, or -1 if none could be used.
    int sendToBestBM(uint8_t* buffer, int sz);
    // Sends to the ALL BM connection. Returns bytes sent, or -1 if none could be used.
    void sendToAllBM(uint8_t* buffer, int sz);

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandom(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);

    // Sends to 'howMany' distinct random valid connections (or fewer if not enough are valid).
    // Returns a vector of bytes-sent per selected connection, in the order of selection.
    std::vector<int> sendToMany(uint8_t* buffer, int sz, std::size_t howMany, uint8_t type, bool randomDejavu, int nodeType);

    // depends on node status, bob will decide which and how many ticks request packets need to be sent out
    int smartTickRequest(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);

    // depends on node status, bob will decide which and how many ticks request packets need to be sent out.
    // If destSummary is non-null, it's filled with a short human-readable
    // description of the chosen peer(s) for logging/diagnostic purposes.
    int smartLogRequest(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu,
                        std::string* destSummary = nullptr);

    int sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu, int nodeType,
                                 std::string* destSummary = nullptr);

    bool checkExistIp(const std::string& ip) const;
private:
    std::vector<QCPtr> conns_;
    std::mt19937 rng_;
    mutable std::mutex mutex_;
};
bool parseEndpoint(const std::string endpoint, ParsedEndpoint& parsed);
void parseConnection(ConnectionPool& connPoolAll,
                     std::vector<std::string>& endpoints);
void doHandshakeAndGetBootstrapInfo(ConnectionPool& cp, bool isTrusted, uint32_t& maxInitTick, uint16_t& maxInitEpoch);
void getComputorList(ConnectionPool& cp, std::string arbitratorIdentity);
std::vector<std::string> GetPeerFromDNS(const int nLite, const int nBob, const std::string mode);
bool DownloadStateFiles(uint16_t epoch);
void GetLatestTickFromExternalSources(uint32_t& tick, uint16_t& epoch);
void CheckInQubicGlobal();
// peerWatchdog runs two independent checks:
//   - idle-disconnect (every 30s, ALWAYS on): for each connection idle longer
//     than IDLE_DISCONNECT_S, call disconnect(). The IO loop reconnects to the
//     same IP/port via QubicConnection::reconnect(). This survives silent
//     half-open sockets caused by NAT/firewall idle drop or peer-side hangs.
//   - DNS-replace (every 180s, allowDnsReplace==true): for the worst-idle
//     connection, swap it out for a fresh peer obtained from the DNS-style
//     discovery service. Used when bob auto-discovered peers at startup; for
//     user-configured P2P_NODES we keep their chosen IPs and only reconnect.
void peerWatchdog(ConnectionPool& conns_, bool allowDnsReplace);