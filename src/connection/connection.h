#pragma once
#include "src/core/structs.h"
#include "src/special_buffer_structs.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <utility>
#include <vector>

// Not thread safe
class QubicConnection
{
public:
    QubicConnection(const char* nodeIp, int nodePort);
    ~QubicConnection();
    int receiveData(uint8_t* buffer, int sz);
    int enqueueSend(uint8_t* buffer, int sz);
    int enqueueWithHeader(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);
    void receiveAFullPacket(RequestResponseHeader& header, std::vector<uint8_t>& buffer);
    bool reconnect();
    void disconnect();
    bool isSocketValid()
    {
        return mSocket>=0;
    }
    char* getNodeIp() { return mNodeIp;}
    void updatePasscode(const uint64_t passcode[4]){ memcpy(mPasscode, passcode, 8*4); }
    void getPasscode(uint64_t* passcode){ memcpy(passcode, mPasscode, 8*4); }
    // Construct from an already-open socket; this connection is NON-reconnectable.
    QubicConnection(int existingSocket);
    // Expose whether this connection is allowed to reconnect.
    bool isReconnectable()
    {
        return mReconnectable;
    }

    // non-thread safe operation, only use these functions for bootstrap
    void getBootstrapTickInfo(uint32_t& tick, uint16_t& epoch);
    void getBootstrapInfo(uint32_t& tick, uint16_t& epoch);
    void doHandshake();
    void getComputorList(const uint16_t epoch, Computors& compList);
    void sendEndPacket(uint32_t dejavu = 0xffffffff);
    void setNodeType(std::string _nodeType) { nodeType = std::move(_nodeType); }
    bool isBM()
    {
        return nodeType == "BM";
    }
    bool isBob(){ return nodeType == "bob";}
private:
    char mNodeIp[32];
    int mNodePort;
    int mSocket;
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
    void removeDisconnectedClient();

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandomBM(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandomBM(uint8_t* buffer, int sz);

    // Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
    int sendToRandom(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu);

    // Sends to 'howMany' distinct random valid connections (or fewer if not enough are valid).
    // Returns a vector of bytes-sent per selected connection, in the order of selection.
    std::vector<int> sendToMany(uint8_t* buffer, int sz, std::size_t howMany, uint8_t type, bool randomDejavu);

    int sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu);

private:
    std::vector<QCPtr> conns_;
    std::mt19937 rng_;
    mutable std::mutex mutex_;
};

void parseConnection(ConnectionPool& connPoolAll,
                     std::vector<std::string>& endpoints);
void doHandshakeAndGetBootstrapInfo(ConnectionPool& cp, bool isTrusted, uint32_t& maxInitTick, uint16_t& maxInitEpoch);
void getComputorList(ConnectionPool& cp, std::string arbitratorIdentity);
std::vector<std::string> GetPeerFromDNS();
bool DownloadStateFiles(uint16_t epoch);
void GetLatestTickFromExternalSources(uint32_t& tick, uint16_t& epoch);
void CheckInQubicGlobal();