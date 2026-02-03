#include <memory>
#include <stdexcept>
#include <algorithm> // For std::min
#include <thread>

#include "connection.h"
#include <arpa/inet.h>
#include <cerrno> // for errno
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/database/db.h"
#include "src/global_var.h"
#include "src/shim.h"

#include <src/logger/logger.h>
static int do_connect(const char* nodeIp, int nodePort)
{
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        Logger::get()->error("socket() failed: {} ({})", errno, strerror(errno));
        return -1;
    }

    // Close-on-exec for safety
    {
        int flags = fcntl(serverSocket, F_GETFD);
        if (flags >= 0) {
            (void)fcntl(serverSocket, F_SETFD, flags | FD_CLOEXEC);
        }
    }

    // Configure timeouts (best-effort)
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof tv) < 0) {
        Logger::get()->warn("setsockopt(SO_RCVTIMEO) failed: {} ({})", errno, strerror(errno));
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof tv) < 0) {
        Logger::get()->warn("setsockopt(SO_SNDTIMEO) failed: {} ({})", errno, strerror(errno));
    }

    // Improve latency and resilience (best-effort)
    {
        int on = 1;
        (void)setsockopt(serverSocket, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        (void)setsockopt(serverSocket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    }

    sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(nodePort));

    if (inet_pton(AF_INET, nodeIp, &addr.sin_addr) <= 0) {
        Logger::get()->error("Invalid IP address '{}'", nodeIp);
        close(serverSocket);
        return -1;
    }

    // Handle EINTR for blocking connect
    int rc;
    do {
        rc = connect(serverSocket, (const sockaddr*)&addr, sizeof(addr));
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) {
//        Logger::get()->error("Failed to connect {}:{} | errno {} ({})", nodeIp, nodePort, errno, strerror(errno));
        close(serverSocket);
        return -1;
    }

    return serverSocket;
}

void QubicConnection::initSendThread()
{
    mBuffer = std::make_unique<MutexRoundBuffer>(0xffffff);
    shouldStop = false;
    sendThreadHDL = std::thread(&QubicConnection::sendThread, this);
}

QubicConnection::QubicConnection(const char* nodeIp, int nodePort)
{
    memset(mPasscode, 0xff, 8*4);
    strncpy(mNodeIp, nodeIp, sizeof(mNodeIp) - 1);
    mNodeIp[sizeof(mNodeIp) - 1] = '\0';
    mNodePort = nodePort;
    mSocket = -1;
    mSocket = do_connect(mNodeIp, mNodePort);
    mReconnectable = true;
    initSendThread();
    nodeType = "null";
}
QubicConnection::~QubicConnection()
{
    disconnect();
    shouldStop = true;
    if (sendThreadHDL.joinable()) {
        sendThreadHDL.join();
    }
}

int QubicConnection::receiveData(uint8_t* buffer, int sz)
{
    int count = 0;
    while (sz > 0)
    {
        auto ret = recv(mSocket, (char*)buffer + count, std::min(1024, sz), 0);
        if (ret < 0)
        {
            return ret;
        }
        if (ret == 0)
        {
            return count;
        }
        count += ret;
        sz -= ret;
    }
	return count;
}
void QubicConnection::receiveAFullPacket(RequestResponseHeader& header, std::vector<uint8_t>& buffer)
{
    // first receive the header
    int recvByte = receiveData((uint8_t*)&header, sizeof(RequestResponseHeader));
    if (recvByte < 0)
    {
        throw std::logic_error("Socket Error");
    }
    if (recvByte != sizeof(RequestResponseHeader)) throw std::logic_error("Failed to get header.");
    int packet_size = header.size();
    if (packet_size > RequestResponseHeader::max_size)
    {
        throw std::logic_error("Malformed header data.");
    }
    buffer.resize(header.size());
    memcpy(buffer.data(), &header, sizeof(RequestResponseHeader));
    // receive the rest
    int remaining_size = packet_size - sizeof(RequestResponseHeader);
    recvByte = receiveData(buffer.data() + sizeof(RequestResponseHeader), remaining_size);
    if (recvByte != remaining_size) throw std::logic_error("Not received enough data.");
}

void QubicConnection::sendEndPacket(uint32_t dejavu)
{
    RequestResponseHeader nop{};
    nop.setType(35);
    if (dejavu != 0xffffffff) nop.setDejavu(dejavu);
    else nop.randomizeDejavu();
    nop.setSize(sizeof(RequestResponseHeader));
    enqueueSend((uint8_t *) &nop, sizeof(nop));
}

void QubicConnection::sendThread()
{
    std::vector<uint8_t> local_buf(0xffffff);
    uint32_t size;
    while (!shouldStop)
    {
        if (mSocket != -1 && mBuffer->TryGetPacket(local_buf.data(), size))
        {
            auto buffer = local_buf.data();
            while (size > 0 && mSocket != -1) {
                int numberOfBytes = send(mSocket, buffer, size, MSG_NOSIGNAL);
                if (numberOfBytes < 0) {
                    if (errno == EINTR) {
                        // Interrupted by a signal, retry the send
                        continue;
                    }
                    // Peer likely closed (EPIPE) or connection reset, mark socket invalid
                    Logger::get()->debug("send() failed on socket {} with errno {}. Disconnecting.", mSocket, errno);
                    disconnect();
                }
                if (numberOfBytes == 0) {
                    // Treat as closed
                    Logger::get()->debug("send() returned 0 on socket {}. Disconnecting.", mSocket);
                    disconnect();
                }
                buffer += numberOfBytes;
                size   -= numberOfBytes;
            }

        }
        else
        {
            SLEEP(10);
        }
    }
}

int QubicConnection::enqueueSend(uint8_t* buffer, int sz)
{
    if (sz >= 8)
    {
        RequestResponseHeader header;
        memcpy((void*)&header, buffer, 8);
        uint32_t dejavu = header.getDejavu();
        if (dejavu)
        {
            requestMapperFrom.add(dejavu, buffer, sz, nullptr);
        }
    }
    mBuffer->EnqueuePacket(buffer);
    return sz;
}

int QubicConnection::enqueueWithHeader(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu)
{
    std::vector<uint8_t> buf;
    buf.resize(sz + sizeof(RequestResponseHeader));
    if (sz) memcpy(buf.data() + sizeof(RequestResponseHeader), buffer, sz);
    RequestResponseHeader h{};
    h.setType(type);
    h.setSize(sz+sizeof(RequestResponseHeader));
    if (randomDejavu) h.randomizeDejavu();
    else h.setDejavu(0);
    memcpy(buf.data(), &h, sizeof(RequestResponseHeader));
    return enqueueSend(buf.data(), buf.size());
}

void QubicConnection::getComputorList(const uint16_t epoch, Computors& compList)
{
    RequestResponseHeader header{};
    std::vector<uint8_t> packet;
    int count = 0;
    while (count < 200)
    {
        // trying to get until Computors packet arrive
        // resend each 20 packets
        if ( count++ % 20 == 0 )
        {
            header.setSize(sizeof(header));
            header.randomizeDejavu();
            header.setType(REQUEST_COMPUTOR_LIST);
            enqueueSend((uint8_t *) &header, 8);
        }
        RequestResponseHeader header{};
        receiveAFullPacket(header, packet);
        if (!packet.empty())
        {
            memcpy((void*)&header, packet.data(), 8);
            if (header.type() == 2)
            {
                if (header.size() == 8 + sizeof(Computors))
                {
                    memcpy((void*)&compList, packet.data() + 8, sizeof(Computors));
                    break;
                }
            }
        }
    }
}

void QubicConnection::doHandshake()
{
    struct
    {
        RequestResponseHeader header;
        uint8_t ip[4][4];
    } payload;
    memset(&payload, 0, sizeof(payload));
    payload.header.randomizeDejavu();
    payload.header.setType(0);
    payload.header.setSize(sizeof(payload));
    enqueueSend((uint8_t *) &payload, sizeof(payload));
}

void QubicConnection::getBootstrapTickInfo(uint32_t& tick, uint16_t& epoch)
{
    RequestResponseHeader header{};
    std::vector<uint8_t> packet;
    int count = 0;
    while (1)
    {
        // trying to get until tickinfo packet arrive
        // resend each 20 packets
        if ( count++ % 20 == 0 )
        {
            header.setSize(sizeof(header));
            header.randomizeDejavu();
            header.setType(REQUEST_CURRENT_TICK_INFO);
            enqueueSend((uint8_t *) &header, 8);
        }
        RequestResponseHeader header{};
        receiveAFullPacket(header, packet);
        if (!packet.empty())
        {
            memcpy((void*)&header, packet.data(), 8);
            if (header.type() == RESPOND_CURRENT_TICK_INFO)
            {
                if (header.size() == 8 + sizeof(CurrentTickInfo))
                {
                    CurrentTickInfo ctick{};
                    memcpy((void*)&ctick, packet.data()+8, sizeof(CurrentTickInfo));
                    tick = ctick.initialTick;
                    epoch = ctick.epoch;
                    break;
                }
            }
        }
    }
}

void QubicConnection::disconnect()
{
    if (mSocket >= 0) {
        shutdown(mSocket, SHUT_RDWR);
        close(mSocket);
        mSocket = -1;
    }
}

bool QubicConnection::reconnect()
{
    // Disallow reconnect if this connection was created from an external socket
    if (!mReconnectable) {
        Logger::get()->debug("reconnect() called on a non-reconnectable connection.");
        return false;
    }
    if (mSocket >= 0) {
        close(mSocket);
        mSocket = -1;
    }

    // Attempt to re-establish connection
    int newSocket = do_connect(mNodeIp, mNodePort);
    if (newSocket < 0) {
        Logger::get()->trace("Failed to reconnect {}:{}", mNodeIp, mNodePort);
        return false;
    }

    mSocket = newSocket;
    return true;
}

QubicConnection::QubicConnection(int existingSocket)
{
    memset(mPasscode, 0xff, 8*4);
    mNodeIp[0] = '\0';
    mNodePort = 0;
    mSocket = existingSocket;
    mReconnectable = false;
    if (mSocket >= 0) {
        // Configure timeouts (best-effort)
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (setsockopt(mSocket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof tv) < 0) {
            Logger::get()->warn("setsockopt(SO_RCVTIMEO) failed: {} ({})", errno, strerror(errno));
        }
        if (setsockopt(mSocket, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof tv) < 0) {
            Logger::get()->warn("setsockopt(SO_SNDTIMEO) failed: {} ({})", errno, strerror(errno));
        }
        int on = 1;
        (void)setsockopt(mSocket, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        (void)setsockopt(mSocket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    }

    initSendThread();
    nodeType = "client";
}

void parseConnection(ConnectionPool& connPoolAll,
                     std::vector<std::string>& endpoints)
{
    // Try endpoints in order, connect to the first that works

    for (const auto& endpoint : endpoints) {
        // Expected format: nodeType:ip:port[:pass0-pass1-pass2-pass3]
        // nodeType must be "BM" (baremetal) or "bob"
        auto p0 = endpoint.find(':');
        if (p0 == std::string::npos || p0 == 0 || p0 == endpoint.size() - 1) {
            Logger::get()->warn("Skipping invalid endpoint '{}', expected nodeType:ip:port or nodeType:ip:port:pass0-pass1-pass2-pass3", endpoint);
            continue;
        }
        std::string nodeType = endpoint.substr(0, p0);
        if (nodeType != "BM" && nodeType != "bob") {
            Logger::get()->warn("Skipping endpoint '{}': nodeType must be 'BM' or 'bob'", endpoint);
            continue;
        }
        std::string rest = endpoint.substr(p0 + 1);

        // Parse ip:port[:pass0-pass1-pass2-pass3] from rest
        auto p1 = rest.find(':');
        if (p1 == std::string::npos || p1 == 0 || p1 == rest.size() - 1) {
            Logger::get()->warn("Skipping invalid endpoint '{}', expected nodeType:ip:port or nodeType:ip:port:pass0-pass1-pass2-pass3", endpoint);
            continue;
        }
        auto p2 = rest.find(':', p1 + 1);
        std::string ip = rest.substr(0, p1);
        std::string port_str;
        std::string passcode_str;

        if (p2 == std::string::npos) {
            port_str = rest.substr(p1 + 1);
        } else {
            if (p2 == rest.size() - 1) {
                Logger::get()->warn("Skipping endpoint '{}': missing passcode after second ':'", endpoint);
                continue;
            }
            port_str = rest.substr(p1 + 1, p2 - (p1 + 1));
            passcode_str = rest.substr(p2 + 1);
        }

        int port = 0;
        try {
            port = std::stoi(port_str);
            if (port <= 0 || port > 65535) {
                throw std::out_of_range("port out of range");
            }
        } catch (...) {
            Logger::get()->warn("Skipping endpoint '{}': invalid port '{}'", endpoint, port_str);
            continue;
        }

        // Optional passcode parsing
        bool has_passcode = false;
        uint64_t passcode_arr[4] = {0,0,0,0};
        if (!passcode_str.empty()) {
            // Split by '-'
            uint64_t parsed[4];
            size_t start = 0;
            int idx = 0;
            while (idx < 4 && start <= passcode_str.size()) {
                size_t dash = passcode_str.find('-', start);
                auto token = passcode_str.substr(start, (dash == std::string::npos) ? std::string::npos : (dash - start));
                if (token.empty()) break;
                try {
                    parsed[idx] = static_cast<uint64_t>(std::stoull(token, nullptr, 10));
                } catch (...) {
                    idx = -1; // mark error
                    break;
                }
                idx++;
                if (dash == std::string::npos) break;
                start = dash + 1;
            }
            if (idx == 4) {
                memcpy(passcode_arr, parsed, sizeof(parsed));
                has_passcode = true;
            } else {
                Logger::get()->warn("Skipping endpoint '{}': invalid passcode format, expected 4 uint64 separated by '-'", endpoint);
                continue;
            }
        }

        QCPtr conn = make_qc(ip.c_str(), port);
        conn->setNodeType(nodeType);
        if (has_passcode) {
            conn->updatePasscode(passcode_arr);
        }
        connPoolAll.add(conn);
        Logger::get()->info("Added {} node {}:{}{}", nodeType, ip, port, has_passcode ? " (trusted)" : "");
    }
}

void doHandshakeAndGetBootstrapInfo(ConnectionPool& cp, bool isTrusted, uint32_t& maxInitTick, uint16_t& maxInitEpoch)
{
    const auto errorBackoff = 1000;
    for (int i = 0; i < cp.size(); i++)
    {
        QCPtr conn = nullptr;
        if (!cp.get(i, conn)) continue;
        try {
            if (conn->isSocketValid())
            {
                uint32_t initTick = 0;
                uint16_t initEpoch = 0;
                conn->doHandshake();
                conn->getBootstrapTickInfo(initTick, initEpoch);
                maxInitTick = std::max(maxInitTick, initTick);
                maxInitEpoch = std::max(maxInitEpoch, initEpoch);
            }
            else
            {
                SLEEP(errorBackoff);
                conn->reconnect();
            }
        }
        catch (...)
        {
            SLEEP(errorBackoff);
            conn->reconnect();
        }
    }
}

void getComputorList(ConnectionPool& cp, std::string arbitratorIdentity)
{
    const auto errorBackoff = 1000;
    for (int i = 0; i < cp.size(); i++) {
        QCPtr conn = nullptr;
        if (!cp.get(i, conn)) continue;
        try {
            if (computorsList.epoch != gCurrentProcessingEpoch.load())
            {
                if (!db_get_computors(gCurrentProcessingEpoch.load(),computorsList))
                {
                    Logger::get()->warn("Trying to get computor list for epoch {}...", gCurrentProcessingEpoch.load());
                    Computors comp{};
                    conn->getComputorList(gCurrentProcessingEpoch.load(),comp);
                    uint8_t digest[32];
                    uint8_t arbitratorPublicKey[32];
                    getPublicKeyFromIdentity(arbitratorIdentity.c_str(), arbitratorPublicKey);
                    KangarooTwelve((uint8_t*)&comp, sizeof(comp) - 64, digest, 32);
                    if (verify(arbitratorPublicKey, digest, comp.signature))
                    {
                        db_insert_computors(comp);
                        computorsList = comp;
                    }
                    else
                    {
                        Logger::get()->critical("Invalid signature in computor list. ARB {}", arbitratorIdentity);
                    }
                }
            }
        }
        catch (...)
        {
            SLEEP(errorBackoff);
            conn->reconnect();
        }
    }
}