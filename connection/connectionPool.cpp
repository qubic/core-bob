#include "connection.h"
#include <mutex>

#include "shim.h"
#include "Logger.h"

ConnectionPool::ConnectionPool()
        : rng_(std::random_device{}()) {}

void ConnectionPool::add(const QCPtr& c) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (c) conns_.push_back(c);
}

void ConnectionPool::add(const std::vector<QCPtr>& cs) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& c : cs) {
        if (c) conns_.push_back(c);
    }
}

std::size_t ConnectionPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return conns_.size();
}

bool ConnectionPool::get(int i, QCPtr& qc) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (i < conns_.size())
    {
        qc = conns_[i];
        return true;
    }
    return false;
}

void ConnectionPool::removeDisconnectedClient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return;
    conns_.erase(
            std::remove_if(conns_.begin(), conns_.end(),
                           [](const QCPtr &conn) { return (!conn) || (!conn->isSocketValid() && !conn->isReconnectable()); }),
            conns_.end());
}

void ConnectionPool::randomlyRemove() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return;
    std::uniform_int_distribution<std::size_t> dist(0, conns_.size() - 1);
    auto idx = dist(rng_);
    conns_.erase(conns_.begin() + idx);
}

void ConnectionPool::randomlyRemoveBob() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::size_t> bobIdx;
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isBob()) bobIdx.push_back(i);
    }
    if (bobIdx.empty()) return;
    std::uniform_int_distribution<std::size_t> dist(0, bobIdx.size() - 1);
    auto chosen = bobIdx[dist(rng_)];
    conns_.erase(conns_.begin() + chosen);
}

// Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
int ConnectionPool::sendToRandomBM(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;

    // Build an index list of currently valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid() && conns_[i]->isBM()) {
            idx.push_back(i);
        }
    }
    if (idx.empty()) return -1;

    std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
    auto chosen = idx[dist(rng_)];
    return conns_[chosen]->enqueueWithHeader(buffer, sz, type, randomDejavu);
}

// Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
int ConnectionPool::sendToRandomBM(uint8_t* buffer, int sz) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;

    // Build an index list of currently valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid() && conns_[i]->isBM()) {
            idx.push_back(i);
        }
    }
    if (idx.empty()) return -1;

    std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
    auto chosen = idx[dist(rng_)];
    return conns_[chosen]->enqueueSend(buffer, sz);
}

// Sends to the best BM connection. Returns bytes sent, or -1 if none could be used.
int ConnectionPool::sendToBestBM(uint8_t* buffer, int sz) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;
    int chosen = -1;
    uint32_t maxTick = 0;
    for (int i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid() && conns_[i]->isBM()) {
            if (conns_[i]->getLatestTick() > maxTick) {
                chosen = i;
                maxTick = conns_[i]->getLatestTick();
            }
        }
    }
    if (chosen != -1) return conns_[chosen]->enqueueSend(buffer, sz);
    return -1;
}

// Sends to one random valid connection. Returns bytes sent, or -1 if none could be used.
int ConnectionPool::sendToRandom(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;

    // Build an index list of currently valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid()) {
            idx.push_back(i);
        }
    }
    if (idx.empty()) return -1;

    std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
    auto chosen = idx[dist(rng_)];
    return conns_[chosen]->enqueueWithHeader(buffer, sz, type, randomDejavu);
}

// Sends to 'howMany' distinct random valid connections (or fewer if not enough are valid).
// Returns a vector of bytes-sent per selected connection, in the order of selection.
std::vector<int> ConnectionPool::sendToMany(uint8_t* buffer, int sz, std::size_t howMany, uint8_t type, bool randomDejavu, int nodeType) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> results;
    if (conns_.empty() || howMany == 0) return results;

    // Collect indices of valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid()) {
            if (nodeType == NODE_TYPE_ANY) idx.push_back(i);
            if (nodeType == NODE_TYPE_BM && conns_[i]->isBM()) idx.push_back(i);
            if (nodeType == NODE_TYPE_BOB && conns_[i]->isBob()) idx.push_back(i);
        }
    }
    if (idx.empty()) return results;

    // Shuffle and take first K
    std::shuffle(idx.begin(), idx.end(), rng_);
    if (howMany < idx.size()) {
        idx.resize(howMany);
    }

    results.reserve(idx.size());
    for (auto i : idx) {
        results.push_back(conns_[i]->enqueueWithHeader(buffer, sz, type, randomDejavu));
    }
    return results;
}

int ConnectionPool::sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu, int nodeType) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;

    // Build an index list of currently valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid()) {
            if (nodeType == NODE_TYPE_ANY) idx.push_back(i);
            if (nodeType == NODE_TYPE_BM && conns_[i]->isBM()) idx.push_back(i);
            if (nodeType == NODE_TYPE_BOB && conns_[i]->isBob()) idx.push_back(i);
        }
    }
    if (idx.empty()) return -1;
    std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
    auto chosen = idx[dist(rng_)];
    conns_[chosen]->getPasscode((uint64_t*)(buffer+passcodeOffset));
    return conns_[chosen]->enqueueWithHeader(buffer, sz, type, randomDejavu);
}

int ConnectionPool::smartTickRequest(uint8_t* buffer, int sz, uint8_t type, bool randomDejavu) {
    if (gLastSeenNetworkTick > gCurrentFetchingTick + 10) {
        sendToMany(buffer, sz, 1, type, randomDejavu, NODE_TYPE_BM);
        sendToMany(buffer, sz, 1, type, randomDejavu, NODE_TYPE_BOB);
        return 3;
    }
    std::uniform_int_distribution<std::size_t> dist{};
    if (dist(rng_) % 2 == 0) {
        sendToMany(buffer, sz, 1, type, randomDejavu, NODE_TYPE_BM);
        return 2;
    }
    sendToMany(buffer, sz, 1, type, randomDejavu, NODE_TYPE_BOB);
    return 1;
}

int ConnectionPool::smartLogRequest(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu) {
    if (gLastSeenNetworkTick > gCurrentFetchingLogTick + 10) {
        int r0 = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BM);
        int r1 = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BOB);
        return r0 + r1;
    }
    std::uniform_int_distribution<std::size_t> dist{};
    if (dist(rng_) % 2 == 0) {
        return sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BM);
    }
    return sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BOB);
}

void peerWatchdog(ConnectionPool& conns_)
{
    std::chrono::seconds checkPeriodPeerRefresh = std::chrono::seconds(180); // 3 minutes
    std::chrono::seconds checkPeriodLastTick = std::chrono::seconds(30); // 30 sec
    auto lastCheckPeerRefresh = std::chrono::high_resolution_clock::now();
    auto lastCheckLastTick = std::chrono::high_resolution_clock::now();
    while (!gStopFlag.load(std::memory_order_relaxed)) {
        auto now = std::chrono::high_resolution_clock::now();
        if (now - lastCheckPeerRefresh >= checkPeriodPeerRefresh) {
            lastCheckPeerRefresh = now;
            uint64_t nowTimestamp = std::time(nullptr);
            uint64_t oldest = std::numeric_limits<uint64_t>::max();
            QCPtr worst = nullptr;
            int N = conns_.size();
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (conns_.get(i,qc)) {
                    if (qc) {
                        if (!qc->isSocketValid()) {
                            worst = qc;
                            break;
                        }
                        uint64_t lastActivityTimestamp = qc->getLastActivityTimestamp();
                        // if a connection has not been active for more than 30 seconds, consider it for removal
                        if (lastActivityTimestamp < nowTimestamp - 30) {
                            if (oldest > lastActivityTimestamp) {
                                worst = qc;
                                oldest = lastActivityTimestamp;
                            }
                        }
                    }
                }
            }
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<int> dist(0, N - 1);
            // if there is no worst, randomly pick 1
            if (!worst) {
                if (N > 0) {
                    int randomIdx = dist(gen);
                    conns_.get(randomIdx, worst);
                }
            }
            if (worst) {
                std::vector<std::string> newPeer;
                std::string mode = dist(gen) % 2 == 0 ? "closest" : "random";
                if (worst->isBM()) {
                    newPeer = GetPeerFromDNS(1, 0, mode);
                } else {
                    newPeer = GetPeerFromDNS(0, 1, mode);
                }
                ParsedEndpoint parsed;
                if (!newPeer.empty() && parseEndpoint(newPeer[0], parsed)) {
                    Logger::get()->info("Replaced peer {}:{} with {}:{}", worst->getNodeIp(), worst->getNodePort(),
                                                                             parsed.ip, parsed.port);
                    worst->replacePeer(parsed.ip, parsed.port);
                    worst->setNodeType(parsed.nodeType);
                    if (parsed.has_passcode) {
                        worst->updatePasscode(parsed.passcode_arr);
                    }
                    worst->disconnect(); // this will be auto reconnect in the IO loop
                }
            }
        }
        if (now - lastCheckLastTick >= checkPeriodLastTick) {
            lastCheckLastTick = now;
            int N = conns_.size();
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (conns_.get(i,qc)) {
                    if (qc) {
                        if (!qc->isSocketValid()) {
                            qc->askForLatestTick();
                        }
                    }
                }
            }
        }
        SLEEP(1000);
    }
    Logger::get()->info("Peer watchdog thread stopped gracefully");
}