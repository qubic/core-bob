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
    static uint64_t logCounter = 0;
    if (logCounter++ % 300 == 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        int bmValid = 0, bobValid = 0, bmTotal = 0, bobTotal = 0;
        for (std::size_t i = 0; i < conns_.size(); ++i) {
            if (conns_[i]) {
                if (conns_[i]->isBM()) { bmTotal++; if (conns_[i]->isSocketValid()) bmValid++; }
                if (conns_[i]->isBob()) { bobTotal++; if (conns_[i]->isSocketValid()) bobValid++; }
            }
        }
        Logger::get()->info("smartLogRequest pool: BM {}/{} valid, bob {}/{} valid", bmValid, bmTotal, bobValid, bobTotal);
    }
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
