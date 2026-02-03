#include "connection.h"
#include <mutex>

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
std::vector<int> ConnectionPool::sendToMany(uint8_t* buffer, int sz, std::size_t howMany, uint8_t type, bool randomDejavu) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> results;
    if (conns_.empty() || howMany == 0) return results;

    // Collect indices of valid connections
    std::vector<std::size_t> idx;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid()) {
            idx.push_back(i);
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

int ConnectionPool::sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu) {
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
    conns_[chosen]->getPasscode((uint64_t*)(buffer+passcodeOffset));
    return conns_[chosen]->enqueueWithHeader(buffer, sz, type, randomDejavu);
}