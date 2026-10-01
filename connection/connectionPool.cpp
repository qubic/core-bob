#include "connection.h"
#include <mutex>
#include <unordered_map>
#include <algorithm>

#include "shim.h"
#include "spdlogDriver/Logger.h"

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
    uint64_t maxTimestamp = 0;
    for (int i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid() && conns_[i]->isBM()) {
            if (conns_[i]->getLastActivityTimestamp() > maxTimestamp) {
                chosen = i;
                maxTimestamp = conns_[i]->getLastActivityTimestamp();
            }
        }
    }
    if (chosen != -1) return conns_[chosen]->enqueueSend(buffer, sz);
    return -1;
}

// Sends to the ALL BM connections
void ConnectionPool::sendToAllBM(uint8_t* buffer, int sz) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return;
    for (int i = 0; i < conns_.size(); ++i) {
        if (conns_[i] && conns_[i]->isSocketValid() && conns_[i]->isBM()) {
            conns_[i]->enqueueSend(buffer, sz);
        }
    }
    return;
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

int ConnectionPool::sendWithPasscodeToRandom(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu, int nodeType,
                                             std::string* destSummary) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return -1;

    // Build an index list of currently valid connections, peers flagged bad kept aside
    std::vector<std::size_t> idx;
    std::vector<std::size_t> idxBad;
    idx.reserve(conns_.size());
    for (std::size_t i = 0; i < conns_.size(); ++i) {
        if (!conns_[i] || !conns_[i]->isSocketValid()) continue;
        bool typeMatches = false;
        if (nodeType == NODE_TYPE_ANY) typeMatches = true;
        if (nodeType == NODE_TYPE_BM && conns_[i]->isBM()) typeMatches = true;
        if (nodeType == NODE_TYPE_BOB && conns_[i]->isBob()) typeMatches = true;
        if (!typeMatches) continue;
        if (conns_[i]->isBad()) {
            idxBad.push_back(i);
        } else {
            idx.push_back(i);
        }
    }
    // every peer of this type is flagged: a bad peer still beats no peer
    if (idx.empty()) idx = idxBad;
    if (idx.empty()) return -1;
    std::uniform_int_distribution<std::size_t> dist(0, idx.size() - 1);
    auto chosen = idx[dist(rng_)];
    conns_[chosen]->getPasscode((uint64_t*)(buffer+passcodeOffset));
    if (destSummary) {
        *destSummary = std::string(conns_[chosen]->getNodeIp()) + ":" + std::to_string(conns_[chosen]->getNodePort());
    }
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

int ConnectionPool::smartLogRequest(uint8_t* buffer, int passcodeOffset, int sz, uint8_t type, bool randomDejavu,
                                    std::string* destSummary) {
    if (gLastSeenNetworkTick > gCurrentFetchingLogTick + 10) {
        std::string bmDest, bobDest;
        int r0 = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BM, &bmDest);
        int r1 = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BOB, &bobDest);
        if (destSummary) {
            *destSummary = (bmDest.empty() ? "-" : "BM:" + bmDest) + " + " + (bobDest.empty() ? "-" : "BOB:" + bobDest);
        }
        return r0 + r1;
    }
    std::uniform_int_distribution<std::size_t> dist{};
    if (dist(rng_) % 2 == 0) {
        std::string dest;
        int r = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BM, &dest);
        if (destSummary) *destSummary = "BM:" + dest;
        return r;
    }
    std::string dest;
    int r = sendWithPasscodeToRandom(buffer, passcodeOffset, sz, type, randomDejavu, NODE_TYPE_BOB, &dest);
    if (destSummary) *destSummary = "BOB:" + dest;
    return r;
}

bool ConnectionPool::checkExistIp(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conns_.empty()) return false;
    int N = conns_.size();
    for (int i = 0; i < N; ++i) {
        std::string ipStr = conns_[i]->getNodeIp();
        if (ipStr == ip) {
            return true;
        }
    }
    return false;
}

void peerWatchdog(ConnectionPool& conns_, bool allowDnsReplace, bool autoban)
{
    // No useful incoming data for 300s -> force reconnect.
    constexpr uint64_t IDLE_DISCONNECT_S = 300;
    // Bad-peer detection: under half of the log requests answered promptly for STRIKES_TO_FLAG
    // samples in a row -> rotate the peer out and keep its IP out of discovery for a while.
    constexpr int STRIKES_TO_FLAG = 2;
    // Peer that answers but has no logs for us: cheap and honest, short cooldown.
    constexpr uint64_t NO_LOG_TTL_S = 600;
    // Peer that does not answer at all: each request wastes a 30s pending entry, long ban.
    constexpr uint64_t BAN_TTL_S = 43200; // 12 h
    // backend caps the exclude list at 64; leave room for our 6 connected IPs so they are never cut off
    constexpr size_t MAX_BANNED_PEERS = 58;
    std::chrono::seconds checkPeriodIdleDisconnect = std::chrono::seconds(30);
    std::chrono::seconds checkPeriodPeerRefresh = std::chrono::seconds(180); // 3 minutes
    // keep-alive + fresh peer tick for the ahead/behind flag (network moves 3-5 ticks/s)
    std::chrono::seconds checkPeriodLastTick = std::chrono::seconds(1);
    std::chrono::seconds checkPeriodSample = std::chrono::seconds(30);
    std::chrono::seconds badRotateBackoff = std::chrono::seconds(30); // min gap between forced rotations
    auto lastCheckIdleDisconnect = std::chrono::high_resolution_clock::now();
    auto lastCheckPeerRefresh = std::chrono::high_resolution_clock::now();
    auto lastCheckLastTick = std::chrono::high_resolution_clock::now();
    auto lastCheckSample = std::chrono::high_resolution_clock::now();
    auto lastBadForce = std::chrono::high_resolution_clock::now() - badRotateBackoff;

    // Sample baseline per peer; connection objects live for the whole process.
    struct PeerSample
    {
        uint64_t sent = 0;
        uint64_t answered = 0;
        uint64_t refused = 0;
        uint64_t noData = 0;
        int strikes = 0;
        bool silent = false; // static peers only: last windows bad and mostly silence (never flagged, only evidence)
    };
    auto resetSample = [](PeerSample& sample, QubicConnection& qc) {
        sample.sent = qc.getLogReqSent();
        sample.answered = qc.getLogReqAnswered();
        sample.refused = qc.getLogReqRefused();
        sample.noData = qc.getLogReqNoData();
        sample.strikes = 0;
    };
    std::unordered_map<QubicConnection*, PeerSample> samples;
    // ip -> unix time the ban expires. Only this thread touches it.
    std::unordered_map<std::string, uint64_t> bannedUntil;
    auto eraseSoonestExpiringBan = [&bannedUntil]() {
        auto soonest = std::min_element(bannedUntil.begin(), bannedUntil.end(), [](const auto& a, const auto& b) { return a.second < b.second; });
        std::string ip = soonest->first;
        bannedUntil.erase(soonest);
        return ip;
    };

    while (!gStopFlag.load(std::memory_order_relaxed)) {
        auto now = std::chrono::high_resolution_clock::now();
        if (now - lastCheckIdleDisconnect >= checkPeriodIdleDisconnect) {
            lastCheckIdleDisconnect = now;
            uint64_t nowTimestamp = std::time(nullptr);
            int N = conns_.size();
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (!conns_.get(i, qc) || !qc) continue;
                if (!qc->isSocketValid()) continue; // already invalid; IO loop will reconnect
                uint64_t lastAct = qc->getLastActivityTimestamp();
                if (lastAct == 0 || lastAct >= nowTimestamp) continue;
                uint64_t idleSec = nowTimestamp - lastAct;
                if (idleSec >= IDLE_DISCONNECT_S) {
                    Logger::get()->warn("Peer {}:{} idle for {}s; forcing reconnect.",
                                        qc->getNodeIp(), qc->getNodePort(), idleSec);
                    qc->disconnect();
                }
            }
        }
        if (autoban && now - lastCheckSample >= checkPeriodSample) {
            lastCheckSample = now;
            int N = conns_.size();
            int outgoingCount = 0; // all outgoing peers incl. static, for the local-network guard
            int badCount = 0;
            int unresponsiveCount = 0;
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (!conns_.get(i, qc) || !qc) continue;
                // incoming clients can't be rotated and get freed (pointer reuse in samples)
                if (!qc->isReconnectable()) continue;
                // static peers are judged the same way but never flagged: their verdict only tells us if our link is fine
                bool isStaticPeer = qc->isStatic();
                outgoingCount++;
                PeerSample& sample = samples[qc.get()];
                uint64_t sentTotal = qc->getLogReqSent();
                uint64_t answeredTotal = qc->getLogReqAnswered();
                uint64_t refusedTotal = qc->getLogReqRefused();
                uint64_t noDataTotal = qc->getLogReqNoData();
                // requests the peer could not have served (it was behind us) do not count either way;
                // a reply can land in a later sample than its request, so never let this go negative
                uint64_t sentDelta = sentTotal - sample.sent;
                uint64_t noDataDelta = noDataTotal - sample.noData;
                uint64_t sentInSample = sentDelta > noDataDelta ? sentDelta - noDataDelta : 0;
                uint64_t answeredInSample = answeredTotal - sample.answered;
                uint64_t refusedInSample = refusedTotal - sample.refused;
                // a window closes once it holds MIN_SENT_PER_SAMPLE judged requests, however long that takes:
                // tick rate on mainnet changes, so we wait for evidence instead of assuming a rate
                bool windowClosed = sentInSample >= MIN_SENT_PER_SAMPLE;
                // peer mostly behind us for a whole window: its old strike is no evidence anymore, start over
                bool peerWasBehind = !windowClosed && noDataDelta >= MIN_SENT_PER_SAMPLE;
                if (windowClosed || peerWasBehind) {
                    sample.sent = sentTotal;
                    sample.answered = answeredTotal;
                    sample.refused = refusedTotal;
                    sample.noData = noDataTotal;
                }
                if (peerWasBehind) {
                    sample.strikes = 0;
                    sample.silent = false;
                } else if (!windowClosed) {
                    // not enough traffic yet, keep accumulating into this window
                } else if (isBadSample(sentInSample, answeredInSample)) {
                    sample.strikes++;
                    if (sample.strikes >= STRIKES_TO_FLAG) {
                        // mostly END/empty = has no logs for us, otherwise it is not answering
                        BadPeerKind kind = (refusedInSample * 2 >= sentInSample) ? BadPeerKind::NoLogs : BadPeerKind::Unresponsive;
                        if (isStaticPeer) {
                            sample.silent = kind == BadPeerKind::Unresponsive;
                        } else if (!qc->isBad()) {
                            qc->markBad(kind);
                            Logger::get()->warn("Peer {}:{} flagged {}: answered {}/{} log requests within {}s ({} refused), {} bad windows in a row",
                                                qc->getNodeIp(), qc->getNodePort(), kind == BadPeerKind::NoLogs ? "no-logs" : "unresponsive",
                                                answeredInSample, sentInSample, PROMPT_RESPONSE_S, refusedInSample, sample.strikes);
                        }
                    }
                } else {
                    sample.strikes = 0;
                    sample.silent = false;
                }
                // dead socket gets no traffic, its window never closes: says nothing about our link
                if (!qc->isSocketValid()) sample.silent = false;
                if (qc->isBad()) badCount++;
                bool silent = isStaticPeer ? sample.silent : qc->getBadKind() == BadPeerKind::Unresponsive;
                if (silent) unresponsiveCount++;
            }
            // most peers silent at the same time (static ones included) = our own network, not theirs.
            // no-logs peers answered us (END/empty), so they prove the link works and keep their flag.
            if (unresponsiveCount >= 2 && unresponsiveCount * 2 >= outgoingCount) {
                int clearedCount = 0;
                for (int i = 0; i < N; i++) {
                    QCPtr qc;
                    if (!conns_.get(i, qc) || !qc || !qc->isReconnectable()) continue;
                    PeerSample& sample = samples[qc.get()];
                    if (qc->isStatic()) {
                        if (sample.silent) sample.strikes = 0;
                        sample.silent = false;
                        continue;
                    }
                    if (qc->getBadKind() != BadPeerKind::Unresponsive) continue;
                    qc->clearBad();
                    sample.strikes = 0;
                    clearedCount++;
                }
                Logger::get()->warn("{} of {} peers unresponsive at once; treating as local network problem, not banning",
                                    unresponsiveCount, outgoingCount);
                badCount -= clearedCount;
            }
            if (badCount > 0 && allowDnsReplace && now - lastBadForce >= badRotateBackoff) {
                // run the DNS-replace block right away instead of waiting for its timer
                lastBadForce = now;
                lastCheckPeerRefresh = now - checkPeriodPeerRefresh;
            }
        }
        if (allowDnsReplace && now - lastCheckPeerRefresh >= checkPeriodPeerRefresh) {
            lastCheckPeerRefresh = now;
            uint64_t nowTimestamp = std::time(nullptr);
            for (auto it = bannedUntil.begin(); it != bannedUntil.end();) {
                if (it->second <= nowTimestamp) {
                    it = bannedUntil.erase(it);
                } else {
                    ++it;
                }
            }
            // backend must return neither a banned peer nor one we already hold
            std::vector<std::string> exclude;
            for (const auto& ban : bannedUntil) {
                exclude.push_back(ban.first);
            }
            int N = conns_.size();
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (!conns_.get(i, qc) || !qc) continue;
                std::string connectedIp = qc->getNodeIp();
                if (!connectedIp.empty()) exclude.push_back(connectedIp);
            }
            uint64_t oldest = std::numeric_limits<uint64_t>::max();
            QCPtr worst = nullptr;
            std::vector<QCPtr> rotatable; // non-static peers eligible for replacement
            for (int i = 0; i < N; i++) {
                QCPtr qc;
                if (conns_.get(i,qc)) {
                    if (qc) {
                        // incoming clients can't dial a new address; replacing one just loses the slot
                        if (qc->isStatic() || !qc->isReconnectable()) continue;
                        rotatable.push_back(qc);
                        // flagged peer always goes first
                        if (qc->isBad()) {
                            worst = qc;
                            break;
                        }
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
            // if there is no worst, randomly pick 1 non-static peer
            if (!worst && !rotatable.empty()) {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<size_t> dist(0, rotatable.size() - 1);
                worst = rotatable[dist(gen)];
            }
            if (worst) {
                std::vector<std::string> newPeer;
                std::string mode = "random";
                bool primaryExhausted = false;
                if (worst->isBM()) {
                    newPeer = GetPeerFromDNS(1, 0, mode, exclude, &primaryExhausted);
                } else {
                    newPeer = GetPeerFromDNS(0, 1, mode, exclude, &primaryExhausted);
                }
                ParsedEndpoint parsed;
                // fallback discovery ignores exclude, so re-check on our side
                bool usable = !newPeer.empty() && parseEndpoint(newPeer[0], parsed)
                              && !conns_.checkExistIp(parsed.ip) && bannedUntil.count(parsed.ip) == 0;
                if (usable) {
                    std::string oldIp = worst->getNodeIp();
                    if (worst->isBad()) {
                        bool noLogs = worst->getBadKind() == BadPeerKind::NoLogs;
                        uint64_t ttlSec = noLogs ? NO_LOG_TTL_S : BAN_TTL_S;
                        bannedUntil[oldIp] = nowTimestamp + ttlSec;
                        Logger::get()->info("Banned peer {} for {}s ({})", oldIp, ttlSec, noLogs ? "no logs" : "no answer");
                        if (bannedUntil.size() > MAX_BANNED_PEERS) {
                            eraseSoonestExpiringBan();
                        }
                    }
                    Logger::get()->info("Replaced peer {}:{} with {}:{}", oldIp, worst->getNodePort(),
                                                                         parsed.ip, parsed.port);
                    worst->replacePeer(parsed.ip, parsed.port);
                    worst->setNodeType(parsed.nodeType);
                    if (parsed.has_passcode) {
                        worst->updatePasscode(parsed.passcode_arr);
                    }
                    worst->disconnect(); // this will be auto reconnect in the IO loop
                    // new peer starts with a clean sample
                    resetSample(samples[worst.get()], *worst);
                }
                else {
                    if (worst->isBad()) {
                        // no replacement available: unflag so it gets traffic again and is re-judged
                        worst->clearBad();
                        samples[worst.get()].strikes = 0;
                    }
                    // discovery has nothing new for us (primary answered empty, or only peers we hold/banned came back):
                    // drop the ban list and start fresh. All backends down/timeout says nothing about peers, keep the bans.
                    bool discoveryExhausted = primaryExhausted || !newPeer.empty();
                    if (discoveryExhausted && !bannedUntil.empty()) {
                        bannedUntil.clear();
                        Logger::get()->info("peer discovery exhausted; cleared all bans");
                    }
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
                        // Keep-alive so healthy idle peers avoid idle-disconnect.
                        if (qc->isSocketValid()) {
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