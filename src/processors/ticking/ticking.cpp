#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <cstring>

#include "src/connection/connection.h"
#include "src/core/structs.h"
#include "src/database/db.h"
#include "src/global_var.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "src/core/k12_and_key_util.h"
#include "src/profiler/profiler.h"
#include "src/utils/utils.h"
using namespace std::chrono_literals;

// verify if:
// - have tick data
// - have enough txs
// - quorum reach in tick votes
bool verifyQuorum(uint32_t tick, TickData& td, std::vector<TickVote>& votes)
{
    // check and fetch more votes
    int count = 0;
    for (int i = 0; i < 676; i++)
    {
        auto& vote = votes[i];
        if (vote.tick != tick)
        {
            db_get_tick_vote(tick, i, vote);
        }
        if (vote.tick == tick && vote.epoch == gCurrentProcessingEpoch) count++;
    }
    if (count < 225) {
        return false;
    }
    // NOTE: this is not fully verification, state digest are not yet verified
    struct ConsensusData
    {
        unsigned int prevResourceTestingDigest;
        unsigned int prevTransactionBodyDigest;
        m256i prevSpectrumDigest;
        m256i prevUniverseDigest;
        m256i prevComputerDigest;
        m256i transactionDigest;

        bool operator<(const ConsensusData &other) const {
            return memcmp(transactionDigest.m256i_u8, other.transactionDigest.m256i_u8, 32) < 0;
        }
    };
    std::map<ConsensusData, int> digestCount;
    for (const auto &vote: votes) {
        if (vote.tick == tick && vote.epoch == gCurrentProcessingEpoch)
        {
            ConsensusData cd{};
            cd.prevResourceTestingDigest = vote.prevResourceTestingDigest;
            cd.prevTransactionBodyDigest = vote.prevTransactionBodyDigest;
            cd.prevSpectrumDigest = vote.prevSpectrumDigest;
            cd.prevUniverseDigest = vote.prevUniverseDigest;
            cd.prevComputerDigest = vote.prevComputerDigest;
            cd.transactionDigest = vote.transactionDigest;
            digestCount[cd]++;
        }
    }

    int maxCount = 0;
    m256i maxDigest;
    bool reachConsensus = false;
    for (const auto &pair: digestCount) {
        if (pair.first.transactionDigest == m256i::zero() && pair.second >= 226) // empty case
        {
            maxCount = pair.second;
            maxDigest = pair.first.transactionDigest;
            reachConsensus = true;
            break;
        }
        if (pair.first.transactionDigest != m256i::zero() && pair.second >= 451) // non-empty case
        {
            maxCount = pair.second;
            maxDigest = pair.first.transactionDigest;
            reachConsensus = true;
            break;
        }
    }
    if (!reachConsensus) return false;
    if (maxDigest == m256i::zero()) return true;

    if (td.tick != tick || td.epoch != gCurrentProcessingEpoch)
    {
        if (!db_get_tick_data(tick, td))
        {
            return false;
        }
    }
    if (td.tick != tick || td.epoch != gCurrentProcessingEpoch)
    {
        return false;
    }
    uint8_t tdHash[32];
    KangarooTwelve((uint8_t*)&td, sizeof(TickData), tdHash, 32);
    if (memcmp(tdHash, maxDigest.m256i_u8, 32) != 0)
    {
        Logger::get()->critical("Consensus error: tickData {} is mismatched (there are potentially 2 tick data). Delete the current one in DB.", td.tick);
        db_delete_tick_data(tick);
        return false;
    }

    for (int i= 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (!(td.transactionDigests[i] == m256i::zero()))
        {
            char qhash[64] = {0};
            getIdentityFromPublicKey(td.transactionDigests[i].m256i_u8, qhash, true);
            std::string hash_str(qhash);
            if (!db_check_transaction_exist(hash_str))
            {
                return false;
            }
        }
    }

    return true; // quorum reach
}

// Requester thread: periodically evaluates what to request next and sends requests over the connection.
// Placeholders (TODO) are included where the request conditions and payloads will be implemented.
void TickingDataRequestThread(ConnectionPool& conn_pool, std::chrono::milliseconds requestCycle, uint32_t futureOffset)
{
    // Optional: pacing/tuning knobs
    auto idleBackoff = 10ms;   // Backoff when there's nothing immediate to request
    const auto errorBackoff = 2000ms; // Backoff after an exception
    auto requestClock = std::chrono::high_resolution_clock::now() - requestCycle;
    while (!gStopFlag.load(std::memory_order_relaxed)) {
        if (gIsEndEpoch) break;

        try {
            if (refetchTickVotes != -1)
            {
                RequestedQuorumTick rqt{};
                rqt.tick = refetchTickVotes;
                memset(rqt.voteFlags, 0, sizeof(rqt.voteFlags));
                int count = 0;
                auto tvs = db_get_tick_votes(refetchTickVotes);
                for (auto& tv: tvs) {
                    int i = tv.computorIndex;
                    rqt.voteFlags[i >> 3] |= (1 << (i & 7)); // turn on the flag if the vote exists
                    count++;
                }
                if (count < 676)
                {
                    conn_pool.sendToMany((uint8_t *) &rqt, sizeof(rqt), 3, RequestedQuorumTick::type, true);
                }
                refetchTickVotes = -1;
            }
            /* Don't need to fetch too far if not yet verifying*/
            if (gCurrentFetchingTick > gCurrentVerifyLoggingTick + 1000)
            {
                SLEEP(idleBackoff);
                continue;
            }
            auto now = std::chrono::high_resolution_clock::now();
            if (now - requestClock >= requestCycle)
            {
                requestClock = now;
                for (uint32_t offset = 0; offset < futureOffset; offset++) {
                    bool have_next_td = false;
                    {
                        if (!db_has_tick_data(gCurrentFetchingTick + offset))
                        {
                            RequestTickData rtd;
                            rtd.tick = gCurrentFetchingTick + offset;
                            conn_pool.sendToMany((uint8_t *) &rtd, sizeof(rtd), 1, RequestTickData::type, true);
                        } else {
                            have_next_td = true;
                        }
                    }

                    {
                        // tick votes
                        RequestedQuorumTick rqt{};
                        rqt.tick = gCurrentFetchingTick + offset;
                        memset(rqt.voteFlags, 0, sizeof(rqt.voteFlags));
                        int count = 0;
                        auto tvs = db_get_tick_votes(gCurrentFetchingTick + offset);
                        for (auto& tv: tvs) {
                            int i = tv.computorIndex;
                            rqt.voteFlags[i >> 3] |= (1 << (i & 7)); // turn on the flag if the vote exists
                            count++;
                        }
                        if (count < 676)
                        {
                            conn_pool.sendToMany((uint8_t *) &rqt, sizeof(rqt), 1, RequestedQuorumTick::type, true);
                        }
                    }

                    {
                        // transactions: requires to have tickdata
                        if (have_next_td) {
                            TickData td{};
                            db_get_tick_data(gCurrentFetchingTick + offset, td);
                            RequestedTickTransactions rtt;
                            rtt.tick = gCurrentFetchingTick + offset;
                            memset(rtt.flag, 0, sizeof(rtt.flag));
                            int count = 0;
                            for (unsigned int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++) {
                                if (td.transactionDigests[i] == m256i::zero()) continue;
                                char qhash[64] = {0};
                                getIdentityFromPublicKey(td.transactionDigests[i].m256i_u8, qhash, true);
                                std::string hash_str(qhash);
                                if (db_check_transaction_exist(hash_str)) {
                                    rtt.flag[i >> 3] |= (1 << (i & 7)); // turn on the flag if the tx exists
                                } else
                                {
                                    count++;
                                }
                            }
                            if (count) conn_pool.sendToMany((uint8_t *) &rtt, sizeof(rtt), 1, RequestedTickTransactions::type, true);
                        }
                    }
                }
            }
            SLEEP(idleBackoff);
        } catch (const std::exception& ex) {
            Logger::get()->warn("IORequestThread exception: {}", ex.what());
            std::this_thread::sleep_for(errorBackoff);
        } catch (...) {
            Logger::get()->warn("IORequestThread unknown exception.");
            std::this_thread::sleep_for(errorBackoff);
        }
    }
}

// this pre-verify tick votes, not fully verifying all digests
void TickingVerifyThread()
{
    const auto idleBackoff = 10ms;
    TickData td{};
    std::vector<TickVote> votes;
    votes.resize(676);
    memset((void*)votes.data(), 0, votes.size() * sizeof(TickVote));
    while (!gStopFlag.load())
    {
        if (gIsEndEpoch) break;
        if (!verifyQuorum(gCurrentFetchingTick, td, votes))
        {
            std::this_thread::sleep_for(idleBackoff);
        }
        else
        {
            auto current_tick = gCurrentFetchingTick.load();
            db_update_latest_tick_and_epoch(gCurrentFetchingTick, gCurrentProcessingEpoch);
            Logger::get()->trace("Progress ticking from {} to {}", gCurrentFetchingTick.load(), gCurrentFetchingTick.load() + 1);
            uint32_t tmp_tick;
            uint16_t tmp_epoch;
            db_get_latest_tick_and_epoch(tmp_tick, tmp_epoch);
            if (current_tick == tmp_tick) gCurrentFetchingTick++;
        }
    }
}

static bool checkAllowedTypeForNonTrusted(int type)
{
    if (type == RespondLog::type()) return false;
    if (type == LogRangesPerTxInTick::type()) return false;
    return true;
}

static bool isRequestType(int type)
{
    if (type == REQUEST_COMPUTOR_LIST) return true;                   // request computor list
    if (type == RequestedQuorumTick::type) return true;               // request vote
    if (type == RequestTickData::type) return true;                   // request tickdata
    if (type == REQUEST_CURRENT_TICK_INFO) return true;               // REQUEST_CURRENT_TICK_INFO
    if (type == RequestedTickTransactions::type) return true;         // request tx
    if (type == RequestLog::type()) return true;                      // request log
    if (type == RequestAllLogIdRangesFromTick::type()) return true;   // request log range
    return false;
}
static bool isDataType(int type)
{
    if (type == TickVote::type()) return true;                        // vote
    if (type == TickData::type()) return true;                        // tickdata
    if (type == BROADCAST_TRANSACTION) return true;                   // tx
    if (type == RespondLog::type()) return true;                      // log
    if (type == LogRangesPerTxInTick::type()) return true;  // logrange
    if (type == RespondContractFunction::type) return true;
    return false;
}


// Receiver thread: continuously receives full packets and enqueues them into the global round buffer (MRB).
void connReceiver(QCPtr conn, const bool isTrustedNode)
{
    using namespace std::chrono_literals;

    const auto errorBackoff = 1000ms;

    std::vector<uint8_t> packet;
    packet.reserve(64 * 1024); // Optional: initial capacity to minimize reallocations
    while (!gStopFlag.load(std::memory_order_relaxed)) {
        try {
            // Blocking receive of a complete packet from the connection.
            RequestResponseHeader hdr{};
            conn->receiveAFullPacket(hdr, packet);
            if (packet.empty()) {
                // Defensive check; shouldn't happen if receiveAFullPacket succeeds.
                if (!conn->isReconnectable()) return;
                Logger::get()->trace("connReceiver error on : {}. Disconnecting", conn->getNodeIp());
                conn->disconnect();
                SLEEP(errorBackoff);
                conn->reconnect();
                continue;
            }
            if (!isTrustedNode)
            {
                if (!gAllowReceiveLogFromIncomingConnection) // if operator already allowed to receive, no need to block
                {
                    if (!checkAllowedTypeForNonTrusted(hdr.type()))
                    {
                        continue; //drop
                    }
                }
            }
            // trusted conn allowed all packets
            if (isDataType(hdr.type()))
            {
                // Enqueue the packet into the global MutexRoundBuffer.
                bool ok = MRB_Data.EnqueuePacket(packet.data());
                if (!ok) {
                    Logger::get()->warn("connReceiver: failed to enqueue packet (size={}, type={}). Dropped.",
                                        packet.size(),
                                        static_cast<unsigned>(hdr.type()));
                }
            }

            if (isRequestType(hdr.type()))
            {
                bool ok = MRB_Request.EnqueuePacket(packet.data());
                if (!ok) {
                    Logger::get()->warn("connReceiver: failed to enqueue packet (size={}, type={}). Dropped.",
                                        packet.size(),
                                        static_cast<unsigned>(hdr.type()));
                }
                else
                {
                    requestMapperTo.add(hdr.getDejavu(), nullptr, 0, conn);
                }
            }

        } catch (const std::logic_error& ex) {
            if (!conn->isReconnectable()) return;
            Logger::get()->trace("connReceiver error on : {}. Disconnecting", conn->getNodeIp());
            conn->disconnect();
            SLEEP(errorBackoff);
            conn->reconnect();
        } catch (...) {
            if (!conn->isReconnectable()) return;
            Logger::get()->trace("connReceiver unknown exception from ip {}", conn->getNodeIp());
            conn->disconnect();
            SLEEP(errorBackoff);
            conn->reconnect();
        }
    }
}