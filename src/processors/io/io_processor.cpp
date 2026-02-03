#include "src/database/db.h"
#include "src/global_var.h"
#include "src/logger/logger.h"
#include "src/shim.h"
#include "src/core/k12_and_key_util.h"
#include <cassert>
#include <iomanip>

class IOProcessorUtils {
public:
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
};

void processTickVote(uint8_t* ptr)
{
    TickVote _vote;
    memcpy((void*)&_vote, ptr, sizeof(TickVote));
    auto vote = (TickVote*)&_vote;

    if (vote->epoch != gCurrentProcessingEpoch) // may also tell that epoch switch
    {
        return;
    }
    if (vote->tick < gCurrentVerifyLoggingTick - 1)
    {
        return; // already verified
    }
    uint8_t* compPubkey = computorsList.publicKeys[vote->computorIndex].m256i_u8;
    vote->computorIndex ^= 3;
    bool ok = verifySignature((void *) vote, compPubkey, sizeof(TickVote));
    vote->computorIndex ^= 3;
    if (ok)
    {
        db_insert_tick_vote(*vote);
    }
    else
    {
        Logger::get()->warn("Vote {}:{} has invalid signature", vote->tick, vote->computorIndex);
    }
}

void processTickData(uint8_t* ptr)
{
    TickData _data;
    memcpy((void*)&_data, ptr, sizeof(TickData));
    auto* data = (TickData*)&_data;
    if (data->epoch != gCurrentProcessingEpoch) // may also tell that epoch switch
    {
        return;
    }
    if (data->tick < gCurrentVerifyLoggingTick - 1)
    {
        return; // already verified
    }
    uint8_t* compPubkey = computorsList.publicKeys[data->computorIndex].m256i_u8;
    data->computorIndex ^= 8;
    bool ok = verifySignature((void *) data, compPubkey, sizeof(TickData));
    data->computorIndex ^= 8;
    if (ok)
    {
        db_insert_tick_data(*data);
    }
    else
    {
        Logger::get()->warn("TickData {}:{} has invalid signature", data->tick, data->computorIndex);
    }

}

void processTransaction(const uint8_t* ptr)
{
    uint8_t buffer[80+1024+64];
    const auto* tx = (Transaction*)buffer;
    memcpy(buffer, ptr, sizeof(Transaction));
    if (tx->inputSize > 1024)
    {
        Logger::get()->warn("Malformed transaction data");
        return;
    }
    if (tx->tick < gCurrentVerifyLoggingTick - 1)
    {
        return; // already verified
    }
    TickData td{};
    if (!db_try_get_tick_data(tx->tick, td))
    {
        return;
    }

    memcpy(buffer+sizeof(Transaction),ptr+sizeof(Transaction), tx->inputSize + SIGNATURE_SIZE);
    m256i tx_digest;
    KangarooTwelve(buffer, sizeof(Transaction) + tx->inputSize + SIGNATURE_SIZE, tx_digest.m256i_u8, 32);
    bool found = false;
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (td.transactionDigests[i] != m256i::zero() && td.transactionDigests[i] == tx_digest)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        return;
    }
    auto* pubkey = (uint8_t*)tx->sourcePublicKey;
    if (verifySignature((void *) buffer, pubkey, sizeof(Transaction) + tx->inputSize + SIGNATURE_SIZE))
    {
        db_insert_transaction(tx);
    }
    else
    {
        char IDEN[64] = {0};
        getIdentityFromPublicKey(tx->sourcePublicKey, IDEN, false);
        Logger::get()->warn("Transaction {}:{} has invalid signature", tx->tick, IDEN);
    }

}

void processLogEvent(const uint8_t* _ptr, uint32_t chunkSize)
{
    uint32_t offset = 0;
    uint64_t maxLogId = 0;
    while (offset < chunkSize)
    {
        auto ptr = _ptr + offset;
        uint16_t epoch;
        uint32_t tick;
        uint32_t tmp;
        uint64_t logId;
        memcpy((void*)&epoch, ptr, sizeof(epoch));
        memcpy((void*)&tick, ptr + 2, sizeof(tick));
        memcpy((void*)&tmp, ptr + 6, sizeof(tmp));
        memcpy((void*)&logId, ptr + 10, sizeof(logId));
        uint32_t messageSize = tmp & 0x00FFFFFF;
        LogEvent le;
        le.updateContent(ptr, messageSize + LogEvent::PackedHeaderSize);
        if (le.selfCheck(gCurrentProcessingEpoch, false /*don't need to show log*/))
        {
            if (!db_insert_log(epoch, tick, logId, messageSize + LogEvent::PackedHeaderSize, ptr))
            {
                Logger::get()->warn("Failed to add log {}", logId);
            }
        }
        else
        {
            // break here and get the rest of logging chunk later
            break;
        }

        offset += messageSize + LogEvent::PackedHeaderSize;
        maxLogId = std::max(maxLogId, logId);
    }
    db_update_latest_log_id(gCurrentProcessingEpoch, maxLogId);
}

void processLogRanges(RequestResponseHeader& header, const uint8_t* ptr)
{
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        uint32_t tick;
    } packet;

    std::vector<uint8_t> request;
    requestMapperFrom.get(header.getDejavu(), request);
    if (request.size() == sizeof(packet))
    {
        memcpy((void*)&packet, request.data(), sizeof(packet));
        int header_sz = header.size();
        int needed_sz = sizeof(RequestResponseHeader) + sizeof(LogRangesPerTxInTick);
        if (header_sz == needed_sz)
        {
            const auto* logRange = reinterpret_cast<const LogRangesPerTxInTick*>(ptr);
            db_insert_log_range(packet.tick, *logRange);
        }
    }
    else
    {
        Logger::get()->warn("Cannot find suitable tick to map the log range. Please increase request-logging-cycle-ms. Your internet is not fast enough for tight request cycle");
    }
}

void recordSmartContractResponse(uint32_t size, uint32_t dejavu, const uint8_t* ptr)
{
    responseSCData.add(dejavu, ptr, size, nullptr);
}

void dataProcessorThread()
{
    std::vector<uint8_t> buf;
    buf.resize(RequestResponseHeader::max_size, 0);
    // Always write the packet to the start of the buffer
    while (!gStopFlag.load())
    {
        uint32_t packet_size = 0;
        if (!MRB_Data.TryGetPacket(buf.data(), packet_size))
        {
            SLEEP(10);
            continue;
        }
        if (packet_size == 0 || packet_size >= RequestResponseHeader::max_size)
        {
            Logger::get()->warn("Malformed packet_size: {}", packet_size);
            continue;
        }
        RequestResponseHeader header{};
        memcpy((void*)&header, buf.data(), 8);
        auto type = header.type();
        const uint8_t* payload = buf.data() + 8;
        switch (type)
        {
            case BROADCAST_TICK_VOTE: // TickVote
                processTickVote(const_cast<uint8_t*>(payload));
                break;
            case TickData::type(): // TickData
                processTickData(const_cast<uint8_t*>(payload));
                break;
            case BROADCAST_TRANSACTION: // Transaction
                processTransaction(payload);
                break;
            case RespondLog::type(): // log event
                processLogEvent(payload, packet_size - 8);
                break;
            case LogRangesPerTxInTick::type(): // logID ranges
                processLogRanges(header, payload);
                break;
            case RespondContractFunction::type:
                recordSmartContractResponse(header.size() - sizeof(RequestResponseHeader), header.getDejavu(), payload);
                break;
            default:
                break;
        }
    }
    gExitDataThreadCounter++;
}

void replyTransaction(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestedTickTransactions *request = (RequestedTickTransactions *)ptr;
    uint32_t tick = request->tick;
    TickData td;
    if (!db_try_get_tick_data(tick, td))
    {
        conn->sendEndPacket(dejavu);
        return;
    }
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (td.transactionDigests[i] != m256i::zero())
        {
            if (!(request->flag[i >> 3] & (1 << (i & 7))))
            {
                char hash[64] = {0};
                getIdentityFromPublicKey(td.transactionDigests[i].m256i_u8, hash, true);
                std::string strHash(hash);
                std::vector<uint8_t> txData;
                if (db_try_get_transaction(strHash, txData))
                {
                    RequestResponseHeader resp;
                    resp.setSize(8 + txData.size());
                    resp.setDejavu(dejavu);
                    resp.setType(BROADCAST_TRANSACTION);
                    std::vector<uint8_t> v_resp;
                    v_resp.resize(8 + txData.size());
                    memcpy(v_resp.data(), &resp, 8);
                    memcpy(v_resp.data() + 8, txData.data(), txData.size());
                    conn->enqueueSend(v_resp.data(), v_resp.size());
                }
            }
        }
    }
    conn->sendEndPacket(dejavu);
    return;
}

void replyComputorList(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    if (computorsList.epoch != 0)
    {
        struct
        {
            RequestResponseHeader resp{};
            Computors comp;
        } pl;

        pl.resp.setSize(8 + sizeof(Computors));
        pl.resp.setDejavu(dejavu);
        pl.resp.setType(RESPOND_COMPUTOR_LIST);
        memcpy((void*)&pl.comp, &computorsList, sizeof(Computors));
        conn->enqueueSend((uint8_t *) &pl, sizeof(pl));
        return;
    }
    conn->sendEndPacket(dejavu);
}

void replyTickVotes(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    auto *request = (RequestedQuorumTick *)ptr;
    uint32_t tick = request->tick;
    if (tick >= gCurrentVerifyLoggingTick)
    {
        conn->sendEndPacket();
        return;
    }
    auto votes = db_try_get_tick_vote(tick);
    for (auto& tv : votes)
    {
        int i = tv.computorIndex;
        if (tv.epoch != 0 && tv.tick == tick)
        {
            if (!(request->voteFlags[i >> 3] & (1 << (i & 7))))
            {
                // Build a tightly packed buffer: header (8) + TickVote
                const uint32_t total = 8 + sizeof(TickVote);
                std::array<uint8_t, 8 + sizeof(TickVote)> buf{};
                RequestResponseHeader hdr{};
                hdr.setSize(total);
                hdr.setDejavu(dejavu);
                hdr.setType(BROADCAST_TICK_VOTE);
                // Copy header (first 8 bytes only) then payload
                memcpy(buf.data(), &hdr, 8);
                memcpy(buf.data() + 8, &tv, sizeof(TickVote));
                conn->enqueueSend(buf.data(), total);
            }
        }
    }
    conn->sendEndPacket(dejavu);
    return;
}

void replyTickData(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    uint32_t tick;
    memcpy((void*)&tick, ptr, 4);
    if (tick >= gCurrentVerifyLoggingTick)
    {
        conn->sendEndPacket();
        return;
    }
    TickData td;
    if (!db_try_get_tick_data(tick, td))
    {
        conn->sendEndPacket(dejavu);
        return;
    }
    // Build a tightly packed buffer: header (8) + TickData
    const uint32_t total = 8 + sizeof(TickData);
    // If your platform/compiler doesn’t support VLAs, use a vector
    std::vector<uint8_t> buf(total);
    RequestResponseHeader hdr{};
    hdr.setType(TickData::type());
    hdr.setDejavu(dejavu);
    hdr.setSize(total);
    memcpy(buf.data(), &hdr, 8);
    memcpy(buf.data() + 8, &td, sizeof(TickData));
    conn->enqueueSend(buf.data(), total);
}

void replyLogEvent(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestLog* request = (RequestLog*)ptr;
    if (request->passcode[0] != 0 ||
            request->passcode[1] != 0 ||
            request->passcode[2] != 0 ||
            request->passcode[3] != 0)
    {
        conn->sendEndPacket();
        return;
    }
    if (request->toid - request->fromid + 1 >= 1000)
    {
        conn->sendEndPacket();
        return;
    }
    RequestResponseHeader header{};
    header.setDejavu(dejavu);
    header.setType(RespondLog::type());
    std::vector<uint8_t> resp;
    for (uint64_t i = request->fromid; i <= request->toid; i++)
    {
        LogEvent le;
        if (db_try_get_log(gCurrentProcessingEpoch, i, le))
        {
            int currentSize = resp.size();
            resp.resize(currentSize + le.getLogSize() + LogEvent::PackedHeaderSize);
            memcpy(resp.data() + currentSize, le.getRawPtr(), le.getLogSize() + LogEvent::PackedHeaderSize);
        }
    }
    header.setSize(8 + resp.size());

    std::vector<uint8_t> v_resp;
    v_resp.resize(8 + resp.size());
    memcpy(v_resp.data(), &header, 8);
    memcpy(v_resp.data() + 8, resp.data(), resp.size());

    conn->enqueueSend(v_resp.data(), v_resp.size());
}

void replyLogRange(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    RequestAllLogIdRangesFromTick* request = (RequestAllLogIdRangesFromTick*)ptr;
    if (request->tick >= gCurrentVerifyLoggingTick)
    {
        conn->sendEndPacket();
        return;
    }
    if (request->passcode[0] != 0 ||
        request->passcode[1] != 0 ||
        request->passcode[2] != 0 ||
        request->passcode[3] != 0)
    {
        conn->sendEndPacket();
        return;
    }
    uint32_t tick = request->tick;
    struct
    {
        RequestResponseHeader resp;
        LogRangesPerTxInTick logRange;
    } pl;

    if (db_try_get_log_ranges(tick, pl.logRange)) {
        pl.resp.setSize(8 + sizeof(LogRangesPerTxInTick));
        pl.resp.setDejavu(dejavu);
        pl.resp.setType(LogRangesPerTxInTick::type());
        conn->enqueueSend((uint8_t *) &pl, sizeof(pl));
        return;
    }
    conn->sendEndPacket(dejavu);
}

void replyCurrentTickInfo(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    struct
    {
        RequestResponseHeader header;
        CurrentTickInfo currentTickInfo;
    } pl;

    pl.header.setType(RESPOND_CURRENT_TICK_INFO);
    pl.header.setSize(sizeof(pl));
    pl.header.setDejavu(dejavu);
    if (computorsList.epoch)
    {
        pl.currentTickInfo.tickDuration = 0;
        pl.currentTickInfo.epoch = gCurrentProcessingEpoch;
        pl.currentTickInfo.tick = gCurrentVerifyLoggingTick - 1;
        pl.currentTickInfo.numberOfAlignedVotes = 0;
        pl.currentTickInfo.numberOfMisalignedVotes = 0;
        pl.currentTickInfo.initialTick = gInitialTick;
    }
    else
    {
        setMem(&pl.currentTickInfo, sizeof(CurrentTickInfo), 0);
    }
    conn->enqueueSend((uint8_t *) &pl, sizeof(pl));
}

void requestProcessorThread()
{
    std::vector<uint8_t> buf;
    buf.resize(RequestResponseHeader::max_size, 0);
    uint8_t* ptr = buf.data();
    while (!gStopFlag.load())
    {
        uint32_t packet_size = 0;
        if (!MRB_Request.TryGetPacket(buf.data(), packet_size))
        {
            SLEEP(10);
            continue;
        }
        if (packet_size == 0 || packet_size >= RequestResponseHeader::max_size)
        {
            Logger::get()->warn("Malformed packet_size: {}", packet_size);
            continue;
        }
        RequestResponseHeader header{};
        memcpy((void*)&header, ptr, 8);
        auto type = header.type();
        ptr += 8;

        std::vector<uint8_t> ignore;
        QCPtr conn;
        requestMapperTo.get(header.getDejavu(), ignore, conn);
        if (conn == nullptr) continue;
        switch (type)
        {
            case REQUEST_COMPUTOR_LIST: // request computors list
                replyComputorList(conn, header.getDejavu(), ptr);
                break;
            case RequestedQuorumTick::type: // TickVote
                replyTickVotes(conn, header.getDejavu(), ptr);
                break;
            case RequestTickData::type: // TickData
                replyTickData(conn, header.getDejavu(), ptr);
                break;
            case REQUEST_CURRENT_TICK_INFO:
                replyCurrentTickInfo(conn, header.getDejavu(), ptr);
                break;
            case REQUEST_TICK_TRANSACTIONS: // Transaction
                replyTransaction(conn, header.getDejavu(), ptr);
                break;
            case RequestLog::type():
                 replyLogEvent(conn, header.getDejavu(), ptr);
                break;
            case RequestAllLogIdRangesFromTick::type(): // logID ranges
                replyLogRange(conn, header.getDejavu(), ptr);
                break;
            default:
                break;
        }
    }
    gExitDataThreadCounter++;
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
                    if (!IOProcessorUtils::checkAllowedTypeForNonTrusted(hdr.type()))
                    {
                        continue; //drop
                    }
                }
            }
            // trusted conn allowed all packets
            if (IOProcessorUtils::isDataType(hdr.type()))
            {
                // Enqueue the packet into the global MutexRoundBuffer.
                bool ok = MRB_Data.EnqueuePacket(packet.data());
                if (!ok) {
                    Logger::get()->warn("connReceiver: failed to enqueue packet (size={}, type={}). Dropped.",
                                        packet.size(),
                                        static_cast<unsigned>(hdr.type()));
                }
            }

            if (IOProcessorUtils::isRequestType(hdr.type()))
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