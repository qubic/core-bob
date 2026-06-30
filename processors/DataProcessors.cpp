#include <sstream>
#include <iomanip>
#include <cassert>
#include "database/db.h"
#include "GlobalVar.h"
#include "spdlogDriver/Logger.h"
#include "K12AndKeyUtil.h"
#include "shim.h"

bool verifySignature(void* ptr, uint8_t* pubkey, int structSize) // structSize include sig 64 bytes
{
    uint8_t* p = (uint8_t*)ptr;
    uint8_t digest[32];
    KangarooTwelve(p, structSize - 64, digest, 32);
    if (verify(pubkey, digest, p + structSize - 64))
    {
        return true;
    }
    return false;
}
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
    if (vote->tick > gCurrentVerifyLoggingTick + 2000) {
        return; // too far in the future, this may cause bob crashing because out of memory
    }
    if (vote->computorIndex >= NUMBER_OF_COMPUTORS) {
        return; // untrusted index; publicKeys[] has only NUMBER_OF_COMPUTORS entries
    }
    uint8_t* compPubkey = computorsList.publicKeys[vote->computorIndex].m256i_u8;
    vote->computorIndex ^= 3;
    bool ok = verifySignature((void *) vote, compPubkey, sizeof(TickVote));
    vote->computorIndex ^= 3;
    unsigned int score = __builtin_bswap64(((unsigned int*)vote->signature)[0]);
    if (score > TARGET_TICK_VOTE_SIGNATURE) {
        Logger::get()->warn("Vote {}:{} has low-diff signature", vote->tick, vote->computorIndex);
        ok = false;
    }
    if (ok)
    {
        db_insert_tick_vote(*vote);
    }
    else
    {
        Logger::get()->warn("Vote {}:{} has invalid signature", vote->tick, vote->computorIndex);
    }
}

void processTickData(uint8_t* ptr, uint32_t payloadSize)
{
    // The wire payload is either a canonical 4096-slot TickData (post
    // epoch 214) or a legacy 1024-slot LegacyTickData (pre 214). Branch
    // by payload size; verify the signature over the bytes actually
    // received (legacy ticks were signed over their 1024-slot byte range).
    TickData _data{};
    size_t verifySize = 0;
    if (payloadSize == sizeof(TickData)) {
        memcpy((void*)&_data, ptr, sizeof(TickData));
        verifySize = sizeof(TickData);
    } else if (payloadSize == sizeof(LegacyTickData)) {
        LegacyTickData legacy{};
        memcpy(&legacy, ptr, sizeof(LegacyTickData));
        upcastLegacyTickData(legacy, _data);
        verifySize = sizeof(LegacyTickData);
    } else {
        Logger::get()->warn("processTickData: unexpected payload size {} (canonical={} legacy={})",
                            payloadSize, sizeof(TickData), sizeof(LegacyTickData));
        return;
    }

    auto* data = (TickData*)&_data;
    if (data->epoch != gCurrentProcessingEpoch) // may also tell that epoch switch
    {
        return;
    }
    if (data->tick < gCurrentVerifyLoggingTick - 1)
    {
        return; // already verified
    }
    if (data->tick > gCurrentVerifyLoggingTick + 2000) {
        return; // too far in the future, this may cause bob crashing because out of memory
    }
    if (data->computorIndex >= NUMBER_OF_COMPUTORS) {
        return; // untrusted index; publicKeys[] has only NUMBER_OF_COMPUTORS entries
    }
    uint8_t* compPubkey = computorsList.publicKeys[data->computorIndex].m256i_u8;
    data->computorIndex ^= 8;
    bool ok = false;
    if (verifySize == sizeof(TickData)) {
        ok = verifySignature((void *) data, compPubkey, sizeof(TickData));
    } else {
        // Legacy ticks were signed over their original 1024-slot byte range.
        // Reconstruct a LegacyTickData buffer (the upcast preserves all
        // fields one-for-one, so the original layout is recoverable) and
        // verify against that.
        LegacyTickData legacyForVerify{};
        legacyForVerify.computorIndex = data->computorIndex;
        legacyForVerify.epoch         = data->epoch;
        legacyForVerify.tick          = data->tick;
        legacyForVerify.millisecond   = data->millisecond;
        legacyForVerify.second        = data->second;
        legacyForVerify.minute        = data->minute;
        legacyForVerify.hour          = data->hour;
        legacyForVerify.day           = data->day;
        legacyForVerify.month         = data->month;
        legacyForVerify.year          = data->year;
        legacyForVerify.timelock      = data->timelock;
        memcpy(legacyForVerify.transactionDigests, data->transactionDigests,
               sizeof(legacyForVerify.transactionDigests));
        memcpy(legacyForVerify.contractFees, data->contractFees,
               sizeof(legacyForVerify.contractFees));
        memcpy(legacyForVerify.signature, data->signature, SIGNATURE_SIZE);
        ok = verifySignature((void *) &legacyForVerify, compPubkey, sizeof(LegacyTickData));
    }
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

void processLogEvent(const uint8_t* _ptr, uint32_t chunkSize, const RequestResponseHeader& hdr)
{
    // Per-peer log-delivery counter is cheap (one atomic inc) and always
    // tracked. Looking up the source string is also cheap (map lookup), but
    // we only need it when diagnostic mode is on (it feeds db_set_log_source
    // below which is the expensive part).
    std::string source;
    const bool diag = gDiagnosticMode.load(std::memory_order_relaxed);
    {
        std::vector<uint8_t> ignore;
        QCPtr conn;
        // requestMapperFrom holds our outgoing requests; connReceiver patches
        // in the responding peer's conn via updateConn() before enqueueing
        // the response. This is the correct map for "who answered our log
        // request". (requestMapperTo is for *incoming* requests from peers.)
        if (requestMapperFrom.get(hdr.getDejavu(), ignore, conn) && conn) {
            conn->incLogsDelivered();
            if (diag) {
                source = std::string(conn->getNodeIp()) + ":" + std::to_string(conn->getNodePort());
            }
        }
    }

    uint32_t offset = 0;
    uint64_t maxLogId = 0;
    while (offset < chunkSize)
    {
        auto ptr = _ptr + offset;
        // Bound every read against the bytes actually present in this chunk.
        // messageSize comes straight off the wire (peer-controlled, up to ~16MB)
        // and is used unbounded below, so without these guards the header reads
        // and updateContent() memcpy can run far past the packet buffer.
        uint32_t remaining = chunkSize - offset;
        if (remaining < LogEvent::PackedHeaderSize)
        {
            break; // not enough bytes left for even a record header
        }
        uint16_t epoch;
        uint32_t tick;
        uint32_t tmp;
        uint64_t logId;
        memcpy((void*)&epoch, ptr, sizeof(epoch));
        memcpy((void*)&tick, ptr + 2, sizeof(tick));
        memcpy((void*)&tmp, ptr + 6, sizeof(tmp));
        memcpy((void*)&logId, ptr + 10, sizeof(logId));
        uint32_t messageSize = tmp & 0x00FFFFFF;
        if ((uint64_t)messageSize + LogEvent::PackedHeaderSize > remaining)
        {
            break; // record claims more bytes than the chunk holds
        }
        LogEvent le;
        le.updateContent(ptr, messageSize + LogEvent::PackedHeaderSize);
        if (le.selfCheck(gCurrentProcessingEpoch, false /*don't need to show log*/))
        {
            if (!db_insert_log(epoch, tick, logId, messageSize + LogEvent::PackedHeaderSize, ptr))
            {
                Logger::get()->warn("Failed to add log {}", logId);
            }
            else if (!source.empty())
            {
                db_set_log_source(epoch, logId, source);
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
        else
        {
            Logger::get()->debug("processLogRanges: size mismatch for tick {}: got {} expected {}", packet.tick, header_sz, needed_sz);
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

void DataProcessorThread()
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
                gRespTickVotes.fetch_add(1, std::memory_order_relaxed);
                processTickVote(const_cast<uint8_t*>(payload));
                break;
            case TickData::type(): // TickData
                gRespTickData.fetch_add(1, std::memory_order_relaxed);
                // packet_size includes the 8-byte header; payload is the rest.
                processTickData(const_cast<uint8_t*>(payload), packet_size - 8);
                break;
            case BROADCAST_TRANSACTION: // Transaction
                gRespTickTxs.fetch_add(1, std::memory_order_relaxed);
                processTransaction(payload);
                break;
            case RespondLog::type(): // log event
                gRespLog.fetch_add(1, std::memory_order_relaxed);
                processLogEvent(payload, packet_size - 8, header);
                break;
            case LogRangesPerTxInTick::type(): // logID ranges
                gRespLogRanges.fetch_add(1, std::memory_order_relaxed);
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

void replyTickVotes(QCPtr& conn, uint32_t dejavu, uint8_t* ptr)
{
    auto *request = (RequestedQuorumTick *)ptr;
    uint32_t tick = request->tick;
    // since all votes have valid signatures, we can allow bob to broadcast not-yet-verified votes
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
    // since tick data has a valid signature, we can allow bob to broadcast not-yet-verified tick data
    TickData td;
    if (!db_try_get_tick_data(tick, td))
    {
        conn->sendEndPacket(dejavu);
        return;
    }
    // Refuse to serve pre-epoch-214 ticks: we only have them upcasted to the
    // canonical 4096-slot layout in memory, but the original signature was
    // computed over the 1024-slot byte range. Replying with the canonical
    // layout would fail signature verification on the requester, so we
    // simply close the response. Pre-cutover peers should re-sync legacy
    // ticks from each other (or from core's archive).
    if (td.epoch != 0 && td.epoch < EPOCH_FIRST_4096_TX_PER_TICK)
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

void RequestProcessorThread()
{
    std::vector<uint8_t> buf;
    buf.resize(RequestResponseHeader::max_size, 0);
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
        memcpy((void*)&header, buf.data(), 8);
        auto type = header.type();
        uint8_t* ptr = buf.data() + 8;

        std::vector<uint8_t> ignore;
        QCPtr conn;
        requestMapperTo.get(header.getDejavu(), ignore, conn);
        if (conn == nullptr) continue;
        switch (type)
        {
            case RequestedQuorumTick::type: // TickVote
                replyTickVotes(conn, header.getDejavu(), ptr);
                break;
            case RequestTickData::type: // TickData
                replyTickData(conn, header.getDejavu(), ptr);
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