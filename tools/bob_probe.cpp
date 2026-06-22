// bob_probe — a standalone Qubic P2P protocol probe.
//
// It speaks the exact same wire protocol bob uses (it reuses bob's own
// structs.h / defines.h / K12AndKeyUtil.h, so every packet is byte-for-byte
// identical to what bob sends), but it is single-threaded, sequential and
// blocking, and it logs *everything* to the console: every byte sent and
// received, every decoded header and struct, sizes, timings and any anomaly.
//
// Use it to see exactly where bob and a (new) node software disagree on the
// wire: an unexpected packet size, a struct-layout mismatch, a missing
// response, a wrong type, etc.
//
// Build (no redis/spdlog/drogon needed — only header-only bob code):
//   g++ -std=c++17 -mavx2 -O2 -I common -I . tools/bob_probe.cpp -o bob_probe
// or just run tools/build_probe.sh
//
// Usage:
//   ./bob_probe <ip> <port> [options]
//
// Options:
//   --tick <N>         Tick to request data/votes/txs for (default: node's current tick)
//   --arb <IDENTITY>   Arbitrator identity → verify the computor-list signature
//   --passcode p0-p1-p2-p3  Passcode for the logging-event requests (the 'logs' step)
//   --steps <list>     Comma list of steps to run. Default (no flag): runs
//                      tickinfo,computors,tickdata,votes,txs — the peer-exchange
//                      handshake is NOT sent. Pass --steps handshake to opt in.
//   --binary-output    Print raw packet hexdumps (OFF by default)
//   --hex <N>          Bytes of hexdump per packet when --binary-output is set (default 128; -1=full)
//   --timeout <sec>    Socket receive timeout (default 8)
//   --max-votes <N>    Stop printing votes after N (default 8; -1 = all)
//   --max-txs <N>      Stop printing transactions after N (default 16; -1 = all)
//   --loop-tickinfo    After the run, poll current-tick-info forever (watch the node live)
//
// Catch-up mode (simulate bob syncing a range of ticks over one open connection):
//   --catchup          Walk ticks [start .. start+count), fetching each tick's data
//                      sequentially. Prints only per-tick timings + a final summary.
//   --count <N>        Number of ticks to walk (default 100)
//   --tick <N>         Start tick (default: node's current tick - count)
//   --steps <list>     Per-tick fetches among tickdata,votes,txs (default: all three)
//   e.g.  ./bob_probe 1.2.3.4 21841 --catchup --tick 56000000 --count 500
//
// Examples:
//   ./bob_probe 65.109.122.174 21841
//   ./bob_probe 1.2.3.4 21841 --tick 23456789 --arb AFZPUAIYV... --binary-output --hex -1
//   ./bob_probe 1.2.3.4 21841 --steps tickinfo --loop-tickinfo

#include "structs.h"          // pulls in defines.h, utils.h, m256i.h, K12AndKeyUtil.h

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <thread>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

// ----------------------------------------------------------------------------
// Terminal colors
// ----------------------------------------------------------------------------
static bool gColor = true;
// When false, per-packet SEND/RECV lines and hexdumps are suppressed (used by
// catch-up mode, which prints only per-tick timings). Errors/warnings still show.
static bool gLogPackets = true;
static const char* C(const char* code) { return gColor ? code : ""; }
#define CRESET  C("\033[0m")
#define CBOLD   C("\033[1m")
#define CDIM    C("\033[2m")
#define CRED    C("\033[31m")
#define CGREEN  C("\033[32m")
#define CYELLOW C("\033[33m")
#define CBLUE   C("\033[34m")
#define CMAG    C("\033[35m")
#define CCYAN   C("\033[36m")
#define CGREY   C("\033[90m")

// ----------------------------------------------------------------------------
// Logging helpers
// ----------------------------------------------------------------------------
static std::chrono::steady_clock::time_point gT0;
static double nowMs() {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - gT0).count();
}
static void logLine(const char* color, const char* tag, const std::string& msg) {
    printf("%s[%9.2fms] %s%-5s%s %s\n", CGREY, nowMs(), color, tag, CRESET, msg.c_str());
    fflush(stdout);
}
static std::string vfmt(const char* fmt, va_list ap) {
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    return std::string(buf);
}
static void INFO (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CCYAN ,"INFO" , vfmt(fmt,a)); va_end(a); }
static void STEP (const char* fmt, ...){ va_list a; va_start(a,fmt); printf("\n%s%s=== ", CBOLD, CMAG); va_end(a);
                                          va_start(a,fmt); vprintf(fmt, a); va_end(a); printf(" ===%s\n", CRESET); fflush(stdout); }
static void SEND (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CBLUE ,"SEND" , vfmt(fmt,a)); va_end(a); }
static void RECV (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CGREEN,"RECV" , vfmt(fmt,a)); va_end(a); }
static void OK   (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CGREEN,"OK"   , vfmt(fmt,a)); va_end(a); }
static void WARN (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CYELLOW,"WARN", vfmt(fmt,a)); va_end(a); }
static void ERR  (const char* fmt, ...){ va_list a; va_start(a,fmt); logLine(CRED  ,"ERROR", vfmt(fmt,a)); va_end(a); }
static void DETAIL(const std::string& s){ printf("            %s%s%s\n", CDIM, s.c_str(), CRESET); fflush(stdout); }

// classic offset | hex | ascii hexdump, capped at maxBytes (maxBytes<0 = all)
static void hexdump(const uint8_t* data, size_t len, long maxBytes) {
    if (maxBytes == 0) return;
    size_t cap = (maxBytes < 0) ? len : std::min(len, (size_t)maxBytes);
    for (size_t off = 0; off < cap; off += 16) {
        std::ostringstream line;
        char addr[24]; snprintf(addr, sizeof(addr), "%04zx  ", off);
        line << CGREY << addr << CRESET;
        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < cap) {
                char b[4]; snprintf(b, sizeof(b), "%02x ", data[off + i]);
                line << b;
                uint8_t c = data[off + i];
                ascii += (c >= 32 && c < 127) ? (char)c : '.';
            } else {
                line << "   ";
            }
            if (i == 7) line << " ";
        }
        line << " " << CGREY << "|" << ascii << "|" << CRESET;
        printf("            %s\n", line.str().c_str());
    }
    if (cap < len) {
        printf("            %s... (%zu of %zu bytes shown; use --hex -1 for full)%s\n",
               CGREY, cap, len, CRESET);
    }
    fflush(stdout);
}

// ----------------------------------------------------------------------------
// Globals the reused bob headers expect to exist (normally in GlobalVar.cpp).
// We define our own minimal copies so we can link standalone.
// ----------------------------------------------------------------------------
// (none needed: structs.h / K12 are fully header-only and self-contained)

// A locally-built computors list + epoch, used for signature verification.
static Computors gComputors{};
static bool      gHaveComputors = false;
static uint16_t  gEpoch = 0;

// Passcode for the logging-event requests (the node whitelists bob's IP and
// hands it this 4×uint64 passcode). Same format as the endpoint config:
// "p0-p1-p2-p3".
static uint64_t  gPasscode[4] = {0, 0, 0, 0};
static bool      gHavePasscode = false;

// Packed log-event header is 26 bytes (see logEventCore/LogEvent.h):
//   0..1 epoch(u16) | 2..5 tick(u32) | 6..9 size(24b)+type(8b) | 10..17 logId(u64) | 18..25 logDigest(u64)
static constexpr size_t LOG_PACKED_HEADER = 26;
static const char* logTypeName(uint32_t t) {
    switch (t) {
        case 0:   return "QU_TRANSFER";
        case 1:   return "ASSET_ISSUANCE";
        case 2:   return "ASSET_OWNERSHIP_CHANGE";
        case 3:   return "ASSET_POSSESSION_CHANGE";
        case 4:   return "CONTRACT_ERROR";
        case 5:   return "CONTRACT_WARNING";
        case 6:   return "CONTRACT_INFO";
        case 7:   return "CONTRACT_DEBUG";
        case 8:   return "BURNING";
        case 10:  return "SPECTRUM_STATS";
        case 11:  return "ASSET_OWNERSHIP_MGMT_CONTRACT_CHANGE";
        case 12:  return "ASSET_POSSESSION_MGMT_CONTRACT_CHANGE";
        case 255: return "CUSTOM_MESSAGE";
        default:  return "UNKNOWN";
    }
}

// --- Per-step timing, summarized at the end ---
struct StepStat {
    std::string name;          // step label
    double sentMs = 0;         // when the request was sent
    double firstDataMs = -1;   // when the first needed-data packet arrived (-1 = none)
    double doneMs = 0;         // when the step finished (END_RESPONSE / last packet / timeout)
    int    items = 0;          // number of needed-data packets received
    long   bytes = 0;          // total payload bytes of needed data
    bool   gotData = false;    // did we get the data this step is after?
};
static std::vector<StepStat> gStats;
// Mark first-data arrival + accumulate, given a step's stat record.
static void noteData(StepStat& st, size_t payloadSize) {
    if (st.firstDataMs < 0) st.firstDataMs = nowMs();
    st.items++;
    st.bytes += (long)payloadSize;
    st.gotData = true;
}

// Map of protocol type → human name for nicer logs.
static const char* typeName(int t) {
    switch (t) {
        case 0:                              return "EXCHANGE_PUBLIC_PEERS";
        case RESPOND_COMPUTOR_LIST:          return "RESPOND_COMPUTOR_LIST(2)";
        case BROADCAST_TICK_VOTE:            return "TICK_VOTE(3)";
        case TickData::type():               return "TICK_DATA(8)";
        case REQUEST_COMPUTOR_LIST:          return "REQUEST_COMPUTOR_LIST(11)";
        case RequestedQuorumTick::type:      return "REQUEST_QUORUM_TICK(14)";
        case REQUEST_TICK_DATA:              return "REQUEST_TICK_DATA(16)";
        case BROADCAST_TRANSACTION:          return "TRANSACTION(24)";
        case REQUEST_CURRENT_TICK_INFO:      return "REQUEST_CURRENT_TICK_INFO(27)";
        case RESPOND_CURRENT_TICK_INFO:      return "RESPOND_CURRENT_TICK_INFO(28)";
        case REQUEST_TICK_TRANSACTIONS:      return "REQUEST_TICK_TRANSACTIONS(29)";
        case 35:                             return "END_RESPONSE/NOP(35)";
        case RequestLog::type():             return "REQUEST_LOG(44)";
        case RespondLog::type():             return "RESPOND_LOG(45)";
        case RequestAllLogIdRangesFromTick::type(): return "REQUEST_ALL_LOG_RANGES(50)";
        case LogRangesPerTxInTick::type():   return "LOG_RANGES(51)";
        default:                             return "UNKNOWN";
    }
}

// ----------------------------------------------------------------------------
// Socket wrapper
// ----------------------------------------------------------------------------
struct Conn {
    int fd = -1;
    int timeoutSec = 8;

    bool connectTo(const char* ip, int port) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { ERR("socket(): %s", strerror(errno)); return false; }
        timeval tv{timeoutSec, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        int on = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) { ERR("bad IP '%s'", ip); return false; }

        INFO("Connecting to %s:%d (recv/send timeout %ds) ...", ip, port, timeoutSec);
        auto t = nowMs();
        if (::connect(fd, (sockaddr*)&addr, sizeof addr) < 0) {
            ERR("connect() failed after %.0fms: %s", nowMs() - t, strerror(errno));
            return false;
        }
        OK("TCP connected in %.1fms", nowMs() - t);
        return true;
    }

    // send all bytes
    bool sendAll(const uint8_t* buf, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) continue;
                ERR("send() failed: %s", strerror(errno));
                return false;
            }
            if (n == 0) { ERR("send() returned 0 (peer closed?)"); return false; }
            sent += n;
        }
        return true;
    }

    // recv exactly len bytes. returns: len ok, 0 = clean EOF, -1 = timeout, -2 = error
    int recvExact(uint8_t* buf, int len) {
        int got = 0;
        while (got < len) {
            ssize_t n = ::recv(fd, buf + got, len - got, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return -1; // timeout
                ERR("recv() failed: %s", strerror(errno));
                return -2;
            }
            if (n == 0) return got; // peer closed; return what we have (maybe 0)
            got += n;
        }
        return got;
    }

    void close_() { if (fd >= 0) { shutdown(fd, SHUT_RDWR); close(fd); fd = -1; } }
};

// A received packet.
struct Packet {
    RequestResponseHeader hdr{};
    std::vector<uint8_t> payload; // payload only (without the 8-byte header)
    int rawSize = 0;              // full packet size on the wire (header + payload)
};

// Receive one full packet (header then payload). hexBytes controls hexdump.
// returns true on success, false on timeout/EOF/error (reason logged).
static bool recvPacket(Conn& c, Packet& pkt, long hexBytes, bool quietTimeout = false) {
    uint8_t hb[sizeof(RequestResponseHeader)];
    int r = c.recvExact(hb, sizeof(RequestResponseHeader));
    if (r == -1) { if (!quietTimeout) WARN("recv header: TIMEOUT (no more data within %ds)", c.timeoutSec); return false; }
    if (r == -2) { ERR("recv header: socket error"); return false; }
    if (r == 0)  { WARN("recv header: peer closed connection (clean EOF)"); return false; }
    if (r != (int)sizeof(RequestResponseHeader)) {
        ERR("recv header: short read (%d of %zu bytes) — peer closed mid-header",
            r, sizeof(RequestResponseHeader));
        return false;
    }
    memcpy(&pkt.hdr, hb, sizeof(RequestResponseHeader));

    unsigned int fullSize = pkt.hdr.size();
    int type = pkt.hdr.type();
    uint32_t dejavu = pkt.hdr.getDejavu();

    // Sanity on size. size()==0 on the wire is reported as INT32_MAX by the
    // header accessor ("size is never zero, zero means broken packets").
    if (fullSize == (unsigned)INT32_MAX) {
        ERR("recv: header reports size 0 on the wire → BROKEN/garbage packet "
            "(raw bytes: %02x %02x %02x type=%02x dejavu=%08x)",
            hb[0], hb[1], hb[2], hb[3], dejavu);
        hexdump(hb, sizeof(RequestResponseHeader), 8);
        return false;
    }
    if (fullSize < sizeof(RequestResponseHeader)) {
        ERR("recv: header size %u < 8 → malformed packet", fullSize);
        hexdump(hb, sizeof(RequestResponseHeader), 8);
        return false;
    }
    if (fullSize > RequestResponseHeader::max_size) {
        ERR("recv: header size %u > max %u → malformed packet", fullSize, RequestResponseHeader::max_size);
        return false;
    }

    int payloadSize = (int)fullSize - (int)sizeof(RequestResponseHeader);
    pkt.payload.resize(payloadSize);
    if (payloadSize > 0) {
        int r2 = c.recvExact(pkt.payload.data(), payloadSize);
        if (r2 == -1) { ERR("recv payload: TIMEOUT after %d/%d bytes (type=%s)", 0, payloadSize, typeName(type)); return false; }
        if (r2 == -2) { ERR("recv payload: socket error"); return false; }
        if (r2 != payloadSize) {
            ERR("recv payload: short read (%d of %d bytes) for type=%s — peer closed or stalled mid-packet",
                r2, payloadSize, typeName(type));
            return false;
        }
    }
    pkt.rawSize = fullSize;

    if (gLogPackets)
        RECV("type=%s%s%s size=%u (payload=%d) dejavu=%08x",
             CBOLD, typeName(type), CRESET, fullSize, payloadSize, dejavu);

    // hexdump the whole packet (header + payload) reconstructed
    if (gLogPackets && hexBytes != 0) {
        std::vector<uint8_t> whole(sizeof(RequestResponseHeader) + payloadSize);
        memcpy(whole.data(), hb, sizeof(RequestResponseHeader));
        if (payloadSize) memcpy(whole.data() + sizeof(RequestResponseHeader), pkt.payload.data(), payloadSize);
        hexdump(whole.data(), whole.size(), hexBytes);
    }
    return true;
}

// Build + send a packet with header. payload may be null/0.
static uint32_t sendPacket(Conn& c, uint8_t type, const void* payload, int payloadSize, long hexBytes, uint32_t dejavu = 0xffffffff) {
    std::vector<uint8_t> buf(sizeof(RequestResponseHeader) + payloadSize);
    RequestResponseHeader h{};
    h.setType(type);
    h.setSize((unsigned)buf.size());
    if (dejavu == 0xffffffff) h.randomizeDejavu();
    else h.setDejavu(dejavu);
    memcpy(buf.data(), &h, sizeof(RequestResponseHeader));
    if (payloadSize) memcpy(buf.data() + sizeof(RequestResponseHeader), payload, payloadSize);

    if (gLogPackets) {
        SEND("type=%s%s%s size=%zu (payload=%d) dejavu=%08x",
             CBOLD, typeName(type), CRESET, buf.size(), payloadSize, h.getDejavu());
        if (hexBytes != 0) hexdump(buf.data(), buf.size(), hexBytes);
    }

    if (!c.sendAll(buf.data(), buf.size())) ERR("failed to send type=%s", typeName(type));
    return h.getDejavu();
}

// ----------------------------------------------------------------------------
// Decoders
// ----------------------------------------------------------------------------
static std::string idOf(const uint8_t* pub) {
    char id[64] = {0};
    getIdentityFromPublicKey(pub, id, false);
    return std::string(id, 60);
}

static void decodeCurrentTickInfo(const Packet& p) {
    if (p.payload.size() != sizeof(CurrentTickInfo)) {
        WARN("RESPOND_CURRENT_TICK_INFO payload size %zu != sizeof(CurrentTickInfo)=%zu — LAYOUT MISMATCH",
             p.payload.size(), sizeof(CurrentTickInfo));
        return;
    }
    CurrentTickInfo ti{};
    memcpy(&ti, p.payload.data(), sizeof ti);
    DETAIL("CurrentTickInfo: tick=" + std::to_string(ti.tick) +
           " initialTick=" + std::to_string(ti.initialTick) +
           " epoch=" + std::to_string(ti.epoch) +
           " tickDuration=" + std::to_string(ti.tickDuration) +
           " alignedVotes=" + std::to_string(ti.numberOfAlignedVotes) +
           " misalignedVotes=" + std::to_string(ti.numberOfMisalignedVotes));
}

static void decodeComputors(const Packet& p, const std::string& arbIdentity) {
    if (p.payload.size() != sizeof(Computors)) {
        WARN("RESPOND_COMPUTOR_LIST payload size %zu != sizeof(Computors)=%zu — LAYOUT MISMATCH",
             p.payload.size(), sizeof(Computors));
        return;
    }
    memcpy(&gComputors, p.payload.data(), sizeof gComputors);
    gHaveComputors = true;
    gEpoch = gComputors.epoch;
    DETAIL("Computors: epoch=" + std::to_string(gComputors.epoch) +
           " (NUMBER_OF_COMPUTORS=" + std::to_string(NUMBER_OF_COMPUTORS) + ")");
    DETAIL("  computor[0]   = " + idOf(gComputors.publicKeys[0].m256i_u8));
    DETAIL("  computor[675] = " + idOf(gComputors.publicKeys[NUMBER_OF_COMPUTORS-1].m256i_u8));

    // Signature verification (same as bob's getComputorList)
    bool zeroSig = isArrayZero(gComputors.signature, 64);
    if (zeroSig) {
        WARN("Computor-list signature is all zero → looks like a TESTNET computor list");
        return;
    }
    if (arbIdentity.empty()) {
        DETAIL("  (pass --arb <ARBITRATOR_IDENTITY> to verify the computor-list signature)");
        return;
    }
    uint8_t arbPub[32];
    getPublicKeyFromIdentity(arbIdentity.c_str(), arbPub);
    uint8_t digest[32];
    KangarooTwelve((uint8_t*)&gComputors, sizeof(Computors) - 64, digest, 32);
    bool ok = verify(arbPub, digest, gComputors.signature);
    if (ok) OK("Computor-list signature VALID against arbitrator %s", arbIdentity.c_str());
    else    ERR("Computor-list signature INVALID against arbitrator %s", arbIdentity.c_str());
}

// Verify a TickData exactly like bob's processTickData (canonical or legacy by size).
static void decodeTickData(const Packet& p) {
    size_t psz = p.payload.size();
    DETAIL("TickData payload size = " + std::to_string(psz) +
           " (canonical sizeof(TickData)=" + std::to_string(sizeof(TickData)) +
           ", legacy sizeof(LegacyTickData)=" + std::to_string(sizeof(LegacyTickData)) + ")");

    TickData td{};
    size_t verifySize = 0;
    bool legacy = false;
    if (psz == sizeof(TickData)) {
        memcpy(&td, p.payload.data(), sizeof td);
        verifySize = sizeof(TickData);
    } else if (psz == sizeof(LegacyTickData)) {
        LegacyTickData lt{};
        memcpy(&lt, p.payload.data(), sizeof lt);
        upcastLegacyTickData(lt, td);
        verifySize = sizeof(LegacyTickData);
        legacy = true;
        WARN("TickData is in LEGACY (1024-slot) layout — node is sending pre-epoch-214 format");
    } else {
        ERR("TickData UNEXPECTED payload size %zu — neither canonical(%zu) nor legacy(%zu). "
            "THIS is exactly what makes bob log 'unexpected payload size' and drop the tick.",
            psz, sizeof(TickData), sizeof(LegacyTickData));
        return;
    }

    int nTx = 0;
    int slots = legacy ? LEGACY_NUMBER_OF_TRANSACTIONS_PER_TICK : NUMBER_OF_TRANSACTIONS_PER_TICK;
    for (int i = 0; i < slots; i++) if (!(td.transactionDigests[i] == m256i::zero())) nTx++;

    char when[64];
    snprintf(when, sizeof(when), "20%02u-%02u-%02u %02u:%02u:%02u.%03u",
             td.year, td.month, td.day, td.hour, td.minute, td.second, td.millisecond);
    DETAIL("  tick=" + std::to_string(td.tick) +
           " epoch=" + std::to_string(td.epoch) +
           " computorIndex=" + std::to_string(td.computorIndex) +
           " time=" + when +
           " nonEmptyTxDigests=" + std::to_string(nTx));

    // signature check (needs computors of matching epoch)
    if (!gHaveComputors) { DETAIL("  (no computor list fetched → skipping signature check)"); return; }
    if (td.computorIndex >= NUMBER_OF_COMPUTORS) { ERR("  computorIndex %u out of range!", td.computorIndex); return; }

    uint8_t* compPub = gComputors.publicKeys[td.computorIndex].m256i_u8;
    bool ok;
    if (!legacy) {
        td.computorIndex ^= 8;
        uint8_t digest[32];
        KangarooTwelve((uint8_t*)&td, sizeof(TickData) - 64, digest, 32);
        ok = verify(compPub, digest, td.signature);
        td.computorIndex ^= 8;
    } else {
        // rebuild legacy buffer and verify over its byte range (as bob does)
        td.computorIndex ^= 8;
        LegacyTickData lv{};
        lv.computorIndex = td.computorIndex; lv.epoch = td.epoch; lv.tick = td.tick;
        lv.millisecond = td.millisecond; lv.second = td.second; lv.minute = td.minute;
        lv.hour = td.hour; lv.day = td.day; lv.month = td.month; lv.year = td.year;
        lv.timelock = td.timelock;
        memcpy(lv.transactionDigests, td.transactionDigests, sizeof(lv.transactionDigests));
        memcpy(lv.contractFees, td.contractFees, sizeof(lv.contractFees));
        memcpy(lv.signature, td.signature, SIGNATURE_SIZE);
        uint8_t digest[32];
        KangarooTwelve((uint8_t*)&lv, sizeof(LegacyTickData) - 64, digest, 32);
        ok = verify(compPub, digest, td.signature);
        td.computorIndex ^= 8;
    }
    if (ok) OK("  TickData signature VALID (computor %u)", td.computorIndex);
    else    ERR("  TickData signature INVALID (computor %u) — bob would log 'TickData has invalid signature'", td.computorIndex);
}

static void decodeTickVote(const Packet& p, int idx) {
    if (p.payload.size() != sizeof(TickVote)) {
        WARN("TICK_VOTE #%d payload size %zu != sizeof(TickVote)=%zu — LAYOUT MISMATCH",
             idx, p.payload.size(), sizeof(TickVote));
        return;
    }
    TickVote v{};
    memcpy(&v, p.payload.data(), sizeof v);
    std::string line = "  vote#" + std::to_string(idx) +
                       " tick=" + std::to_string(v.tick) +
                       " epoch=" + std::to_string(v.epoch) +
                       " computorIndex=" + std::to_string(v.computorIndex);

    if (gHaveComputors && v.computorIndex < NUMBER_OF_COMPUTORS) {
        uint8_t* compPub = gComputors.publicKeys[v.computorIndex].m256i_u8;
        v.computorIndex ^= 3;
        uint8_t digest[32];
        KangarooTwelve((uint8_t*)&v, sizeof(TickVote) - 64, digest, 32);
        bool ok = verify(compPub, digest, v.signature);
        v.computorIndex ^= 3;
        unsigned int score = __builtin_bswap64(((unsigned int*)v.signature)[0]);
        line += ok ? std::string(" sig=") + "VALID" : std::string(" sig=") + "INVALID";
        if (score > TARGET_TICK_VOTE_SIGNATURE) line += " [LOW-DIFF sig!]";
    }
    DETAIL(line);
}

static void decodeTransaction(const Packet& p, int idx) {
    if (p.payload.size() < sizeof(Transaction)) {
        WARN("TRANSACTION #%d payload size %zu < sizeof(Transaction)=%zu", idx, p.payload.size(), sizeof(Transaction));
        return;
    }
    Transaction t{};
    memcpy(&t, p.payload.data(), sizeof t);
    size_t expect = sizeof(Transaction) + t.inputSize + SIGNATURE_SIZE;
    std::string line = "  tx#" + std::to_string(idx) +
                       " tick=" + std::to_string(t.tick) +
                       " amount=" + std::to_string(t.amount) +
                       " inputType=" + std::to_string(t.inputType) +
                       " inputSize=" + std::to_string(t.inputSize) +
                       " from=" + idOf(t.sourcePublicKey).substr(0, 16) + "..." +
                       " to=" + idOf(t.destinationPublicKey).substr(0, 16) + "...";
    if (p.payload.size() != expect)
        line += " [size " + std::to_string(p.payload.size()) + " != expected " + std::to_string(expect) + "!]";
    DETAIL(line);
}

// Parse "p0-p1-p2-p3" into out[4]. Returns true on success.
static bool parsePasscode(const std::string& s, uint64_t out[4]) {
    size_t start = 0; int idx = 0;
    while (idx < 4 && start <= s.size()) {
        size_t dash = s.find('-', start);
        std::string tok = s.substr(start, dash == std::string::npos ? std::string::npos : dash - start);
        if (tok.empty()) return false;
        try { out[idx] = (uint64_t)std::stoull(tok, nullptr, 10); } catch (...) { return false; }
        idx++;
        if (dash == std::string::npos) break;
        start = dash + 1;
    }
    return idx == 4;
}

// Decode a LogRangesPerTxInTick (type 51). Returns true and fills min/max logId
// (inclusive range across all txs of the tick) if the payload is well-formed.
static bool decodeLogRanges(const Packet& p, long long& minId, long long& maxId, bool verbose) {
    if (p.payload.size() != sizeof(LogRangesPerTxInTick)) {
        WARN("LOG_RANGES(51) payload size %zu != sizeof(LogRangesPerTxInTick)=%zu — LAYOUT MISMATCH",
             p.payload.size(), sizeof(LogRangesPerTxInTick));
        return false;
    }
    LogRangesPerTxInTick lr{};
    memcpy(&lr, p.payload.data(), sizeof lr);
    lr.getMinMax(minId, maxId);  // maxId here is exclusive end (fromLogId+length)
    if (verbose) {
        if (minId < 0 || maxId < 0)
            DETAIL("LogRanges: tick has no logs (min/max = " + std::to_string(minId) + "/" + std::to_string(maxId) + ")");
        else
            DETAIL("LogRanges: logId range [" + std::to_string(minId) + " .. " + std::to_string(maxId - 1) +
                   "]  → " + std::to_string(maxId - minId) + " log ids");
    }
    return true;
}

// Parse a RespondLog (type 45) payload: a back-to-back stream of packed log
// events. Returns the number of events; fills perType counts. Prints up to
// maxPrint events when verbose.
static int parseLogEvents(const uint8_t* data, size_t len, bool verbose, int maxPrint) {
    size_t off = 0; int n = 0;
    while (off + LOG_PACKED_HEADER <= len) {
        uint16_t epoch; uint32_t tick; uint32_t combo; uint64_t logId;
        memcpy(&epoch, data + off + 0, 2);
        memcpy(&tick,  data + off + 2, 4);
        memcpy(&combo, data + off + 6, 4);
        memcpy(&logId, data + off + 10, 8);
        uint32_t bodySize = combo & 0x00FFFFFFu;
        uint32_t type     = (combo >> 24) & 0xFFu;
        if (off + LOG_PACKED_HEADER + bodySize > len) {
            if (verbose) WARN("  log event at offset %zu claims body %u but only %zu bytes left — truncated/garbage",
                              off, bodySize, len - off - LOG_PACKED_HEADER);
            break;
        }
        if (verbose && n < maxPrint)
            DETAIL("  log#" + std::to_string(n) + " logId=" + std::to_string(logId) +
                   " tick=" + std::to_string(tick) + " epoch=" + std::to_string(epoch) +
                   " type=" + std::to_string(type) + "(" + logTypeName(type) + ")" +
                   " bodySize=" + std::to_string(bodySize));
        else if (verbose && n == maxPrint)
            DETAIL("  ... (further log events hidden)");
        off += LOG_PACKED_HEADER + bodySize;
        n++;
    }
    return n;
}

// ----------------------------------------------------------------------------
// A response-draining loop: keep reading packets and dispatch, until an
// END_RESPONSE(35) with the matching dejavu, a timeout, or maxPackets.
// onPacket returns true to keep going, false to stop early.
// ----------------------------------------------------------------------------
template <typename Fn>
static void drainResponses(Conn& c, uint32_t expectDejavu, long hexBytes, int maxPackets, Fn onPacket) {
    int count = 0;
    while (maxPackets < 0 || count < maxPackets) {
        Packet pkt;
        if (!recvPacket(c, pkt, hexBytes)) break; // timeout / eof / error already logged
        count++;
        int type = pkt.hdr.type();
        uint32_t dj = pkt.hdr.getDejavu();

        if (expectDejavu != 0 && dj != expectDejavu && dj != 0 && type != 35 && type != 0) {
            WARN("dejavu mismatch: got %08x, expected %08x (type=%s) — unexpected/late packet",
                 dj, expectDejavu, typeName(type));
        }
        if (type == 35) { // END_RESPONSE / NOP
            if (gLogPackets) OK("END_RESPONSE received (dejavu=%08x) — node finished this response", dj);
            break;
        }
        if (!onPacket(pkt)) break;
    }
    if (gLogPackets && maxPackets >= 0 && count >= maxPackets)
        INFO("(stopped after %d packets; raise the limit to see more)", count);
}

// Fetch all logging events for a tick (the same 2-step flow bob uses):
//   1) RequestAllLogIdRangesFromTick (50) → LogRangesPerTxInTick (51): get logId range
//   2) RequestLog (44) in chunks of 128 → RespondLog (45): the packed log events
// Returns elapsed ms; fills bytes (all responses), events (parsed), ok (node served us).
static double fetchLogsForTick(Conn& c, uint32_t tick, long hexBytes, bool verbose,
                               long& bytes, int& events, bool& ok) {
    double t0 = nowMs();
    bytes = 0; events = 0; ok = false;

    // 1) log id ranges
    RequestAllLogIdRangesFromTick ralr{};
    memcpy(ralr.passcode, gPasscode, sizeof ralr.passcode);
    ralr.tick = tick;
    long long minId = -1, maxId = -1; bool gotRange = false;
    uint32_t dj = sendPacket(c, RequestAllLogIdRangesFromTick::type(), &ralr, sizeof ralr, hexBytes);
    drainResponses(c, dj, hexBytes, 50, [&](const Packet& p) {
        if (p.hdr.type() == LogRangesPerTxInTick::type()) {
            gotRange = true; bytes += (long)p.payload.size();
            decodeLogRanges(p, minId, maxId, verbose);
            return false; // single packet, no terminator on success
        }
        return true;
    });
    if (!gotRange) return nowMs() - t0; // only END_RESPONSE → rejected (bad passcode / tick not verified yet)
    ok = true; // node served the range (tick may legitimately have no logs)

    // 2) log content, chunked by 128 logIds (bob's BOB_LOG_EVENT_CHUNK_SIZE; node rejects >= 1000)
    if (minId >= 0 && maxId > minId) {
        const long long CHUNK = 128;
        for (long long s = minId; s < maxId; s += CHUNK) {
            long long e = std::min(maxId - 1, s + CHUNK - 1);
            RequestLog rl{};
            memcpy(rl.passcode, gPasscode, sizeof rl.passcode);
            rl.fromid = (unsigned long long)s;
            rl.toid   = (unsigned long long)e;
            uint32_t dj2 = sendPacket(c, RequestLog::type(), &rl, sizeof rl, hexBytes);
            drainResponses(c, dj2, hexBytes, 50, [&](const Packet& p) {
                if (p.hdr.type() == RespondLog::type()) {
                    bytes += (long)p.payload.size();
                    events += parseLogEvents(p.payload.data(), p.payload.size(), verbose, 5);
                    return false;
                }
                return true;
            });
        }
    }
    return nowMs() - t0;
}

// ----------------------------------------------------------------------------
// Catch-up mode: keep the connection open and walk a range of ticks, fetching
// each tick's data sequentially (like bob during sync), printing only per-tick
// timings and a summary at the end. No per-tick data is decoded/printed.
// ----------------------------------------------------------------------------
struct Acc {
    int    n = 0, fails = 0;
    double total = 0, mn = 1e18, mx = 0;
    long   bytes = 0, items = 0;
    void add(double ms, long b, int it, bool ok) {
        n++; total += ms; if (ms < mn) mn = ms; if (ms > mx) mx = ms;
        bytes += b; items += it; if (!ok) fails++;
    }
    double avg() const { return n ? total / n : 0; }
};

// One quiet fetch of a single response stream. Returns elapsed ms; fills bytes/
// items/ok. stopType<0 means "drain until END_RESPONSE" (votes/txs); otherwise
// stop on the first packet of stopType (tickdata).
static double quietFetch(Conn& c, uint8_t reqType, const void* payload, int payloadSize,
                         int wantType, bool stopOnFirst, long& bytes, int& items, bool& ok) {
    double t0 = nowMs();
    bytes = 0; items = 0; ok = false;
    uint32_t dj = sendPacket(c, reqType, payload, payloadSize, 0);
    drainResponses(c, dj, 0, 100000, [&](const Packet& p) {
        if (p.hdr.type() == wantType) {
            items++; bytes += (long)p.payload.size(); ok = true;
            if (stopOnFirst) return false; // tickdata: exactly one packet, no terminator
        }
        return true; // keep draining (votes/txs end on END_RESPONSE)
    });
    return nowMs() - t0;
}

static void fmtBytes(double b, char* out, size_t n) {
    if      (b >= 1024.0*1024*1024) snprintf(out, n, "%.2f GB", b/(1024.0*1024*1024));
    else if (b >= 1024.0*1024)      snprintf(out, n, "%.2f MB", b/(1024.0*1024));
    else if (b >= 1024.0)           snprintf(out, n, "%.1f KB", b/1024.0);
    else                            snprintf(out, n, "%.0f B",  b);
}

// Run the catch-up. Returns 0 on success.
static int runCatchup(Conn& c, uint32_t startTick, long count,
                      bool fTd, bool fVotes, bool fTxs, bool fLogs, long timeoutS) {
    STEP("CATCH-UP — ticks %u .. %u (%ld ticks), connection kept open", startTick, startTick + (uint32_t)count - 1, count);
    {
        std::string sel;
        if (fTd)    sel += "tickdata ";
        if (fVotes) sel += "votes ";
        if (fTxs)   sel += "txs ";
        if (fLogs)  sel += "logs ";
        if (fLogs && !gHavePasscode)
            WARN("logs requested but no --passcode given — the node will reject log requests (expect all 'empty').");
        INFO("Per-tick fetch: %s| sequential (one tick at a time), signature checks skipped (timing only)", sel.c_str());
        INFO("Note: bob pipelines requests during real sync; this measures per-tick round-trip latency.");
        INFO("'empty' column = ticks where the node returned no data for that type (normal for empty tx ticks).");
    }

    Acc accTd, accVotes, accTxs, accLogs;
    double wall0 = nowMs();
    int gotTdTicks = 0, emptyTicks = 0;

    // Suppress per-packet logging for the whole loop; restore after.
    bool prevLog = gLogPackets;
    gLogPackets = false;

    for (long i = 0; i < count; i++) {
        uint32_t tick = startTick + (uint32_t)i;
        std::string line;
        char buf[96];
        bool anyData = false;

        if (fTd) {
            RequestTickData rtd{}; rtd.tick = tick;
            long b; int it; bool ok;
            double ms = quietFetch(c, REQUEST_TICK_DATA, &rtd, sizeof rtd, TickData::type(), true, b, it, ok);
            accTd.add(ms, b, it, ok);
            char bs[24]; fmtBytes((double)b, bs, sizeof bs);
            snprintf(buf, sizeof buf, "td %6.1fms %-9s", ms, ok ? bs : "(no data)");
            line += buf;
            if (ok) { gotTdTicks++; anyData = true; }
        }
        if (fVotes) {
            RequestedQuorumTick rqt{}; rqt.tick = tick; memset(rqt.voteFlags, 0, sizeof rqt.voteFlags);
            long b; int it; bool ok;
            double ms = quietFetch(c, RequestedQuorumTick::type, &rqt, sizeof rqt, BROADCAST_TICK_VOTE, false, b, it, ok);
            accVotes.add(ms, b, it, ok);
            snprintf(buf, sizeof buf, "  votes %6.1fms x%-3d", ms, it);
            line += buf;
            if (ok) anyData = true;
        }
        if (fTxs) {
            RequestedTickTransactions rtt{}; rtt.tick = tick; memset(rtt.flag, 0, sizeof rtt.flag);
            long b; int it; bool ok;
            double ms = quietFetch(c, REQUEST_TICK_TRANSACTIONS, &rtt, sizeof rtt, BROADCAST_TRANSACTION, false, b, it, ok);
            accTxs.add(ms, b, it, ok);
            snprintf(buf, sizeof buf, "  txs %6.1fms x%-3d", ms, it);
            line += buf;
            if (ok) anyData = true;
        }
        if (fLogs) {
            long b; int ev; bool ok;
            double ms = fetchLogsForTick(c, tick, 0, false, b, ev, ok);
            accLogs.add(ms, b, ev, ok);
            snprintf(buf, sizeof buf, "  logs %6.1fms x%-4d", ms, ev);
            line += buf;
            if (ok) anyData = true;
        }
        if (!anyData) emptyTicks++;

        // Compact per-tick timing line (printed even with packet logging off).
        printf("  %s[%4ld/%ld]%s tick %u  %s\n",
               CGREY, i + 1, count, CRESET, tick, line.c_str());
        fflush(stdout);

        if (c.fd < 0) { ERR("connection lost at tick %u — node closed the socket", tick); gLogPackets = prevLog; return 3; }
    }

    gLogPackets = prevLog;
    double wallMs = nowMs() - wall0;

    // ---- Summary ----
    STEP("CATCH-UP TIMING SUMMARY");
    printf("            %s%-9s %6s %6s %10s %8s %8s %8s %12s%s\n",
           CBOLD, "type", "ticks", "empty", "total", "avg", "min", "max", "bytes", CRESET);
    printf("            %s--------- ------ ------ ---------- -------- -------- -------- ------------%s\n", CGREY, CRESET);
    auto row = [&](const char* name, const Acc& a) {
        if (a.n == 0) return;
        char bs[24]; fmtBytes((double)a.bytes, bs, sizeof bs);
        const char* col = a.fails ? CYELLOW : CGREEN;
        printf("            %s%-9s%s %6d %s%6d%s %8.2fs %7.1fms %7.1fms %7.1fms %12s\n",
               col, name, CRESET, a.n, a.fails ? CYELLOW : CGREY, a.fails, CRESET,
               a.total / 1000.0, a.avg(), (a.mn > 1e17 ? 0.0 : a.mn), a.mx, bs);
    };
    row("tickdata", accTd);
    row("votes",    accVotes);
    row("txs",      accTxs);
    row("logs",     accLogs);
    printf("            %s--------- ------ ------ ---------- -------- -------- -------- ------------%s\n", CGREY, CRESET);

    double totalBytes = (double)(accTd.bytes + accVotes.bytes + accTxs.bytes + accLogs.bytes);
    char tb[24]; fmtBytes(totalBytes, tb, sizeof tb);
    double ticksPerSec = (wallMs > 0) ? (count / (wallMs / 1000.0)) : 0;
    double mbPerSec = (wallMs > 0) ? (totalBytes / (1024.0*1024.0) / (wallMs / 1000.0)) : 0;

    INFO("Walked %ld ticks in %.2fs  →  %.1f ticks/s, %s transferred, %.2f MB/s",
         count, wallMs / 1000.0, ticksPerSec, tb, mbPerSec);
    if (fTd)
        INFO("Tick data present for %d/%ld ticks (%d ticks returned no data at all)",
             gotTdTicks, count, emptyTicks);
    if (fLogs)
        INFO("Log events parsed: %ld total across %d ticks that served logs", accLogs.items, accLogs.n - accLogs.fails);
    INFO("avg per tick (all enabled fetches): %.1fms", count ? wallMs / count : 0);
    return 0;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
static void printUsage(const char* argv0) {
    printf("Usage: %s <ip> <port> [options]\n", argv0);
    printf("  --tick <N>        tick to request (default: node's current tick)\n");
    printf("  --arb <IDENTITY>  arbitrator identity to verify computor-list signature\n");
    printf("  --passcode p0-p1-p2-p3  passcode for logging-event requests (logs step)\n");
    printf("  --steps <list>    tickinfo,computors,tickdata,votes,txs (default: all of these)\n");
    printf("                    'handshake' (EXCHANGE_PUBLIC_PEERS) is opt-in only, never run by default\n");
    printf("                    'logs' is opt-in (needs --passcode); runs by default only if --passcode given\n");
    printf("  --binary-output   print raw packet hexdumps (OFF by default)\n");
    printf("  --hex <N>         hexdump bytes per packet when --binary-output is set (default 128; -1=full)\n");
    printf("  --timeout <sec>   socket recv timeout (default 8)\n");
    printf("  --max-votes <N>   max votes to print (default 8; -1=all)\n");
    printf("  --max-txs <N>     max transactions to print (default 16; -1=all)\n");
    printf("  --loop-tickinfo   after the run, poll current-tick-info forever\n");
    printf("  --no-color        disable ANSI colors\n");
    printf("\n");
    printf("  Catch-up mode (keep connection open, walk a range of ticks, timings only):\n");
    printf("  --catchup         enable catch-up mode\n");
    printf("  --count <N>       number of ticks to walk (default 100)\n");
    printf("  --tick <N>        start tick (default: node current tick - count)\n");
    printf("  --steps <list>    in catch-up, picks per-tick fetches among tickdata,votes,txs,logs\n");
    printf("                    (default: tickdata,votes,txs; 'logs' needs --passcode)\n");
    printf("  e.g. ./bob_probe <ip> 21841 --catchup --tick 56000000 --count 500 --steps tickdata\n");
    printf("  e.g. ./bob_probe <ip> 21841 --catchup --count 200 --steps logs --passcode 1-2-3-4\n");
}

int main(int argc, char** argv) {
    gT0 = std::chrono::steady_clock::now();
    if (argc < 3) { printUsage(argv[0]); return 1; }

    std::string ip = argv[1];
    int port = atoi(argv[2]);

    long     tickArg   = -1;        // -1 = use node's current tick
    std::string arb;
    std::set<std::string> steps;
    long     hexBytes  = 128;
    bool     binaryOutput = false;  // raw hexdumps are gated behind --binary-output
    int      timeoutS  = 8;
    int      maxVotes  = 8;
    int      maxTxs    = 16;
    bool     loopTickInfo = false;
    bool     catchup   = false;     // catch-up mode: walk a range of ticks
    long     count     = 100;       // number of ticks to walk in catch-up

    for (int i = 3; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { ERR("%s needs a value", name); exit(1); }
            return argv[++i];
        };
        if      (a == "--tick")        tickArg = atol(next("--tick").c_str());
        else if (a == "--arb")         arb = next("--arb");
        else if (a == "--passcode") {
            std::string pc = next("--passcode");
            if (!parsePasscode(pc, gPasscode)) { ERR("--passcode must be 4 uint64 like p0-p1-p2-p3"); return 1; }
            gHavePasscode = true;
        }
        else if (a == "--hex")         hexBytes = atol(next("--hex").c_str());
        else if (a == "--binary-output") binaryOutput = true;
        else if (a == "--timeout")     timeoutS = atoi(next("--timeout").c_str());
        else if (a == "--max-votes")   maxVotes = atoi(next("--max-votes").c_str());
        else if (a == "--max-txs")     maxTxs = atoi(next("--max-txs").c_str());
        else if (a == "--loop-tickinfo") loopTickInfo = true;
        else if (a == "--catchup")     catchup = true;
        else if (a == "--count")       count = atol(next("--count").c_str());
        else if (a == "--no-color")    gColor = false;
        else if (a == "--steps") {
            std::stringstream ss(next("--steps")); std::string s;
            while (std::getline(ss, s, ',')) if (!s.empty()) steps.insert(s);
        }
        else { ERR("unknown option '%s'", a.c_str()); printUsage(argv[0]); return 1; }
    }
    // Raw packet hexdumps only happen when --binary-output is given.
    if (!binaryOutput) hexBytes = 0;
    bool all = steps.empty();
    auto want = [&](const char* s){ return all || steps.count(s); };
    // Peer-exchange handshake is OFF by default for testing: it is only run
    // when explicitly requested via --steps handshake, never as part of "all".
    auto wantHandshake = [&](){ return steps.count("handshake") > 0; };

    printf("%s%s================ bob_probe — Qubic P2P protocol probe ================%s\n", CBOLD, CCYAN, CRESET);
    INFO("Target node     : %s:%d", ip.c_str(), port);
    INFO("This build's struct sizes (what bob expects on the wire):");
    DETAIL("  RequestResponseHeader = " + std::to_string(sizeof(RequestResponseHeader)));
    DETAIL("  CurrentTickInfo       = " + std::to_string(sizeof(CurrentTickInfo)));
    DETAIL("  Computors             = " + std::to_string(sizeof(Computors)) +
           "  (NUMBER_OF_COMPUTORS=" + std::to_string(NUMBER_OF_COMPUTORS) + ")");
    DETAIL("  TickData (canonical)  = " + std::to_string(sizeof(TickData)) +
           "  (NUMBER_OF_TRANSACTIONS_PER_TICK=" + std::to_string(NUMBER_OF_TRANSACTIONS_PER_TICK) + ")");
    DETAIL("  LegacyTickData        = " + std::to_string(sizeof(LegacyTickData)) +
           "  (LEGACY slots=" + std::to_string(LEGACY_NUMBER_OF_TRANSACTIONS_PER_TICK) + ")");
    DETAIL("  TickVote              = " + std::to_string(sizeof(TickVote)));
    DETAIL("  Transaction (header)  = " + std::to_string(sizeof(Transaction)));
    DETAIL("  RequestTickData       = " + std::to_string(sizeof(RequestTickData)));
    DETAIL("  RequestedQuorumTick   = " + std::to_string(sizeof(RequestedQuorumTick)));
    DETAIL("  RequestedTickTransactions = " + std::to_string(sizeof(RequestedTickTransactions)));
    DETAIL("  RequestLog                = " + std::to_string(sizeof(RequestLog)) +
           "  RequestAllLogIdRangesFromTick = " + std::to_string(sizeof(RequestAllLogIdRangesFromTick)));
    DETAIL("  LogRangesPerTxInTick      = " + std::to_string(sizeof(LogRangesPerTxInTick)) +
           "  (LOG_TX_PER_TICK=" + std::to_string(LOG_TX_PER_TICK) + ", log packed header=" + std::to_string(LOG_PACKED_HEADER) + ")");

    Conn c; c.timeoutSec = timeoutS;
    if (!c.connectTo(ip.c_str(), port)) return 2;

    uint32_t nodeTick = 0;
    uint16_t nodeEpoch = 0;

    // ======================= CATCH-UP MODE ==============================
    if (catchup) {
        if (count <= 0) { ERR("--count must be > 0"); return 1; }
        // Which per-tick data to fetch: subset of {tickdata,votes,txs}, or all
        // three if --steps was not given.
        bool noSteps = steps.empty();
        bool fTd    = noSteps || steps.count("tickdata");
        bool fVotes = noSteps || steps.count("votes");
        bool fTxs   = noSteps || steps.count("txs");
        // logs need a passcode: included explicitly via --steps logs, or in a
        // default run (no --steps) whenever a --passcode was supplied.
        bool fLogs  = steps.count("logs") || (noSteps && gHavePasscode);

        // Determine the start tick. If --tick not given, derive it from the
        // node's current tick so we catch up the most recent `count` ticks.
        uint32_t startTick = (tickArg >= 0) ? (uint32_t)tickArg : 0;
        if (tickArg < 0) {
            STEP("STEP tickinfo — REQUEST_CURRENT_TICK_INFO (27) to pick a start tick");
            uint32_t dj = sendPacket(c, REQUEST_CURRENT_TICK_INFO, nullptr, 0, hexBytes);
            drainResponses(c, dj, hexBytes, 50, [&](const Packet& p) {
                if (p.hdr.type() == RESPOND_CURRENT_TICK_INFO && p.payload.size() == sizeof(CurrentTickInfo)) {
                    CurrentTickInfo ti{}; memcpy(&ti, p.payload.data(), sizeof ti);
                    nodeTick = ti.tick; nodeEpoch = ti.epoch; return false;
                }
                return true;
            });
            if (nodeTick == 0) { ERR("could not get current tick; pass --tick <start> explicitly"); return 2; }
            startTick = (nodeTick > (uint32_t)count) ? (nodeTick - (uint32_t)count) : 1;
            INFO("Node current tick = %u (epoch %u). No --tick given → starting at %u",
                 nodeTick, nodeEpoch, startTick);
        }

        int rc = runCatchup(c, startTick, count, fTd, fVotes, fTxs, fLogs, timeoutS);
        c.close_();
        return rc;
    }
    // ====================================================================

    // ---- Step: handshake (EXCHANGE_PUBLIC_PEERS, type 0), as bob does for BM ----
    if (wantHandshake()) {
        STEP("STEP handshake — EXCHANGE_PUBLIC_PEERS (type 0)");
        struct { uint8_t ip[4][4]; } peers{};
        memset(&peers, 0, sizeof peers);
        sendPacket(c, 0, &peers, sizeof peers, hexBytes);
        INFO("Reading any unsolicited packets the node sends right after handshake (until timeout)...");
        // Node may push EXCHANGE_PUBLIC_PEERS / votes / txs unsolicited. Read briefly.
        for (int i = 0; i < 32; i++) {
            Packet pkt;
            if (!recvPacket(c, pkt, hexBytes, /*quietTimeout*/true)) break;
        }
    }

    // ---- Step: current tick info ----
    if (want("tickinfo") || tickArg < 0) {
        STEP("STEP tickinfo — REQUEST_CURRENT_TICK_INFO (27) → RESPOND_CURRENT_TICK_INFO (28)");
        StepStat st{"tickinfo"}; st.sentMs = nowMs();
        uint32_t dj = sendPacket(c, REQUEST_CURRENT_TICK_INFO, nullptr, 0, hexBytes);
        drainResponses(c, dj, hexBytes, 50, [&](const Packet& p) {
            if (p.hdr.type() == RESPOND_CURRENT_TICK_INFO) {
                noteData(st, p.payload.size());
                decodeCurrentTickInfo(p);
                if (p.payload.size() == sizeof(CurrentTickInfo)) {
                    CurrentTickInfo ti{}; memcpy(&ti, p.payload.data(), sizeof ti);
                    nodeTick = ti.tick; nodeEpoch = ti.epoch;
                }
                return false; // stop after we get it
            }
            return true;
        });
        st.doneMs = nowMs();
        if (!st.gotData) ERR("Node did not return RESPOND_CURRENT_TICK_INFO — it may not support type 27, or layout differs");
        else OK("Node current tick = %u, epoch = %u  (took %.1fms)", nodeTick, nodeEpoch, st.firstDataMs - st.sentMs);
        gStats.push_back(st);
    }

    uint32_t reqTick = (tickArg >= 0) ? (uint32_t)tickArg : nodeTick;
    if (reqTick == 0) {
        WARN("No tick to request (node tick unknown and --tick not given). Tickdata/votes/txs steps need a tick.");
    } else {
        INFO("Will use tick %u for tickdata/votes/txs steps", reqTick);
    }

    // ---- Step: computor list ----
    if (want("computors")) {
        STEP("STEP computors — REQUEST_COMPUTOR_LIST (11) → RESPOND_COMPUTOR_LIST (2)");
        StepStat st{"computors"}; st.sentMs = nowMs();
        uint32_t dj = sendPacket(c, REQUEST_COMPUTOR_LIST, nullptr, 0, hexBytes);
        drainResponses(c, dj, hexBytes, 50, [&](const Packet& p) {
            if (p.hdr.type() == RESPOND_COMPUTOR_LIST) { noteData(st, p.payload.size()); decodeComputors(p, arb); return false; }
            return true;
        });
        st.doneMs = nowMs();
        if (!st.gotData) ERR("Node did not return RESPOND_COMPUTOR_LIST (type 2)");
        else OK("Computor list received (took %.1fms)", st.firstDataMs - st.sentMs);
        gStats.push_back(st);
    }

    // ---- Step: tick data ----
    if (want("tickdata") && reqTick) {
        STEP("STEP tickdata — REQUEST_TICK_DATA (16) for tick %u → TickData (8)", reqTick);
        StepStat st{"tickdata"}; st.sentMs = nowMs();
        RequestTickData rtd{}; rtd.tick = reqTick;
        uint32_t dj = sendPacket(c, REQUEST_TICK_DATA, &rtd, sizeof rtd, hexBytes);
        drainResponses(c, dj, hexBytes, 50, [&](const Packet& p) {
            if (p.hdr.type() == TickData::type()) {
                noteData(st, p.payload.size());
                decodeTickData(p);
                // A successful REQUEST_TICK_DATA reply is exactly ONE TickData
                // packet with NO END_RESPONSE terminator (see bob's replyTickData:
                // sendEndPacket is only called when the node has no data). So stop
                // here instead of waiting 8s for a terminator that never comes.
                return false;
            }
            return true;
        });
        st.doneMs = nowMs();
        if (!st.gotData) WARN("No TickData(8) received for tick %u (node may not have it, or only sent END_RESPONSE)", reqTick);
        else OK("TickData received (took %.1fms)", st.firstDataMs - st.sentMs);
        gStats.push_back(st);
    }

    // ---- Step: quorum tick votes ----
    if (want("votes") && reqTick) {
        STEP("STEP votes — REQUEST_QUORUM_TICK (14) for tick %u → TICK_VOTE (3) x N", reqTick);
        StepStat st{"votes"}; st.sentMs = nowMs();
        RequestedQuorumTick rqt{}; rqt.tick = reqTick; memset(rqt.voteFlags, 0, sizeof rqt.voteFlags);
        uint32_t dj = sendPacket(c, RequestedQuorumTick::type, &rqt, sizeof rqt, hexBytes);
        int nVotes = 0;
        drainResponses(c, dj, /*hex per vote off after first few*/ hexBytes, 800, [&](const Packet& p) {
            if (p.hdr.type() == BROADCAST_TICK_VOTE) {
                noteData(st, p.payload.size());
                if (maxVotes < 0 || nVotes < maxVotes) decodeTickVote(p, nVotes);
                else if (nVotes == maxVotes) DETAIL("  ... (further votes hidden; --max-votes -1 to show all)");
                nVotes++;
                return true;
            }
            return true;
        });
        st.doneMs = nowMs();
        if (st.gotData) OK("Received %d vote packet(s) for tick %u  (first %.1fms, all %.1fms)",
                           nVotes, reqTick, st.firstDataMs - st.sentMs, st.doneMs - st.sentMs);
        else            WARN("Received 0 vote packet(s) for tick %u (node may not have it for this tick)", reqTick);
        gStats.push_back(st);
    }

    // ---- Step: tick transactions ----
    if (want("txs") && reqTick) {
        STEP("STEP txs — REQUEST_TICK_TRANSACTIONS (29) for tick %u → TRANSACTION (24) x N", reqTick);
        StepStat st{"txs"}; st.sentMs = nowMs();
        RequestedTickTransactions rtt{}; rtt.tick = reqTick; memset(rtt.flag, 0, sizeof rtt.flag);
        uint32_t dj = sendPacket(c, REQUEST_TICK_TRANSACTIONS, &rtt, sizeof rtt, hexBytes);
        int nTx = 0;
        drainResponses(c, dj, hexBytes, 5000, [&](const Packet& p) {
            if (p.hdr.type() == BROADCAST_TRANSACTION) {
                noteData(st, p.payload.size());
                if (maxTxs < 0 || nTx < maxTxs) decodeTransaction(p, nTx);
                else if (nTx == maxTxs) DETAIL("  ... (further txs hidden; --max-txs -1 to show all)");
                nTx++;
                return true;
            }
            return true;
        });
        st.doneMs = nowMs();
        if (st.gotData) OK("Received %d transaction packet(s) for tick %u  (first %.1fms, all %.1fms)",
                           nTx, reqTick, st.firstDataMs - st.sentMs, st.doneMs - st.sentMs);
        else            WARN("Received 0 transaction packet(s) for tick %u", reqTick);
        gStats.push_back(st);
    }

    // ---- Step: logging events (passcode-gated) ----
    // Opt-in: runs if 'logs' is in --steps, or in a default run when a passcode
    // was supplied (no point hammering the node for logs without one).
    if ((steps.count("logs") || (all && gHavePasscode)) && reqTick) {
        STEP("STEP logs — REQUEST_ALL_LOG_RANGES (50) → LOG_RANGES (51), then REQUEST_LOG (44) → RESPOND_LOG (45) for tick %u", reqTick);
        if (!gHavePasscode)
            WARN("No --passcode given — the node will reject log requests (expect END_RESPONSE / no data).");
        StepStat st{"logs"}; st.sentMs = nowMs();
        long bytes; int events; bool ok;
        double ms = fetchLogsForTick(c, reqTick, hexBytes, /*verbose*/true, bytes, events, ok);
        st.doneMs = nowMs();
        if (ok) {
            st.firstDataMs = st.sentMs; st.items = events; st.bytes = bytes; st.gotData = true;
            OK("Logs for tick %u: %d event(s), %ld bytes (took %.1fms)", reqTick, events, bytes, ms);
        } else {
            WARN("No logs served for tick %u — bad/missing passcode, or tick not yet verified on the node "
                 "(node only serves ticks < its current verify tick)", reqTick);
        }
        gStats.push_back(st);
    }

    // ---- Optional: live poll current tick info ----
    if (loopTickInfo) {
        STEP("LOOP — polling REQUEST_CURRENT_TICK_INFO every 1s (Ctrl-C to stop)");
        while (true) {
            uint32_t dj = sendPacket(c, REQUEST_CURRENT_TICK_INFO, nullptr, 0, /*hex*/0);
            drainResponses(c, dj, 0, 20, [&](const Packet& p) {
                if (p.hdr.type() == RESPOND_CURRENT_TICK_INFO) { decodeCurrentTickInfo(p); return false; }
                return true;
            });
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    STEP("TIMING SUMMARY — how long it took to get the needed data");
    {
        printf("            %s%-12s %12s %12s %8s %12s  %s%s\n",
               CBOLD, "step", "time-to-1st", "total", "packets", "bytes", "status", CRESET);
        printf("            %s------------ ------------ ------------ -------- ------------  ------%s\n", CGREY, CRESET);
        double sumFirst = 0, sumTotal = 0;
        long   sumBytes = 0;
        for (const auto& s : gStats) {
            const char* color = s.gotData ? CGREEN : CYELLOW;
            char first[24], total[24];
            if (s.gotData) snprintf(first, sizeof first, "%.1fms", s.firstDataMs - s.sentMs);
            else           snprintf(first, sizeof first, "%s", "-");
            snprintf(total, sizeof total, "%.1fms", s.doneMs - s.sentMs);
            printf("            %s%-12s%s %12s %12s %8d %12ld  %s%s%s\n",
                   color, s.name.c_str(), CRESET,
                   first, total, s.items, s.bytes,
                   color, s.gotData ? "OK" : "NO DATA", CRESET);
            if (s.gotData) { sumFirst += (s.firstDataMs - s.sentMs); sumBytes += s.bytes; }
            sumTotal += (s.doneMs - s.sentMs);
        }
        printf("            %s------------ ------------ ------------ -------- ------------  ------%s\n", CGREY, CRESET);
        printf("            %s%-12s %12.1f %12.1f %8s %12ld%s\n",
               CBOLD, "TOTAL (ms)", sumFirst, sumTotal, "", sumBytes, CRESET);
        DETAIL("time-to-1st = request sent → first needed packet decoded");
        DETAIL("total       = request sent → END_RESPONSE / last packet / timeout");
        INFO("Wall-clock since start: %.1fms (includes TCP connect %s)",
             nowMs(), (want("tickinfo")||want("computors")||want("tickdata")||want("votes")||want("txs")) ? "+ all steps" : "");
    }

    STEP("DONE");
    INFO("Probe finished. Review the SEND/RECV lines above; any WARN/ERROR marks a likely incompatibility.");
    c.close_();
    return 0;
}
