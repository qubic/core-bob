// tests/test_LoggingEventProcessor.cpp
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "m256i.h"
#include "structs.h"
#include "logEventCore/LogEvent.h"
#include "Entity.h"
#include "Asset.h"
#include "GlobalVar.h"  // spectrum[], assets[], spectrumDigests[], etc.
#include "logEventCore/LoggingEventProcessorCore.h"

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Build a minimal valid LogEvent with a packed header + body.
// Digest is computed so selfCheck() passes.
static LogEvent makeLogEvent(uint16_t epoch, uint32_t tick, uint8_t type,
                              const void* body, uint32_t bodySize)
{
    // Header layout (26 bytes):
    //   [0..1]  epoch
    //   [2..5]  tick
    //   [6..9]  combo: upper byte = type, lower 24 bits = bodySize
    //   [10..17] logId
    //   [18..25] logDigest  <- KangarooTwelve(body, bodySize, out, 8)
    constexpr size_t HDR = LogEvent::PackedHeaderSize; // 26
    std::vector<uint8_t> buf(HDR + bodySize, 0);

    memcpy(buf.data() + 0, &epoch, 2);
    memcpy(buf.data() + 2, &tick,  4);

    uint32_t combo = (static_cast<uint32_t>(type) << 24) | (bodySize & 0x00FFFFFFu);
    memcpy(buf.data() + 6, &combo, 4);

    uint64_t logId = 0;
    memcpy(buf.data() + 10, &logId, 8);

    if (body && bodySize)
        memcpy(buf.data() + HDR, body, bodySize);

    // Compute digest over body so selfCheck() passes
    uint64_t digest = 0;
    KangarooTwelve(buf.data() + HDR, bodySize, reinterpret_cast<uint8_t*>(&digest), 8);
    memcpy(buf.data() + 18, &digest, 8);

    LogEvent le;
    le.updateContent(buf.data(), static_cast<int>(buf.size()));
    return le;
}

// Seed a spectrum slot for a given public key with the given balance.
// Returns the spectrum index used.
static int seedSpectrum(const m256i& pk, long long balance)
{
    unsigned int idx = pk.m256i_u32[0] & (SPECTRUM_CAPACITY - 1);
    // Linear probe to find empty slot (mirrors the real algorithm)
    while (!isZero(spectrum[idx].publicKey) && !(spectrum[idx].publicKey == pk))
        idx = (idx + 1) & (SPECTRUM_CAPACITY - 1);

    spectrum[idx].publicKey         = pk;
    spectrum[idx].incomingAmount    = balance;
    spectrum[idx].outgoingAmount    = 0;
    spectrum[idx].numberOfIncomingTransfers = 1;
    spectrum[idx].numberOfOutgoingTransfers = 0;
    spectrum[idx].latestIncomingTransferTick = 1;
    spectrum[idx].latestOutgoingTransferTick = 0;
    return static_cast<int>(idx);
}

// ─────────────────────────────────────────────────────────────────────────────
// Base fixture: wipes spectrum and assets before every test
// ─────────────────────────────────────────────────────────────────────────────

class LogProcessorTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(spectrum,          0, SPECTRUM_CAPACITY * sizeof(EntityRecord));
        memset(assets,            0, ASSETS_CAPACITY   * sizeof(AssetRecord));
        memset(assetChangeFlags,  0, ASSETS_CAPACITY / 8);
        memset(spectrumChangeFlags, 0, SPECTRUM_CAPACITY / 8);
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// processQuTransfer
// ═════════════════════════════════════════════════════════════════════════════

class QuTransferTest : public LogProcessorTest {};

TEST_F(QuTransferTest, ValidSource_MovesBalance) {
    m256i src(1, 0, 0, 0), dst(2, 0, 0, 0);
    seedSpectrum(src, 1000LL);

    QuTransfer qt{src, dst, 400LL};
    processQuTransfer(qt, 10);

    int si = spectrumIndex(src);
    ASSERT_NE(si, -1);
    EXPECT_EQ(energy(si), 600LL);   // 1000 - 400

    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 400LL);
}

TEST_F(QuTransferTest, InvalidSource_ZeroKey_OnlyIncreasesDestination) {
    m256i dst(3, 0, 0, 0);
    // source = zero key → spectrumIndex returns -1
    QuTransfer qt{m256i::zero(), dst, 100LL};
    processQuTransfer(qt, 20);

    // destination receives funds
    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 100LL);
}

TEST_F(QuTransferTest, SourceNotInSpectrum_OnlyIncreasesDestination) {
    // src has a non-zero key but was never seeded → spectrumIndex returns -1
    m256i src(99, 0, 0, 0), dst(5, 0, 0, 0);
    QuTransfer qt{src, dst, 50LL};
    processQuTransfer(qt, 30);

    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 50LL);
}

TEST_F(QuTransferTest, ZeroAmount_NoBalanceChange) {
    m256i src(6, 0, 0, 0), dst(7, 0, 0, 0);
    seedSpectrum(src, 500LL);

    QuTransfer qt{src, dst, 0LL};
    processQuTransfer(qt, 40);

    int si = spectrumIndex(src);
    EXPECT_EQ(energy(si), 500LL);  // unchanged

    // dst created with 0 balance
    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 0LL);
}

TEST_F(QuTransferTest, InsufficientBalance_DecreaseEnergyFails_DestinationStillReceives) {
    // decreaseEnergy returns false when balance < amount, but increaseEnergy is still called
    m256i src(8, 0, 0, 0), dst(9, 0, 0, 0);
    seedSpectrum(src, 10LL);

    QuTransfer qt{src, dst, 9999LL};
    processQuTransfer(qt, 50);

    // src balance unchanged (decrease failed)
    int si = spectrumIndex(src);
    EXPECT_EQ(energy(si), 10LL);

    // dst still receives (processQuTransfer always calls increaseEnergy)
    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 9999LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processQuBurn
// ═════════════════════════════════════════════════════════════════════════════

class QuBurnTest : public LogProcessorTest {};

TEST_F(QuBurnTest, ValidSource_ReducesBalance) {
    m256i src(10, 0, 0, 0);
    seedSpectrum(src, 800LL);

    Burning b{src, 300LL, 0};
    LogEvent le = makeLogEvent(1, 100, 8 /*BURNING*/, &b, sizeof(b));

    processQuBurn(le);

    int si = spectrumIndex(src);
    ASSERT_NE(si, -1);
    EXPECT_EQ(energy(si), 500LL);
}

TEST_F(QuBurnTest, ZeroKey_NoChange) {
    Burning b{m256i::zero(), 100LL, 0};
    LogEvent le = makeLogEvent(1, 100, 8, &b, sizeof(b));

    processQuBurn(le);
    // Nothing to assert beyond "no crash"; zero key → spectrumIndex == -1 → no-op
}

TEST_F(QuBurnTest, SourceNotInSpectrum_NoChange) {
    m256i src(77, 0, 0, 0);
    // not seeded
    Burning b{src, 50LL, 0};
    LogEvent le = makeLogEvent(1, 100, 8, &b, sizeof(b));

    processQuBurn(le);
    EXPECT_EQ(spectrumIndex(src), -1);
}

TEST_F(QuBurnTest, BurnMoreThanBalance_BalanceUnchanged) {
    m256i src(11, 0, 0, 0);
    seedSpectrum(src, 100LL);

    Burning b{src, 9999LL, 0};
    LogEvent le = makeLogEvent(1, 100, 8, &b, sizeof(b));

    processQuBurn(le);

    int si = spectrumIndex(src);
    EXPECT_EQ(energy(si), 100LL);  // decreaseEnergy rejected
}

// ═════════════════════════════════════════════════════════════════════════════
// processDistributeDividends
// ═════════════════════════════════════════════════════════════════════════════

class DistributeDividendsTest : public LogProcessorTest {};

// Build a QU_TRANSFER LogEvent from a QuTransfer value
static LogEvent makeQtEvent(uint16_t epoch, uint32_t tick, const QuTransfer& qt) {
    return makeLogEvent(epoch, tick, 0 /*QU_TRANSFER*/, &qt, sizeof(qt));
}

TEST_F(DistributeDividendsTest, EmptyVector_ReturnsTrue) {
    std::vector<LogEvent> vle;
    EXPECT_TRUE(processDistributeDividends(vle));
}

TEST_F(DistributeDividendsTest, NonQUTransferEntry_ReturnsFalse) {
    Burning b{m256i(1,0,0,0), 100LL, 0};
    LogEvent le = makeLogEvent(1, 100, 8 /*BURNING*/, &b, sizeof(b));
    std::vector<LogEvent> vle = {le};

    EXPECT_FALSE(processDistributeDividends(vle));
}

TEST_F(DistributeDividendsTest, MismatchedSources_ReturnsFalse) {
    m256i src1(20, 0, 0, 0), src2(21, 0, 0, 0), dst(22, 0, 0, 0);
    seedSpectrum(src1, 1000LL);
    seedSpectrum(src2, 1000LL);

    QuTransfer qt1{src1, dst, 100LL};
    QuTransfer qt2{src2, dst, 200LL};  // different source!

    std::vector<LogEvent> vle = {
        makeQtEvent(1, 100, qt1),
        makeQtEvent(1, 100, qt2),
    };
    EXPECT_FALSE(processDistributeDividends(vle));
}

TEST_F(DistributeDividendsTest, SourceNotInSpectrum_ReturnsFalse) {
    m256i src(30, 0, 0, 0), dst(31, 0, 0, 0);
    // src not seeded

    QuTransfer qt{src, dst, 100LL};
    std::vector<LogEvent> vle = { makeQtEvent(1, 100, qt) };

    EXPECT_FALSE(processDistributeDividends(vle));
}

TEST_F(DistributeDividendsTest, ValidDistribution_DeductsTotalAndDistributes) {
    m256i src(40, 0, 0, 0);
    m256i dst1(41, 0, 0, 0), dst2(42, 0, 0, 0);
    seedSpectrum(src, 1000LL);

    QuTransfer qt1{src, dst1, 300LL};
    QuTransfer qt2{src, dst2, 700LL};
    std::vector<LogEvent> vle = {
        makeQtEvent(1, 200, qt1),
        makeQtEvent(1, 200, qt2),
    };

    EXPECT_TRUE(processDistributeDividends(vle));

    int si = spectrumIndex(src);
    EXPECT_EQ(energy(si), 0LL);   // 1000 - (300+700)

    int d1 = spectrumIndex(dst1);
    ASSERT_NE(d1, -1);
    EXPECT_EQ(energy(d1), 300LL);

    int d2 = spectrumIndex(dst2);
    ASSERT_NE(d2, -1);
    EXPECT_EQ(energy(d2), 700LL);
}

TEST_F(DistributeDividendsTest, SingleRecipient_Works) {
    m256i src(50, 0, 0, 0), dst(51, 0, 0, 0);
    seedSpectrum(src, 500LL);

    QuTransfer qt{src, dst, 500LL};
    std::vector<LogEvent> vle = { makeQtEvent(1, 300, qt) };

    EXPECT_TRUE(processDistributeDividends(vle));
    EXPECT_EQ(energy(spectrumIndex(src)), 0LL);
    EXPECT_EQ(energy(spectrumIndex(dst)), 500LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processIssueAsset
// ═════════════════════════════════════════════════════════════════════════════

class IssueAssetTest : public LogProcessorTest {};

TEST_F(IssueAssetTest, BasicIssuance_CreatesRecords) {
    m256i issuer(60, 0, 0, 0);

    AssetIssuance ai{};
    ai.issuerPublicKey        = issuer;
    ai.numberOfShares         = 1000000LL;
    ai.managingContractIndex  = 1;
    memcpy(ai.name, "MYTKN\0\0", 7);
    ai.numberOfDecimalPlaces  = 0;
    memset(ai.unitOfMeasurement, 0, 7);

    LogEvent le = makeLogEvent(1, 400, 1 /*ASSET_ISSUANCE*/, &ai, sizeof(ai));

    processIssueAsset(le);

    long long ownerBal, possBal;
    uint64_t assetName = 0;
    memcpy(&assetName, ai.name, 7);
    getAssetBalances(issuer, issuer, assetName, 1, ownerBal, possBal);

    EXPECT_EQ(ownerBal, 1000000LL);
    EXPECT_EQ(possBal,  1000000LL);
}

TEST_F(IssueAssetTest, DuplicateIssuance_SecondCallIsNoOp) {
    m256i issuer(61, 0, 0, 0);

    AssetIssuance ai{};
    ai.issuerPublicKey        = issuer;
    ai.numberOfShares         = 500LL;
    ai.managingContractIndex  = 0;
    memcpy(ai.name, "DUPTK\0\0", 7);

    LogEvent le = makeLogEvent(1, 401, 1, &ai, sizeof(ai));
    processIssueAsset(le);
    processIssueAsset(le);  // second call → issueAsset returns 0

    uint64_t assetName = 0;
    memcpy(&assetName, ai.name, 7);
    long long ownerBal, possBal;
    getAssetBalances(issuer, issuer, assetName, 0, ownerBal, possBal);

    // Still only the original shares, not doubled
    EXPECT_EQ(ownerBal, 500LL);
    EXPECT_EQ(possBal,  500LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processChangeOwnershipAndPossession
// ═════════════════════════════════════════════════════════════════════════════

class OwnershipPossessionTest : public LogProcessorTest {};

// Helper: issue an asset and return its name as uint64
static uint64_t issueTestAsset(const m256i& issuer, const char* name,
                                long long shares, uint16_t managingContractIndex)
{
    AssetIssuance ai{};
    ai.issuerPublicKey       = issuer;
    ai.numberOfShares        = shares;
    ai.managingContractIndex = managingContractIndex;
    memcpy(ai.name, name, 7);

    int ii, oi, pi;
    issueAsset(ai.issuerPublicKey, ai.name, ai.numberOfDecimalPlaces,
               ai.unitOfMeasurement, ai.numberOfShares,
               static_cast<unsigned short>(ai.managingContractIndex),
               &ii, &oi, &pi);

    uint64_t assetName = 0;
    memcpy(&assetName, name, 7);
    return assetName;
}

TEST_F(OwnershipPossessionTest, OwnershipFirst_TransfersShares) {
    m256i issuer(70, 0, 0, 0);
    m256i newOwner(71, 0, 0, 0);
    uint64_t assetName = issueTestAsset(issuer, "TRNSFR\0", 1000LL, 1);

    // Build matching ownership + possession change events
    AssetOwnershipChange aoc{};
    aoc.sourcePublicKey      = issuer;
    aoc.destinationPublicKey = newOwner;
    aoc.issuerPublicKey      = issuer;
    aoc.numberOfShares       = 1000LL;
    aoc.managingContractIndex = 1;
    memcpy(aoc.name, "TRNSFR\0", 7);

    // AssetPossessionChange has identical layout for the fields we compare
    AssetPossessionChange apc{};
    memcpy(&apc, &aoc, sizeof(aoc));

    LogEvent le0 = makeLogEvent(1, 500, 2 /*ASSET_OWNERSHIP_CHANGE*/,  &aoc, sizeof(aoc));
    LogEvent le1 = makeLogEvent(1, 500, 3 /*ASSET_POSSESSION_CHANGE*/, &apc, sizeof(apc));

    processChangeOwnershipAndPossession(le0, le1);

    long long ownerBal, possBal;
    getAssetBalances(newOwner, issuer, assetName, 1, ownerBal, possBal);
    EXPECT_EQ(ownerBal, 1000LL);
    EXPECT_EQ(possBal,  1000LL);
}

TEST_F(OwnershipPossessionTest, PossessionFirst_OrderIndependent) {
    m256i issuer(72, 0, 0, 0);
    m256i newOwner(73, 0, 0, 0);
    uint64_t assetName = issueTestAsset(issuer, "ORDTST\0", 500LL, 2);

    AssetOwnershipChange aoc{};
    aoc.sourcePublicKey      = issuer;
    aoc.destinationPublicKey = newOwner;
    aoc.issuerPublicKey      = issuer;
    aoc.numberOfShares       = 500LL;
    aoc.managingContractIndex = 2;
    memcpy(aoc.name, "ORDTST\0", 7);

    AssetPossessionChange apc{};
    memcpy(&apc, &aoc, sizeof(aoc));

    // Swap: possession comes first
    LogEvent le0 = makeLogEvent(1, 501, 3 /*ASSET_POSSESSION_CHANGE*/, &apc, sizeof(apc));
    LogEvent le1 = makeLogEvent(1, 501, 2 /*ASSET_OWNERSHIP_CHANGE*/,  &aoc, sizeof(aoc));

    processChangeOwnershipAndPossession(le0, le1);

    long long ownerBal, possBal;
    getAssetBalances(newOwner, issuer, assetName, 2, ownerBal, possBal);
    EXPECT_EQ(ownerBal, 500LL);
    EXPECT_EQ(possBal,  500LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// quorum threshold logic (pure arithmetic, no globals needed)
// ═════════════════════════════════════════════════════════════════════════════

struct QuorumResult { bool hasTickData; bool matchedQuorum; bool ambiguous; };

static QuorumResult evalQuorum(int emptyTick, int nonEmptyTick, int voteCount) {
    QuorumResult r{false, false, false};
    if      (emptyTick   >= 226) r.hasTickData = false;
    else if (nonEmptyTick >= 451) r.hasTickData = true;
    else { r.ambiguous = true; return r; }

    r.matchedQuorum = r.hasTickData ? (voteCount >= 451) : (voteCount >= 226);
    return r;
}

TEST(QuorumLogic, EmptyTickPath_QuorumReached) {
    auto r = evalQuorum(226, 0, 226);
    EXPECT_FALSE(r.ambiguous);
    EXPECT_FALSE(r.hasTickData);
    EXPECT_TRUE(r.matchedQuorum);
}

TEST(QuorumLogic, EmptyTickPath_QuorumNotReached) {
    auto r = evalQuorum(226, 0, 225);
    EXPECT_FALSE(r.matchedQuorum);
}

TEST(QuorumLogic, NonEmptyTickPath_QuorumReached) {
    auto r = evalQuorum(0, 451, 451);
    EXPECT_TRUE(r.hasTickData);
    EXPECT_TRUE(r.matchedQuorum);
}

TEST(QuorumLogic, NonEmptyTickPath_QuorumNotReached) {
    auto r = evalQuorum(0, 451, 450);
    EXPECT_TRUE(r.hasTickData);
    EXPECT_FALSE(r.matchedQuorum);
}

TEST(QuorumLogic, AmbiguousVotes_FlagsAmbiguous) {
    auto r = evalQuorum(225, 450, 300);  // neither threshold met
    EXPECT_TRUE(r.ambiguous);
}

TEST(QuorumLogic, ExactBoundaries_EmptyTickWins) {
    // 226 empty beats 450 non-empty
    auto r = evalQuorum(226, 450, 226);
    EXPECT_FALSE(r.ambiguous);
    EXPECT_FALSE(r.hasTickData);
    EXPECT_TRUE(r.matchedQuorum);
}

// ═════════════════════════════════════════════════════════════════════════════
// LogEvent structural tests (selfCheck, header parsing)
// ═════════════════════════════════════════════════════════════════════════════

class LogEventTest : public ::testing::Test {};

TEST_F(LogEventTest, WellFormedEvent_SelfCheckPasses) {
    QuTransfer qt{m256i(1,0,0,0), m256i(2,0,0,0), 42LL};
    LogEvent le = makeLogEvent(7, 999, 0 /*QU_TRANSFER*/, &qt, sizeof(qt));

    EXPECT_TRUE(le.selfCheck(7, false));
    EXPECT_EQ(le.getEpoch(), 7);
    EXPECT_EQ(le.getTick(),  999u);
    EXPECT_EQ(le.getType(),  0u);
    EXPECT_EQ(le.getLogSize(), static_cast<uint32_t>(sizeof(QuTransfer)));
}

TEST_F(LogEventTest, WrongEpoch_SelfCheckFails) {
    QuTransfer qt{m256i(1,0,0,0), m256i(2,0,0,0), 1LL};
    LogEvent le = makeLogEvent(5, 100, 0, &qt, sizeof(qt));

    EXPECT_FALSE(le.selfCheck(6, false));  // epoch mismatch
}

TEST_F(LogEventTest, TamperedBody_DigestMismatch_SelfCheckFails) {
    QuTransfer qt{m256i(1,0,0,0), m256i(2,0,0,0), 100LL};
    LogEvent le = makeLogEvent(1, 10, 0, &qt, sizeof(qt));

    // Flip a byte in the body
    auto* raw = le.getRawPtr();
    raw[LogEvent::PackedHeaderSize] ^= 0xFF;

    EXPECT_FALSE(le.selfCheck(1, false));
}

TEST_F(LogEventTest, EmptyContent_SelfCheckFails) {
    LogEvent le;
    EXPECT_FALSE(le.selfCheck(1, false));
}

TEST_F(LogEventTest, CustomMessage_Parsed) {
    uint64_t msg = 0xDEADBEEFCAFEBABEULL;
    LogEvent le = makeLogEvent(1, 1, 255 /*CUSTOM_MESSAGE*/, &msg, 8);

    EXPECT_TRUE(le.selfCheck(1, false));
    EXPECT_EQ(le.getCustomMessage(), msg);
}

TEST_F(LogEventTest, CustomMessage_WrongSize_ReturnsZero) {
    uint32_t shortMsg = 0x12345678;
    LogEvent le = makeLogEvent(1, 1, 255, &shortMsg, 4);  // only 4 bytes, need 8

    // selfCheck will fail (body too small for CUSTOM_MESSAGE min=8)
    EXPECT_FALSE(le.selfCheck(1, false));
    EXPECT_EQ(le.getCustomMessage(), 0ULL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processQuTransfer (LogEvent overload)
// ═════════════════════════════════════════════════════════════════════════════

class QuTransferLogEventTest : public LogProcessorTest {};

TEST_F(QuTransferLogEventTest, ValidEvent_MovesBalance) {
    m256i src(200, 0, 0, 0), dst(201, 0, 0, 0);
    seedSpectrum(src, 1000LL);

    QuTransfer qt{src, dst, 300LL};
    LogEvent le = makeLogEvent(1, 10, 0 /*QU_TRANSFER*/, &qt, sizeof(qt));

    processQuTransfer(le);

    EXPECT_EQ(energy(spectrumIndex(src)), 700LL);
    EXPECT_EQ(energy(spectrumIndex(dst)), 300LL);
}

TEST_F(QuTransferLogEventTest, TickPropagated_ToIncrease) {
    // Verify the tick from the LogEvent header is forwarded to increaseEnergy
    // by checking the destination's latestIncomingTransferTick after the call.
    m256i src(202, 0, 0, 0), dst(203, 0, 0, 0);
    seedSpectrum(src, 500LL);

    QuTransfer qt{src, dst, 100LL};
    LogEvent le = makeLogEvent(1, 42 /*tick*/, 0, &qt, sizeof(qt));

    processQuTransfer(le);

    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(spectrum[di].latestIncomingTransferTick, 42u);
}

TEST_F(QuTransferLogEventTest, ZeroSourceKey_OnlyCreditsDestination) {
    m256i dst(204, 0, 0, 0);
    QuTransfer qt{m256i::zero(), dst, 50LL};
    LogEvent le = makeLogEvent(1, 5, 0, &qt, sizeof(qt));

    processQuTransfer(le);

    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 50LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processChangeManagingContract
// ═════════════════════════════════════════════════════════════════════════════

class ChangeManagingContractTest : public LogProcessorTest {};

// Helper: build AssetOwnershipManagingContractChange / AssetPossessionManagingContractChange
// and wrap them in LogEvents with the right type codes.
static void makeManagingContractEvents(
    const m256i& issuer,
    const m256i& owner,
    const m256i& possessor,
    const char*  name,
    long long    nshares,
    uint16_t     srcContract,
    uint16_t     dstContract,
    LogEvent&    outOwnership,
    LogEvent&    outPossession)
{
    AssetOwnershipManagingContractChange omcc{};
    omcc.issuerPublicKey         = issuer;
    omcc.ownershipPublicKey      = owner;
    omcc.numberOfShares          = nshares;
    omcc.sourceContractIndex     = srcContract;
    omcc.destinationContractIndex = dstContract;
    memcpy(omcc.assetName, name, 7);

    AssetPossessionManagingContractChange pmcc{};
    pmcc.issuerPublicKey          = issuer;
    pmcc.ownershipPublicKey       = owner;
    pmcc.possessionPublicKey      = possessor;
    pmcc.numberOfShares           = nshares;
    pmcc.sourceContractIndex      = srcContract;
    pmcc.destinationContractIndex = dstContract;
    memcpy(pmcc.assetName, name, 7);

    outOwnership  = makeLogEvent(1, 600, ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE, &omcc, sizeof(omcc));
    outPossession = makeLogEvent(1, 600, ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE, &pmcc, sizeof(pmcc));
}

TEST_F(ChangeManagingContractTest, OwnershipFirst_TransfersManagementRights) {
    m256i issuer(80, 0, 0, 0);
    uint64_t assetName = issueTestAsset(issuer, "MGRTST\0", 1000LL, 1 /*srcContract*/);

    LogEvent le0, le1;
    makeManagingContractEvents(issuer, issuer, issuer, "MGRTST\0",
                               1000LL, 1 /*src*/, 2 /*dst*/, le0, le1);

    processChangeManagingContract(le0, le1);

    // After transfer, shares should be managed by contract 2
    long long ownerBal, possBal;
    getAssetBalances(issuer, issuer, assetName, 2 /*new contract*/, ownerBal, possBal);
    EXPECT_EQ(ownerBal, 1000LL);
    EXPECT_EQ(possBal,  1000LL);
}

TEST_F(ChangeManagingContractTest, PossessionFirst_OrderIndependent) {
    m256i issuer(81, 0, 0, 0);
    uint64_t assetName = issueTestAsset(issuer, "MGRORD\0", 500LL, 3 /*srcContract*/);

    LogEvent leOwnership, lePossession;
    makeManagingContractEvents(issuer, issuer, issuer, "MGRORD\0",
                               500LL, 3 /*src*/, 4 /*dst*/, leOwnership, lePossession);

    // Swap order: possession event first
    processChangeManagingContract(lePossession, leOwnership);

    long long ownerBal, possBal;
    getAssetBalances(issuer, issuer, assetName, 4 /*new contract*/, ownerBal, possBal);
    EXPECT_EQ(ownerBal, 500LL);
    EXPECT_EQ(possBal,  500LL);
}

// ═════════════════════════════════════════════════════════════════════════════
// processSendToManyBenchmark
// ═════════════════════════════════════════════════════════════════════════════

class SendToManyBenchmarkTest : public LogProcessorTest {};

// The QUTIL benchmark log body layout (mirrors the struct in the .cpp):
struct QUTILSendToManyBenchmarkLog {
    uint32_t contractId;
    uint32_t logType;
    m256i    startId;
    int64_t  dstCount;
    int64_t  numTransfersEach;
};

// CONTRACT_INFORMATION_MESSAGE = 12 (adjust if your enum differs)
static constexpr uint8_t CONTRACT_INFORMATION_MESSAGE_TYPE = 12;
static constexpr uint32_t QUTIL_STMB_LOG_TYPE_VALUE = 2; // value used in production code

static LogEvent makeStmbEvent(uint16_t epoch, uint32_t tick,
                              const m256i& startId,
                              int64_t dstCount,
                              int64_t numTransfersEach)
{
    QUTILSendToManyBenchmarkLog body{};
    body.contractId       = 4;                    // scIndex == 4 triggers the branch
    body.logType          = QUTIL_STMB_LOG_TYPE_VALUE;
    body.startId          = startId;
    body.dstCount         = dstCount;
    body.numTransfersEach = numTransfersEach;
    return makeLogEvent(epoch, tick, CONTRACT_INFORMATION_MESSAGE_TYPE, &body, sizeof(body));
}

TEST_F(SendToManyBenchmarkTest, ReturnsTrue) {
    // Seed a few destination addresses near the startId so qpi_next_id finds them
    m256i startId(300, 0, 0, 0);
    m256i dst1(301, 0, 0, 0);
    m256i dst2(302, 0, 0, 0);
    seedSpectrum(dst1, 0LL);
    seedSpectrum(dst2, 0LL);

    // Source is hardcoded in processSendToManyBenchmark as m256i(4,0,0,0)
    m256i benchSrc(4, 0, 0, 0);
    seedSpectrum(benchSrc, 100000LL);

    LogEvent le = makeStmbEvent(1, 700, startId, 2 /*dstCount*/, 1 /*transfersEach*/);
    EXPECT_TRUE(processSendToManyBenchmark(le));
}

TEST_F(SendToManyBenchmarkTest, ZeroDstCount_NoTransfers_ReturnsTrue) {
    m256i startId(400, 0, 0, 0);
    m256i benchSrc(4, 0, 0, 0);
    seedSpectrum(benchSrc, 50000LL);

    LogEvent le = makeStmbEvent(1, 701, startId, 0 /*dstCount*/, 5);
    EXPECT_TRUE(processSendToManyBenchmark(le));

    // Source balance must be unchanged because dstCount == 0 → no transfers
    int si = spectrumIndex(benchSrc);
    ASSERT_NE(si, -1);
    EXPECT_EQ(energy(si), 50000LL);
}

TEST_F(SendToManyBenchmarkTest, MultipleTransfersEach_CreditsDestinations) {
    m256i startId(500, 0, 0, 0);
    int startSlot = seedSpectrum(startId, 0LL);

    // Find a dst key whose natural slot is > startSlot
    m256i dst;
    int dstSlot = -1;
    for (uint32_t k = 501; k < 100000u; ++k) {
        m256i candidate(k, 0, 0, 0);
        unsigned int slot = candidate.m256i_u32[0] & (SPECTRUM_CAPACITY - 1);
        if (static_cast<int>(slot) > startSlot) {
            dst = candidate;
            dstSlot = static_cast<int>(slot);
            break;
        }
    }
    ASSERT_NE(dstSlot, -1) << "Could not find a dst key with slot > startSlot";
    seedSpectrum(dst, 0LL);

    m256i benchSrc(4, 0, 0, 0);
    seedSpectrum(benchSrc, 100000LL);

    // 1 destination, 3 transfers of 1 QU each → dst gets 3 QU total
    LogEvent le = makeStmbEvent(1, 702, startId, 1, 3);
    EXPECT_TRUE(processSendToManyBenchmark(le));

    int di = spectrumIndex(dst);
    ASSERT_NE(di, -1);
    EXPECT_EQ(energy(di), 3LL);
}