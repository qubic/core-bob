// tests/test_bad_peer.cpp
#include <gtest/gtest.h>
#include <cstring>

#include "connection/connection.h"
#include "RequestMap.h"
#include "spdlogDriver/Logger.h"

TEST(BadPeer, BadSampleNeedsEnoughTraffic)
{
    EXPECT_FALSE(isBadSample(14, 0)); // too few requests, no verdict
    EXPECT_FALSE(isBadSample(16, 8)); // exactly half answered is still fine
    EXPECT_TRUE(isBadSample(16, 7));
    EXPECT_FALSE(isBadSample(100, 97));
    EXPECT_TRUE(isBadSample(100, 0));
}

TEST(BadPeer, LogRequestTypesOnly)
{
    EXPECT_TRUE(isLogRequestType(RequestLog::type()));
    EXPECT_FALSE(isLogRequestType(RequestAllLogIdRangesFromTick::type())); // healthy bobs END future ticks
    EXPECT_FALSE(isLogRequestType(RequestedQuorumTick::type));
    EXPECT_FALSE(isLogRequestType(END_RESPONSE));
}

TEST(BadPeer, ServedLogAnswerNeedsPayload)
{
    const size_t headerSize = sizeof(RequestResponseHeader);
    EXPECT_TRUE(isServedLogAnswer(RespondLog::type(), headerSize + 1));
    EXPECT_FALSE(isServedLogAnswer(RespondLog::type(), headerSize)); // empty RespondLog = no logs
    EXPECT_FALSE(isServedLogAnswer(END_RESPONSE, headerSize));
    EXPECT_FALSE(isServedLogAnswer(LogRangesPerTxInTick::type(), headerSize + 100));
}

TEST(BadPeer, FlagClearedOnReplace)
{
    Logger::init("off");
    {
        // port 1 on loopback is refused right away, object stays valid with an invalid socket
        QubicConnection conn("127.0.0.1", 1);
        EXPECT_FALSE(conn.isBad());

        conn.markBad(BadPeerKind::Unresponsive);
        EXPECT_TRUE(conn.isBad());
        EXPECT_EQ(conn.getBadKind(), BadPeerKind::Unresponsive);

        conn.replacePeer("1.2.3.4", 1);
        EXPECT_FALSE(conn.isBad());
        EXPECT_EQ(conn.getBadKind(), BadPeerKind::None);
        EXPECT_STREQ(conn.getNodeIp(), "1.2.3.4");
    }
    // release the "bob" logger so later fixtures can init it again
    spdlog::shutdown();
}

TEST(RequestMapAge, UpdateConnReturnsAgeAndType)
{
    RequestMap map;
    RequestResponseHeader header{};
    header.setType(RequestLog::type());
    header.setSize(sizeof(RequestResponseHeader));
    header.setDejavu(7);
    map.add(7, reinterpret_cast<const uint8_t*>(&header), sizeof(header), nullptr);

    uint8_t requestType = 0;
    EXPECT_EQ(map.updateConn(7, nullptr, requestType), 0);
    EXPECT_EQ(requestType, RequestLog::type());
    EXPECT_EQ(map.updateConn(8, nullptr, requestType), -1);
}
